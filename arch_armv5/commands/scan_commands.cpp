/*
 * ARMv5 Scan Commands
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This file implements plugin commands for running firmware analysis scans.
 * Commands are accessible via:
 *   - Command Palette (Ctrl/Cmd + P)
 *   - Right-click menu (Plugins > ARMv5 > ...)
 *   - Scripting API
 *
 * ============================================================================
 * IMPLEMENTATION NOTES
 * ============================================================================
 *
 * Each command:
 * 1. Validates the view is an ARMv5/Firmware view
 * 2. Loads settings (global + per-file overrides)
 * 3. Creates a background task for progress feedback
 * 4. Runs the scan in a background thread
 * 5. Applies results to the view
 *
 * The IsValid callback controls when commands appear in menus.
 *
 * ============================================================================
 */

#include "scan_commands.h"
#include "firmware/firmware_internal.h"
#include "firmware/firmware_settings.h"
#include "firmware/firmware_view.h"
#include "firmware/firmware_scan_job.h"
#include "analysis/rtos_detector.h"
#include "settings/plugin_settings.h"
#include "common/armv5_utils.h"

#include <thread>
#include <fstream>
#include <regex>
#include <set>

using namespace BinaryNinja;
using namespace armv5;

namespace
{

/**
 * Resolve the correct platform (ARM or Thumb) for an address.
 * 
 * Only detects Thumb when bit 0 is explicitly set. For pure ARM binaries,
 * addresses that are 2-byte aligned but not 4-byte aligned are invalid.
 */
static Ref<Platform> ResolvePlatformForAddress(
	const Ref<BinaryView>& view,
	uint64_t addr)
{
	Ref<Platform> basePlat = view->GetDefaultPlatform();
	if (!basePlat)
		return basePlat;

	Ref<Architecture> baseArch = view->GetDefaultArchitecture();
	if (!baseArch)
		return basePlat;

	// Only detect Thumb if bit 0 is explicitly set
	uint64_t tempAddr = addr;
	Ref<Architecture> targetArch = baseArch->GetAssociatedArchitectureByAddress(tempAddr);
	if (targetArch && targetArch != baseArch)
	{
		Ref<Platform> related = basePlat->GetRelatedPlatform(targetArch);
		if (related)
			return related;
	}

	return basePlat;
}

/*
 * Check if a view is valid for ARMv5 commands.
 * Commands work on both firmware views and ELF/raw binaries with ARMv5 arch.
 */
bool IsArmv5View(BinaryView* view)
{
	if (!view)
		return false;

	// Accept ARMv5 Firmware views
	std::string typeName = view->GetTypeName();
	if (typeName == "ARMv5 Firmware")
		return true;

	// Accept other views with ARMv5 architecture
	Ref<Architecture> arch = view->GetDefaultArchitecture();
	if (!arch)
		return false;

	std::string archName = arch->GetName();
	return archName == "armv5" || archName == "armv5t";
}

/*
 * Check if a view is specifically a firmware view.
 * Some commands (like running all scans) only make sense on firmware views.
 */
bool IsFirmwareView(BinaryView* view)
{
	if (!view)
		return false;
	return view->GetTypeName() == "ARMv5 Firmware";
}

/*
 * Load settings with global + per-file merging.
 * Global settings (armv5.firmware.*) provide defaults.
 * Per-file settings (loader.armv5.firmware.*) override when present.
 */
FirmwareSettings LoadMergedSettings(BinaryView* view)
{
	// Start with defaults
	FirmwareSettings settings = DefaultFirmwareSettings(FirmwareSettingsMode::Command);

	// Apply global settings
	Ref<Settings> globalSettings = Settings::Instance();
	if (globalSettings)
	{
		// Scan toggles
		if (globalSettings->Contains("armv5.firmware.scanPrologues"))
			settings.enablePrologueScan = globalSettings->Get<bool>("armv5.firmware.scanPrologues");
		if (globalSettings->Contains("armv5.firmware.scanCallTargets"))
			settings.enableCallTargetScan = globalSettings->Get<bool>("armv5.firmware.scanCallTargets");
		if (globalSettings->Contains("armv5.firmware.scanPointerTargets"))
			settings.enablePointerTargetScan = globalSettings->Get<bool>("armv5.firmware.scanPointerTargets");
		if (globalSettings->Contains("armv5.firmware.scanOrphanCode"))
			settings.enableOrphanCodeScan = globalSettings->Get<bool>("armv5.firmware.scanOrphanCode");

		// Orphan tuning
		if (globalSettings->Contains("armv5.firmware.orphanMinValidInstr"))
			settings.orphanMinValidInstr = static_cast<uint32_t>(globalSettings->Get<uint64_t>("armv5.firmware.orphanMinValidInstr"));
		if (globalSettings->Contains("armv5.firmware.orphanMinBodyInstr"))
			settings.orphanMinBodyInstr = static_cast<uint32_t>(globalSettings->Get<uint64_t>("armv5.firmware.orphanMinBodyInstr"));
		if (globalSettings->Contains("armv5.firmware.orphanMinSpacingBytes"))
			settings.orphanMinSpacingBytes = static_cast<uint32_t>(globalSettings->Get<uint64_t>("armv5.firmware.orphanMinSpacingBytes"));
		if (globalSettings->Contains("armv5.firmware.orphanMaxPerPage"))
			settings.orphanMaxPerPage = static_cast<uint32_t>(globalSettings->Get<uint64_t>("armv5.firmware.orphanMaxPerPage"));
		if (globalSettings->Contains("armv5.firmware.orphanRequirePrologue"))
			settings.orphanRequirePrologue = globalSettings->Get<bool>("armv5.firmware.orphanRequirePrologue");

		// Limits
		if (globalSettings->Contains("armv5.firmware.maxFunctionAdds"))
			settings.maxFunctionAdds = static_cast<uint32_t>(globalSettings->Get<uint64_t>("armv5.firmware.maxFunctionAdds"));

		// Cleanup
		if (globalSettings->Contains("armv5.firmware.cleanupInvalidFunctions"))
			settings.enableInvalidFunctionCleanup = globalSettings->Get<bool>("armv5.firmware.cleanupInvalidFunctions");
		if (globalSettings->Contains("armv5.firmware.cleanupMaxSize"))
			settings.cleanupMaxSizeBytes = static_cast<uint32_t>(globalSettings->Get<uint64_t>("armv5.firmware.cleanupMaxSize"));

		// Advanced
		if (globalSettings->Contains("armv5.firmware.typeLiteralPools"))
			settings.enableLiteralPoolTyping = globalSettings->Get<bool>("armv5.firmware.typeLiteralPools");
		if (globalSettings->Contains("armv5.firmware.clearAutoDataOnCodeRefs"))
			settings.enableClearAutoDataOnCodeRefs = globalSettings->Get<bool>("armv5.firmware.clearAutoDataOnCodeRefs");
		if (globalSettings->Contains("armv5.firmware.disablePointerSweep"))
			settings.disablePointerSweep = globalSettings->Get<bool>("armv5.firmware.disablePointerSweep");
		if (globalSettings->Contains("armv5.firmware.disableLinearSweep"))
			settings.disableLinearSweep = globalSettings->Get<bool>("armv5.firmware.disableLinearSweep");
		if (globalSettings->Contains("armv5.firmware.verboseLogging"))
			settings.enableVerboseLogging = globalSettings->Get<bool>("armv5.firmware.verboseLogging");
		if (globalSettings->Contains("armv5.firmware.skipFirmwareScans"))
			settings.skipFirmwareScans = globalSettings->Get<bool>("armv5.firmware.skipFirmwareScans");
	}

	// Apply per-file overrides (loader.armv5.firmware.*)
	if (view)
	{
		Ref<Settings> loadSettings = view->GetLoadSettings(view->GetTypeName());
		if (loadSettings)
			settings = LoadFirmwareSettings(loadSettings, view, FirmwareSettingsMode::Command);
	}

	return settings;
}

/*
 * Get the logger for scan commands.
 */
Ref<Logger> GetCommandLogger()
{
	return LogRegistry::CreateLogger("BinaryView.ARMv5Commands");
}

/*
 * Show a notification to the user.
 */
void ShowNotification(const std::string& message)
{
	// Use the log window - Binary Ninja doesn't have a simple notification API
	Ref<Logger> logger = GetCommandLogger();
	if (logger)
		logger->LogInfo("%s", message.c_str());
}

}  // anonymous namespace

namespace Armv5Commands
{

/*
 * Command: Run All Firmware Scans
 *
 * Re-runs all firmware analysis passes using current settings.
 */
static void RunAllFirmwareScans(BinaryView* view)
{
	if (!view)
		return;

	Ref<Logger> logger = GetCommandLogger();
	if (logger)
		logger->LogInfo("Running all firmware scans...");

	// Schedule the scan job (same as workflow callback)
	Ref<BinaryView> viewRef = view;
	ScheduleArmv5FirmwareScanJob(viewRef);
}

static bool RunAllFirmwareScansIsValid(BinaryView* view)
{
	return IsFirmwareView(view);
}

/*
 * Command: Detect RTOS
 *
 * Runs RTOS detection and applies type definitions.
 */
static void RunRTOSDetection(BinaryView* view)
{
	if (!view)
		return;

	Ref<Logger> logger = GetCommandLogger();
	if (logger)
		logger->LogInfo("Running RTOS detection...");

	// Run RTOS detection
	auto result = armv5::RTOSDetector::DetectRTOS(view);

	if (result.type == armv5::RTOSType::Unknown)
	{
		ShowNotification("RTOS detection: No known RTOS detected");
		return;
	}

	// Report findings
	std::string rtosName = armv5::RTOSTypeToString(result.type);
	if (logger)
		logger->LogInfo("RTOS detected: %s (confidence: %u, tasks: %zu)",
			rtosName.c_str(), result.confidence, result.tasks.size());

	// Define types
	armv5::RTOSDetector::DefineRTOSTypes(view, result.type);

	// Apply task conventions and annotate TCBs
	if (!result.tasks.empty())
	{
		armv5::RTOSDetector::ApplyTaskConventions(view, result.tasks);
		armv5::RTOSDetector::AnnotateTCBs(view, result.tasks, result.type);
	}

	ShowNotification("RTOS detected: " + rtosName + " (" + std::to_string(result.tasks.size()) + " tasks)");
}

/*
 * Command: Debug RTOS Detection
 *
 * Shows detailed information about what the RTOS detector finds.
 */
static void DebugRTOSDetection(BinaryView* view)
{
	if (!view)
		return;

	Ref<Logger> logger = GetCommandLogger();
	if (logger)
		logger->LogInfo("=== RTOS Detection Debug ===");

	// Search for Nucleus PLUS specific strings
	auto strings = view->GetStrings();
	size_t nucleusStringCount = 0;
	std::vector<std::string> nucleusPatterns = {
		"nucleus", "nu_", "tcd_", "tmd_", "qud_",
		"mentor", "accelerated"
	};

	if (logger)
		logger->LogInfo("Searching %zu strings for RTOS patterns...", strings.size());

	for (const auto& strRef : strings)
	{
		if (strRef.length > 256)
			continue;  // Skip very long strings

		DataBuffer buf = view->ReadBuffer(strRef.start, strRef.length);
		if (buf.GetLength() == 0)
			continue;

		std::string str(reinterpret_cast<const char*>(buf.GetData()), buf.GetLength());

		// Convert to lowercase for matching
		std::string lowerStr = str;
		std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);

		for (const auto& pattern : nucleusPatterns)
		{
			if (lowerStr.find(pattern) != std::string::npos)
			{
				nucleusStringCount++;
				if (logger)
					logger->LogInfo("  Found RTOS-related string at 0x%llx: \"%s\"",
						(unsigned long long)strRef.start, str.c_str());
				break;
			}
		}
	}

	// Check for symbols
	auto allSymbols = view->GetSymbols();
	size_t nucleusSymbolCount = 0;
	std::vector<std::string> symbolPatterns = {
		"NU_", "TCD_", "TMD_", "QUD_", "EVD_", "SMD_"
	};

	if (logger)
		logger->LogInfo("Searching %zu symbols for RTOS patterns...", allSymbols.size());

	for (const auto& sym : allSymbols)
	{
		std::string name = sym->GetShortName();
		for (const auto& pattern : symbolPatterns)
		{
			if (name.find(pattern) != std::string::npos)
			{
				nucleusSymbolCount++;
				if (logger)
					logger->LogInfo("  Found RTOS-related symbol at 0x%llx: \"%s\"",
						(unsigned long long)sym->GetAddress(), name.c_str());
				break;
			}
		}
	}

	if (logger)
	{
		logger->LogInfo("=== Summary ===");
		logger->LogInfo("  Nucleus-related strings: %zu", nucleusStringCount);
		logger->LogInfo("  Nucleus-related symbols: %zu", nucleusSymbolCount);
		logger->LogInfo("================");
	}

	// Run actual detection
	auto result = armv5::RTOSDetector::DetectRTOS(view);
	if (logger)
	{
		logger->LogInfo("Detection result: %s (confidence: %u)",
			armv5::RTOSTypeToString(result.type), result.confidence);
		if (!result.reason.empty())
			logger->LogInfo("Reason: %s", result.reason.c_str());
	}
}

static bool RunRTOSDetectionIsValid(BinaryView* view)
{
	return IsArmv5View(view);
}

static bool DebugRTOSDetectionIsValid(BinaryView* view)
{
	return IsArmv5View(view);
}

/*
 * Command: Validate Function Detection
 *
 * Loads an IDC file with known function addresses and compares against
 * our detected functions to measure precision and recall.
 */
static void ValidateFunctionDetection(BinaryView* view)
{
	if (!view)
		return;

	Ref<Logger> logger = GetCommandLogger();

	// Prompt for IDC file
	std::string idcPath;
	if (!BinaryNinja::GetOpenFileNameInput(idcPath, "Select IDC file with known functions", "*.idc"))
		return;
	if (idcPath.empty())
		return;

	// Parse IDC file for MakeName entries
	std::map<uint64_t, std::string> knownFunctions;
	std::ifstream idcFile(idcPath);
	if (!idcFile.is_open())
	{
		if (logger)
			logger->LogError("Failed to open IDC file: %s", idcPath.c_str());
		return;
	}

	std::string line;
	std::regex makeNameRegex(R"(MakeName\s*\(\s*0[xX]([0-9A-Fa-f]+)\s*,\s*\"([^\"]+)\"\s*\))");
	while (std::getline(idcFile, line))
	{
		std::smatch match;
		if (std::regex_search(line, match, makeNameRegex))
		{
			uint64_t addr = std::stoull(match[1].str(), nullptr, 16);
			std::string name = match[2].str();
			knownFunctions[addr] = name;
		}
	}
	idcFile.close();

	if (logger)
		logger->LogInfo("Loaded %zu known functions from IDC file", knownFunctions.size());

	// Get our detected functions
	auto detectedFuncs = view->GetAnalysisFunctionList();
	std::set<uint64_t> detectedAddrs;
	for (const auto& func : detectedFuncs)
	{
		if (func)
			detectedAddrs.insert(func->GetStart());
	}

	if (logger)
		logger->LogInfo("We detected %zu functions total", detectedAddrs.size());

	// Calculate metrics
	size_t truePositives = 0;   // Known functions we found
	size_t falseNegatives = 0;  // Known functions we missed
	size_t falsePositives = 0;  // Functions we found that aren't in the known list

	std::vector<std::pair<uint64_t, std::string>> missed;
	std::vector<uint64_t> extraFunctions;

	for (const auto& [addr, name] : knownFunctions)
	{
		if (detectedAddrs.find(addr) != detectedAddrs.end())
		{
			truePositives++;
		}
		else
		{
			falseNegatives++;
			missed.push_back({addr, name});
		}
	}

	// Count functions we found that aren't in the known list
	// (not necessarily false positives - the IDC list may be incomplete)
	for (uint64_t addr : detectedAddrs)
	{
		if (knownFunctions.find(addr) == knownFunctions.end())
		{
			falsePositives++;
			if (extraFunctions.size() < 50)  // Limit output
				extraFunctions.push_back(addr);
		}
	}

	// Calculate precision and recall
	double precision = (truePositives + falsePositives > 0)
		? (double)truePositives / (truePositives + falsePositives) : 0.0;
	double recall = (truePositives + falseNegatives > 0)
		? (double)truePositives / (truePositives + falseNegatives) : 0.0;
	double f1 = (precision + recall > 0)
		? 2.0 * (precision * recall) / (precision + recall) : 0.0;

	if (logger)
	{
		logger->LogInfo("=== Function Detection Validation ===");
		logger->LogInfo("Known functions (ground truth): %zu", knownFunctions.size());
		logger->LogInfo("Detected functions: %zu", detectedAddrs.size());
		logger->LogInfo("");
		logger->LogInfo("True positives (found known): %zu", truePositives);
		logger->LogInfo("False negatives (missed known): %zu", falseNegatives);
		logger->LogInfo("Extra functions (not in ground truth): %zu", falsePositives);
		logger->LogInfo("");
		logger->LogInfo("Recall (coverage of known): %.2f%% (%zu/%zu)",
			recall * 100.0, truePositives, knownFunctions.size());
		logger->LogInfo("Precision (vs ground truth): %.2f%%", precision * 100.0);
		logger->LogInfo("F1 Score: %.2f%%", f1 * 100.0);
		logger->LogInfo("");

		// Show some missed functions
		if (!missed.empty())
		{
			logger->LogInfo("First %zu missed functions:", std::min(missed.size(), (size_t)20));
			for (size_t i = 0; i < std::min(missed.size(), (size_t)20); i++)
			{
				logger->LogInfo("  0x%llx: %s",
					(unsigned long long)missed[i].first, missed[i].second.c_str());
			}
		}

		logger->LogInfo("=====================================");
	}

	// Show a summary notification
	char summary[256];
	snprintf(summary, sizeof(summary),
		"Recall: %.1f%% (%zu/%zu known)\nExtra: %zu functions",
		recall * 100.0, truePositives, knownFunctions.size(), falsePositives);
	ShowNotification(summary);
}

static bool ValidateFunctionDetectionIsValid(BinaryView* view)
{
	return IsArmv5View(view);
}

/*
 * Command: Run Prologue Scan
 *
 * Runs only the function prologue scan pass.
 */
static void RunPrologueScan(BinaryView* view)
{
	if (!view)
		return;

	Ref<Logger> logger = GetCommandLogger();
	FirmwareSettings settings = LoadMergedSettings(view);

	if (logger)
		logger->LogInfo("Running prologue scan...");

	// Create a background task for UI feedback
	Ref<BackgroundTask> task = new BackgroundTask("ARMv5: Prologue Scan", true);

	// Run in background thread
	Ref<BinaryView> viewRef = view;
	std::thread([viewRef, task, settings, logger]() mutable {
		try
		{
			task->SetProgressText("Scanning for function prologues...");

			uint64_t imageBase = viewRef->GetStart();
			uint64_t length = viewRef->GetLength();
			DataBuffer buf = viewRef->ReadBuffer(imageBase, length);
			const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
			uint64_t dataLen = buf.GetLength();

			Ref<Architecture> armArch = viewRef->GetDefaultArchitecture();
			Ref<Architecture> thumbArch;
			if (armArch)
			{
				std::string archName = armArch->GetName();
				if (archName == "armv5")
					thumbArch = Architecture::GetByName("armv5t");
				else if (archName == "armv5t")
				{
					thumbArch = armArch;
					armArch = Architecture::GetByName("armv5");
				}
			}

			std::set<uint64_t> seededFunctions;
			FirmwareScanPlan plan;
			FirmwareScanTuning tuning = settings.tuning;

			size_t found = ScanForFunctionPrologues(viewRef, data, dataLen, viewRef->GetDefaultEndianness(),
				imageBase, length, armArch, thumbArch, viewRef->GetDefaultPlatform(), logger,
				settings.enableVerboseLogging, tuning, settings.codeDataBoundary, &seededFunctions, &plan);

			// Apply results with proper platform resolution and alignment validation
			if (!plan.addFunctions.empty() || !plan.addUserFunctions.empty())
			{
				for (uint64_t addr : plan.addFunctions)
				{
					Ref<Platform> plat = ResolvePlatformForAddress(viewRef, addr);
					uint64_t cleanAddr = addr & ~1ULL;
					if (!IsValidFunctionStart(viewRef, plat, cleanAddr))
						continue;
					viewRef->AddFunctionForAnalysis(plat, cleanAddr);
				}
				for (uint64_t addr : plan.addUserFunctions)
				{
					Ref<Platform> plat = ResolvePlatformForAddress(viewRef, addr);
					uint64_t cleanAddr = addr & ~1ULL;
					if (!IsValidFunctionStart(viewRef, plat, cleanAddr))
						continue;
					viewRef->CreateUserFunction(plat, cleanAddr);
				}
			}

			if (logger)
				logger->LogInfo("Prologue scan complete: found %zu candidates, added %zu functions",
					found, plan.addFunctions.size() + plan.addUserFunctions.size());

			task->SetProgressText("Prologue scan complete");
		}
		catch (const std::exception& e)
		{
			if (logger)
				logger->LogError("Prologue scan failed: %s", e.what());
		}

		try { task->Finish(); } catch (...) {}
	}).detach();
}

static bool RunPrologueScanIsValid(BinaryView* view)
{
	return IsArmv5View(view);
}

/*
 * Command: Run Call Target Scan
 *
 * Runs only the call target scan pass.
 */
static void RunCallTargetScan(BinaryView* view)
{
	if (!view)
		return;

	Ref<Logger> logger = GetCommandLogger();
	FirmwareSettings settings = LoadMergedSettings(view);

	if (logger)
		logger->LogInfo("Running call target scan...");

	Ref<BackgroundTask> task = new BackgroundTask("ARMv5: Call Target Scan", true);
	Ref<BinaryView> viewRef = view;

	std::thread([viewRef, task, settings, logger]() mutable {
		try
		{
			task->SetProgressText("Scanning for call targets...");

			uint64_t imageBase = viewRef->GetStart();
			uint64_t length = viewRef->GetLength();
			DataBuffer buf = viewRef->ReadBuffer(imageBase, length);
			const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
			uint64_t dataLen = buf.GetLength();

			std::set<uint64_t> seededFunctions;
			FirmwareScanPlan plan;
			FirmwareScanTuning tuning = settings.tuning;

			size_t found = ScanForCallTargets(viewRef, data, dataLen, viewRef->GetDefaultEndianness(),
				imageBase, length, viewRef->GetDefaultPlatform(), logger,
				settings.enableVerboseLogging, tuning, settings.codeDataBoundary, &seededFunctions, &plan);

			// Apply results with proper platform resolution and alignment validation
			for (uint64_t addr : plan.addFunctions)
			{
				Ref<Platform> plat = ResolvePlatformForAddress(viewRef, addr);
				uint64_t cleanAddr = addr & ~1ULL;
				if (!IsValidFunctionStart(viewRef, plat, cleanAddr))
					continue;
				viewRef->AddFunctionForAnalysis(plat, cleanAddr);
			}

			if (logger)
				logger->LogInfo("Call target scan complete: found %zu candidates", found);

			task->SetProgressText("Call target scan complete");
		}
		catch (const std::exception& e)
		{
			if (logger)
				logger->LogError("Call target scan failed: %s", e.what());
		}

		try { task->Finish(); } catch (...) {}
	}).detach();
}

static bool RunCallTargetScanIsValid(BinaryView* view)
{
	return IsArmv5View(view);
}

/*
 * Command: Run Pointer Target Scan
 *
 * Runs only the pointer target scan pass.
 */
static void RunPointerTargetScan(BinaryView* view)
{
	if (!view)
		return;

	Ref<Logger> logger = GetCommandLogger();
	FirmwareSettings settings = LoadMergedSettings(view);

	if (logger)
		logger->LogInfo("Running pointer target scan...");

	Ref<BackgroundTask> task = new BackgroundTask("ARMv5: Pointer Target Scan", true);
	Ref<BinaryView> viewRef = view;

	std::thread([viewRef, task, settings, logger]() mutable {
		try
		{
			task->SetProgressText("Scanning for pointer targets...");

			uint64_t imageBase = viewRef->GetStart();
			uint64_t length = viewRef->GetLength();
			DataBuffer buf = viewRef->ReadBuffer(imageBase, length);
			const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
			uint64_t dataLen = buf.GetLength();

			std::set<uint64_t> addedFunctions;
			FirmwareScanPlan plan;
			FirmwareScanTuning tuning = settings.tuning;

			size_t found = ScanForPointerTargets(viewRef, data, dataLen, viewRef->GetDefaultEndianness(),
				imageBase, length, viewRef->GetDefaultPlatform(), logger,
				settings.enableVerboseLogging, tuning, settings.codeDataBoundary, &addedFunctions, &plan);

			// Apply results with proper platform resolution and alignment validation
			for (uint64_t addr : plan.addFunctions)
			{
				Ref<Platform> plat = ResolvePlatformForAddress(viewRef, addr);
				uint64_t cleanAddr = addr & ~1ULL;
				if (!IsValidFunctionStart(viewRef, plat, cleanAddr))
					continue;
				viewRef->AddFunctionForAnalysis(plat, cleanAddr);
			}

			if (logger)
				logger->LogInfo("Pointer target scan complete: found %zu pointer tables", found);

			task->SetProgressText("Pointer target scan complete");
		}
		catch (const std::exception& e)
		{
			if (logger)
				logger->LogError("Pointer target scan failed: %s", e.what());
		}

		try { task->Finish(); } catch (...) {}
	}).detach();
}

static bool RunPointerTargetScanIsValid(BinaryView* view)
{
	return IsArmv5View(view);
}

/*
 * Command: Run Orphan Code Scan
 *
 * Runs only the orphan code block scan pass.
 */
static void RunOrphanCodeScan(BinaryView* view)
{
	if (!view)
		return;

	Ref<Logger> logger = GetCommandLogger();
	FirmwareSettings settings = LoadMergedSettings(view);

	if (logger)
		logger->LogInfo("Running orphan code scan...");

	Ref<BackgroundTask> task = new BackgroundTask("ARMv5: Orphan Code Scan", true);
	Ref<BinaryView> viewRef = view;

	std::thread([viewRef, task, settings, logger]() mutable {
		try
		{
			task->SetProgressText("Scanning for orphan code blocks...");

			uint64_t imageBase = viewRef->GetStart();
			uint64_t length = viewRef->GetLength();
			DataBuffer buf = viewRef->ReadBuffer(imageBase, length);
			const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
			uint64_t dataLen = buf.GetLength();

			std::set<uint64_t> addedFunctions;
			FirmwareScanPlan plan;
			FirmwareScanTuning tuning = settings.tuning;

			size_t found = ScanForOrphanCodeBlocks(viewRef, data, dataLen, viewRef->GetDefaultEndianness(),
				imageBase, length, viewRef->GetDefaultPlatform(), logger,
				settings.enableVerboseLogging, tuning, settings.codeDataBoundary,
				settings.orphanMinValidInstr, settings.orphanMinBodyInstr,
				settings.orphanMinSpacingBytes, settings.orphanMaxPerPage,
				settings.orphanRequirePrologue, &addedFunctions, &plan);

			// Apply results with proper platform resolution and alignment validation
			for (uint64_t addr : plan.addFunctions)
			{
				Ref<Platform> plat = ResolvePlatformForAddress(viewRef, addr);
				uint64_t cleanAddr = addr & ~1ULL;
				if (!IsValidFunctionStart(viewRef, plat, cleanAddr))
					continue;
				viewRef->AddFunctionForAnalysis(plat, cleanAddr);
			}

			if (logger)
				logger->LogInfo("Orphan code scan complete: found %zu orphan blocks", found);

			task->SetProgressText("Orphan code scan complete");
		}
		catch (const std::exception& e)
		{
			if (logger)
				logger->LogError("Orphan code scan failed: %s", e.what());
		}

		try { task->Finish(); } catch (...) {}
	}).detach();
}

static bool RunOrphanCodeScanIsValid(BinaryView* view)
{
	return IsArmv5View(view);
}

/*
 * Command: Run Cleanup Pass
 *
 * Runs only the invalid function cleanup pass.
 */
static void RunCleanupPass(BinaryView* view)
{
	if (!view)
		return;

	Ref<Logger> logger = GetCommandLogger();
	FirmwareSettings settings = LoadMergedSettings(view);

	if (logger)
		logger->LogInfo("Running cleanup pass...");

	Ref<BackgroundTask> task = new BackgroundTask("ARMv5: Cleanup Invalid Functions", true);
	Ref<BinaryView> viewRef = view;

	std::thread([viewRef, task, settings, logger]() mutable {
		try
		{
			task->SetProgressText("Cleaning up invalid functions...");

			uint64_t imageBase = viewRef->GetStart();
			uint64_t length = viewRef->GetLength();
			DataBuffer buf = viewRef->ReadBuffer(imageBase, length);
			const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
			uint64_t dataLen = buf.GetLength();

			FirmwareScanPlan plan;
			FirmwareScanTuning tuning = settings.tuning;
			
			// Build protected starts from firmware view's seeded functions
			std::set<uint64_t> protectedStarts;
			auto* fwView = dynamic_cast<Armv5FirmwareView*>(viewRef.GetPtr());
			if (fwView)
			{
				auto addProtected = [&](uint64_t addr) {
					protectedStarts.insert(addr);
					protectedStarts.insert(addr & ~1ULL);
				};
				for (uint64_t addr : fwView->GetSeededFunctions())
					addProtected(addr);
				for (uint64_t addr : fwView->GetSeededUserFunctions())
					addProtected(addr);
			}

			size_t removed = CleanupInvalidFunctions(viewRef, data, dataLen, viewRef->GetDefaultEndianness(),
				imageBase, length, logger, settings.enableVerboseLogging, tuning,
				settings.cleanupMaxSizeBytes, settings.cleanupRequireZeroRefs,
				settings.cleanupRequirePcWriteStart, viewRef->GetEntryPoint(),
				protectedStarts, &plan);

			// Apply removals
			for (uint64_t addr : plan.removeFunctions)
			{
				auto funcs = viewRef->GetAnalysisFunctionsForAddress(addr);
				for (auto& func : funcs)
					viewRef->RemoveAnalysisFunction(func);
			}

			if (logger)
				logger->LogInfo("Cleanup complete: removed %zu invalid functions", removed);

			task->SetProgressText("Cleanup complete");
		}
		catch (const std::exception& e)
		{
			if (logger)
				logger->LogError("Cleanup pass failed: %s", e.what());
		}

		try { task->Finish(); } catch (...) {}
	}).detach();
}

static bool RunCleanupPassIsValid(BinaryView* view)
{
	return IsArmv5View(view);
}

/*
 * Register all ARMv5 scan commands.
 */
void RegisterScanCommands()
{
	// Run All Firmware Scans
	PluginCommand::Register(
		"ARMv5\\Run All Firmware Scans",
		"Re-run all firmware analysis scans with current settings",
		RunAllFirmwareScans,
		RunAllFirmwareScansIsValid);

	// Individual scan passes
	PluginCommand::Register(
		"ARMv5\\Scans\\Run Prologue Scan",
		"Scan for function prologues (PUSH, STMFD patterns)",
		RunPrologueScan,
		RunPrologueScanIsValid);

	PluginCommand::Register(
		"ARMv5\\Scans\\Run Call Target Scan",
		"Scan for BL/BLX call targets",
		RunCallTargetScan,
		RunCallTargetScanIsValid);

	PluginCommand::Register(
		"ARMv5\\Scans\\Run Pointer Target Scan",
		"Scan for code pointers in data tables",
		RunPointerTargetScan,
		RunPointerTargetScanIsValid);

	PluginCommand::Register(
		"ARMv5\\Scans\\Run Orphan Code Scan",
		"Scan for orphaned code blocks",
		RunOrphanCodeScan,
		RunOrphanCodeScanIsValid);

	PluginCommand::Register(
		"ARMv5\\Scans\\Run Cleanup Pass",
		"Remove invalid auto-discovered functions",
		RunCleanupPass,
		RunCleanupPassIsValid);

	// RTOS detection
	PluginCommand::Register(
		"ARMv5\\Detect RTOS",
		"Detect RTOS and apply type definitions",
		RunRTOSDetection,
		RunRTOSDetectionIsValid);

	PluginCommand::Register(
		"ARMv5\\Debug RTOS Detection",
		"Show detailed debug info for RTOS detection (check Log window)",
		DebugRTOSDetection,
		DebugRTOSDetectionIsValid);

	// Validation
	PluginCommand::Register(
		"ARMv5\\Validate Function Detection",
		"Compare detected functions against an IDC file with known functions",
		ValidateFunctionDetection,
		ValidateFunctionDetectionIsValid);
}

}  // namespace Armv5Commands
