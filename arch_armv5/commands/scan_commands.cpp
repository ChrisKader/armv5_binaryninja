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

#include <thread>

using namespace BinaryNinja;

namespace
{

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

static bool RunRTOSDetectionIsValid(BinaryView* view)
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
				settings.enableVerboseLogging, tuning, &seededFunctions, &plan);

			// Apply results
			if (!plan.addFunctions.empty() || !plan.addUserFunctions.empty())
			{
				for (uint64_t addr : plan.addFunctions)
					viewRef->AddFunctionForAnalysis(viewRef->GetDefaultPlatform(), addr);
				for (uint64_t addr : plan.addUserFunctions)
					viewRef->CreateUserFunction(viewRef->GetDefaultPlatform(), addr);
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
				settings.enableVerboseLogging, tuning, &seededFunctions, &plan);

			// Apply results
			for (uint64_t addr : plan.addFunctions)
				viewRef->AddFunctionForAnalysis(viewRef->GetDefaultPlatform(), addr);

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
				settings.enableVerboseLogging, tuning, &addedFunctions, &plan);

			// Apply results
			for (uint64_t addr : plan.addFunctions)
				viewRef->AddFunctionForAnalysis(viewRef->GetDefaultPlatform(), addr);

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
				settings.enableVerboseLogging, tuning,
				settings.orphanMinValidInstr, settings.orphanMinBodyInstr,
				settings.orphanMinSpacingBytes, settings.orphanMaxPerPage,
				settings.orphanRequirePrologue, &addedFunctions, &plan);

			// Apply results
			for (uint64_t addr : plan.addFunctions)
				viewRef->AddFunctionForAnalysis(viewRef->GetDefaultPlatform(), addr);

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
			std::set<uint64_t> protectedStarts;

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
}

}  // namespace Armv5Commands
