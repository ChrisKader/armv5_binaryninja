/*
 * ARMv5 Firmware Settings
 */

#include "firmware_settings.h"
#include "settings/env_config.h"

#include <cstdint>

using namespace BinaryNinja;

std::shared_ptr<Armv5Settings::SettingsComponent> GetFirmwareSettingsComponent()
{
	return Armv5Settings::RegisterComponent(kFirmwareComponentName);
}

static void DisableFirmwareScanByToken(FirmwareSettings& settings, const std::string& token)
{
	if (token == "all")
	{
		settings.skipFirmwareScans = true;
		settings.enablePrologueScan = false;
		settings.enableCallTargetScan = false;
		settings.enablePointerTargetScan = false;
		settings.enableOrphanCodeScan = false;
		settings.enableLiteralPoolTyping = false;
		settings.enableClearAutoDataOnCodeRefs = false;
		settings.enableInvalidFunctionCleanup = false;
		return;
	}
	if (token == "skip" || token == "skip_scans" || token == "skip_firmware_scans")
	{
		settings.skipFirmwareScans = true;
		return;
	}
	if (token == "prologue" || token == "prologues" || token == "prologue_scan" || token == "scan_prologues")
	{
		settings.enablePrologueScan = false;
		return;
	}
	if (token == "call" || token == "calls" || token == "call_scan" || token == "scan_call_targets"
		|| token == "call_targets" || token == "call_target")
	{
		settings.enableCallTargetScan = false;
		return;
	}
	if (token == "pointer" || token == "pointers" || token == "pointer_scan" || token == "scan_pointer_targets"
		|| token == "pointer_targets" || token == "pointer_target")
	{
		settings.enablePointerTargetScan = false;
		return;
	}
	if (token == "orphan" || token == "orphans" || token == "orphan_scan" || token == "scan_orphan_code"
		|| token == "orphan_code")
	{
		settings.enableOrphanCodeScan = false;
		return;
	}
	if (token == "literal" || token == "literals" || token == "literal_pools" || token == "literal_pool"
		|| token == "type_literal_pools")
	{
		settings.enableLiteralPoolTyping = false;
		return;
	}
	if (token == "clear_auto" || token == "clear_auto_data" || token == "clear_auto_data_on_code_refs")
	{
		settings.enableClearAutoDataOnCodeRefs = false;
		return;
	}
	if (token == "cleanup" || token == "cleanup_invalid" || token == "cleanup_invalid_functions")
	{
		settings.enableInvalidFunctionCleanup = false;
		return;
	}
	if (token == "pointer_sweep" || token == "disable_pointer_sweep")
	{
		settings.disablePointerSweep = true;
		return;
	}
	if (token == "linear_sweep" || token == "disable_linear_sweep")
	{
		settings.disableLinearSweep = true;
		return;
	}
	if (token == "partial_linear_sweep")
	{
		settings.enablePartialLinearSweep = false;
		return;
	}
}

static void ApplyFirmwareEnvOverrides(FirmwareSettings& settings)
{
	const char* disableScans = Armv5EnvConfig::GetEnv(Armv5EnvConfig::kDisableScans);
	if (!disableScans || disableScans[0] == '\0')
		return;

	auto tokens = Armv5EnvConfig::ParseTokenList(disableScans);
	for (auto& token : tokens)
	{
		auto normalized = Armv5EnvConfig::NormalizeToken(token);
		if (!normalized.empty())
			DisableFirmwareScanByToken(settings, normalized);
	}
}

static void NormalizeFirmwareSettings(FirmwareSettings& settings)
{
	if (settings.tuning.minValidInstr == 0)
		settings.tuning.minValidInstr = 1;
	if (settings.tuning.minPointerRun == 0)
		settings.tuning.minPointerRun = 1;
}

FirmwareSettings DefaultFirmwareSettings(FirmwareSettingsMode mode)
{
	FirmwareSettings settings{};
	settings.enablePrologueScan = true;
	settings.enableCallTargetScan = true;
	settings.enablePointerTargetScan = true;
	settings.enableOrphanCodeScan = true;
	settings.enableLiteralPoolTyping = true;
	settings.enableClearAutoDataOnCodeRefs = true;
	settings.enableVerboseLogging = false;
	settings.enableInvalidFunctionCleanup = true;
	// Disable BN's generic pointer sweep for firmware - our ARM-specific scan is more conservative
	// and avoids false positives from data that looks like pointers
	settings.disablePointerSweep = true;
	// Disable BN's linear sweep - function discovery is entirely handled by our ARM-specific scans
	// (prologues, call targets, pointer tables, orphan code). BN still handles function analysis
	// (IL lifting, type propagation, etc.) for the functions we discover.
	settings.disableLinearSweep = true;
	// Partial linear sweep is disabled by default since we're handling function discovery ourselves
	// Users can enable this if they want BN's linear sweep as a supplement to our scans
	settings.enablePartialLinearSweep = false;
	settings.skipFirmwareScans = false;
	settings.cleanupMaxSizeBytes = 0;        // 0 = no size limit, clean any invalid function
	settings.cleanupRequireZeroRefs = false;  // Remove even if has callers (caller is wrong)
	settings.cleanupRequirePcWriteStart = false;  // Don't require PC write - remove data too
	settings.orphanMinValidInstr = 4;
	settings.orphanMinBodyInstr = 2;
	settings.orphanMinSpacingBytes = 0x80;
	// More aggressive orphan scanning for command/workflow modes
	settings.orphanMaxPerPage = (mode == FirmwareSettingsMode::Init) ? 6 : 8;
	// Require prologue only during initial analysis
	settings.orphanRequirePrologue = (mode == FirmwareSettingsMode::Init);
	settings.maxFunctionAdds = 50000;
	settings.tuning = FirmwareScanTuning{};
	settings.tuning.scanRawPointerTables = true;
	// Unified recognizer settings - enabled by default for better function detection
	// Uses FunctionDetector with linear sweep, switch resolution, and tail call analysis
	settings.useUnifiedRecognizer = true;
	settings.recognizerMinScorePct = 30;  // 30% - allow linear sweep candidates to pass
	settings.recognizerPreset = 0;        // default preset for balanced detection
	settings.codeDataBoundary = 0;        // 0 = auto-detect based on prologues
	return settings;
}

FirmwareSettings LoadFirmwareSettings(const Ref<Settings>& settings, BinaryView* view, FirmwareSettingsMode mode)
{
	FirmwareSettings result = DefaultFirmwareSettings(mode);
	if (!settings)
	{
		ApplyFirmwareEnvOverrides(result);
		NormalizeFirmwareSettings(result);
		return result;
	}

	auto fw = GetFirmwareSettingsComponent();
	using namespace FirmwareSettingNames;

	auto key = [&](const char* name) { return fw->GetKey(name); };

	if (settings->Contains(key(kScanPrologues)))
		result.enablePrologueScan = settings->Get<bool>(key(kScanPrologues), view);
	if (settings->Contains(key(kScanCallTargets)))
		result.enableCallTargetScan = settings->Get<bool>(key(kScanCallTargets), view);
	if (settings->Contains(key(kScanPointerTargets)))
		result.enablePointerTargetScan = settings->Get<bool>(key(kScanPointerTargets), view);
	if (settings->Contains(key(kScanOrphanCode)))
		result.enableOrphanCodeScan = settings->Get<bool>(key(kScanOrphanCode), view);
	if (settings->Contains(key(kOrphanMinValidInstr)))
		result.orphanMinValidInstr = (uint32_t)settings->Get<uint64_t>(key(kOrphanMinValidInstr), view);
	if (settings->Contains(key(kOrphanMinBodyInstr)))
		result.orphanMinBodyInstr = (uint32_t)settings->Get<uint64_t>(key(kOrphanMinBodyInstr), view);
	if (settings->Contains(key(kOrphanMinSpacingBytes)))
		result.orphanMinSpacingBytes = (uint32_t)settings->Get<uint64_t>(key(kOrphanMinSpacingBytes), view);
	if (settings->Contains(key(kOrphanMaxPerPage)))
		result.orphanMaxPerPage = (uint32_t)settings->Get<uint64_t>(key(kOrphanMaxPerPage), view);
	if (settings->Contains(key(kOrphanRequirePrologue)))
		result.orphanRequirePrologue = settings->Get<bool>(key(kOrphanRequirePrologue), view);
	if (settings->Contains(key(kMaxFunctionAdds)))
		result.maxFunctionAdds = (uint32_t)settings->Get<uint64_t>(key(kMaxFunctionAdds), view);
	if (settings->Contains(key(kPartialLinearSweep)))
		result.enablePartialLinearSweep = settings->Get<bool>(key(kPartialLinearSweep), view);
	if (settings->Contains(key(kSkipFirmwareScans)))
		result.skipFirmwareScans = settings->Get<bool>(key(kSkipFirmwareScans), view);
	if (settings->Contains(key(kTypeLiteralPools)))
		result.enableLiteralPoolTyping = settings->Get<bool>(key(kTypeLiteralPools), view);
	if (settings->Contains(key(kClearAutoDataOnCodeRefs)))
		result.enableClearAutoDataOnCodeRefs = settings->Get<bool>(key(kClearAutoDataOnCodeRefs), view);
	if (settings->Contains(key(kVerboseLogging)))
		result.enableVerboseLogging = settings->Get<bool>(key(kVerboseLogging), view);
	if (settings->Contains(key(kDisablePointerSweep)))
		result.disablePointerSweep = settings->Get<bool>(key(kDisablePointerSweep), view);
	if (settings->Contains(key(kDisableLinearSweep)))
		result.disableLinearSweep = settings->Get<bool>(key(kDisableLinearSweep), view);
	if (settings->Contains(key(kScanMinValidInstr)))
		result.tuning.minValidInstr = (uint32_t)settings->Get<uint64_t>(key(kScanMinValidInstr), view);
	if (settings->Contains(key(kScanMinBodyInstr)))
		result.tuning.minBodyInstr = (uint32_t)settings->Get<uint64_t>(key(kScanMinBodyInstr), view);
	if (settings->Contains(key(kScanMaxLiteralRun)))
		result.tuning.maxLiteralRun = (uint32_t)settings->Get<uint64_t>(key(kScanMaxLiteralRun), view);
	if (settings->Contains(key(kScanRawPointerTables)))
		result.tuning.scanRawPointerTables = settings->Get<bool>(key(kScanRawPointerTables), view);
	if (settings->Contains(key(kRawPointerTableMinRun)))
		result.tuning.minPointerRun = (uint32_t)settings->Get<uint64_t>(key(kRawPointerTableMinRun), view);
	if (settings->Contains(key(kRawPointerTableRequireCodeRefs)))
		result.tuning.requirePointerTableCodeRefs = settings->Get<bool>(key(kRawPointerTableRequireCodeRefs), view);
	if (settings->Contains(key(kRawPointerTableAllowInCode)))
		result.tuning.allowPointerTablesInCode = settings->Get<bool>(key(kRawPointerTableAllowInCode), view);
	if (settings->Contains(key(kCallScanRequireInFunction)))
		result.tuning.requireCallInFunction = settings->Get<bool>(key(kCallScanRequireInFunction), view);
	if (settings->Contains(key(kCleanupInvalidFunctions)))
		result.enableInvalidFunctionCleanup = settings->Get<bool>(key(kCleanupInvalidFunctions), view);
	// Note: Don't disable cleanup for raw firmware (no segments) - cleanup is especially
	// important for raw firmware where we have less type information and more false positives
	if (settings->Contains(key(kCleanupInvalidMaxSize)))
		result.cleanupMaxSizeBytes = (uint32_t)settings->Get<uint64_t>(key(kCleanupInvalidMaxSize), view);
	if (settings->Contains(key(kCleanupInvalidRequireZeroRefs)))
		result.cleanupRequireZeroRefs = settings->Get<bool>(key(kCleanupInvalidRequireZeroRefs), view);
	if (settings->Contains(key(kCleanupInvalidRequirePcWrite)))
		result.cleanupRequirePcWriteStart = settings->Get<bool>(key(kCleanupInvalidRequirePcWrite), view);

	// Unified recognizer settings
	if (settings->Contains(key(kUseUnifiedRecognizer)))
		result.useUnifiedRecognizer = settings->Get<bool>(key(kUseUnifiedRecognizer), view);
	if (settings->Contains(key(kRecognizerMinScore)))
		result.recognizerMinScorePct = (uint32_t)settings->Get<uint64_t>(key(kRecognizerMinScore), view);
	if (settings->Contains(key(kRecognizerPreset)))
		result.recognizerPreset = (uint32_t)settings->Get<uint64_t>(key(kRecognizerPreset), view);
	if (settings->Contains(key(kCodeDataBoundary)))
		result.codeDataBoundary = settings->Get<uint64_t>(key(kCodeDataBoundary), view);

	ApplyFirmwareEnvOverrides(result);
	NormalizeFirmwareSettings(result);
	return result;
}

void LogFirmwareSettingsSummary(const Ref<Logger>& logger, const FirmwareSettings& settings)
{
	if (!logger)
		return;

	logger->LogInfo(
		"Firmware settings: prologue_scan=%d call_scan=%d pointer_scan=%d orphan_scan=%d "
		"orphan_min_valid=%u orphan_min_body=%u orphan_min_spacing=0x%x orphan_max_per_page=%u "
		"orphan_require_prologue=%d partial_linear_sweep=%d skip_firmware_scans=%d "
		"raw_ptr_tables=%d raw_ptr_min_run=%u raw_ptr_require_refs=%d raw_ptr_allow_in_code=%d "
		"call_scan_require_in_func=%d max_function_adds=%u disable_pointer_sweep=%d disable_linear_sweep=%d "
		"cleanup_invalid=%d cleanup_max_size=%u cleanup_zero_refs=%d cleanup_pc_write=%d "
		"type_literal_pools=%d clear_auto_data_on_code_refs=%d scan_min_valid=%u scan_min_body=%u scan_max_literal_run=%u",
		settings.enablePrologueScan, settings.enableCallTargetScan, settings.enablePointerTargetScan, settings.enableOrphanCodeScan,
		settings.orphanMinValidInstr, settings.orphanMinBodyInstr, settings.orphanMinSpacingBytes, settings.orphanMaxPerPage,
		settings.orphanRequirePrologue, settings.enablePartialLinearSweep, settings.skipFirmwareScans,
		settings.tuning.scanRawPointerTables, settings.tuning.minPointerRun, settings.tuning.requirePointerTableCodeRefs,
		settings.tuning.allowPointerTablesInCode, settings.tuning.requireCallInFunction, settings.maxFunctionAdds,
		settings.disablePointerSweep, settings.disableLinearSweep, settings.enableInvalidFunctionCleanup,
		settings.cleanupMaxSizeBytes, settings.cleanupRequireZeroRefs, settings.cleanupRequirePcWriteStart,
		settings.enableLiteralPoolTyping,
		settings.enableClearAutoDataOnCodeRefs, settings.tuning.minValidInstr, settings.tuning.minBodyInstr,
		settings.tuning.maxLiteralRun);
}

uint64_t GetEffectiveCodeDataBoundary(const Ref<BinaryView>& view, const FirmwareSettings& settings)
{
	if (!view || !view->GetObject())
		return 0;

	// If explicitly configured, use that value
	if (settings.codeDataBoundary != 0)
		return settings.codeDataBoundary;

	// Auto-detect based on binary structure
	uint64_t imageStart = view->GetStart();
	uint64_t imageEnd = view->GetEnd();
	uint64_t length = imageEnd - imageStart;

	// For binaries with sections, find the end of the last executable section
	auto sections = view->GetSections();
	if (!sections.empty())
	{
		uint64_t lastCodeEnd = 0;
		for (const auto& section : sections)
		{
			// ReadOnlyCodeSectionSemantics is the only code section semantic
			if (section->GetSemantics() == ReadOnlyCodeSectionSemantics)
			{
				uint64_t sectionEnd = section->GetStart() + section->GetLength();
				if (sectionEnd > lastCodeEnd)
					lastCodeEnd = sectionEnd;
			}
		}
		if (lastCodeEnd > 0)
			return lastCodeEnd;
	}

	// For binaries with segments, find the end of the last executable segment
	auto segments = view->GetSegments();
	if (!segments.empty())
	{
		uint64_t lastExecEnd = 0;
		for (const auto& segment : segments)
		{
			if (segment->GetFlags() & SegmentExecutable)
			{
				uint64_t segEnd = segment->GetStart() + segment->GetLength();
				if (segEnd > lastExecEnd)
					lastExecEnd = segEnd;
			}
		}
		if (lastExecEnd > 0)
			return lastExecEnd;
	}

	// For raw firmware without segments/sections, use halfway point
	// This is a conservative heuristic - most ARM firmware has code in the
	// first half and data/constants in the second half
	return imageStart + (length / 2);
}

bool IsAddressInDataRegion(const Ref<BinaryView>& view, const FirmwareSettings& settings, uint64_t addr)
{
	uint64_t boundary = GetEffectiveCodeDataBoundary(view, settings);
	if (boundary == 0)
		return false;  // No boundary detected, allow all addresses

	// Clear Thumb bit for comparison
	uint64_t cleanAddr = addr & ~1ULL;
	return cleanAddr >= boundary;
}

void RegisterFirmwareSettings(const Ref<Settings>& settings)
{
	if (!settings)
		return;

	auto fw = GetFirmwareSettingsComponent();
	using namespace FirmwareSettingNames;

	fw->RegisterBool(settings, kScanPrologues, true,
		"Scan for function prologues",
		"Discover additional function entry points by scanning for common prologue patterns.");

	fw->RegisterBool(settings, kScanCallTargets, true,
		"Scan for call targets",
		"Discover additional function entry points from direct call and indirect branch targets.");

	fw->RegisterBool(settings, kScanPointerTargets, true,
		"Scan for pointer targets",
		"Discover function entry points referenced by data pointers.");

	fw->RegisterBool(settings, kScanOrphanCode, true,
		"Scan for orphan code blocks",
		"Discover unreachable functions post-analysis by finding orphaned code blocks and basic block boundaries.");

	fw->RegisterNumber(settings, kOrphanMinValidInstr, 6, 1, 16,
		"Orphan scan min valid instructions",
		"Minimum consecutive valid ARM instructions required for an orphan code candidate.");

	fw->RegisterNumber(settings, kOrphanMinBodyInstr, 2, 0, 16,
		"Orphan scan min body instructions",
		"Minimum valid instructions after the candidate prologue when validating orphan code.");

	fw->RegisterNumber(settings, kOrphanMinSpacingBytes, 128, 0, 4096,
		"Orphan scan min spacing bytes",
		"Minimum spacing between orphan functions added during the post-analysis scan.");

	fw->RegisterNumber(settings, kOrphanMaxPerPage, 6, 0, 64,
		"Orphan scan max per 4KB page",
		"Maximum orphan functions to add per 4KB page (0 disables the cap).");

	fw->RegisterBool(settings, kPartialLinearSweep, false,
		"Partial linear sweep",
		"Enable Binary Ninja's partial linear sweep (no CFG pass) as a supplement to our ARM-specific scans. "
		"Disabled by default since function discovery is handled by our scans.");

	fw->RegisterBool(settings, kSkipFirmwareScans, false,
		"Skip firmware scans",
		"Disable the firmware-specific pointer/orphan/call scans so only the core sweep runs.");

	fw->RegisterBool(settings, kOrphanRequirePrologue, true,
		"Orphan scan require prologue",
		"Require a prologue-like instruction at the candidate start to reduce false positives.");

	fw->RegisterBool(settings, kScanRawPointerTables, true,
		"Scan raw pointer tables",
		"Scan untyped data for runs of pointers into code to recover function starts when pointer sweep is disabled.");

	fw->RegisterNumber(settings, kRawPointerTableMinRun, 3, 1, 16,
		"Raw pointer table min run",
		"Minimum consecutive pointers required to treat a region as a pointer table.");

	fw->RegisterBool(settings, kRawPointerTableRequireCodeRefs, true,
		"Raw pointer table require code refs",
		"Require at least one code reference into a raw pointer table before using it.");

	fw->RegisterBool(settings, kRawPointerTableAllowInCode, false,
		"Raw pointer table allow in code",
		"Allow raw pointer tables inside code semantics when code references are not required.");

	fw->RegisterBool(settings, kCallScanRequireInFunction, false,
		"Call scan require in-function",
		"Restrict call-target scanning to instructions already inside functions.");

	fw->RegisterNumber(settings, kMaxFunctionAdds, 50000, 0, 100000,
		"Max firmware function additions",
		"Cap the number of functions added per firmware scan run (0 disables the cap).");

	fw->RegisterBool(settings, kDisablePointerSweep, true,
		"Disable core pointer sweep",
		"Disable Binary Ninja's generic pointer sweep (analysis.pointerSweep.autorun). "
		"Recommended for firmware because our ARM-specific pointer scan is more conservative "
		"and avoids false positives from data that resembles pointers.");

	fw->RegisterBool(settings, kDisableLinearSweep, true,
		"Disable core linear sweep",
		"Disable Binary Ninja's linear sweep so function discovery is entirely handled by our "
		"ARM-specific scans (prologues, call targets, pointer tables, orphan code). BN still "
		"handles function analysis (IL lifting, type propagation) for discovered functions.");

	fw->RegisterBool(settings, kCleanupInvalidFunctions, true,
		"Cleanup invalid functions",
		"Remove tiny auto-discovered functions that fail ARMv5 validation checks after analysis.");

	fw->RegisterNumber(settings, kCleanupInvalidMaxSize, 0, 0, 10000,
		"Cleanup invalid max size",
		"Maximum size (bytes) for functions eligible for invalid cleanup. 0 means no limit.");

	fw->RegisterBool(settings, kCleanupInvalidRequireZeroRefs, false,
		"Cleanup invalid require zero refs",
		"Only remove invalid functions with zero incoming references.");

	fw->RegisterBool(settings, kCleanupInvalidRequirePcWrite, false,
		"Cleanup invalid require PC write",
		"Only remove invalid functions whose first instruction writes PC. Disable to also remove data-as-code.");

	fw->RegisterBool(settings, kTypeLiteralPools, true,
		"Type literal pool entries",
		"Define literal pool entries as data to avoid disassembling them as code.");

	fw->RegisterBool(settings, kClearAutoDataOnCodeRefs, true,
		"Clear auto data on code references",
		"Undefine auto-discovered data at code-referenced addresses when nearby bytes decode as valid instructions.");

	fw->RegisterBool(settings, kVerboseLogging, true,
		"Verbose firmware analysis logging",
		"Emit per-pass summary logs for firmware analysis heuristics without enabling global debug logging.");

	fw->RegisterNumber(settings, kScanMinValidInstr, 2, 1, 16,
		"Scan minimum valid instructions",
		"Minimum number of consecutive valid ARM instructions required to accept a firmware scan candidate.");

	fw->RegisterNumber(settings, kScanMinBodyInstr, 1, 0, 16,
		"Scan minimum body instructions",
		"Minimum number of valid instructions after the prologue when validating a scan candidate.");

	fw->RegisterNumber(settings, kScanMaxLiteralRun, 2, 0, 16,
		"Scan max literal run",
		"Maximum consecutive PC-relative literal loads allowed in the validation window.");

	// Unified recognizer settings - enabled by default for better function detection
	fw->RegisterBool(settings, kUseUnifiedRecognizer, true,
		"Use unified function recognizer",
		"Use the advanced FunctionRecognizer instead of legacy scan functions. "
		"The recognizer combines linear sweep, switch table resolution, and tail call analysis "
		"with configurable weights for better function detection.");

	// Register min score as integer percentage (0-100) - balanced default
	fw->RegisterNumber(settings, kRecognizerMinScore, 45, 0, 100,
		"Recognizer minimum score (%)",
		"Minimum confidence percentage (0-100) for the unified recognizer to accept a function candidate. "
		"Lower values allow more candidates but may include false positives; higher values require stronger evidence.");

	// Register preset as enum (0=default, 1=aggressive, 2=conservative, 3=prologue, 4=calls)
	// Default to default (0) for balanced detection
	fw->RegisterNumber(settings, kRecognizerPreset, 0, 0, 4,
		"Recognizer preset",
		"Function detection preset: 0=default (balanced), 1=aggressive, 2=conservative, 3=prologue-only, 4=call-targets-only.");

	fw->RegisterNumber(settings, kCodeDataBoundary, 0, 0, UINT64_MAX,
		"Code-data boundary address",
		"Address where code ends and data begins. 0 = auto-detect based on prologue locations. "
		"Set to a specific address to manually define the boundary for binaries where automatic detection fails.");

}
