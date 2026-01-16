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
	settings.disablePointerSweep = false;
	settings.disableLinearSweep = false;
	// Partial linear sweep only during initial analysis
	settings.enablePartialLinearSweep = (mode == FirmwareSettingsMode::Init);
	settings.skipFirmwareScans = false;
	settings.cleanupMaxSizeBytes = 8;
	settings.cleanupRequireZeroRefs = true;
	settings.cleanupRequirePcWriteStart = true;
	settings.orphanMinValidInstr = 4;
	settings.orphanMinBodyInstr = 2;
	settings.orphanMinSpacingBytes = 0x80;
	// More aggressive orphan scanning for command/workflow modes
	settings.orphanMaxPerPage = (mode == FirmwareSettingsMode::Init) ? 6 : 8;
	// Require prologue only during initial analysis
	settings.orphanRequirePrologue = (mode == FirmwareSettingsMode::Init);
	settings.maxFunctionAdds = 2000;
	settings.tuning = FirmwareScanTuning{};
	settings.tuning.scanRawPointerTables = true;
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
	if (view && view->GetSegments().empty())
		result.enableInvalidFunctionCleanup = false;
	if (settings->Contains(key(kCleanupInvalidMaxSize)))
		result.cleanupMaxSizeBytes = (uint32_t)settings->Get<uint64_t>(key(kCleanupInvalidMaxSize), view);
	if (settings->Contains(key(kCleanupInvalidRequireZeroRefs)))
		result.cleanupRequireZeroRefs = settings->Get<bool>(key(kCleanupInvalidRequireZeroRefs), view);
	if (settings->Contains(key(kCleanupInvalidRequirePcWrite)))
		result.cleanupRequirePcWriteStart = settings->Get<bool>(key(kCleanupInvalidRequirePcWrite), view);

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

	fw->RegisterBool(settings, kPartialLinearSweep, true,
		"Partial linear sweep",
		"Enable Binary Ninja's partial linear sweep (no CFG pass) alongside the firmware scans.");

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

	fw->RegisterNumber(settings, kMaxFunctionAdds, 2000, 0, 100000,
		"Max firmware function additions",
		"Cap the number of functions added per firmware scan run (0 disables the cap).");

	fw->RegisterBool(settings, kDisablePointerSweep, false,
		"Disable core pointer sweep",
		"Disable Binary Ninja's core pointer sweep (analysis.pointerSweep.autorun) to reduce false positives in raw firmware blobs.");

	fw->RegisterBool(settings, kDisableLinearSweep, false,
		"Disable core linear sweep",
		"Disable Binary Ninja's core linear sweep so firmware scans drive function discovery.");

	fw->RegisterBool(settings, kCleanupInvalidFunctions, true,
		"Cleanup invalid functions",
		"Remove tiny auto-discovered functions that fail ARMv5 validation checks after analysis.");

	fw->RegisterNumber(settings, kCleanupInvalidMaxSize, 8, 4, 32,
		"Cleanup invalid max size",
		"Maximum size (bytes) for functions eligible for invalid cleanup.");

	fw->RegisterBool(settings, kCleanupInvalidRequireZeroRefs, true,
		"Cleanup invalid require zero refs",
		"Only remove invalid functions with zero incoming references.");

	fw->RegisterBool(settings, kCleanupInvalidRequirePcWrite, true,
		"Cleanup invalid require PC write",
		"Only remove invalid functions whose first instruction writes PC.");

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
}
