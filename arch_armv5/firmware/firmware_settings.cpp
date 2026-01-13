/*
 * ARMv5 Firmware Settings
 */

#include "firmware_settings.h"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

using namespace BinaryNinja;

static std::vector<std::string> SplitScanList(const char* value)
{
	std::vector<std::string> tokens;
	if (!value)
		return tokens;
	std::string current;
	for (const char* p = value; *p; ++p)
	{
		char c = *p;
		if (c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
		{
			if (!current.empty())
			{
				tokens.emplace_back(current);
				current.clear();
			}
			continue;
		}
		current.push_back(c);
	}
	if (!current.empty())
		tokens.emplace_back(current);
	return tokens;
}

static std::string NormalizeToken(std::string token)
{
	for (char& ch : token)
	{
		if (ch == '-')
			ch = '_';
		ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
	}
	return token;
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
	const char* disableScans = getenv("BN_ARMV5_FIRMWARE_DISABLE_SCANS");
	if (!disableScans || disableScans[0] == '\0')
		return;

	auto tokens = SplitScanList(disableScans);
	for (auto& token : tokens)
	{
		auto normalized = NormalizeToken(token);
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
	settings.enablePartialLinearSweep = (mode == FirmwareSettingsMode::Init);
	settings.skipFirmwareScans = false;
	settings.cleanupMaxSizeBytes = 8;
	settings.cleanupRequireZeroRefs = true;
	settings.cleanupRequirePcWriteStart = true;
	settings.orphanMinValidInstr = 4;
	settings.orphanMinBodyInstr = 2;
	settings.orphanMinSpacingBytes = 0x80;
	settings.orphanMaxPerPage = (mode == FirmwareSettingsMode::Init) ? 6 : 8;
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

	if (settings->Contains(FirmwareSettingKeys::kScanPrologues))
		result.enablePrologueScan = settings->Get<bool>(FirmwareSettingKeys::kScanPrologues, view);
	if (settings->Contains(FirmwareSettingKeys::kScanCallTargets))
		result.enableCallTargetScan = settings->Get<bool>(FirmwareSettingKeys::kScanCallTargets, view);
	if (settings->Contains(FirmwareSettingKeys::kScanPointerTargets))
		result.enablePointerTargetScan = settings->Get<bool>(FirmwareSettingKeys::kScanPointerTargets, view);
	if (settings->Contains(FirmwareSettingKeys::kScanOrphanCode))
		result.enableOrphanCodeScan = settings->Get<bool>(FirmwareSettingKeys::kScanOrphanCode, view);
	if (settings->Contains(FirmwareSettingKeys::kOrphanMinValidInstr))
		result.orphanMinValidInstr = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kOrphanMinValidInstr, view);
	if (settings->Contains(FirmwareSettingKeys::kOrphanMinBodyInstr))
		result.orphanMinBodyInstr = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kOrphanMinBodyInstr, view);
	if (settings->Contains(FirmwareSettingKeys::kOrphanMinSpacingBytes))
		result.orphanMinSpacingBytes = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kOrphanMinSpacingBytes, view);
	if (settings->Contains(FirmwareSettingKeys::kOrphanMaxPerPage))
		result.orphanMaxPerPage = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kOrphanMaxPerPage, view);
	if (settings->Contains(FirmwareSettingKeys::kOrphanRequirePrologue))
		result.orphanRequirePrologue = settings->Get<bool>(FirmwareSettingKeys::kOrphanRequirePrologue, view);
	if (settings->Contains(FirmwareSettingKeys::kMaxFunctionAdds))
		result.maxFunctionAdds = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kMaxFunctionAdds, view);
	if (settings->Contains(FirmwareSettingKeys::kPartialLinearSweep))
		result.enablePartialLinearSweep = settings->Get<bool>(FirmwareSettingKeys::kPartialLinearSweep, view);
	if (settings->Contains(FirmwareSettingKeys::kSkipFirmwareScans))
		result.skipFirmwareScans = settings->Get<bool>(FirmwareSettingKeys::kSkipFirmwareScans, view);
	if (settings->Contains(FirmwareSettingKeys::kTypeLiteralPools))
		result.enableLiteralPoolTyping = settings->Get<bool>(FirmwareSettingKeys::kTypeLiteralPools, view);
	if (settings->Contains(FirmwareSettingKeys::kClearAutoDataOnCodeRefs))
		result.enableClearAutoDataOnCodeRefs = settings->Get<bool>(FirmwareSettingKeys::kClearAutoDataOnCodeRefs, view);
	if (settings->Contains(FirmwareSettingKeys::kVerboseLogging))
		result.enableVerboseLogging = settings->Get<bool>(FirmwareSettingKeys::kVerboseLogging, view);
	if (settings->Contains(FirmwareSettingKeys::kDisablePointerSweep))
		result.disablePointerSweep = settings->Get<bool>(FirmwareSettingKeys::kDisablePointerSweep, view);
	if (settings->Contains(FirmwareSettingKeys::kDisableLinearSweep))
		result.disableLinearSweep = settings->Get<bool>(FirmwareSettingKeys::kDisableLinearSweep, view);
	if (settings->Contains(FirmwareSettingKeys::kScanMinValidInstr))
		result.tuning.minValidInstr = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kScanMinValidInstr, view);
	if (settings->Contains(FirmwareSettingKeys::kScanMinBodyInstr))
		result.tuning.minBodyInstr = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kScanMinBodyInstr, view);
	if (settings->Contains(FirmwareSettingKeys::kScanMaxLiteralRun))
		result.tuning.maxLiteralRun = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kScanMaxLiteralRun, view);
	if (settings->Contains(FirmwareSettingKeys::kScanRawPointerTables))
		result.tuning.scanRawPointerTables = settings->Get<bool>(FirmwareSettingKeys::kScanRawPointerTables, view);
	if (settings->Contains(FirmwareSettingKeys::kRawPointerTableMinRun))
		result.tuning.minPointerRun = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kRawPointerTableMinRun, view);
	if (settings->Contains(FirmwareSettingKeys::kRawPointerTableRequireCodeRefs))
		result.tuning.requirePointerTableCodeRefs = settings->Get<bool>(FirmwareSettingKeys::kRawPointerTableRequireCodeRefs, view);
	if (settings->Contains(FirmwareSettingKeys::kRawPointerTableAllowInCode))
		result.tuning.allowPointerTablesInCode = settings->Get<bool>(FirmwareSettingKeys::kRawPointerTableAllowInCode, view);
	if (settings->Contains(FirmwareSettingKeys::kCallScanRequireInFunction))
		result.tuning.requireCallInFunction = settings->Get<bool>(FirmwareSettingKeys::kCallScanRequireInFunction, view);
	if (settings->Contains(FirmwareSettingKeys::kCleanupInvalidFunctions))
		result.enableInvalidFunctionCleanup = settings->Get<bool>(FirmwareSettingKeys::kCleanupInvalidFunctions, view);
	if (settings->Contains(FirmwareSettingKeys::kCleanupInvalidMaxSize))
		result.cleanupMaxSizeBytes = (uint32_t)settings->Get<uint64_t>(FirmwareSettingKeys::kCleanupInvalidMaxSize, view);
	if (settings->Contains(FirmwareSettingKeys::kCleanupInvalidRequireZeroRefs))
		result.cleanupRequireZeroRefs = settings->Get<bool>(FirmwareSettingKeys::kCleanupInvalidRequireZeroRefs, view);
	if (settings->Contains(FirmwareSettingKeys::kCleanupInvalidRequirePcWrite))
		result.cleanupRequirePcWriteStart = settings->Get<bool>(FirmwareSettingKeys::kCleanupInvalidRequirePcWrite, view);

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

	settings->RegisterSetting(FirmwareSettingKeys::kScanPrologues,
		R"({
		"title" : "Scan for function prologues",
		"type" : "boolean",
		"default" : true,
		"description" : "Discover additional function entry points by scanning for common prologue patterns."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kScanCallTargets,
		R"({
		"title" : "Scan for call targets",
		"type" : "boolean",
		"default" : true,
		"description" : "Discover additional function entry points from direct call and indirect branch targets."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kScanPointerTargets,
		R"({
		"title" : "Scan for pointer targets",
		"type" : "boolean",
		"default" : true,
		"description" : "Discover function entry points referenced by data pointers."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kScanOrphanCode,
		R"({
		"title" : "Scan for orphan code blocks",
		"type" : "boolean",
		"default" : true,
		"description" : "Discover unreachable functions post-analysis by finding orphaned code blocks and basic block boundaries."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kOrphanMinValidInstr,
		R"({
		"title" : "Orphan scan min valid instructions",
		"type" : "number",
		"default" : 6,
		"min" : 1,
		"max" : 16,
		"description" : "Minimum consecutive valid ARM instructions required for an orphan code candidate."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kOrphanMinBodyInstr,
		R"({
		"title" : "Orphan scan min body instructions",
		"type" : "number",
		"default" : 2,
		"min" : 0,
		"max" : 16,
		"description" : "Minimum valid instructions after the candidate prologue when validating orphan code."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kOrphanMinSpacingBytes,
		R"({
		"title" : "Orphan scan min spacing bytes",
		"type" : "number",
		"default" : 128,
		"min" : 0,
		"max" : 4096,
		"description" : "Minimum spacing between orphan functions added during the post-analysis scan."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kOrphanMaxPerPage,
		R"({
		"title" : "Orphan scan max per 4KB page",
		"type" : "number",
		"default" : 6,
		"min" : 0,
		"max" : 64,
		"description" : "Maximum orphan functions to add per 4KB page (0 disables the cap)."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kPartialLinearSweep,
		R"({
		"title" : "Partial linear sweep",
		"type" : "boolean",
		"default" : true,
		"description" : "Enable Binary Ninja's partial linear sweep (no CFG pass) alongside the firmware scans."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kSkipFirmwareScans,
		R"({
		"title" : "Skip firmware scans",
		"type" : "boolean",
		"default" : false,
		"description" : "Disable the firmware-specific pointer/orphan/call scans so only the core sweep runs."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kOrphanRequirePrologue,
		R"({
		"title" : "Orphan scan require prologue",
		"type" : "boolean",
		"default" : true,
		"description" : "Require a prologue-like instruction at the candidate start to reduce false positives."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kScanRawPointerTables,
		R"({
		"title" : "Scan raw pointer tables",
		"type" : "boolean",
		"default" : true,
		"description" : "Scan untyped data for runs of pointers into code to recover function starts when pointer sweep is disabled."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kRawPointerTableMinRun,
		R"({
		"title" : "Raw pointer table min run",
		"type" : "number",
		"default" : 3,
		"min" : 1,
		"max" : 16,
		"description" : "Minimum consecutive pointers required to treat a region as a pointer table."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kRawPointerTableRequireCodeRefs,
		R"({
		"title" : "Raw pointer table require code refs",
		"type" : "boolean",
		"default" : true,
		"description" : "Require at least one code reference into a raw pointer table before using it."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kRawPointerTableAllowInCode,
		R"({
		"title" : "Raw pointer table allow in code",
		"type" : "boolean",
		"default" : false,
		"description" : "Allow raw pointer tables inside code semantics when code references are not required."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kCallScanRequireInFunction,
		R"({
		"title" : "Call scan require in-function",
		"type" : "boolean",
		"default" : false,
		"description" : "Restrict call-target scanning to instructions already inside functions."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kMaxFunctionAdds,
		R"({
		"title" : "Max firmware function additions",
		"type" : "number",
		"default" : 2000,
		"min" : 0,
		"max" : 100000,
		"description" : "Cap the number of functions added per firmware scan run (0 disables the cap)."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kDisablePointerSweep,
		R"({
		"title" : "Disable core pointer sweep",
		"type" : "boolean",
		"default" : false,
		"description" : "Disable Binary Ninja's core pointer sweep (analysis.pointerSweep.autorun) to reduce false positives in raw firmware blobs."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kDisableLinearSweep,
		R"({
		"title" : "Disable core linear sweep",
		"type" : "boolean",
		"default" : false,
		"description" : "Disable Binary Ninja's core linear sweep so firmware scans drive function discovery."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kCleanupInvalidFunctions,
		R"({
		"title" : "Cleanup invalid functions",
		"type" : "boolean",
		"default" : true,
		"description" : "Remove tiny auto-discovered functions that fail ARMv5 validation checks after analysis."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kCleanupInvalidMaxSize,
		R"({
		"title" : "Cleanup invalid max size",
		"type" : "number",
		"default" : 8,
		"min" : 4,
		"max" : 32,
		"description" : "Maximum size (bytes) for functions eligible for invalid cleanup."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kCleanupInvalidRequireZeroRefs,
		R"({
		"title" : "Cleanup invalid require zero refs",
		"type" : "boolean",
		"default" : true,
		"description" : "Only remove invalid functions with zero incoming references."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kCleanupInvalidRequirePcWrite,
		R"({
		"title" : "Cleanup invalid require PC write",
		"type" : "boolean",
		"default" : true,
		"description" : "Only remove invalid functions whose first instruction writes PC."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kTypeLiteralPools,
		R"({
		"title" : "Type literal pool entries",
		"type" : "boolean",
		"default" : true,
		"description" : "Define literal pool entries as data to avoid disassembling them as code."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kClearAutoDataOnCodeRefs,
		R"({
		"title" : "Clear auto data on code references",
		"type" : "boolean",
		"default" : true,
		"description" : "Undefine auto-discovered data at code-referenced addresses when nearby bytes decode as valid instructions."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kVerboseLogging,
		R"({
		"title" : "Verbose firmware analysis logging",
		"type" : "boolean",
		"default" : true,
		"description" : "Emit per-pass summary logs for firmware analysis heuristics without enabling global debug logging."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kScanMinValidInstr,
		R"({
		"title" : "Scan minimum valid instructions",
		"type" : "number",
		"default" : 2,
		"min" : 1,
		"max" : 16,
		"description" : "Minimum number of consecutive valid ARM instructions required to accept a firmware scan candidate."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kScanMinBodyInstr,
		R"({
		"title" : "Scan minimum body instructions",
		"type" : "number",
		"default" : 1,
		"min" : 0,
		"max" : 16,
		"description" : "Minimum number of valid instructions after the prologue when validating a scan candidate."
		})");
	settings->RegisterSetting(FirmwareSettingKeys::kScanMaxLiteralRun,
		R"({
		"title" : "Scan max literal run",
		"type" : "number",
		"default" : 2,
		"min" : 0,
		"max" : 16,
		"description" : "Maximum consecutive PC-relative literal loads allowed in the validation window."
		})");
}
