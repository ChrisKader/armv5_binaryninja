/*
 * ARMv5 Firmware Settings
 *
 * Settings keys and load helpers for firmware analysis.
 * Uses the centralized settings infrastructure from settings/plugin_settings.h.
 */

#pragma once

#include "firmware_internal.h"
#include "settings/plugin_settings.h"

#include <cstdint>

enum class FirmwareSettingsMode
{
	Init,
	Workflow
};

// Firmware component name for settings registration
constexpr const char* kFirmwareComponentName = "firmware";

// Setting names (without prefix) - used with component->GetKey()
namespace FirmwareSettingNames
{
	constexpr const char* kScanPrologues = "scanPrologues";
	constexpr const char* kScanCallTargets = "scanCallTargets";
	constexpr const char* kScanPointerTargets = "scanPointerTargets";
	constexpr const char* kScanOrphanCode = "scanOrphanCode";
	constexpr const char* kOrphanMinValidInstr = "orphanMinValidInstr";
	constexpr const char* kOrphanMinBodyInstr = "orphanMinBodyInstr";
	constexpr const char* kOrphanMinSpacingBytes = "orphanMinSpacingBytes";
	constexpr const char* kOrphanMaxPerPage = "orphanMaxPerPage";
	constexpr const char* kOrphanRequirePrologue = "orphanRequirePrologue";
	constexpr const char* kPartialLinearSweep = "partialLinearSweep";
	constexpr const char* kSkipFirmwareScans = "skipFirmwareScans";
	constexpr const char* kTypeLiteralPools = "typeLiteralPools";
	constexpr const char* kClearAutoDataOnCodeRefs = "clearAutoDataOnCodeRefs";
	constexpr const char* kVerboseLogging = "verboseLogging";
	constexpr const char* kDisablePointerSweep = "disablePointerSweep";
	constexpr const char* kDisableLinearSweep = "disableLinearSweep";
	constexpr const char* kScanMinValidInstr = "scanMinValidInstr";
	constexpr const char* kScanMinBodyInstr = "scanMinBodyInstr";
	constexpr const char* kScanMaxLiteralRun = "scanMaxLiteralRun";
	constexpr const char* kScanRawPointerTables = "scanRawPointerTables";
	constexpr const char* kRawPointerTableMinRun = "rawPointerTableMinRun";
	constexpr const char* kRawPointerTableRequireCodeRefs = "rawPointerTableRequireCodeRefs";
	constexpr const char* kRawPointerTableAllowInCode = "rawPointerTableAllowInCode";
	constexpr const char* kCallScanRequireInFunction = "callScanRequireInFunction";
	constexpr const char* kMaxFunctionAdds = "maxFunctionAdds";
	constexpr const char* kCleanupInvalidFunctions = "cleanupInvalidFunctions";
	constexpr const char* kCleanupInvalidMaxSize = "cleanupInvalidMaxSize";
	constexpr const char* kCleanupInvalidRequireZeroRefs = "cleanupInvalidRequireZeroRefs";
	constexpr const char* kCleanupInvalidRequirePcWrite = "cleanupInvalidRequirePcWrite";
}

// Get the firmware settings component (registers if not already registered)
std::shared_ptr<Armv5Settings::SettingsComponent> GetFirmwareSettingsComponent();

struct FirmwareSettings
{
	bool enablePrologueScan;
	bool enableCallTargetScan;
	bool enablePointerTargetScan;
	bool enableOrphanCodeScan;
	bool enableLiteralPoolTyping;
	bool enableClearAutoDataOnCodeRefs;
	bool enableVerboseLogging;
	bool enableInvalidFunctionCleanup;
	bool disablePointerSweep;
	bool disableLinearSweep;
	bool enablePartialLinearSweep;
	bool skipFirmwareScans;
	uint32_t cleanupMaxSizeBytes;
	bool cleanupRequireZeroRefs;
	bool cleanupRequirePcWriteStart;
	uint32_t orphanMinValidInstr;
	uint32_t orphanMinBodyInstr;
	uint32_t orphanMinSpacingBytes;
	uint32_t orphanMaxPerPage;
	bool orphanRequirePrologue;
	uint32_t maxFunctionAdds;
	FirmwareScanTuning tuning;
};

FirmwareSettings DefaultFirmwareSettings(FirmwareSettingsMode mode);
FirmwareSettings LoadFirmwareSettings(const BinaryNinja::Ref<BinaryNinja::Settings>& settings,
	BinaryNinja::BinaryView* view, FirmwareSettingsMode mode);
void LogFirmwareSettingsSummary(const BinaryNinja::Ref<BinaryNinja::Logger>& logger,
	const FirmwareSettings& settings);
void RegisterFirmwareSettings(const BinaryNinja::Ref<BinaryNinja::Settings>& settings);
