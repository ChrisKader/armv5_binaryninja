/*
 * ARMv5 Firmware Settings
 *
 * Centralized settings keys and load helpers for firmware analysis.
 */

#pragma once

#include "firmware_internal.h"

#include <cstdint>

enum class FirmwareSettingsMode
{
	Init,
	Workflow
};

namespace FirmwareSettingKeys
{
	static constexpr const char* kImageBase = "loader.imageBase";
	static constexpr const char* kPlatform = "loader.platform";
	static constexpr const char* kScanPrologues = "loader.armv5.firmware.scanPrologues";
	static constexpr const char* kScanCallTargets = "loader.armv5.firmware.scanCallTargets";
	static constexpr const char* kScanPointerTargets = "loader.armv5.firmware.scanPointerTargets";
	static constexpr const char* kScanOrphanCode = "loader.armv5.firmware.scanOrphanCode";
	static constexpr const char* kOrphanMinValidInstr = "loader.armv5.firmware.orphanMinValidInstr";
	static constexpr const char* kOrphanMinBodyInstr = "loader.armv5.firmware.orphanMinBodyInstr";
	static constexpr const char* kOrphanMinSpacingBytes = "loader.armv5.firmware.orphanMinSpacingBytes";
	static constexpr const char* kOrphanMaxPerPage = "loader.armv5.firmware.orphanMaxPerPage";
	static constexpr const char* kOrphanRequirePrologue = "loader.armv5.firmware.orphanRequirePrologue";
	static constexpr const char* kPartialLinearSweep = "loader.armv5.firmware.partialLinearSweep";
	static constexpr const char* kSkipFirmwareScans = "loader.armv5.firmware.skipFirmwareScans";
	static constexpr const char* kTypeLiteralPools = "loader.armv5.firmware.typeLiteralPools";
	static constexpr const char* kClearAutoDataOnCodeRefs = "loader.armv5.firmware.clearAutoDataOnCodeRefs";
	static constexpr const char* kVerboseLogging = "loader.armv5.firmware.verboseLogging";
	static constexpr const char* kDisablePointerSweep = "loader.armv5.firmware.disablePointerSweep";
	static constexpr const char* kDisableLinearSweep = "loader.armv5.firmware.disableLinearSweep";
	static constexpr const char* kScanMinValidInstr = "loader.armv5.firmware.scanMinValidInstr";
	static constexpr const char* kScanMinBodyInstr = "loader.armv5.firmware.scanMinBodyInstr";
	static constexpr const char* kScanMaxLiteralRun = "loader.armv5.firmware.scanMaxLiteralRun";
	static constexpr const char* kScanRawPointerTables = "loader.armv5.firmware.scanRawPointerTables";
	static constexpr const char* kRawPointerTableMinRun = "loader.armv5.firmware.rawPointerTableMinRun";
	static constexpr const char* kRawPointerTableRequireCodeRefs = "loader.armv5.firmware.rawPointerTableRequireCodeRefs";
	static constexpr const char* kRawPointerTableAllowInCode = "loader.armv5.firmware.rawPointerTableAllowInCode";
	static constexpr const char* kCallScanRequireInFunction = "loader.armv5.firmware.callScanRequireInFunction";
	static constexpr const char* kCleanupInvalidFunctions = "loader.armv5.firmware.cleanupInvalidFunctions";
	static constexpr const char* kCleanupInvalidMaxSize = "loader.armv5.firmware.cleanupInvalidMaxSize";
	static constexpr const char* kCleanupInvalidRequireZeroRefs = "loader.armv5.firmware.cleanupInvalidRequireZeroRefs";
	static constexpr const char* kCleanupInvalidRequirePcWrite = "loader.armv5.firmware.cleanupInvalidRequirePcWrite";
}

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
	FirmwareScanTuning tuning;
};

FirmwareSettings DefaultFirmwareSettings(FirmwareSettingsMode mode);
FirmwareSettings LoadFirmwareSettings(const BinaryNinja::Ref<BinaryNinja::Settings>& settings,
	BinaryNinja::BinaryView* view, FirmwareSettingsMode mode);
void LogFirmwareSettingsSummary(const BinaryNinja::Ref<BinaryNinja::Logger>& logger,
	const FirmwareSettings& settings);
void RegisterFirmwareSettings(const BinaryNinja::Ref<BinaryNinja::Settings>& settings);
