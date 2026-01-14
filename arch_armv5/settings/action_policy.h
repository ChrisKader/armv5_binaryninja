/*
 * ARMv5 Firmware Action Policy
 *
 * Controls what actions the firmware scans are allowed to perform.
 * Parsed from BN_ARMV5_FIRMWARE_DISABLE_ACTIONS environment variable.
 */

#pragma once

namespace Armv5Settings
{

struct FirmwareActionPolicy
{
	bool allowAddFunction = true;
	bool allowDefineData = true;
	bool allowClearData = true;
	bool allowDefineSymbol = true;
	bool allowRemoveFunction = true;
};

// Get the cached action policy (parsed once at first call)
const FirmwareActionPolicy& GetFirmwareActionPolicy();

}
