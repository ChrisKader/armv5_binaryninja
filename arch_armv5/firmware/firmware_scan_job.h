/*
 * ARMv5 Firmware Scan Job
 *
 * Schedules firmware scans outside of workflow callbacks and applies results
 * in small batches with cancellation support.
 */

#pragma once

#include "firmware_internal.h"

namespace BinaryNinja
{
	// Takes Ref<> that must be passed through from workflow callback - do NOT
	// create a new Ref<> from a raw pointer as that causes shutdown crashes.
	void ScheduleArmv5FirmwareScanJob(Ref<BinaryView> view);
	// Synchronous version for workflow callbacks (which are already on worker threads)
	void RunArmv5FirmwareScanJobSync(Ref<BinaryView> view);
	void CancelArmv5FirmwareScanJob(uint64_t instanceId, bool allowRelease = true);

	// Thread tracking for shutdown coordination
	// Returns the number of currently active firmware scan threads
	int GetActiveArmv5ScanCount();
	// Wait for all firmware scans to complete, with timeout in milliseconds
	// Returns true if all scans completed, false if timed out
	bool WaitForArmv5ScansToComplete(uint32_t timeoutMs);
}
