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
	void CancelArmv5FirmwareScanJob(uint64_t instanceId, bool allowRelease = true);
}
