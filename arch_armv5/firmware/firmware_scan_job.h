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
	void ScheduleArmv5FirmwareScanJob(const Ref<BinaryView>& view);
	void CancelArmv5FirmwareScanJob(uint64_t instanceId);
}
