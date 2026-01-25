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
	/**
	 * Plugin version for analysis caching.
	 *
	 * INCREMENT THIS when making changes that affect analysis results:
	 * - Function detection algorithm changes
	 * - Scoring weight adjustments
	 * - New detection patterns
	 * - Bug fixes that change detected functions
	 *
	 * This version is stored in the bndb metadata. When reopening a bndb,
	 * analysis is skipped if the stored version matches the current version.
	 */
	constexpr uint32_t ARMV5_PLUGIN_VERSION = 2;

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

	/**
	 * Plugin version tracking for bndb caching.
	 *
	 * When analysis completes, we store the plugin version in bndb metadata.
	 * On subsequent opens, we check if the stored version matches the current
	 * plugin version. If it matches, we skip re-analysis.
	 */

	// Store the current plugin version in bndb metadata (call after scan completes)
	void StorePluginVersionInView(const Ref<BinaryView>& view);

	// Check if the stored plugin version matches the current version
	// Returns true if versions match (skip analysis), false otherwise (run analysis)
	bool CheckPluginVersionInView(const Ref<BinaryView>& view);

	// Force re-analysis by clearing the stored version
	void ClearPluginVersionInView(const Ref<BinaryView>& view);
}
