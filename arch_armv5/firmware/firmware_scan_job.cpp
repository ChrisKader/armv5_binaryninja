/*
 * ARMv5 Firmware Scan Job
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This file implements the background task system for firmware scans.
 * Firmware analysis involves multiple compute-intensive passes that shouldn't
 * block the UI. We run them in a detached background thread with proper
 * cancellation support.
 *
 * ============================================================================
 * THREADING MODEL
 * ============================================================================
 *
 * Pattern: Detached thread with BackgroundTask for UI feedback
 *
 *   Main Thread                      Background Thread
 *   -----------                      -----------------
 *   ScheduleArmv5FirmwareScanJob()
 *       |
 *       +-- Create BackgroundTask
 *       +-- std::thread(...).detach()
 *                                    RunFirmwareScanJob()
 *                                        |
 *                                        +-- WaitForAnalysisIdle()
 *                                        +-- Run scan passes
 *                                        +-- ApplyPlanBatchesDirect()
 *                                        +-- task->Finish()
 *
 * This is the same pattern used by Binary Ninja's EFI resolver and other
 * analysis plugins. The detached thread is self-managing - it finishes
 * the BackgroundTask and releases references before exiting.
 *
 * ============================================================================
 * CANCELLATION
 * ============================================================================
 *
 * Scans can be cancelled via multiple mechanisms:
 * 1. User clicks Cancel on the BackgroundTask progress bar
 * 2. User closes the view (triggers IsFirmwareViewClosingById)
 * 3. Binary Ninja shutdown (BNIsShutdownRequested)
 * 4. Explicit cancel via CancelArmv5FirmwareScanJob
 *
 * ShouldCancel() checks all of these conditions. Scan passes call it
 * periodically to bail out cleanly.
 *
 * ============================================================================
 * LIFETIME SAFETY
 * ============================================================================
 *
 * CRITICAL: The background thread must handle lifetime correctly:
 *
 * 1. Ref<BinaryView> is passed by VALUE to the thread
 *    - This ensures the view stays alive while the thread runs
 *    - Do NOT create new Ref<> from raw pointers in the thread
 *
 * 2. BackgroundTask MUST be finished before thread exits
 *    - Call task->Finish() in all exit paths
 *    - Wrap in try/catch because Finish() may fail during shutdown
 *
 * 3. Check instanceId validity before accessing view
 *    - IsFirmwareViewAliveById() confirms the view is still valid
 *    - Don't assume dynamic_cast will work (wrappers may be used)
 *
 * 4. Release references before thread exits
 *    - Set view = nullptr, task = nullptr explicitly
 *    - This prevents reference cycles and ensures clean shutdown
 *
 * ============================================================================
 * PLAN SYSTEM
 * ============================================================================
 *
 * Scans don't modify the view directly. They populate a FirmwareScanPlan
 * with proposed changes (functions to add/remove, data to define, etc.).
 * ApplyPlanBatchesDirect() then commits the plan atomically.
 *
 * Benefits:
 * - Cancellation discards partial work cleanly
 * - Undo support (entire plan is one undo action)
 * - Debugging (can log the plan before applying)
 *
 * ============================================================================
 * REFERENCE: Similar patterns in:
 * - Binary Ninja EFI resolver
 * - Binary Ninja SharedCache view
 * ============================================================================
 */

#include "firmware_scan_job.h"
#include "firmware_settings.h"
#include "firmware_view.h"
#include "firmware_internal.h"
#include "analysis/rtos_detector.h"
#include "analysis/function_recognizer.h"
#include "analysis/string_detector.h"

#include <binaryninjaapi.h>
#include <binaryninjacore.h>

#include <algorithm>
#include <chrono>
#include <set>
#include <thread>

using namespace BinaryNinja;
using namespace std;

/* Forward declaration for mutex defined in firmware_view.cpp */
extern std::mutex FirmwareViewMutex;

namespace
{
	static constexpr uint64_t kMaxBufferedLength = 64ULL * 1024 * 1024;

static void UpdateTaskText(const Ref<BackgroundTask>& task, uint64_t instanceId, const char* text)
{
	if (!task || !text)
		return;
	// Check shutdown FIRST - if shutting down, don't call any functions that might access static state
	if (BNIsShutdownRequested())
		return;
	// Don't update if view is closing
	if (IsFirmwareViewClosingById(instanceId) || !IsFirmwareViewAliveById(instanceId))
		return;
	// Call SetProgressText directly from background thread (like EFI resolver does)
	// Wrap in try-catch to handle UI destruction during shutdown
	try
	{
		task->SetProgressText(text);
	}
	catch (...)
	{
		// If SetProgressText fails (e.g., UI shutting down), ignore it
	}
}

static void FinishTask(const Ref<BackgroundTask>& task, uint64_t instanceId)
{
	if (!task)
		return;
	// ALWAYS try to finish the task - BackgroundTasks MUST be finished or cancelled
	// Don't check IsFinished() - it might access UI. Just call Finish() and let try-catch handle failures
	try
	{
		task->Finish();
	}
	catch (...)
	{
		// If Finish fails (e.g., UI shutting down), ignore it - task will be cleaned up by BN
	}
}

	static bool ShouldCancel(uint64_t instanceId, const Ref<BinaryView>& view, const Ref<BackgroundTask>& task)
	{
		// Check shutdown FIRST - if shutting down, return true immediately without touching BackgroundTask
		if (BNIsShutdownRequested())
			return true;
		if (IsFirmwareViewClosingById(instanceId))
			return true;
		// Don't check task->IsCancelled() during shutdown - it may access destroyed UI
		if (task && !BNIsShutdownRequested())
		{
			try
			{
				if (task->IsCancelled())
					return true;
			}
			catch (...)
			{
				// If IsCancelled fails, treat as cancelled
				return true;
			}
		}
		if (IsFirmwareViewScanCancelledById(instanceId))
			return true;
		if (!view || !view->GetObject())
			return true;
		if (!IsFirmwareViewAliveById(instanceId))
			return true;
		return false;
	}

bool WaitForAnalysisIdle(uint64_t instanceId, const Ref<BinaryView>& view,
	const Ref<BackgroundTask>& task, const Ref<Logger>& logger)
{
	if (!view || !view->GetObject())
		return false;
	const auto start = chrono::steady_clock::now();
	constexpr auto kSleep = chrono::milliseconds(100);
	constexpr auto kLogInterval = chrono::seconds(5);
		auto nextLog = start + kLogInterval;
	UpdateTaskText(task, instanceId, "ARMv5 firmware scans: waiting for analysis to idle");
		while (true)
		{
			if (ShouldCancel(instanceId, view, task))
				return false;
			BNAnalysisState state = view->GetAnalysisInfo().state;
			if (state == IdleState || state == HoldState)
				break;
			auto now = chrono::steady_clock::now();
			if (logger && now >= nextLog)
			{
				logger->LogInfo("Firmware workflow scan: waiting for analysis to idle");
				nextLog = now + kLogInterval;
			}
			this_thread::sleep_for(kSleep);
		}
	UpdateTaskText(task, instanceId, "ARMv5 firmware scans: running");
		return true;
	}

	// Simple cancellation check for synchronous workflow execution
	bool ScanCancelled(const Ref<BinaryView>& view)
	{
		if (BNIsShutdownRequested())
			return true;
		if (!view || !view->GetObject())
			return true;
		if (IsFirmwareViewClosing(view.GetPtr()))
			return true;
		if (IsFirmwareViewScanCancelled(view.GetPtr()))
			return true;
		return false;
	}

	void DedupAddresses(vector<uint64_t>& addrs)
	{
		sort(addrs.begin(), addrs.end());
		addrs.erase(unique(addrs.begin(), addrs.end()), addrs.end());
	}

	unordered_set<uint64_t> SnapshotFunctionStarts(const Ref<BinaryView>& view)
	{
		unordered_set<uint64_t> starts;
		if (!view || !view->GetObject())
			return starts;
		auto funcs = view->GetAnalysisFunctionList();
		starts.reserve(funcs.size());
		for (const auto& func : funcs)
		{
			if (!func)
				continue;
			starts.insert(func->GetStart());
		}
		return starts;
	}

	void LogFunctionDiff(const Ref<Logger>& logger,
		const unordered_set<uint64_t>& before,
		const unordered_set<uint64_t>& after,
		bool logLists)
	{
		if (!logger)
			return;
		vector<uint64_t> added;
		vector<uint64_t> removed;
		added.reserve(after.size());
		removed.reserve(before.size());
		for (uint64_t addr : after)
		{
			if (before.find(addr) == before.end())
				added.push_back(addr);
		}
		for (uint64_t addr : before)
		{
			if (after.find(addr) == after.end())
				removed.push_back(addr);
		}
		sort(added.begin(), added.end());
		sort(removed.begin(), removed.end());
		logger->LogInfo("Firmware scan: function diff added=%zu removed=%zu", added.size(), removed.size());
		const size_t kMaxLog = 50;
		if (logLists && !added.empty())
		{
			string line = "Firmware scan: added functions:";
			for (size_t i = 0; i < added.size() && i < kMaxLog; ++i)
				line += fmt::format(" 0x{:x}", added[i]);
			if (added.size() > kMaxLog)
				line += fmt::format(" ... (+{} more)", added.size() - kMaxLog);
			logger->LogInfo("%s", line.c_str());
		}
		if (logLists && !removed.empty())
		{
			string line = "Firmware scan: removed functions:";
			for (size_t i = 0; i < removed.size() && i < kMaxLog; ++i)
				line += fmt::format(" 0x{:x}", removed[i]);
			if (removed.size() > kMaxLog)
				line += fmt::format(" ... (+{} more)", removed.size() - kMaxLog);
			logger->LogWarn("%s", line.c_str());
		}
	}

	bool IsValidFunctionStart(const Ref<BinaryView>& view,
		const Ref<Platform>& platform,
		uint64_t addr,
		bool verbose,
		const Ref<Logger>& logger)
	{
		if (!view || !view->GetObject())
			return false;

		Ref<Architecture> arch = platform ? platform->GetArchitecture() : view->GetDefaultArchitecture();
		if (!arch)
			return false;
		
		const bool enforceExecutable = !view->GetSegments().empty();
		const bool enforceCodeSemantics = !view->GetSections().empty();

		const size_t align = arch->GetInstructionAlignment();
		uint64_t checkAddr = addr & ~1ULL;  // Clear potential Thumb bit
		
		// Reject misaligned addresses
		if (align == 4 && (checkAddr & 3))
		{
			if (verbose && logger)
				logger->LogDebug("IsValidFunctionStart: rejected misaligned ARM address 0x%llx", (unsigned long long)addr);
			return false;
		}
		if (align == 2 && (checkAddr & 1))
		{
			if (verbose && logger)
				logger->LogDebug("IsValidFunctionStart: rejected misaligned Thumb address 0x%llx", (unsigned long long)addr);
			return false;
		}

		if (!view->IsValidOffset(checkAddr))
			return false;
		if (!view->IsOffsetBackedByFile(checkAddr))
			return false;
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(checkAddr))
			return false;
		DataVariable dataVar;
		if (view->GetDataVariableAtAddress(checkAddr, dataVar) && (dataVar.address == checkAddr))
			return false;
		if (enforceExecutable && view->IsOffsetExecutable(checkAddr) == false)
			return false;

		/*
		 * Validate multiple consecutive instructions.
		 * A valid function should have multiple valid instructions in a row.
		 * Checking just the first instruction isn't enough - data can accidentally
		 * decode to a single valid instruction.
		 */
		constexpr size_t kMinValidInstructions = 3;
		constexpr size_t kMaxBytesToCheck = 16;
		
		DataBuffer buf = view->ReadBuffer(checkAddr, kMaxBytesToCheck);
		if (buf.GetLength() < 4)
			return false;

		const uint8_t* bytes = static_cast<const uint8_t*>(buf.GetData());
		size_t offset = 0;
		size_t validCount = 0;
		
		while (offset + 4 <= buf.GetLength() && validCount < kMinValidInstructions)
		{
			const uint8_t* instrBytes = bytes + offset;
			const bool allZero = instrBytes[0] == 0 && instrBytes[1] == 0 && 
			                     instrBytes[2] == 0 && instrBytes[3] == 0;
			const bool allFF = instrBytes[0] == 0xFF && instrBytes[1] == 0xFF && 
			                   instrBytes[2] == 0xFF && instrBytes[3] == 0xFF;
			if (allZero || allFF)
				return false;

			InstructionInfo info;
			if (!arch->GetInstructionInfo(instrBytes, checkAddr + offset, buf.GetLength() - offset, info))
				return false;
			
			if (info.length == 0)
				return false;

			validCount++;
			offset += info.length;
			
			/* Stop if we hit an unconditional branch/return - function might be short */
			for (size_t i = 0; i < info.branchCount; i++)
			{
				if (info.branchType[i] == UnconditionalBranch ||
				    info.branchType[i] == FunctionReturn)
				{
					if (validCount >= 1)
						return true;
				}
			}
		}

		return validCount >= kMinValidInstructions;
	}

	// Apply plan batches directly (called from workflow context, no main thread dispatch needed)
	bool ApplyPlanBatchesDirect(const Ref<BinaryView>& view,
		const FirmwareSettings& fwSettings, const FirmwareScanPlan& plan, const Ref<Logger>& logger)
	{
		if (ScanCancelled(view))
			return false;

		Ref<Platform> platform = view->GetDefaultPlatform();
		if (!platform)
			return false;
		Ref<Architecture> baseArch = view->GetDefaultArchitecture();
		auto resolvePlatformForAddress = [&](uint64_t& addr) -> Ref<Platform> {
			Ref<Platform> targetPlat = platform;
			if (baseArch)
			{
				// Only detect Thumb if bit 0 is explicitly set
				Ref<Architecture> targetArch = baseArch->GetAssociatedArchitectureByAddress(addr);
				if (targetArch && targetArch != baseArch)
				{
					Ref<Platform> related = platform->GetRelatedPlatform(targetArch);
					if (related)
						targetPlat = related;
				}
			}
			return targetPlat;
		};

		bool prevDisabled = view->GetFunctionAnalysisUpdateDisabled();
		view->SetFunctionAnalysisUpdateDisabled(true);

		struct UndoGuard
		{
			Ref<BinaryView> view;
			std::string id;
			bool active = false;
			explicit UndoGuard(const Ref<BinaryView>& v) : view(v) {}
			void Begin()
			{
				if (!view || !view->GetObject())
					return;
				id = view->BeginUndoActions(false);
				active = !id.empty();
			}
			void Commit()
			{
				if (active && view && view->GetObject())
					view->CommitUndoActions(id);
				active = false;
			}
			void Revert()
			{
				if (active && view && view->GetObject())
					view->RevertUndoActions(id);
				active = false;
			}
		} undoGuard(view);

		if (!BNIsShutdownRequested() && !IsFirmwareViewClosing(view.GetPtr()))
			undoGuard.Begin();

		bool loggedAbort = false;
		auto shouldAbort = [&]() -> bool {
			if (ScanCancelled(view))
				return true;
			if (view->AnalysisIsAborted())
			{
				if (!loggedAbort && logger)
					logger->LogWarn("Firmware scan: stopping apply because analysis was aborted");
				loggedAbort = true;
				return true;
			}
			return false;
		};

		auto finishUpdatesGuard = [&]() {
			if (!view || !view->GetObject())
				return;
			if (BNIsShutdownRequested())
				return;
			if (IsFirmwareViewClosing(view.GetPtr()))
				return;
			view->SetFunctionAnalysisUpdateDisabled(prevDisabled);
		};

		vector<uint64_t> userAddrs = plan.addUserFunctions;
		DedupAddresses(userAddrs);

		const size_t batchSize = 256;
		for (size_t i = 0; i < userAddrs.size(); i += batchSize)
		{
			if (shouldAbort())
			{
				undoGuard.Revert();
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(userAddrs.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
			{
				uint64_t addr = userAddrs[j];

				// HARD BOUNDARY: Don't create functions in known data regions
				uint64_t dataBoundary = fwSettings.codeDataBoundary;
				if (dataBoundary == 0)
				{
					// Auto-detect: skip addresses that are very high in the binary
					// Use a conservative heuristic - halfway point in the view
					dataBoundary = view->GetStart() + (view->GetLength() / 2);
				}
				if (addr >= dataBoundary)
				{
					if (logger)
						logger->LogDebug("Plan apply: Skipping user function at 0x%llx - in data region (>= 0x%llx)",
							(unsigned long long)addr, (unsigned long long)dataBoundary);
					continue;
				}

				Ref<Platform> targetPlat = resolvePlatformForAddress(addr);
				if (!targetPlat)
					targetPlat = platform;
				if (!IsValidFunctionStart(view, targetPlat, addr, fwSettings.enableVerboseLogging, logger))
					continue;
				Ref<Function> func = view->GetAnalysisFunction(targetPlat.GetPtr(), addr);
				if (!func)
				{
					func = view->CreateUserFunction(targetPlat.GetPtr(), addr);
					if (!func)
					{
						// Fall back to analysis function creation if user creation fails.
						view->AddFunctionForAnalysis(targetPlat.GetPtr(), addr, true);
						if (logger)
							logger->LogWarn("Firmware scan: user function create failed at 0x%llx, falling back to analysis",
								(unsigned long long)addr);
					}
				}
			}
			// Delay to prevent overwhelming the analysis system
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}

		vector<uint64_t> addrs = plan.addFunctions;
		DedupAddresses(addrs);
		if (!userAddrs.empty() && !addrs.empty())
		{
			// Avoid adding the same function twice (user + analysis).
			vector<uint64_t> filtered;
			filtered.reserve(addrs.size());
			size_t i = 0;
			size_t j = 0;
			while (i < addrs.size())
			{
				while (j < userAddrs.size() && userAddrs[j] < addrs[i])
					++j;
				if (j < userAddrs.size() && userAddrs[j] == addrs[i])
				{
					++i;
					continue;
				}
				filtered.push_back(addrs[i]);
				++i;
			}
			addrs.swap(filtered);
		}
		// Use configured limit - ARMv7 handles thousands fine, issue must be ARMv5-specific
		if (fwSettings.maxFunctionAdds > 0 && addrs.size() > fwSettings.maxFunctionAdds)
		{
			if (logger)
				logger->LogWarn("Firmware scan: capping function adds at %u (had %zu)",
					fwSettings.maxFunctionAdds, addrs.size());
			addrs.resize(fwSettings.maxFunctionAdds);
		}

		for (size_t i = 0; i < addrs.size(); i += batchSize)
		{
			if (shouldAbort())
			{
				undoGuard.Revert();
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(addrs.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
			{
				uint64_t addr = addrs[j];

				// HARD BOUNDARY: Don't create functions in known data regions
				uint64_t dataBoundary = fwSettings.codeDataBoundary;
				if (dataBoundary == 0)
				{
					// Auto-detect: skip addresses that are very high in the binary
					// Use a conservative heuristic - halfway point in the view
					dataBoundary = view->GetStart() + (view->GetLength() / 2);
				}
				if (addr >= dataBoundary)
				{
					if (logger)
						logger->LogDebug("Plan apply: Skipping analysis function at 0x%llx - in data region (>= 0x%llx)",
							(unsigned long long)addr, (unsigned long long)dataBoundary);
					continue;
				}

				Ref<Platform> targetPlat = resolvePlatformForAddress(addr);
				if (!targetPlat)
					targetPlat = platform;
				if (!IsValidFunctionStart(view, targetPlat, addr, fwSettings.enableVerboseLogging, logger))
					continue;
				// Create function with analysis initially disabled for UI stability
				Ref<Function> func = view->CreateUserFunction(targetPlat.GetPtr(), addr);
				if (!func)
					view->AddFunctionForAnalysis(targetPlat.GetPtr(), addr, true);
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}

		for (size_t i = 0; i < plan.defineData.size(); i += batchSize)
		{
			if (shouldAbort())
			{
				undoGuard.Revert();
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(plan.defineData.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
			{
				const auto& def = plan.defineData[j];
				if (def.type)
				{
					if (def.user)
						view->DefineUserDataVariable(def.address, def.type);
					else
						view->DefineDataVariable(def.address, def.type);
				}
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}

		for (size_t i = 0; i < plan.undefineData.size(); i += batchSize)
		{
			if (shouldAbort())
			{
				undoGuard.Revert();
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(plan.undefineData.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
				view->UndefineDataVariable(plan.undefineData[j], false);
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}

		for (size_t i = 0; i < plan.defineSymbols.size(); i += batchSize)
		{
			if (shouldAbort())
			{
				undoGuard.Revert();
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(plan.defineSymbols.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
				view->DefineAutoSymbol(plan.defineSymbols[j]);
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}

		for (size_t i = 0; i < plan.removeFunctions.size(); i += batchSize)
		{
			if (shouldAbort())
			{
				undoGuard.Revert();
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(plan.removeFunctions.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
			{
				uint64_t addr = plan.removeFunctions[j];
				Ref<Function> func = view->GetAnalysisFunction(platform.GetPtr(), addr);
				if (!func)
				{
					auto funcs = view->GetAnalysisFunctionsContainingAddress(addr);
					if (!funcs.empty())
						func = funcs.front();
				}
				if (func)
				{
					if (logger)
						logger->LogWarn("Firmware scan: removing function at 0x%llx (plan remove)",
							(unsigned long long)addr);
					view->RemoveAnalysisFunction(func, true);
				}
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}

		finishUpdatesGuard();
		undoGuard.Commit();
		return true;
	}

	void RunFirmwareScanJob(Ref<BinaryView> view, Ref<BackgroundTask> task, uint64_t instanceId)
	{
		// Ensure task is finished before thread exits, even during shutdown
		// BackgroundTasks MUST be finished or cancelled, otherwise they persist
		auto ensureTaskFinished = [&task]() {
			if (task)
			{
				try
				{
					task->Finish();
				}
				catch (...)
				{
					// Ignore failures - task will be cleaned up by BN
				}
				// Explicitly release the reference
				task = nullptr;
			}
		};

		// Check shutdown FIRST - if shutting down, finish task and exit immediately
		if (BNIsShutdownRequested())
		{
			ensureTaskFinished();
			return;
		}

		if (!view || !view->GetObject())
		{
			FinishTask(task, instanceId);
			return;
		}

		Ref<Logger> logger = LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareView");

	auto finishTask = [&]() {
		FinishTask(task, instanceId);
	};

	try
	{
		if (ShouldCancel(instanceId, view, task))
		{
			finishTask();
			return;
		}

		UpdateTaskText(task, instanceId, "ARMv5 firmware scans: preparing");

		uint64_t length = view->GetParentView()->GetLength();
		if (ScanCancelled(view))
		{
			finishTask();
			return;
		}
		if (!WaitForAnalysisIdle(instanceId, view, task, logger))
		{
			finishTask();
			return;
		}

		Ref<Settings> settings = view->GetLoadSettings(view->GetTypeName());
		FirmwareSettings fwSettings = LoadFirmwareSettings(settings, view.GetPtr(), FirmwareSettingsMode::Workflow);
		const FirmwareScanTuning& tuning = fwSettings.tuning;

		if (fwSettings.skipFirmwareScans)
		{
			if (logger)
				logger->LogInfo("Firmware workflow scan skipped (skipFirmwareScans enabled)");
			finishTask();
			SetFirmwareViewScanCancelled(instanceId, false);
			return;
		}

		uint64_t imageBase = view->GetStart();
		uint64_t bufferLen = (length < kMaxBufferedLength) ? length : kMaxBufferedLength;
		DataBuffer fileBuf = view->GetParentView()->ReadBuffer(0, bufferLen);
		const uint8_t* fileData = static_cast<const uint8_t*>(fileBuf.GetData());
		uint64_t fileDataLen = fileBuf.GetLength();
		if (!fileData || fileDataLen == 0)
		{
			finishTask();
			return;
		}

		Ref<BinaryView> parentView = view->GetParentView();
		if (!parentView)
		{
			finishTask();
			return;
		}
		BinaryReader reader(parentView);
		reader.SetEndianness(view->GetDefaultEndianness());

		// dynamic_cast may fail if view is a wrapper from analysis context
		// Use instanceId lookup like we do elsewhere
		Armv5FirmwareView* firmwareView = dynamic_cast<Armv5FirmwareView*>(view.GetPtr());
		if (!firmwareView)
		{
			firmwareView = GetFirmwareViewForInstanceId(instanceId);
			if (!firmwareView)
			{
				if (logger) logger->LogInfo("RunFirmwareScanJob: failed to get firmwareView for instanceId=%llx", (unsigned long long)instanceId);
				finishTask();
				return;
			}
		}

		FirmwareScanPlan plan;
		std::set<uint64_t> seededFunctions = firmwareView->GetSeededFunctions();
		const auto& seededUserFunctions = firmwareView->GetSeededUserFunctions();
		const auto& seededDefines = firmwareView->GetSeededDataDefines();
		const auto& seededSymbols = firmwareView->GetSeededSymbols();
		std::set<uint64_t> addedFunctions;
		if (!seededFunctions.empty())
		{
			for (uint64_t addr : seededFunctions)
				plan.addFunctions.push_back(addr);
		}
		if (!seededUserFunctions.empty())
		{
			for (uint64_t addr : seededUserFunctions)
				plan.addUserFunctions.push_back(addr);
		}
		if (!seededDefines.empty())
			plan.defineData.insert(plan.defineData.end(), seededDefines.begin(), seededDefines.end());
		if (!seededSymbols.empty())
			plan.defineSymbols.insert(plan.defineSymbols.end(), seededSymbols.begin(), seededSymbols.end());

		auto timePass = [&](const char* label, auto&& fn)
		{
			if (!fwSettings.enableVerboseLogging)
			{
				fn();
				return;
			}
			auto start = chrono::steady_clock::now();
			fn();
			double seconds = chrono::duration_cast<chrono::duration<double>>(
				chrono::steady_clock::now() - start).count();
			if (logger)
				logger->LogInfo("Firmware workflow timing: %s took %.3f s", label, seconds);
		};

		FirmwareScanContext scanCtx{
			reader, fileData, fileDataLen, view->GetDefaultEndianness(), imageBase, length,
			view->GetDefaultArchitecture(), view->GetDefaultPlatform(),
			logger, fwSettings.enableVerboseLogging, view, &plan
		};
		auto refreshViewForPhase = [&]() -> bool {
			if (!view || !view->GetObject())
				return false;
			if (IsFirmwareViewClosingById(instanceId) || !IsFirmwareViewAliveById(instanceId))
				return false;
			scanCtx.view = view.GetPtr();
			scanCtx.arch = view->GetDefaultArchitecture();
			scanCtx.plat = view->GetDefaultPlatform();
			scanCtx.endian = view->GetDefaultEndianness();
			return true;
		};

		if (logger)
			logger->LogInfo("Firmware workflow scan: start");

		if (!refreshViewForPhase())
		{
			finishTask();
			return;
		}
		if (fwSettings.enableLiteralPoolTyping)
		{
			timePass("Literal pool typing", [&]() { TypeLiteralPoolEntries(scanCtx); });
			if (fwSettings.enableClearAutoDataOnCodeRefs)
				timePass("Clear auto data on code refs", [&]() { ClearAutoDataOnCodeReferences(scanCtx); });
		}

		if (ScanCancelled(view))
		{
			finishTask();
			return;
		}

		// =====================================================================
		// UNIFIED RECOGNIZER PATH (when enabled)
		// =====================================================================
		// The unified FunctionRecognizer combines all detection heuristics into
		// a single pass with configurable weights. When enabled, it replaces
		// the legacy prologue/call/pointer/orphan scan functions.
		//
		// DARM APPROACH: When using the unified recognizer, we suppress BN's
		// automatic function creation at call targets. This prevents false
		// positives where BN creates functions at epilogue stubs (e.g., BX LR).
		// Our recognizer explicitly validates each candidate before adding it.
		if (fwSettings.useUnifiedRecognizer)
		{
			if (!refreshViewForPhase())
			{
				finishTask();
				return;
			}

			UpdateTaskText(task, instanceId, "ARMv5 scans: running unified function recognizer");

			timePass("Unified function recognizer", [&]() {
				auto* recognizer = Armv5Analysis::GetRecognizerForView(view.GetPtr());
				if (!recognizer)
				{
					if (logger)
						logger->LogError("Failed to get FunctionRecognizer for view");
					return;
				}

				// Apply preset (0=default, 1=aggressive, 2=conservative, 3=prologue, 4=calls)
				switch (fwSettings.recognizerPreset)
				{
				case 1: recognizer->UseAggressiveSettings(); break;
				case 2: recognizer->UseConservativeSettings(); break;
				case 3: recognizer->UsePrologueOnlySettings(); break;
				case 4: recognizer->UseCallTargetOnlySettings(); break;
				default: recognizer->UseDefaultSettings(); break;
				}

				// Run recognition
				auto result = recognizer->RunRecognition();

				if (result.cancelled)
				{
					if (logger)
						logger->LogInfo("Function recognition cancelled");
					return;
				}

				if (!result.completed)
				{
					if (logger)
						logger->LogError("Function recognition failed: %s", result.errorMessage.c_str());
					return;
				}

				// Use lower threshold to match ARMv7's function discovery capability
				// ARMv7 finds 2813 mostly valid functions, so ARMv5 should be able to find more
				double minScore = std::min(0.15, fwSettings.recognizerMinScorePct / 100.0);  // 15% minimum

				// Add candidates to the plan
				auto candidateAddrs = recognizer->GetCandidateAddresses(result, minScore);
				for (const auto& [addr, isThumb] : candidateAddrs)
				{
					plan.addFunctions.push_back(addr);
					addedFunctions.insert(addr);
				}

				if (logger)
				{
					logger->LogInfo("Function recognizer found %zu candidates (min_score=%.2f): "
						"%zu high, %zu med, %zu low confidence",
						result.candidates.size(), minScore,
						result.highConfidenceCount, result.mediumConfidenceCount,
						result.lowConfidenceCount);
				}
			});

			// Skip legacy scans when unified recognizer is enabled
			goto after_legacy_scans;
		}

		// =====================================================================
		// LEGACY SCAN PATH (prologue, call targets, pointer targets, orphan)
		// =====================================================================

		if (!refreshViewForPhase())
		{
			finishTask();
			return;
		}
		if (fwSettings.enablePrologueScan)
		{
			Ref<Architecture> thumbArch = Architecture::GetByName("armv5t");
			timePass("Function prologue scan", [&]() {
				ScanForFunctionPrologues(view, fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, view->GetDefaultArchitecture(), thumbArch, view->GetDefaultPlatform(),
					logger, fwSettings.enableVerboseLogging, tuning, fwSettings.codeDataBoundary, &seededFunctions, &plan);
			});
		}

		if (ScanCancelled(view))
		{
			finishTask();
			return;
		}

		if (!refreshViewForPhase())
		{
			finishTask();
			return;
		}
		if (fwSettings.enableClearAutoDataOnCodeRefs)
		{
			timePass("Clear auto data in function entry blocks", [&]() {
				ClearAutoDataInFunctionEntryBlocks(scanCtx, &seededFunctions);
			});
		}

		if (!refreshViewForPhase())
		{
			finishTask();
			return;
		}
		if (fwSettings.enableCallTargetScan)
		{
			timePass("Call target scan", [&]() {
				ScanForCallTargets(view, fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, view->GetDefaultPlatform(), logger, fwSettings.enableVerboseLogging,
					tuning, fwSettings.codeDataBoundary, &seededFunctions, &plan);
			});
		}

		if (ScanCancelled(view))
		{
			finishTask();
			return;
		}

		if (!refreshViewForPhase())
		{
			finishTask();
			return;
		}
		if (fwSettings.enablePointerTargetScan)
		{
			timePass("Pointer target scan", [&]() {
				ScanForPointerTargets(view, fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, view->GetDefaultPlatform(), logger, fwSettings.enableVerboseLogging,
					tuning, fwSettings.codeDataBoundary, &addedFunctions, &plan);
			});
		}

		if (ScanCancelled(view))
		{
			finishTask();
			return;
		}

		if (!refreshViewForPhase())
		{
			finishTask();
			return;
		}
		if (fwSettings.enableOrphanCodeScan)
		{
			timePass("Orphan code block scan", [&]() {
				ScanForOrphanCodeBlocks(view, fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, view->GetDefaultPlatform(), logger, fwSettings.enableVerboseLogging,
					tuning, fwSettings.codeDataBoundary, fwSettings.orphanMinValidInstr, fwSettings.orphanMinBodyInstr,
					fwSettings.orphanMinSpacingBytes, fwSettings.orphanMaxPerPage,
					fwSettings.orphanRequirePrologue, &addedFunctions, &plan);
			});
		}

		if (!addedFunctions.empty())
			seededFunctions.insert(addedFunctions.begin(), addedFunctions.end());

		if (!refreshViewForPhase())
		{
			finishTask();
			return;
		}
		if (fwSettings.enableClearAutoDataOnCodeRefs && !addedFunctions.empty())
		{
			timePass("Clear auto data in new function entry blocks", [&]() {
				ClearAutoDataInFunctionEntryBlocks(scanCtx, &addedFunctions);
			});
		}

		// Cleanup is now performed after plan application (see below after_legacy_scans)
		// This allows it to catch functions created by BN's core analysis too

	after_legacy_scans:  // Jump target for unified recognizer path

		if (logger)
		{
			logger->LogInfo("Firmware scan plan: user_add=%zu add=%zu remove=%zu define=%zu undefine=%zu symbols=%zu",
				plan.addUserFunctions.size(), plan.addFunctions.size(), plan.removeFunctions.size(), plan.defineData.size(),
				plan.undefineData.size(), plan.defineSymbols.size());
		}

		bool applied = false;
		unordered_set<uint64_t> beforeFunctions = SnapshotFunctionStarts(view);
		if (!refreshViewForPhase())
		{
			finishTask();
			return;
		}
		if (!ScanCancelled(view))
			applied = ApplyPlanBatchesDirect(view, fwSettings, plan, logger);

		WaitForAnalysisIdle(instanceId, view, task, logger);
		auto afterFunctions = SnapshotFunctionStarts(view);
		
		// Run cleanup AFTER applying the plan and waiting for analysis
		// This ensures we remove functions that BN created with invalid instructions
		if (fwSettings.enableInvalidFunctionCleanup && !ScanCancelled(view))
		{
			if (logger)
				logger->LogInfo("Cleanup invalid functions: running post-analysis cleanup (max_size=%u zero_refs=%d pc_write=%d)",
					fwSettings.cleanupMaxSizeBytes,
					fwSettings.cleanupRequireZeroRefs ? 1 : 0,
					fwSettings.cleanupRequirePcWriteStart ? 1 : 0);
			
			std::set<uint64_t> protectedStarts;
			auto addProtected = [&](uint64_t addr) {
				protectedStarts.insert(addr);
				protectedStarts.insert(addr & ~1ULL);
			};
			for (uint64_t addr : seededFunctions)
				addProtected(addr);
			for (uint64_t addr : seededUserFunctions)
				addProtected(addr);
			
			// Run cleanup directly (not via plan) since plan was already applied
			size_t removed = CleanupInvalidFunctions(view, fileData, fileDataLen, view->GetDefaultEndianness(),
				imageBase, length, logger, fwSettings.enableVerboseLogging, tuning,
				fwSettings.cleanupMaxSizeBytes, fwSettings.cleanupRequireZeroRefs,
				fwSettings.cleanupRequirePcWriteStart, view->GetEntryPoint(), protectedStarts, nullptr);
			
			if (logger)
				logger->LogInfo("Cleanup invalid functions: removed %zu functions", removed);
			
			// Update function snapshot after cleanup
			WaitForAnalysisIdle(instanceId, view, task, logger);
			afterFunctions = SnapshotFunctionStarts(view);

			// Run an additional cleanup pass to catch late-added functions.
			// Core analysis can still add functions after the first cleanup.
			for (int pass = 0; pass < 2; ++pass)
			{
				if (ScanCancelled(view))
					break;
				size_t removedPass = CleanupInvalidFunctions(view, fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, logger, fwSettings.enableVerboseLogging, tuning,
					fwSettings.cleanupMaxSizeBytes, fwSettings.cleanupRequireZeroRefs,
					fwSettings.cleanupRequirePcWriteStart, view->GetEntryPoint(), protectedStarts, nullptr);
				if (logger)
					logger->LogInfo("Cleanup invalid functions: pass %d removed %zu functions", pass + 2, removedPass);
				if (removedPass == 0)
					break;
				WaitForAnalysisIdle(instanceId, view, task, logger);
			}
		}
		LogFunctionDiff(logger, beforeFunctions, afterFunctions, fwSettings.enableVerboseLogging);
		StoreFirmwareFunctionSnapshot(instanceId, afterFunctions);

		// Run RTOS detection after scans complete
		if (!ScanCancelled(view))
		{
			UpdateTaskText(task, instanceId, "ARMv5 firmware scans: detecting RTOS");
			auto rtosResult = armv5::RTOSDetector::DetectRTOS(view.GetPtr());
			if (rtosResult.type != armv5::RTOSType::Unknown)
			{
				if (logger)
					logger->LogInfo("RTOS detected: %s (%zu tasks)", 
						armv5::RTOSTypeToString(rtosResult.type), rtosResult.tasks.size());
				
				// Define RTOS types
				armv5::RTOSDetector::DefineRTOSTypes(view.GetPtr(), rtosResult.type);
				
				// Apply task conventions
				if (!rtosResult.tasks.empty())
				{
					armv5::RTOSDetector::ApplyTaskConventions(view.GetPtr(), rtosResult.tasks);
					armv5::RTOSDetector::AnnotateTCBs(view.GetPtr(), rtosResult.tasks, rtosResult.type);
				}
			}
		}

		// DISABLED: ARMv5 custom string detection creates false positives
		// Core Binary Ninja string analysis works correctly for ARMv5
		// Just like it does for ARMv7
		/*
		if (!ScanCancelled(view))
		{
			UpdateTaskText(task, instanceId, "ARMv5 firmware scans: string detection");
			Armv5Analysis::StringDetector stringDetector(view.GetPtr());
			auto detectedStrings = stringDetector.Detect(Armv5Analysis::StringDetectionSettings{});

			// Define detected strings in the BinaryView
			for (const auto& str : detectedStrings)
			{
				// Check if a data variable already exists at this address
				DataVariable existingVar;
				bool hasExistingVar = view->GetDataVariableAtAddress(str.address, existingVar);

				if (!hasExistingVar)
				{
					// Create string type (null-terminated array of chars)
					auto stringType = Type::ArrayType(Type::IntegerType(1, true), str.length + 1); // +1 for null terminator
					view->DefineDataVariable(str.address, stringType);
				}

				// Create a symbol for the string based on its category (only if no symbol exists)
				if (!view->GetSymbolByAddress(str.address))
				{
					std::string symbolName;
					switch (str.category) {
					case Armv5Analysis::StringCategory::ErrorMessage: symbolName = "str_err_"; break;
					case Armv5Analysis::StringCategory::DebugMessage: symbolName = "str_dbg_"; break;
					case Armv5Analysis::StringCategory::FilePath: symbolName = "str_path_"; break;
					case Armv5Analysis::StringCategory::URL: symbolName = "str_url_"; break;
					case Armv5Analysis::StringCategory::Version: symbolName = "str_ver_"; break;
					case Armv5Analysis::StringCategory::FormatString: symbolName = "str_fmt_"; break;
					case Armv5Analysis::StringCategory::Command: symbolName = "str_cmd_"; break;
					case Armv5Analysis::StringCategory::Identifier: symbolName = "str_id_"; break;
					case Armv5Analysis::StringCategory::Crypto: symbolName = "str_crypto_"; break;
					default: symbolName = "str_"; break;
					}
					symbolName += std::to_string(str.address);
					view->DefineAutoSymbol(new Symbol(DataSymbol, symbolName, str.address, LocalBinding));
				}
			}

			if (logger) {
				logger->LogInfo("String detection: found %zu strings (%zu new, %zu unreferenced, %zu in code)",
					stringDetector.GetStats().totalFound, stringDetector.GetStats().newStrings,
					stringDetector.GetStats().unreferenced, stringDetector.GetStats().inLiteralPools);
			}
		}
		*/

		// Analysis is not suppressed - functions are analyzed normally

		// Post-analysis cleanup: DISABLED - causing crashes
		// TODO: Investigate thread safety issues with PostAnalysisCleanup
		/*
		if (!ScanCancelled(view))
		{
			UpdateTaskText(task, instanceId, "ARMv5 firmware scans: post-analysis cleanup");
			PostAnalysisCleanup(view, logger);
		}
		*/

		// Ensure string references are properly typed as data variables
		// Core string analysis creates string references but may not create typed data variables
		if (!ScanCancelled(view))
		{
			auto strings = view->GetStrings();

			// Also scan for null-terminated strings that Binary Ninja missed
			std::vector<BNStringReference> additionalStrings;
			const size_t scanChunkSize = 1024 * 1024; // 1MB chunks
			uint64_t startAddr = view->GetStart();
			uint64_t endAddr = view->GetEnd();

			if (logger)
			{
				logger->LogInfo("Scanning address range 0x%llx - 0x%llx for additional strings", startAddr, endAddr);
			}

			for (uint64_t addr = startAddr; addr < endAddr; addr += scanChunkSize)
			{
				if (ScanCancelled(view))
					break;

				uint64_t chunkEnd = std::min(addr + scanChunkSize, endAddr);
				DataBuffer buffer = view->ReadBuffer(addr, chunkEnd - addr);
				if (buffer.GetLength() == 0)
					continue;

				const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());
				size_t length = buffer.GetLength();

				// Scan for null-terminated ASCII/UTF-8 strings
				for (size_t i = 0; i < length; )
				{
					// Skip null bytes
					if (data[i] == 0x00)
					{
						i++;
						continue;
					}

					// Start at printable character or specific allowed non-printable
					uint8_t firstByte = data[i];
					bool validStart = (firstByte >= 0x20 && firstByte <= 0x7E) || // Printable ASCII
					                 (firstByte == 0x1B) || // ESC for ANSI sequences
					                 (firstByte == 0x0A) || // \n (LF)
					                 (firstByte == 0x0D);   // \r (CR)

					if (!validStart)
					{
						i++;
						continue;
					}

					size_t start = i;

					// Find null terminator
					while (i < length && data[i] != 0x00)
						i++;

					if (i >= length)
						break; // No null terminator found

					size_t strLen = i - start;
					i++; // Skip the null terminator

					// Validate the string
					if (strLen >= 2 && strLen <= 256) // Reasonable length limits
					{
						size_t printableCount = 0;
						size_t alphaNumCount = 0;
						bool hasConsecutiveNonPrintable = false;
						size_t consecutiveNonPrintable = 0;

						for (size_t j = 0; j < strLen; ++j)
						{
							uint8_t c = data[start + j];
							bool isPrintable = (c >= 0x20 && c <= 0x7E);

							// Count printable characters (space to ~)
							if (isPrintable)
							{
								printableCount++;
								consecutiveNonPrintable = 0; // Reset consecutive counter
							}
							else
							{
								consecutiveNonPrintable++;
								if (consecutiveNonPrintable >= 2)
									hasConsecutiveNonPrintable = true;
							}

							// Count alphanumeric characters
							if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
								alphaNumCount++;
						}

						// Accept strings with good printable and alphanumeric ratios
						double printableRatio = static_cast<double>(printableCount) / strLen;
						double alphaNumRatio = static_cast<double>(alphaNumCount) / strLen;

						// Special case: allow ANSI escape sequences (start with ESC, may have some non-printable)
						bool isAnsiSequence = (strLen >= 3 && data[start] == 0x1B && data[start + 1] == 0x5B);

						// Require high quality: most characters printable, some alphanumeric, no consecutive non-printable
						if ((printableRatio >= 0.8 && alphaNumRatio >= 0.4 && !hasConsecutiveNonPrintable) ||
							(isAnsiSequence && printableRatio >= 0.6))
						{
							// Check if this string is already detected by Binary Ninja
							bool alreadyDetected = false;
							for (const auto& existing : strings)
							{
								if (existing.start == addr + start && existing.length == strLen)
								{
									alreadyDetected = true;
									break;
								}
							}

							if (!alreadyDetected)
							{
						// Check if this looks like UTF-16 or UTF-32
						bool looksLikeUtf16 = false;
						bool looksLikeUtf32 = false;

						// Check UTF-16 patterns (decode actual UTF-16 characters)
						if (strLen >= 4 && (strLen % 2) == 0)
						{
							bool isValidUtf16 = true;
							bool hasNullTerminator = false;

							for (size_t j = 0; j < strLen && isValidUtf16; j += 2)
							{
								// Decode UTF-16 character (assuming little-endian byte order)
								uint16_t wc = data[start + j] | (data[start + j + 1] << 8);

								if (wc == 0)
								{
									hasNullTerminator = true;
									break; // Null terminator found
								}

								if (wc < 0x20 || wc > 0x7E)
								{
									isValidUtf16 = false;
								}
							}

							// If we have a valid UTF-16 sequence, check for null termination
							if (isValidUtf16)
							{
								looksLikeUtf16 = true;

								// Check if null terminator exists in the buffer
								if (!hasNullTerminator && buffer.GetLength() >= strLen + 2)
								{
									uint16_t nullCheck = data[start + strLen] | (data[start + strLen + 1] << 8);
									if (nullCheck == 0)
									{
										hasNullTerminator = true;
										strLen += 2; // Include null terminator in length
									}
								}
							}
						}

						// Check UTF-32 patterns (4 bytes per char) - little endian
						if (!looksLikeUtf16 && strLen >= 8 && (strLen % 4) == 0)
						{
							bool isValidUtf32 = true;
							bool hasNullTerminator = false;

							for (size_t j = 0; j < strLen && isValidUtf32; j += 4)
							{
								uint32_t wc = data[start + j] | (data[start + j + 1] << 8) |
											 (data[start + j + 2] << 16) | (data[start + j + 3] << 24);

								if (wc == 0)
								{
									hasNullTerminator = true;
									break; // Null terminator found
								}

								// For ASCII characters in UTF-32: should be 0x000000XX where XX is printable
								if (wc < 0x20 || wc > 0x7E)
								{
									isValidUtf32 = false;
								}
							}

							// If we have a valid UTF-32 sequence, check for null termination
							if (isValidUtf32)
							{
								looksLikeUtf32 = true;

								// Check if null terminator exists in the buffer
								if (!hasNullTerminator && buffer.GetLength() >= strLen + 4)
								{
									uint32_t nullCheck = data[start + strLen] | (data[start + strLen + 1] << 8) |
														(data[start + strLen + 2] << 16) | (data[start + strLen + 3] << 24);
									if (nullCheck == 0)
									{
										hasNullTerminator = true;
										strLen += 4; // Include null terminator in length
									}
								}
							}
						}

						// Adjust length for null-terminated strings
						size_t adjustedLength = strLen;
						if (looksLikeUtf16)
						{
							if (buffer.GetLength() >= strLen + 2)
							{
								uint16_t nullCheck = data[start + strLen] | (data[start + strLen + 1] << 8);
								if (logger)
								{
									logger->LogInfo("UTF-16 null check at 0x%llx: 0x%04x (buffer len %zu, strLen %zu)",
										addr + start + strLen, nullCheck, buffer.GetLength(), strLen);
								}
								if (nullCheck == 0)
								{
									adjustedLength += 2; // Include UTF-16 null terminator
									if (logger)
									{
										logger->LogInfo("UTF-16 null terminator found, adjusted length: %zu -> %zu",
											strLen, adjustedLength);
									}
								}
							}
							else if (logger)
							{
								logger->LogInfo("UTF-16 null check failed: buffer too short (need %zu, have %zu)",
									strLen + 2, buffer.GetLength());
							}
						}
						else if (looksLikeUtf32)
						{
							if (buffer.GetLength() >= strLen + 4)
							{
								uint32_t nullCheck = data[start + strLen] | (data[start + strLen + 1] << 8) |
													(data[start + strLen + 2] << 16) | (data[start + strLen + 3] << 24);
								if (nullCheck == 0)
								{
									adjustedLength += 4; // Include UTF-32 null terminator
								}
							}
						}

						BNStringReference newStr;
						newStr.start = addr + start;
						newStr.length = adjustedLength;

						if (looksLikeUtf32)
						{
							newStr.type = Utf32String; // Assuming BN supports this
							size_t utf32Length = adjustedLength / 4;

							if (logger)
							{
								logger->LogInfo("Found additional UTF-32 string at 0x%llx: length=%zu bytes (%zu chars)",
									newStr.start, newStr.length, utf32Length);
							}
						}
						else if (looksLikeUtf16)
						{
							newStr.type = Utf16String;
							size_t utf16Length = adjustedLength / 2;

							if (logger)
							{
								logger->LogInfo("Found additional UTF-16 string at 0x%llx: length=%zu bytes (%zu chars)",
									newStr.start, newStr.length, utf16Length);
							}
						}
						else
						{
							newStr.type = AsciiString;

							if (logger)
							{
								logger->LogInfo("Found additional ASCII string at 0x%llx: length=%zu (printable=%.1f%%, alpha=%.1f%%)",
									newStr.start, newStr.length, printableRatio * 100, alphaNumRatio * 100);
							}
						}

						additionalStrings.push_back(newStr);
							}
						}
					}
				}
			}

			// Create individual string pointer variables for pointers that point to strings
			std::set<uint64_t> stringAddresses;
			for (const auto& str : strings)
			{
				stringAddresses.insert(str.start);
			}
			for (const auto& str : additionalStrings)
			{
				stringAddresses.insert(str.start);
			}

			// Scan for individual pointers that reference our strings
			for (uint64_t addr = startAddr; addr < endAddr; addr += 4) // 4-byte aligned
			{
				if (ScanCancelled(view))
					break;

				DataBuffer entryBuffer = view->ReadBuffer(addr, 4);
				if (entryBuffer.GetLength() < 4)
					continue;

				const uint8_t* entryData = static_cast<const uint8_t*>(entryBuffer.GetData());
				uint64_t pointedAddr = entryData[0] | (entryData[1] << 8) | (entryData[2] << 16) | (entryData[3] << 24);

				// Check if this points to a known string
				if (stringAddresses.find(pointedAddr) != stringAddresses.end())
				{
					// This is a pointer to a string - create a char* variable
					Ref<Type> stringPtrType = Type::PointerType(4, Type::IntegerType(1, true)); // char*

					// Ensure the pointed-to string is properly typed first
					DataVariable stringVar;
					if (!view->GetDataVariableAtAddress(pointedAddr, stringVar))
					{
						// Find the string in our lists to get its type
						bool found = false;
						for (const auto& str : strings)
						{
							if (str.start == pointedAddr)
							{
								// For proper display in main view, try creating named types that Binary Ninja recognizes
								Ref<Type> stringType;
								if (str.type == Utf32String)
								{
									Ref<Type> elementType = Type::IntegerType(4, false); // uint32_t
									size_t arrayLength = str.length / 4; // Include null terminator in array
									stringType = Type::ArrayType(elementType, arrayLength);
								}
								else if (str.type == Utf16String)
								{
									// Try using a wide char type for better display
									Ref<Type> elementType = Type::WideCharType(2); // UTF-16 wide char (wchar16)
									size_t arrayLength = str.length / 2; // Include null terminator in array
									stringType = Type::ArrayType(elementType, arrayLength);
								}
								else
								{
									Ref<Type> elementType = Type::IntegerType(1, true); // char
									size_t arrayLength = (str.length + 1 - 1) / 1; // elementSize = 1
									stringType = Type::ArrayType(elementType, arrayLength);
								}
								view->DefineUserDataVariable(pointedAddr, stringType);
								found = true;
								break;
							}
						}
						if (!found)
						{
							for (const auto& str : additionalStrings)
							{
								if (str.start == pointedAddr)
								{
									// Create appropriate array type for the string using wide char types for proper display
									Ref<Type> stringType;
									if (str.type == Utf32String)
									{
										Ref<Type> elementType = Type::WideCharType(4); // UTF-32 wide char
										size_t arrayLength = str.length / 4; // Include null terminator in array
										stringType = Type::ArrayType(elementType, arrayLength);
									}
									else if (str.type == Utf16String)
									{
										Ref<Type> elementType = Type::WideCharType(2); // UTF-16 wide char (wchar16)
										size_t arrayLength = str.length / 2; // Include null terminator in array
										stringType = Type::ArrayType(elementType, arrayLength);
									}
									else
									{
										Ref<Type> elementType = Type::IntegerType(1, true); // char
										size_t arrayLength = (str.length + 1 - 1) / 1; // elementSize = 1
										stringType = Type::ArrayType(elementType, arrayLength);
									}
									view->DefineUserDataVariable(pointedAddr, stringType);
									found = true;
									break;
								}
							}
						}
					}

					// Create the pointer variable if not already typed
					DataVariable existingVar;
					if (!view->GetDataVariableAtAddress(addr, existingVar))
					{
						view->DefineUserDataVariable(addr, stringPtrType);

						if (logger)
						{
							logger->LogInfo("Created string pointer at 0x%llx -> 0x%llx", addr, pointedAddr);
						}
					}
				}
			}

			// Add detected strings to the list
			strings.insert(strings.end(), additionalStrings.begin(), additionalStrings.end());

			size_t typed = 0;
			size_t skipped = 0;

			for (const auto& str : strings)
			{
				// Additional validation to filter out obviously invalid strings
				if (str.length < 2)
				{
					skipped++;
					continue; // Too short
				}

				// Read the actual string data to validate it (including potential null terminators)
				// Need up to 4 extra bytes for UTF-32 null terminator
				DataBuffer buffer = view->ReadBuffer(str.start, str.length + 4);
				if (buffer.GetLength() <= str.length)
				{
					skipped++;
					continue; // Can't read the data
				}

				const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());
				size_t printable = 0;
				size_t alphaNum = 0;
				size_t totalChars = 0;

				// Count printable and alphanumeric characters
				for (size_t i = 0; i < str.length; )
				{
					uint8_t c = data[i];

					// Handle different encodings
					if (str.type == Utf16String && i + 1 < str.length)
					{
						// UTF-16: check if it's a valid character (skip null bytes)
						uint16_t wc = data[i] | (data[i + 1] << 8);
						if (wc == 0) break; // Null terminator

						// Count as printable if it's a reasonable Unicode character
						if (wc >= 0x20 && wc < 0x7F)
						{
							printable++;
							if ((wc >= 'A' && wc <= 'Z') || (wc >= 'a' && wc <= 'z') ||
								(wc >= '0' && wc <= '9'))
							{
								alphaNum++;
							}
						}
						else if (wc >= 0x80 && wc <= 0xFFFD) // Extended Unicode range
						{
							printable++; // Accept extended characters
						}
						totalChars++;
						i += 2;
					}
					else if (str.type == Utf32String && i + 3 < str.length)
					{
						// UTF-32: similar logic
						uint32_t wc = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);
						if (wc == 0) break;

						if ((wc >= 0x20 && wc <= 0x7F) || (wc >= 0x80 && wc <= 0x10FFFF))
						{
							printable++;
							if ((wc >= 'A' && wc <= 'Z') || (wc >= 'a' && wc <= 'z') ||
								(wc >= '0' && wc <= '9'))
							{
								alphaNum++;
							}
						}
						totalChars++;
						i += 4;
					}
					else
					{
						// ASCII/UTF-8
						if (c == 0) break; // Null terminator
						if (c >= 0x20 && c <= 0x7E)
						{
							printable++;
							if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
								(c >= '0' && c <= '9'))
							{
								alphaNum++;
							}
						}
						else if (c >= 0x80 && str.type == Utf8String)
						{
							printable++; // Accept UTF-8 multi-byte sequences
						}
						totalChars++;
						i++;
					}
				}

				if (totalChars == 0)
				{
					skipped++;
					continue; // No valid characters
				}

				// Require at least 50% printable characters and 20% alphanumeric
				double printableRatio = static_cast<double>(printable) / totalChars;
				double alphaNumRatio = static_cast<double>(alphaNum) / totalChars;

				if (printableRatio < 0.5 || alphaNumRatio < 0.2)
				{
					skipped++;
					continue; // Not enough valid characters
				}

				// Require at least one alphanumeric sequence of 2+ characters
				bool hasWord = false;
				int consecutiveAlphaNum = 0;
				for (size_t i = 0; i < str.length && !hasWord; )
				{
					uint8_t c = data[i];
					if (str.type == Utf16String && i + 1 < str.length)
					{
						uint16_t wc = data[i] | (data[i + 1] << 8);
						if ((wc >= 'A' && wc <= 'Z') || (wc >= 'a' && wc <= 'z') ||
							(wc >= '0' && wc <= '9'))
						{
							consecutiveAlphaNum++;
							if (consecutiveAlphaNum >= 2) hasWord = true;
						}
						else
						{
							consecutiveAlphaNum = 0;
						}
						i += 2;
					}
					else if (str.type == Utf32String && i + 3 < str.length)
					{
						uint32_t wc = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);
						if ((wc >= 'A' && wc <= 'Z') || (wc >= 'a' && wc <= 'z') ||
							(wc >= '0' && wc <= '9'))
						{
							consecutiveAlphaNum++;
							if (consecutiveAlphaNum >= 2) hasWord = true;
						}
						else
						{
							consecutiveAlphaNum = 0;
						}
						i += 4;
					}
					else
					{
						if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
							(c >= '0' && c <= '9'))
						{
							consecutiveAlphaNum++;
							if (consecutiveAlphaNum >= 2) hasWord = true;
						}
						else
						{
							consecutiveAlphaNum = 0;
						}
						i++;
					}
				}

				if (!hasWord)
				{
					skipped++;
					continue; // No word-like sequences
				}

				// Determine element size for null termination check
				size_t elementSize = 1;
				switch (str.type)
				{
				case AsciiString:
				case Utf8String:
					elementSize = 1;
					break;
				case Utf16String:
					elementSize = 2;
					break;
				case Utf32String:
					elementSize = 4;
					break;
				default:
					elementSize = 1;
					break;
				}

				// All strings that pass our validation must be null terminated
				// If we're checking for printable characters, we expect proper string formatting

				// Check for proper null termination (look 1 byte past the detected string length)
				bool isNullTerminated = false;
				size_t nullTerminatorSize = 1;
				switch (str.type)
				{
				case AsciiString:
				case Utf8String:
					nullTerminatorSize = 1;
					break;
				case Utf16String:
					nullTerminatorSize = 2;
					break;
				case Utf32String:
					nullTerminatorSize = 4;
					break;
				default:
					nullTerminatorSize = 1;
					break;
				}

				if (buffer.GetLength() >= str.length + nullTerminatorSize)
				{
					switch (str.type)
					{
					case AsciiString:
					case Utf8String:
						isNullTerminated = (data[str.length] == 0x00);
						break;
					case Utf16String:
						isNullTerminated = (data[str.length] == 0x00 && data[str.length + 1] == 0x00);
						break;
					case Utf32String:
						isNullTerminated = (data[str.length] == 0x00 && data[str.length + 1] == 0x00 &&
										   data[str.length + 2] == 0x00 && data[str.length + 3] == 0x00);
						break;
					default:
						isNullTerminated = (data[str.length] == 0x00);
						break;
					}
				}

				if (!isNullTerminated)
				{
					skipped++;
					continue; // Not properly null-terminated
				}

				// String passed validation - now type it
				// Create a string array type with the correct encoding
				Ref<Type> elementType;
				switch (str.type)
				{
				case AsciiString:
				case Utf8String:
					elementType = Type::IntegerType(1, true);  // char (signed 8-bit)
					break;
				case Utf16String:
					elementType = Type::WideCharType(2); // UTF-16 wide char (wchar16)
					break;
				case Utf32String:
					elementType = Type::WideCharType(4); // UTF-32 wide char
					break;
				default:
					elementType = Type::IntegerType(1, true);  // Default to char
					break;
				}

				// Calculate array length (include null terminator)
				size_t arrayLength = (str.length + elementSize - 1) / elementSize + 1;
				Ref<Type> stringType = Type::ArrayType(elementType, arrayLength);

				// Use DefineUserDataVariable to ensure our string typing takes precedence
				// This will override any existing auto-detected types
				view->DefineUserDataVariable(str.start, stringType);
				typed++;
			}

			if (logger)
			{
				logger->LogInfo("String validation: %zu total strings detected", strings.size());
				if (typed > 0)
					logger->LogInfo("Typed %zu string data variables", typed);
				if (skipped > 0)
					logger->LogInfo("Skipped %zu invalid string candidates", skipped);
			}
		}

		if (logger)
			logger->LogInfo("Firmware workflow scan: done (applied=%s)", applied ? "true" : "false");

		finishTask();
		SetFirmwareViewScanCancelled(instanceId, false);
	}
	catch (const std::exception& e)
	{
		if (logger)
			logger->LogError("Firmware workflow scan: exception caught: %s", e.what());
		finishTask();
		SetFirmwareViewScanCancelled(instanceId, false);
	}
	catch (...)
	{
		if (logger)
			logger->LogError("Firmware workflow scan: unknown exception caught");
		finishTask();
		SetFirmwareViewScanCancelled(instanceId, false);
	}
	
	// Ensure task is finished before thread exits (safety net)
	// This handles cases where finishTask() might have failed silently
	if (task)
	{
		try
		{
			task->Finish();
		}
		catch (...)
		{
			// Ignore - task will be cleaned up by BN
		}
		// Explicitly release the reference before thread exits
		task = nullptr;
	}
	// Also release view reference to ensure clean shutdown
	view = nullptr;
}

}

// Re-enable analysis for important functions that have analysis suppressed
void ReEnableAnalysisForImportantFunctions(const Ref<BinaryView>& view, const Ref<Logger>& logger)
{
	if (!view || !view->GetObject())
		return;

	// Get seeded functions from ARMv5 view
	auto* fwView = dynamic_cast<Armv5FirmwareView*>(view.GetPtr());
	std::set<uint64_t> seededFunctions;
	if (fwView)
	{
		auto seeded = fwView->GetSeededFunctions();
		auto seededUser = fwView->GetSeededUserFunctions();
		seededFunctions.insert(seeded.begin(), seeded.end());
		seededFunctions.insert(seededUser.begin(), seededUser.end());

		if (logger)
		{
			logger->LogInfo("Found %zu seeded functions, %zu seeded user functions",
				seeded.size(), seededUser.size());
		}
	}
	else
	{
		if (logger)
			logger->LogError("Failed to cast view to Armv5FirmwareView for seeded functions");
	}

	size_t reenabledCount = 0;
	size_t totalFunctions = 0;
	size_t seededCount = 0;

	// Re-enable analysis for important functions
	auto funcList = view->GetAnalysisFunctionList();
	totalFunctions = funcList.size();

	for (auto& func : funcList)
	{
		if (!func)
			continue;

		uint64_t addr = func->GetStart();
		bool shouldAnalyze = false;

		// Only analyze seeded functions (created by ARMv5 plugin) for UI stability
		// Complex functions stay disabled to prevent UI overload
		if (seededFunctions.find(addr) != seededFunctions.end())
		{
			shouldAnalyze = true;
			seededCount++;
		}

		if (shouldAnalyze && func->GetAnalysisSkipOverride() != BNFunctionAnalysisSkipOverride::NeverSkipFunctionAnalysis)
		{
			func->SetAnalysisSkipOverride(BNFunctionAnalysisSkipOverride::NeverSkipFunctionAnalysis);
			reenabledCount++;

			if (logger && reenabledCount <= 10)  // Log first 10 to avoid spam
				logger->LogDebug("Re-enabled analysis for seeded function at 0x%llx", (unsigned long long)addr);
		}
	}

	if (logger)
		logger->LogInfo("Processed %zu total functions, found %zu seeded functions, re-enabled analysis for %zu",
			totalFunctions, seededCount, reenabledCount);
}

// Re-enable analysis for functions that have analysis suppressed
void ReEnableAnalysisForSuppressedFunctions(const Ref<BinaryView>& view, const Ref<Logger>& logger)
{
	if (!view || !view->GetObject())
		return;

	size_t reenabledCount = 0;

	// Find all functions that have suppressed analysis and re-enable them
	for (auto& func : view->GetAnalysisFunctionList())
	{
		if (!func)
			continue;

		uint64_t addr = func->GetStart();

		// Check if analysis is suppressed for this function
		if (func->GetAnalysisSkipOverride() != BNFunctionAnalysisSkipOverride::NeverSkipFunctionAnalysis)
		{
			func->SetAnalysisSkipOverride(BNFunctionAnalysisSkipOverride::NeverSkipFunctionAnalysis);
			reenabledCount++;

			if (logger)
				logger->LogDebug("Re-enabled analysis for function at 0x%llx", (unsigned long long)addr);
		}
	}

	if (logger && reenabledCount > 0)
		logger->LogInfo("Re-enabled analysis for %zu suppressed functions", reenabledCount);
}

// Post-analysis cleanup to fix incomplete function analysis caused by
// incorrectly marked __noreturn functions
void PostAnalysisCleanup(const Ref<BinaryView>& view, const Ref<Logger>& logger)
{
	if (!view || !view->GetObject())
		return;

	// Wait for any pending analysis to complete
	WaitForAnalysisIdle(0, view, nullptr, logger);

	std::set<uint64_t> funcsNeedingReanalysis;

	// Method 1: Find functions that call __noreturn functions but themselves have return paths
	for (auto& func : view->GetAnalysisFunctionList())
	{
		if (!func)
			continue;

		bool hasNoreturnCall = false;
		bool hasReturnPath = false;

		// Check if function has any basic blocks
		auto blocks = func->GetBasicBlocks();
		if (blocks.empty())
			continue;

		// Check if function has a return path (any block can exit)
		for (auto& block : blocks)
		{
			if (block->CanExit())
			{
				hasReturnPath = true;
				break;
			}
		}

		if (!hasReturnPath)
			continue; // Function doesn't return anyway, skip

		// Check for calls to functions marked as __noreturn
		// Get the called addresses from this function
		auto callSites = func->GetCallSites();
		for (auto& callSite : callSites)
		{
			auto targetFuncs = view->GetAnalysisFunctionsForAddress(callSite.addr);
			for (auto& targetFunc : targetFuncs)
			{
				if (targetFunc && !targetFunc->CanReturn().GetValue())
				{
					hasNoreturnCall = true;
					break;
				}
			}
			if (hasNoreturnCall)
				break;
		}

		// If function calls __noreturn but has return path, it needs re-analysis
		if (hasNoreturnCall && hasReturnPath)
		{
			funcsNeedingReanalysis.insert(func->GetStart());
			if (logger)
				logger->LogInfo("PostAnalysisCleanup: function 0x%llx calls __noreturn but has return path (%zu blocks) - needs re-analysis",
					(unsigned long long)func->GetStart(), blocks.size());
		}
	}

	// Method 2: Find functions with unreachable code after their analyzed end
	for (auto& func : view->GetAnalysisFunctionList())
	{
		if (!func || func->GetBasicBlocks().empty())
			continue;

		uint64_t funcEnd = func->GetHighestAddress();
		uint64_t funcStart = func->GetStart();

		// Check if there's valid code after the function's analyzed end
		// Look for instruction sequences that could be continuation of the function
		const uint64_t checkDistance = 64; // Check up to 64 bytes after function end
		uint64_t checkAddr = funcEnd;

		for (uint64_t offset = 0; offset < checkDistance && checkAddr < view->GetEnd(); offset += 4, checkAddr += 4)
		{
			// Skip if this address is already part of another function
			if (view->GetAnalysisFunctionsForAddress(checkAddr).size() > 0)
				break;

			// Check if this looks like valid ARM code
			DataBuffer data = view->ReadBuffer(checkAddr, 4);
			if (data.GetLength() < 4)
				break;

			uint32_t instr = 0;
			memcpy(&instr, data.GetData(), 4);
			if (view->GetDefaultEndianness() == BigEndian)
				instr = Swap32(instr);

			// Quick heuristic: check if it looks like a valid ARM instruction
			// (not all zeros, not undefined, not obviously data)
			if (instr == 0 || instr == 0xFFFFFFFF)
				continue;

			// Check if this could be reached from the function (basic connectivity check)
			bool couldBeConnected = false;
			for (auto& block : func->GetBasicBlocks())
			{
				if (block->CanExit() && block->GetEnd() <= checkAddr && checkAddr - block->GetEnd() <= 16)
				{
					couldBeConnected = true;
					break;
				}
			}

			if (couldBeConnected)
			{
				if (logger)
					logger->LogInfo("PostAnalysisCleanup: found potentially unreachable code at 0x%llx after function 0x%llx (ends at 0x%llx)",
						(unsigned long long)checkAddr, (unsigned long long)funcStart, (unsigned long long)funcEnd);
				funcsNeedingReanalysis.insert(funcStart);
				break;
			}
		}
	}

	// Force re-analysis of functions that may have incomplete analysis
	for (uint64_t addr : funcsNeedingReanalysis)
	{
		auto funcs = view->GetAnalysisFunctionsForAddress(addr);
		for (auto& func : funcs)
		{
			if (func)
			{
				func->Reanalyze(BNFunctionUpdateType::FullAutoFunctionUpdate);
				if (logger)
					logger->LogInfo("PostAnalysisCleanup: reanalyzing function at 0x%llx", (unsigned long long)addr);
			}
		}
	}

	// Wait for re-analysis to complete
	if (!funcsNeedingReanalysis.empty())
		WaitForAnalysisIdle(0, view, nullptr, logger);
}

void BinaryNinja::ScheduleArmv5FirmwareScanJob(Ref<BinaryView> view)
{
	// Run scans in a background thread (pattern used by EFI resolver).
	// Takes Ref<> by value - MUST be passed through from workflow callback,
	// do NOT create new Ref<> from raw pointer as that causes shutdown crashes.
	if (!view || !view->GetObject())
		return;
	if (BNIsShutdownRequested())
		return;
	if (Armv5Settings::PluginConfig::Get().AreAllScansDisabled())
		return;
	if (view->GetTypeName() != "ARMv5 Firmware")
		return;

	// Look up instanceId - dynamic_cast may fail if view is a wrapper from analysis context
	uint64_t instanceId = 0;
	Armv5FirmwareView* fwView = dynamic_cast<Armv5FirmwareView*>(view.GetPtr());
	if (fwView)
		instanceId = fwView->GetInstanceId();
	else
		instanceId = GetInstanceIdFromView(view.GetPtr());

	if (instanceId == 0)
		return;
	if (IsFirmwareViewClosingById(instanceId))
		return;
	if (BNIsShutdownRequested())
		return;

	SetFirmwareViewScanCancelled(instanceId, false);
	if (BNIsShutdownRequested())
		return;

	Ref<BackgroundTask> task = new BackgroundTask("ARMv5 firmware scans...", true);
	std::thread([view, task, instanceId]() { RunFirmwareScanJob(view, task, instanceId); }).detach();
}

void BinaryNinja::CancelArmv5FirmwareScanJob(uint64_t viewId, bool allowRelease)
{
	SetFirmwareViewScanCancelled(viewId, true);
	(void)allowRelease;
}
