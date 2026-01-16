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
#include "common/armv5_utils.h"
#include "analysis/rtos_detector.h"

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

		uint64_t checkAddr = addr;
		const size_t align = arch->GetInstructionAlignment();
		if (align > 1)
			checkAddr &= ~(static_cast<uint64_t>(align) - 1);

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

		DataBuffer buf = view->ReadBuffer(checkAddr, arch->GetMaxInstructionLength());
		if (buf.GetLength() == 0)
			return false;
		if (buf.GetLength() >= 4)
		{
			const uint8_t* bytes = static_cast<const uint8_t*>(buf.GetData());
			const bool allZero = bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0;
			const bool allFF = bytes[0] == 0xFF && bytes[1] == 0xFF && bytes[2] == 0xFF && bytes[3] == 0xFF;
			if ((allZero || allFF))
				return false;
		}

		InstructionInfo info;
		if (!arch->GetInstructionInfo(static_cast<const uint8_t*>(buf.GetData()), checkAddr, buf.GetLength(), info))
			return false;
		if (info.length == 0)
			return false;

		return true;
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
				Ref<Platform> targetPlat = resolvePlatformForAddress(addr);
				if (!targetPlat)
					targetPlat = platform;
				if (!IsValidFunctionStart(view, targetPlat, addr, fwSettings.enableVerboseLogging, logger))
					continue;
				Ref<Function> func = view->GetAnalysisFunction(targetPlat.GetPtr(), addr);
				if (!func)
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
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
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
				Ref<Platform> targetPlat = resolvePlatformForAddress(addr);
				if (!targetPlat)
					targetPlat = platform;
				if (!IsValidFunctionStart(view, targetPlat, addr, fwSettings.enableVerboseLogging, logger))
					continue;
				Ref<Function> func = view->CreateUserFunction(targetPlat.GetPtr(), addr);
				if (!func)
					func = view->GetAnalysisFunction(targetPlat.GetPtr(), addr);
				if (!func)
				{
					view->AddFunctionForAnalysis(targetPlat.GetPtr(), addr, true);
					if (logger)
						logger->LogWarn("Firmware scan: user function create failed at 0x%llx, falling back to analysis",
							(unsigned long long)addr);
				}
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
					logger, fwSettings.enableVerboseLogging, tuning, &seededFunctions, &plan);
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
					tuning, &seededFunctions, &plan);
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
					tuning, &addedFunctions, &plan);
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
					tuning, fwSettings.orphanMinValidInstr, fwSettings.orphanMinBodyInstr,
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

		if (!refreshViewForPhase())
		{
			finishTask();
			return;
		}
		if (fwSettings.enableInvalidFunctionCleanup)
		{
			if (logger)
				logger->LogInfo("Cleanup invalid functions: enabled (max_size=%u zero_refs=%d pc_write=%d)",
					fwSettings.cleanupMaxSizeBytes,
					fwSettings.cleanupRequireZeroRefs ? 1 : 0,
					fwSettings.cleanupRequirePcWriteStart ? 1 : 0);
			std::set<uint64_t> protectedStarts;
			auto addProtected = [&](uint64_t addr) {
				protectedStarts.insert(addr);
				protectedStarts.insert(addr & ~1ULL); // cover Thumb-bit addresses
			};
			for (uint64_t addr : seededFunctions)
				addProtected(addr);
			for (uint64_t addr : seededUserFunctions)
				addProtected(addr);
			timePass("Cleanup invalid functions", [&]() {
				CleanupInvalidFunctions(view, fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, logger, fwSettings.enableVerboseLogging, tuning,
					fwSettings.cleanupMaxSizeBytes, fwSettings.cleanupRequireZeroRefs,
					fwSettings.cleanupRequirePcWriteStart, view->GetEntryPoint(), protectedStarts, &plan);
			});
		}
		else if (logger)
		{
			const bool rawView = view && view->GetSegments().empty();
			const char* reason = rawView ? " (raw view)" : " (enable cleanup with BN_ARMV5_FIRMWARE_ENABLE_CLEANUP)";
			logger->LogInfo("Cleanup invalid functions: disabled%s", reason);
		}

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
