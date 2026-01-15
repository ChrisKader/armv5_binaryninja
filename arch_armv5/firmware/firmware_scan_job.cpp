/*
 * ARMv5 Firmware Scan Job
 */

#include "firmware_scan_job.h"
#include "firmware_settings.h"
#include "firmware_view.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <thread>
#include <unordered_map>

using namespace BinaryNinja;
using namespace std;

namespace
{
	static constexpr uint64_t kMaxBufferedLength = 64ULL * 1024 * 1024;

	struct FirmwareScanJobState
	{
		uint64_t viewId = 0;
		uint64_t instanceId = 0;
		atomic<bool> cancelled{false};
		atomic<bool> running{false};
		Ref<BackgroundTask> task;
	};

	mutex& FirmwareScanJobMutex()
	{
		static mutex* m = new mutex();
		return *m;
	}

	unordered_map<uint64_t, shared_ptr<FirmwareScanJobState>>& FirmwareScanJobs()
	{
		static auto* map = new unordered_map<uint64_t, shared_ptr<FirmwareScanJobState>>();
		return *map;
	}

shared_ptr<FirmwareScanJobState> GetJob(uint64_t instanceId)
{
	lock_guard<mutex> lock(FirmwareScanJobMutex());
	auto it = FirmwareScanJobs().find(instanceId);
	if (it == FirmwareScanJobs().end())
		return nullptr;
	return it->second;
}

void RemoveJob(uint64_t instanceId)
{
	lock_guard<mutex> lock(FirmwareScanJobMutex());
	FirmwareScanJobs().erase(instanceId);
	SetFirmwareViewScanCancelled(instanceId, false);
	}

	bool ShouldCancel(const shared_ptr<FirmwareScanJobState>& job, const Ref<BinaryView>& view)
	{
		if (!job)
			return true;
		if (BNIsShutdownRequested())
		{
			LogInfo("Firmware scan: cancelling due to shutdown request");
			return true;
		}
		if (job->task && job->task->IsCancelled())
		{
			job->cancelled.store(true);
			return true;
		}
		if (job->cancelled.load())
			return true;
		if (!view || !view->GetObject())
			return true;
	// If the alive token indicates the view is gone, cancel
	if (!IsFirmwareViewAliveById(job->instanceId))
		return true;
	return false;
	}

bool CanUpdateTaskProgress(const shared_ptr<FirmwareScanJobState>& job, const Ref<Logger>& logger = nullptr)
{
	if (!job)
	{
		if (logger) logger->LogInfo("CanUpdateTaskProgress: job null");
		return false;
	}
	if (!job->task)
	{
		if (logger) logger->LogDebug("CanUpdateTaskProgress: task not yet created");
		return false;
	}
	if (BNIsShutdownRequested())
	{
		if (logger) logger->LogInfo("CanUpdateTaskProgress: shutting down");
		return false;
	}
	if (!IsFirmwareViewAliveById(job->instanceId))
	{
		if (logger) logger->LogInfoF("CanUpdateTaskProgress: instanceId=%llx not alive", (unsigned long long)job->instanceId);
		return false;
	}
	if (IsFirmwareViewClosingById(job->instanceId))
	{
		if (logger) logger->LogInfoF("CanUpdateTaskProgress: instanceId=%llx closing", (unsigned long long)job->instanceId);
		return false;
	}
	return true;
}

bool WaitForAnalysisIdle(const shared_ptr<FirmwareScanJobState>& job, const Ref<BinaryView>& view,
	const Ref<Logger>& logger)
{
	if (!view || !view->GetObject())
		return false;
	const auto start = chrono::steady_clock::now();
	constexpr auto kSleep = chrono::milliseconds(100);
	constexpr auto kLogInterval = chrono::seconds(5);
		auto nextLog = start + kLogInterval;
	if (CanUpdateTaskProgress(job, logger))
	{
		ExecuteOnMainThread([job, logger]() {
			if (job && job->task && CanUpdateTaskProgress(job, logger))
				job->task->SetProgressText("ARMv5 firmware scans: waiting for analysis to idle");
		});
	}
		while (true)
		{
			if (ShouldCancel(job, view))
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
	if (CanUpdateTaskProgress(job, logger))
	{
		ExecuteOnMainThread([job, logger]() {
			if (job && job->task && CanUpdateTaskProgress(job, logger))
				job->task->SetProgressText("ARMv5 firmware scans: running");
		});
	}
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
				view->AddFunctionForAnalysis(targetPlat.GetPtr(), addr, true);
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}

		for (size_t i = 0; i < plan.defineData.size(); i += batchSize)
		{
			if (shouldAbort())
			{
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
					view->RemoveAnalysisFunction(func, true);
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}

		finishUpdatesGuard();
		return true;
	}

	bool ApplyPlanBatchesOnMainThread(const Ref<BinaryView>& view,
		const FirmwareSettings& fwSettings, const FirmwareScanPlan& plan, const Ref<Logger>& logger)
	{
		if (!view || !view->GetObject())
			return false;
		bool result = false;

		if (BNIsShutdownRequested())
			return false;

		// Schedule the work on the main thread without blocking it. Use a promise to get the result and
	// poll the future periodically while checking lifecycle state so we can abort during shutdown.
	std::promise<bool> promise;
	auto fut = promise.get_future();
	ExecuteOnMainThread([view, &fwSettings, &plan, &logger, &promise]() mutable {
		if (!view || !view->GetObject())
		{
			promise.set_value(false);
			return;
		}
		if (BNIsShutdownRequested())
		{
			promise.set_value(false);
			return;
		}
		if (IsFirmwareViewClosing(view.GetPtr()))
		{
			promise.set_value(false);
			return;
		}
		bool r = ApplyPlanBatchesDirect(view, fwSettings, plan, logger);
		promise.set_value(r);
	});

	// Wait for the main-thread work to complete, but poll periodically so we can bail out cleanly
	// if shutdown or view-closing happens.
	using namespace std::chrono_literals;
	while (fut.wait_for(100ms) != std::future_status::ready)
	{
		if (BNIsShutdownRequested() || IsFirmwareViewClosing(view.GetPtr()))
		{
			if (logger)
				logger->LogInfo("ApplyPlanBatchesOnMainThread: aborted due to shutdown or view closing");
			return false;
		}
	}
	result = fut.get();
		return result;
	}

	void RunFirmwareScanJob(const shared_ptr<FirmwareScanJobState>& job)
	{
		if (!job)
			return;
		struct RunningGuard
		{
			const shared_ptr<FirmwareScanJobState>& jobRef;
			~RunningGuard() { if (jobRef) jobRef->running.store(false); }
		} runningGuard{job};

		Ref<Logger> logger = LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareView");

	auto finishTask = [&]() {
		// Avoid touching UI/main-thread during shutdown or when the view is closing.
		if (!job || !job->task)
			return;
		if (job->task->IsFinished())
			return;
		// Schedule finish on main thread without waiting to avoid shutdown deadlocks.
		ExecuteOnMainThread([job, logger]() {
			if (!job || !job->task)
				return;
			if (job->task->IsFinished())
				return;
			if (!CanUpdateTaskProgress(job, logger))
				return;
			job->task->Finish();
		});
	};

	try
	{
		if (BNIsShutdownRequested() || IsFirmwareViewClosingById(job->instanceId))
		{
			RemoveJob(job->instanceId);
			return;
		}
		auto resolveView = [&]() -> Ref<BinaryView> {
			if (IsFirmwareViewClosingById(job->instanceId))
				return nullptr;
			if (!IsFirmwareViewAliveById(job->instanceId))
				return nullptr;
			Armv5FirmwareView* firmwareView = GetFirmwareViewForInstanceId(job->instanceId);
			if (!firmwareView)
				return nullptr;
			Ref<BinaryView> view = firmwareView;
			if (!view || !view->GetObject())
				return nullptr;
			return view;
		};

		Ref<BinaryView> view = resolveView();
		if (!view)
		{
			if (logger)
				logger->LogInfo("Firmware workflow scan: view lookup failed");
			finishTask();
			RemoveJob(job->instanceId);
			return;
		}

		// Create BackgroundTask on main thread after we have a valid view and know it's safe.
		if (!job->task && CanUpdateTaskProgress(job, logger))
		{
			ExecuteOnMainThread([job, logger]() {
				if (!CanUpdateTaskProgress(job, logger))
					return;
				if (!job->task)
					job->task = new BackgroundTask("ARMv5 firmware scans...", true);
				if (job->task && CanUpdateTaskProgress(job, logger))
					job->task->SetProgressText("ARMv5 firmware scans: preparing");
			});
		}

		uint64_t length = view->GetParentView()->GetLength();
		if (ScanCancelled(view))
		{
			finishTask();
			RemoveJob(job->instanceId);
			return;
		}
		if (!WaitForAnalysisIdle(job, view, logger))
		{
			finishTask();
			RemoveJob(job->instanceId);
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
			RemoveJob(job->instanceId);
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
			RemoveJob(job->instanceId);
			return;
		}

		Ref<BinaryView> parentView = view->GetParentView();
		if (!parentView)
		{
			finishTask();
			RemoveJob(job->instanceId);
			return;
		}
		BinaryReader reader(parentView);
		reader.SetEndianness(view->GetDefaultEndianness());

		Armv5FirmwareView* firmwareView = dynamic_cast<Armv5FirmwareView*>(view.GetPtr());
		if (!firmwareView)
		{
			finishTask();
			RemoveJob(job->instanceId);
			return;
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
			view = resolveView();
			if (!view)
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
			RemoveJob(job->instanceId);
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
			RemoveJob(job->instanceId);
			return;
		}

		if (!refreshViewForPhase())
		{
			finishTask();
			RemoveJob(job->instanceId);
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
			RemoveJob(job->instanceId);
			return;
		}

		if (!refreshViewForPhase())
		{
			finishTask();
			RemoveJob(job->instanceId);
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
			RemoveJob(job->instanceId);
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
			RemoveJob(job->instanceId);
			return;
		}

		if (!refreshViewForPhase())
		{
			finishTask();
			RemoveJob(job->instanceId);
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
			RemoveJob(job->instanceId);
			return;
		}

		if (!refreshViewForPhase())
		{
			finishTask();
			RemoveJob(job->instanceId);
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
			RemoveJob(job->instanceId);
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
			RemoveJob(job->instanceId);
			return;
		}
		if (fwSettings.enableInvalidFunctionCleanup)
		{
			std::set<uint64_t> protectedStarts = seededFunctions;
			protectedStarts.insert(seededUserFunctions.begin(), seededUserFunctions.end());
			timePass("Cleanup invalid functions", [&]() {
				CleanupInvalidFunctions(view, fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, logger, fwSettings.enableVerboseLogging, tuning,
					fwSettings.cleanupMaxSizeBytes, fwSettings.cleanupRequireZeroRefs,
					fwSettings.cleanupRequirePcWriteStart, view->GetEntryPoint(), protectedStarts, &plan);
			});
		}

		if (logger)
		{
			logger->LogInfo("Firmware scan plan: user_add=%zu add=%zu remove=%zu define=%zu undefine=%zu symbols=%zu",
				plan.addUserFunctions.size(), plan.addFunctions.size(), plan.removeFunctions.size(), plan.defineData.size(),
				plan.undefineData.size(), plan.defineSymbols.size());
		}

		bool applied = false;
		if (!refreshViewForPhase())
		{
			finishTask();
			RemoveJob(job->instanceId);
			return;
		}
		if (!ScanCancelled(view))
			applied = ApplyPlanBatchesDirect(view, fwSettings, plan, logger);

		if (logger)
			logger->LogInfo("Firmware workflow scan: done (applied=%s)", applied ? "true" : "false");

		finishTask();
		SetFirmwareViewScanCancelled(job->instanceId, false);
		RemoveJob(job->instanceId);
	}
	catch (const std::exception& e)
	{
		if (logger)
			logger->LogError("Firmware workflow scan: exception caught: %s", e.what());
		finishTask();
		SetFirmwareViewScanCancelled(job->instanceId, false);
		RemoveJob(job->instanceId);
	}
	catch (...)
	{
		if (logger)
			logger->LogError("Firmware workflow scan: unknown exception caught");
		finishTask();
		SetFirmwareViewScanCancelled(job->instanceId, false);
		RemoveJob(job->instanceId);
	}
}

}

void BinaryNinja::ScheduleArmv5FirmwareScanJob(const Ref<BinaryView>& view)
{
	// Run scans in a background thread (pattern used by EFI resolver).
	if (!view || !view->GetObject())
		return;
	if (BNIsShutdownRequested())
		return;
	if (view->GetTypeName() != "ARMv5 Firmware")
		return;
	// Use the view's instanceId so we can map back to the tracked Armv5FirmwareView
	Armv5FirmwareView* fwView = dynamic_cast<Armv5FirmwareView*>(view.GetPtr());
	if (!fwView)
		return;
	uint64_t instanceId = fwView->GetInstanceId();
	if (instanceId == 0)
		return;
	if (IsFirmwareViewClosingById(instanceId))
		return;

	// Check if already running
	{
		lock_guard<mutex> lock(FirmwareScanJobMutex());
		auto it = FirmwareScanJobs().find(instanceId);
		if (it != FirmwareScanJobs().end() && it->second && it->second->running.load())
			return;
	}

	SetFirmwareViewScanCancelled(instanceId, false);
	auto job = make_shared<FirmwareScanJobState>();
		job->instanceId = instanceId; // ensure instanceId is set
		job->viewId = instanceId; // maintain backward-compatible viewId for now
	job->running.store(true);
	// Defer creating the BackgroundTask until we are sure the view still exists and we are not shutting down.
	{
		lock_guard<mutex> lock(FirmwareScanJobMutex());
		FirmwareScanJobs()[instanceId] = job;
	}
	// Run in a background thread (pattern used by EFI resolver).
	std::thread([job]() { RunFirmwareScanJob(job); }).detach();
}

void BinaryNinja::CancelArmv5FirmwareScanJob(uint64_t viewId)
{
	shared_ptr<FirmwareScanJobState> job = GetJob(viewId);
	if (!job)
		return;
	SetFirmwareViewScanCancelled(viewId, true);
	job->cancelled.store(true);
	if (CanUpdateTaskProgress(job) && job->task->CanCancel())
		job->task->Cancel();
}
