/*
 * ARMv5 Firmware Scan Job
 */

#include "firmware_scan_job.h"
#include "firmware_settings.h"
#include "firmware_view.h"

#include <algorithm>
#include <atomic>
#include <chrono>
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
		atomic<bool> cancelled{false};
		atomic<bool> running{false};
		// Note: BackgroundTask removed - it was causing issues during shutdown
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

	shared_ptr<FirmwareScanJobState> GetJob(uint64_t viewId)
	{
		lock_guard<mutex> lock(FirmwareScanJobMutex());
		auto it = FirmwareScanJobs().find(viewId);
		if (it == FirmwareScanJobs().end())
			return nullptr;
		return it->second;
	}

	void RemoveJob(uint64_t viewId)
	{
		lock_guard<mutex> lock(FirmwareScanJobMutex());
		FirmwareScanJobs().erase(viewId);
		SetFirmwareViewScanCancelled(viewId, false);
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
		if (job->cancelled.load())
			return true;
				if (!view || !view->GetObject())
			return true;
		if (IsFirmwareViewClosingById(job->viewId))
			return true;
		// Note: We no longer check AnalysisIsAborted() here because it returns true when
		// maxFunctionUpdateCount is hit, which would stop our scans prematurely.
		// The BNIsShutdownRequested() and job->cancelled checks are sufficient.
		return false;
	}

	bool WaitForAnalysisIdle(const shared_ptr<FirmwareScanJobState>& job, const Ref<BinaryView>& view,
		const Ref<Logger>& logger)
	{
		if (!view || !view->GetObject())
			return false;
		const auto start = chrono::steady_clock::now();
		constexpr auto kSleep = chrono::milliseconds(100);
		constexpr auto kLogInterval = chrono::seconds(5);
		constexpr auto kMaxWait = chrono::seconds(10);
		auto nextLog = start + kLogInterval;
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
			if (now - start >= kMaxWait)
			{
				if (logger)
					logger->LogInfo("Firmware workflow scan: proceeding without idle state");
				break;
			}
			this_thread::sleep_for(kSleep);
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

		bool prevDisabled = view->GetFunctionAnalysisUpdateDisabled();
		view->SetFunctionAnalysisUpdateDisabled(true);

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
			if (ScanCancelled(view))
			{
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(userAddrs.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
				view->CreateUserFunction(platform.GetPtr(), userAddrs[j]);
		}

		vector<uint64_t> addrs = plan.addFunctions;
		DedupAddresses(addrs);
		if (fwSettings.maxFunctionAdds > 0 && addrs.size() > fwSettings.maxFunctionAdds)
		{
			if (logger)
				logger->LogWarn("Firmware scan: capping function adds at %u (had %zu)",
					fwSettings.maxFunctionAdds, addrs.size());
			addrs.resize(fwSettings.maxFunctionAdds);
		}

		for (size_t i = 0; i < addrs.size(); i += batchSize)
		{
			if (ScanCancelled(view))
			{
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(addrs.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
				view->AddFunctionForAnalysis(platform.GetPtr(), addrs[j], true);
		}

		for (size_t i = 0; i < plan.defineData.size(); i += batchSize)
		{
			if (ScanCancelled(view))
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
		}

		for (size_t i = 0; i < plan.undefineData.size(); i += batchSize)
		{
			if (ScanCancelled(view))
			{
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(plan.undefineData.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
				view->UndefineDataVariable(plan.undefineData[j], false);
		}

		for (size_t i = 0; i < plan.defineSymbols.size(); i += batchSize)
		{
			if (ScanCancelled(view))
			{
				finishUpdatesGuard();
				return false;
			}
			size_t end = min(plan.defineSymbols.size(), i + batchSize);
			for (size_t j = i; j < end; ++j)
				view->DefineAutoSymbol(plan.defineSymbols[j]);
		}

		for (size_t i = 0; i < plan.removeFunctions.size(); i += batchSize)
		{
			if (ScanCancelled(view))
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
		ExecuteOnMainThreadAndWait([&]() {
			if (!view || !view->GetObject())
				return;
			if (BNIsShutdownRequested())
				return;
			if (IsFirmwareViewClosing(view.GetPtr()))
				return;
			result = ApplyPlanBatchesDirect(view, fwSettings, plan, logger);
		});
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
		Armv5FirmwareView* firmwareView = GetFirmwareViewForSessionId(job->viewId);
		if (!firmwareView)
		{
			if (logger)
				logger->LogInfo("Firmware workflow scan: view lookup failed");
			RemoveJob(job->viewId);
			return;
		}

	Ref<BinaryView> view = firmwareView;
	if (ScanCancelled(view))
	{
		RemoveJob(job->viewId);
		return;
	}
	if (!WaitForAnalysisIdle(job, view, logger))
	{
		RemoveJob(job->viewId);
		return;
	}

		Ref<Settings> settings = view->GetLoadSettings(view->GetTypeName());
		FirmwareSettings fwSettings = LoadFirmwareSettings(settings, view.GetPtr(), FirmwareSettingsMode::Workflow);
		const FirmwareScanTuning& tuning = fwSettings.tuning;

		if (fwSettings.skipFirmwareScans)
		{
			if (logger)
				logger->LogInfo("Firmware workflow scan skipped (skipFirmwareScans enabled)");
			RemoveJob(job->viewId);
			return;
		}

		uint64_t length = view->GetLength();
		if (!length)
		{
			RemoveJob(job->viewId);
			return;
		}

		uint64_t imageBase = view->GetStart();
		uint64_t bufferLen = (length < kMaxBufferedLength) ? length : kMaxBufferedLength;
		DataBuffer fileBuf = view->GetParentView()->ReadBuffer(0, bufferLen);
		const uint8_t* fileData = static_cast<const uint8_t*>(fileBuf.GetData());
		uint64_t fileDataLen = fileBuf.GetLength();
		if (!fileData || fileDataLen == 0)
		{
			RemoveJob(job->viewId);
			return;
		}

		BinaryReader reader(view->GetParentView());
		reader.SetEndianness(view->GetDefaultEndianness());

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
			logger, fwSettings.enableVerboseLogging, view.GetPtr(), &plan
		};

		if (logger)
			logger->LogInfo("Firmware workflow scan: start");

		if (fwSettings.enableLiteralPoolTyping)
		{
			timePass("Literal pool typing", [&]() { TypeLiteralPoolEntries(scanCtx); });
			if (fwSettings.enableClearAutoDataOnCodeRefs)
				timePass("Clear auto data on code refs", [&]() { ClearAutoDataOnCodeReferences(scanCtx); });
		}

		if (ScanCancelled(view))
		{
			RemoveJob(job->viewId);
			return;
		}

		if (fwSettings.enablePrologueScan)
		{
			Ref<Architecture> thumbArch = Architecture::GetByName("armv5t");
			timePass("Function prologue scan", [&]() {
				ScanForFunctionPrologues(view.GetPtr(), fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, view->GetDefaultArchitecture(), thumbArch, view->GetDefaultPlatform(),
					logger, fwSettings.enableVerboseLogging, tuning, &seededFunctions, &plan);
			});
		}

		if (ScanCancelled(view))
		{
			RemoveJob(job->viewId);
			return;
		}

		if (fwSettings.enableClearAutoDataOnCodeRefs)
		{
			timePass("Clear auto data in function entry blocks", [&]() {
				ClearAutoDataInFunctionEntryBlocks(scanCtx, &seededFunctions);
			});
		}

		if (fwSettings.enableCallTargetScan)
		{
			timePass("Call target scan", [&]() {
				ScanForCallTargets(view.GetPtr(), fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, view->GetDefaultPlatform(), logger, fwSettings.enableVerboseLogging,
					tuning, &seededFunctions, &plan);
			});
		}

		if (ScanCancelled(view))
		{
			RemoveJob(job->viewId);
			return;
		}

		if (fwSettings.enablePointerTargetScan)
		{
			timePass("Pointer target scan", [&]() {
				ScanForPointerTargets(view.GetPtr(), fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, view->GetDefaultPlatform(), logger, fwSettings.enableVerboseLogging,
					tuning, &addedFunctions, &plan);
			});
		}

		if (ScanCancelled(view))
		{
			RemoveJob(job->viewId);
			return;
		}

		if (fwSettings.enableOrphanCodeScan)
		{
			timePass("Orphan code block scan", [&]() {
				ScanForOrphanCodeBlocks(view.GetPtr(), fileData, fileDataLen, view->GetDefaultEndianness(),
					imageBase, length, view->GetDefaultPlatform(), logger, fwSettings.enableVerboseLogging,
					tuning, fwSettings.orphanMinValidInstr, fwSettings.orphanMinBodyInstr,
					fwSettings.orphanMinSpacingBytes, fwSettings.orphanMaxPerPage,
					fwSettings.orphanRequirePrologue, &addedFunctions, &plan);
			});
		}

		if (!addedFunctions.empty())
			seededFunctions.insert(addedFunctions.begin(), addedFunctions.end());

		if (fwSettings.enableClearAutoDataOnCodeRefs && !addedFunctions.empty())
		{
			timePass("Clear auto data in new function entry blocks", [&]() {
				ClearAutoDataInFunctionEntryBlocks(scanCtx, &addedFunctions);
			});
		}

		if (fwSettings.enableInvalidFunctionCleanup)
		{
			std::set<uint64_t> protectedStarts = seededFunctions;
			timePass("Cleanup invalid functions", [&]() {
				CleanupInvalidFunctions(view.GetPtr(), fileData, fileDataLen, view->GetDefaultEndianness(),
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
		if (!ScanCancelled(view))
			applied = ApplyPlanBatchesDirect(view, fwSettings, plan, logger);

		if (logger)
			logger->LogInfo("Firmware workflow scan: done (applied=%s)", applied ? "true" : "false");

		SetFirmwareViewScanCancelled(job->viewId, false);
		RemoveJob(job->viewId);
	}
}

void BinaryNinja::ScheduleArmv5FirmwareScanJob(const Ref<BinaryView>& view)
{
	// Run scans synchronously in the analysis callback context (like RTTI plugin does).
	// Avoid background threads and main-thread dispatch to keep teardown safe.
	if (!view || !view->GetObject())
		return;
	if (view->GetTypeName() != "ARMv5 Firmware")
		return;
	Ref<FileMetadata> file = view->GetFile();
	if (!file)
		return;
	uint64_t viewId = file->GetSessionId();
	if (viewId == 0)
		return;

	// Check if already running
	{
		lock_guard<mutex> lock(FirmwareScanJobMutex());
		auto it = FirmwareScanJobs().find(viewId);
		if (it != FirmwareScanJobs().end() && it->second && it->second->running.load())
			return;
	}

	SetFirmwareViewScanCancelled(viewId, false);
	auto job = make_shared<FirmwareScanJobState>();
	job->viewId = viewId;
	job->running.store(true);
	// Note: BackgroundTask removed - it may have been causing issues during shutdown
	// since it registers with BN's internal task tracking

	{
		lock_guard<mutex> lock(FirmwareScanJobMutex());
		FirmwareScanJobs()[viewId] = job;
	}

	// Run synchronously - we're called from analysis workflow/initial-completion context.
	RunFirmwareScanJob(job);
}

void BinaryNinja::CancelArmv5FirmwareScanJob(uint64_t viewId)
{
	// Since we now run synchronously, cancellation is just setting flags.
	// The scan loops check these flags and will exit early.
	shared_ptr<FirmwareScanJobState> job = GetJob(viewId);
	if (!job)
		return;
	SetFirmwareViewScanCancelled(viewId, true);
	job->cancelled.store(true);
}
