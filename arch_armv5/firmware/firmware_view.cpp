/*
 * ARMv5 Firmware BinaryViewType
 *
 * Custom BinaryViewType for bare metal ARM firmware detection and analysis.
 * This is one of the most complex and carefully designed components in the plugin.
 *
 * ============================================================================
 * WHY A CUSTOM BINARYVIEWTYPE?
 * ============================================================================
 *
 * Standard Binary Ninja loaders (ELF, PE, Mach-O) require structured file formats
 * with headers that describe segments, sections, and entry points. Bare metal
 * firmware (bootloaders, RTOS images, embedded systems code) lacks these headers.
 *
 * This custom BinaryViewType:
 * 1. Detects ARM firmware by recognizing vector table patterns at offset 0
 * 2. Automatically determines the image base address from vector table entries
 * 3. Creates a single executable segment spanning the entire image
 * 4. Seeds initial functions from exception vector handlers
 * 5. Runs firmware-specific scan passes to discover additional functions
 *
 * ============================================================================
 * LIFETIME MANAGEMENT - CRITICAL DESIGN DECISIONS
 * ============================================================================
 *
 * BinaryView lifetime management in Binary Ninja is complex. Views can be closed
 * by the user at any time, and background analysis tasks may still hold references.
 * We learned through extensive trial and error that:
 *
 * 1. NEVER store raw BinaryView* pointers in global maps
 *    - Views can be destroyed while your pointer is still "valid"
 *    - Use InstanceId (uint64_t) as keys instead
 *
 * 2. NEVER hold Ref<BinaryView> across workflow callback boundaries
 *    - This extends the view's lifetime beyond user expectations
 *    - Can cause memory leaks and prevent proper cleanup
 *    - Re-acquire the view from AnalysisContext in each callback
 *
 * 3. Use heap-allocated static maps (new std::unordered_map)
 *    - Stack-allocated static variables can be destroyed during shutdown
 *    - Heap-allocated maps survive until process exit
 *    - Access them through getter functions that handle null checks
 *
 * 4. Use alive tokens for background task cancellation
 *    - std::shared_ptr<std::atomic<bool>> shared between view and tasks
 *    - Set to false when view is closing
 *    - Tasks check periodically and bail out cleanly
 *
 * ============================================================================
 * INSTANCE TRACKING SYSTEM
 * ============================================================================
 *
 * We use a unique InstanceId (incrementing uint64_t) for each firmware view:
 *
 * - FirmwareViewMap: InstanceId -> Armv5FirmwareView*
 *   Primary registry of all active firmware views.
 *
 * - FirmwareFileSessionMap: FileSession -> InstanceId
 *   Maps Binary Ninja's file session ID to our instance ID.
 *   Used to find our instance from workflow callbacks.
 *
 * - FirmwareViewPointerToInstanceMap: uintptr_t -> InstanceId
 *   Maps raw pointer values to instance IDs.
 *   Used when we only have the pointer but need the ID.
 *
 * - FirmwareViewClosingSet: Set of InstanceIds currently closing
 *   Prevents new operations from starting on a closing view.
 *
 * - FirmwareViewScanCancelSet: Set of InstanceIds with cancelled scans
 *   Signals background scan tasks to abort.
 *
 * - FirmwareViewAliveMap: InstanceId -> shared_ptr<atomic<bool>>
 *   Alive tokens for safe background task cancellation.
 *
 * ============================================================================
 * THREAD SAFETY
 * ============================================================================
 *
 * All access to the global maps is protected by FirmwareViewMutex.
 * This is a single global mutex (not per-view) because:
 * 1. Simplifies reasoning about locking order
 * 2. View creation/destruction is rare, so contention is minimal
 * 3. Matches the pattern used by KernelCacheController in Binary Ninja
 *
 * LOCK ORDERING: Always acquire FirmwareViewMutex before any BinaryView locks.
 *
 * ============================================================================
 * REFERENCE: binaryninja-api/view/kernelcache/core/KernelCacheController.cpp
 * ============================================================================
 */

#include "firmware_internal.h"
#include "firmware_view.h"
#include "firmware_scan_job.h"
#include "firmware_settings.h"
#include "common/armv5_utils.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;
using namespace BinaryNinja;
using namespace armv5;

/*
 * Maximum size for buffering the entire binary in memory.
 * Larger binaries will use on-demand reads via BinaryReader.
 * 64MB should cover most embedded firmware images.
 */
static constexpr uint64_t kMaxBufferedLength = 64ULL * 1024 * 1024;

/*
 * Global view type singleton.
 * Registered once at plugin init, lives for the lifetime of Binary Ninja.
 */
static Armv5FirmwareViewType *g_armv5FirmwareViewType = nullptr;

/*
 * ============================================================================
 * LIFETIME TRACKING IMPLEMENTATION
 * ============================================================================
 *
 * The following code implements the instance tracking system described in the
 * file header. This is one of the most carefully designed parts of the plugin.
 *
 * KEY INSIGHT: Binary Ninja views can be closed at any time by the user, but
 * background analysis tasks may still be running. We cannot safely use raw
 * pointers because the view may be destroyed while a task holds the pointer.
 *
 * SOLUTION: Assign each view a unique InstanceId (uint64_t). Background tasks
 * store the InstanceId, not the pointer. Before using a view, tasks look up
 * the InstanceId in FirmwareViewMap to get the current pointer (if still valid).
 *
 * WHY NOT JUST USE Ref<BinaryView>?
 * ---------------------------------
 * Holding a Ref<> extends the view's lifetime. This causes problems:
 * 1. User closes the view, but it stays alive due to our reference
 * 2. Analysis continues on a "closed" view, confusing the user
 * 3. Memory isn't released until our reference goes away
 * 4. Workflow callbacks may access stale state
 *
 * By using InstanceId, we can detect when a view is closing and abort
 * gracefully without preventing cleanup.
 */

/**
 * Check if we should skip lifetime tracking.
 *
 * During Binary Ninja shutdown, we might want to skip tracking to avoid
 * races with destruction. Currently we always track because destruction
 * callbacks handle cleanup properly.
 */
static bool ShouldSkipLifetimeTracking()
{
	/*
	 * Don't check BNIsShutdownRequested() here. Destruction callbacks are
	 * invoked during shutdown before the process exits, so we need tracking
	 * to work until then.
	 */
	return false;
}

/*
 * Global mutex protecting all instance tracking maps.
 *
 * WHY A SINGLE GLOBAL MUTEX?
 * --------------------------
 * 1. Simplifies reasoning about lock ordering (only one lock to acquire)
 * 2. View creation/destruction is rare - contention is minimal
 * 3. Matches the pattern used by KernelCacheController in Binary Ninja
 *
 * LOCK ORDERING RULE: Always acquire FirmwareViewMutex before any
 * Binary Ninja internal locks (implicitly acquired by API calls).
 */
static std::mutex FirmwareViewMutex;

/*
 * InstanceId: A unique identifier for each firmware view instance.
 *
 * We use uint64_t instead of pointers because:
 * 1. Pointers can be reused after view destruction (ABA problem)
 * 2. Comparing uint64_t is safe; comparing freed pointers is UB
 * 3. InstanceIds never wrap in practice (2^64 is huge)
 */
using InstanceId = uint64_t;

/**
 * Get the next unique instance ID.
 *
 * Thread-safe due to being called under FirmwareViewMutex.
 * Starts at 1 so that 0 can indicate "no instance".
 */
static InstanceId &GetNextInstanceId()
{
	static InstanceId id = 1;
	return id;
}

/*
 * ============================================================================
 * INSTANCE TRACKING MAPS
 * ============================================================================
 *
 * These maps track the state of all firmware view instances. They are all
 * heap-allocated via `new` to ensure they survive until process exit.
 *
 * WHY HEAP-ALLOCATED?
 * -------------------
 * Static local variables are destroyed in reverse order of construction
 * when main() exits. If these maps were stack-allocated statics, they
 * might be destroyed while destruction callbacks are still running,
 * causing use-after-free. Heap allocation ensures the maps exist until
 * the process truly exits.
 */

/**
 * Set of instance IDs for views that are currently closing.
 *
 * When a view begins closing, its ID is added here. Background tasks
 * check this set to abort early rather than continuing on a dying view.
 */
static std::unordered_set<InstanceId> &FirmwareViewClosingSet()
{
	static auto *set = new std::unordered_set<InstanceId>();
	return *set;
}

/**
 * Set of instance IDs with cancelled firmware scans.
 *
 * Scans can be cancelled explicitly (e.g., user action) or implicitly
 * (view closing). Tasks check this set periodically and bail out cleanly.
 */
static std::unordered_set<InstanceId> &FirmwareViewScanCancelSet()
{
	static auto *set = new std::unordered_set<InstanceId>();
	return *set;
}

/**
 * Primary registry: InstanceId -> Armv5FirmwareView*
 *
 * This is the authoritative map of active firmware views. When a view
 * is destroyed, its entry is removed. Background tasks use this to
 * check if a view is still alive before accessing it.
 */
static std::unordered_map<InstanceId, Armv5FirmwareView*> &FirmwareViewMap()
{
	static auto *map = new std::unordered_map<InstanceId, Armv5FirmwareView*>();
	return *map;
}

/**
 * FileSession -> InstanceId mapping.
 *
 * Binary Ninja's FileMetadata has a session ID that persists across
 * saves/reloads. We use this to find our instance from workflow callbacks
 * that only have access to the FileMetadata.
 */
static std::unordered_map<uint64_t, InstanceId> &FirmwareFileSessionMap()
{
	static auto *map = new std::unordered_map<uint64_t, InstanceId>();
	return *map;
}

/**
 * Raw pointer -> InstanceId reverse lookup.
 *
 * Sometimes we receive a raw BinaryView* (e.g., from C API callbacks)
 * and need to find our InstanceId. This map provides that lookup.
 *
 * CAUTION: The pointer is cast to uintptr_t for the key. This is safe
 * because we only use it for lookup while the view is alive.
 */
static std::unordered_map<uintptr_t, InstanceId> &FirmwareViewPointerToInstanceMap()
{
	static auto *map = new std::unordered_map<uintptr_t, InstanceId>();
	return *map;
}

/**
 * Snapshot of function starts for each instance.
 *
 * Before running firmware scans, we snapshot the current functions.
 * After scans complete, we compare to detect which functions were added.
 * This helps with incremental analysis and avoiding duplicate work.
 */
static std::unordered_map<InstanceId, std::unordered_set<uint64_t>> &FirmwareFunctionSnapshotMap()
{
	static auto *map = new std::unordered_map<InstanceId, std::unordered_set<uint64_t>>();
	return *map;
}

/**
 * Create a snapshot of all function start addresses in a view.
 *
 * Used before/after firmware scans to track which functions were added.
 * Returns an empty set if the view is invalid.
 */
static std::unordered_set<uint64_t> SnapshotFunctionsForView(const Ref<BinaryView>& view)
{
	std::unordered_set<uint64_t> starts;
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

/*
 * NOTE: IsValidFunctionStart is now in common/armv5_utils.h
 * Use armv5::IsValidFunctionStart(view, platform, addr) instead.
 */

/*
 * ============================================================================
 * ALIVE TOKENS FOR BACKGROUND TASKS
 * ============================================================================
 *
 * Background tasks need to know when a view is being destroyed so they can
 * abort cleanly. But they can't safely access the view pointer to check!
 *
 * SOLUTION: Each view gets an "alive token" - a shared_ptr<atomic<bool>>.
 * - When the view is created, the token is set to true
 * - When the view starts closing, the token is set to false
 * - Background tasks hold a copy of the shared_ptr and check the bool
 *
 * This is safe because:
 * 1. shared_ptr ensures the atomic<bool> stays allocated
 * 2. atomic<bool> ensures thread-safe read/write
 * 3. The task never touches the view pointer after seeing false
 */

/**
 * Alive tokens for each instance.
 *
 * Maps InstanceId to a shared alive flag. The shared_ptr ensures the flag
 * outlives both the view and any background tasks referencing it.
 */
static std::unordered_map<InstanceId, std::shared_ptr<std::atomic<bool>>> &FirmwareViewAliveMap()
{
	static auto *map = new std::unordered_map<InstanceId, std::shared_ptr<std::atomic<bool>>>();
	return *map;
}

/*
 * NOTE ON BACKGROUND TASKS:
 * -------------------------
 * We don't track BackgroundTask objects explicitly. Instead, we use the
 * detached-thread pattern (like the EFI resolver in Binary Ninja).
 * Tasks check for cancellation via ShouldCancel(), which internally
 * checks BNIsShutdownRequested() and IsFirmwareViewClosingById().
 * During shutdown, tasks are simply abandoned (their threads exit naturally).
 */

/*
 * ============================================================================
 * PUBLIC INTERFACE FUNCTIONS
 * ============================================================================
 *
 * These functions provide the external API for querying view state.
 * They are used by workflow callbacks, scan passes, and other components.
 */

/**
 * Get the InstanceId for a BinaryView.
 *
 * This is the primary way to safely identify a view from external code.
 * Returns 0 if the view is not a firmware view or has been destroyed.
 *
 * USAGE:
 *   InstanceId id = GetInstanceIdFromView(view);
 *   if (id == 0) { return; }  // Not our view or invalid
 *   // Now use id for lookups instead of storing the view pointer
 *
 * @param view The view to look up (can be null).
 * @return The InstanceId, or 0 if not found/invalid.
 */
InstanceId BinaryNinja::GetInstanceIdFromView(const BinaryView *view)
{
	if (!view)
		return 0;
	
	/*
	 * Fast path: If it's our own Armv5FirmwareView type, get ID directly.
	 * This avoids map lookup and is the common case.
	 */
	const Armv5FirmwareView* fwView = dynamic_cast<const Armv5FirmwareView*>(view);
	if (fwView)
		return fwView->GetInstanceId();
	
	/*
	 * Slow path: Look up by object pointer.
	 * This handles cases where we receive a wrapper BinaryView that
	 * delegates to our firmware view.
	 */
	if (!view->GetObject())
		return 0;

	/* During shutdown, static objects may be destroyed - bail out */
	if (BNIsShutdownRequested())
		return 0;
	
	uintptr_t viewPtr = reinterpret_cast<uintptr_t>(view->GetObject());
	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	auto it = FirmwareViewPointerToInstanceMap().find(viewPtr);
	if (it != FirmwareViewPointerToInstanceMap().end())
		return it->second;
	
	return 0;
}

static void OnFirmwareInitialAnalysisComplete(BinaryView *view)
{
	auto logger = LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareView");
	if (!view || !view->GetObject())
		return;
	if (view->GetTypeName() != "ARMv5 Firmware")
		return;

	const auto& config = Armv5Settings::PluginConfig::Get();
	if (config.AreAllScansDisabled())
	{
		if (logger)
			logger->LogInfo("OnFirmwareInitialAnalysisComplete: scans disabled by env");
		return;
	}
	// If workflow is enabled, it will schedule scans. Avoid double scheduling here.
	if (!config.IsWorkflowDisabled())
	{
		if (logger)
			logger->LogInfo("OnFirmwareInitialAnalysisComplete: workflow enabled, skipping");
		return;
	}

	InstanceId instanceId = GetInstanceIdFromView(view);
	if (logger)
		logger->LogInfo("OnFirmwareInitialAnalysisComplete: instanceId=%llx", (unsigned long long)instanceId);

	if (instanceId == 0)
		return;
	if (IsFirmwareViewClosingById(instanceId))
	{
		if (logger)
			logger->LogInfo("OnFirmwareInitialAnalysisComplete: view closing");
		return;
	}

	auto firmwareView = GetFirmwareViewForInstanceId(instanceId);
	if (!firmwareView)
	{
		if (logger)
			logger->LogInfo("OnFirmwareInitialAnalysisComplete: firmwareView not found in map");
		return;
	}
	if (!firmwareView->TryBeginWorkflowScans())
	{
		if (logger)
			logger->LogInfo("OnFirmwareInitialAnalysisComplete: scans already scheduled");
		return;
	}

	if (logger)
		logger->LogInfo("OnFirmwareInitialAnalysisComplete: scheduling scan job");
	ScheduleArmv5FirmwareScanJob(Ref<BinaryView>(firmwareView));
}

static void OnFirmwareViewFinalization(BinaryView *view)
{
	if (!view)
		return;
	// Only process ARMv5 Firmware views
	if (view->GetTypeName() != "ARMv5 Firmware")
		return;
	// Finalization is an analysis event, not a teardown signal. Avoid mutating
	// lifetime state here; destruction callbacks and the view destructor handle cleanup.
	auto logger = LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareView");
	if (logger)
		logger->LogInfo("OnFirmwareViewFinalization: analysis finalization event");

	InstanceId instanceId = GetInstanceIdFromView(view);
	if (instanceId == 0)
		return;
	auto previous = LoadFirmwareFunctionSnapshot(instanceId);
	if (previous.empty())
		return;
	auto current = SnapshotFunctionsForView(Ref<BinaryView>(view));
	if (current.empty())
		return;

	if (logger)
		logger->LogInfo("Firmware finalization: functions before=%zu after=%zu",
			previous.size(), current.size());

	std::vector<uint64_t> removed;
	removed.reserve(previous.size());
	for (uint64_t addr : previous)
	{
		if (current.find(addr) == current.end())
			removed.push_back(addr);
	}
	if (!removed.empty() && logger)
	{
		sort(removed.begin(), removed.end());
		string line = "Firmware finalization: functions removed after scans:";
		const size_t kMaxLog = 50;
		for (size_t i = 0; i < removed.size() && i < kMaxLog; ++i)
			line += fmt::format(" 0x{:x}", removed[i]);
		if (removed.size() > kMaxLog)
			line += fmt::format(" ... (+{} more)", removed.size() - kMaxLog);
		logger->LogWarn("%s", line.c_str());
	}
}

static void RegisterFirmwareViewDestructionCallbacks()
{
	static BNObjectDestructionCallbacks callbacks = {};
	static bool registered = false;
	if (registered)
		return;

	callbacks.destructBinaryView = [](void* ctx, BNBinaryView* obj) -> void {
		(void)ctx;
		if (!obj)
			return;
		// Clean up our tracking maps when BinaryView is destroyed
		// Simple cleanup like KernelCacheController/SharedCacheController - just remove from maps
		std::lock_guard<std::mutex> lock(FirmwareViewMutex);
		uintptr_t viewPtr = reinterpret_cast<uintptr_t>(obj);
		auto itPtr = FirmwareViewPointerToInstanceMap().find(viewPtr);
		if (itPtr != FirmwareViewPointerToInstanceMap().end())
		{
			InstanceId instanceId = itPtr->second;
			FirmwareViewClosingSet().insert(instanceId);
			FirmwareViewMap().erase(instanceId);
			FirmwareViewPointerToInstanceMap().erase(itPtr);
			auto itAlive = FirmwareViewAliveMap().find(instanceId);
			if (itAlive != FirmwareViewAliveMap().end())
			{
				itAlive->second->store(false);
				FirmwareViewAliveMap().erase(itAlive);
			}
		}
	};
	callbacks.destructFileMetadata = [](void* ctx, BNFileMetadata* obj) -> void {
		(void)ctx;
		if (!obj)
			return;
		// Clean up our tracking maps when FileMetadata is destroyed
		// Simple cleanup like KernelCacheController/SharedCacheController - just remove from maps
		const auto file = FileMetadata(obj);
		const uint64_t fileSessionId = file.GetSessionId();
		std::lock_guard<std::mutex> lock(FirmwareViewMutex);
		auto& fileMap = FirmwareFileSessionMap();
		auto it = fileMap.find(fileSessionId);
		if (it != fileMap.end())
		{
			InstanceId instanceId = it->second;
			fileMap.erase(it);
			FirmwareViewMap().erase(instanceId);
			for (auto itPtr = FirmwareViewPointerToInstanceMap().begin();
					 itPtr != FirmwareViewPointerToInstanceMap().end(); )
			{
				if (itPtr->second == instanceId)
					itPtr = FirmwareViewPointerToInstanceMap().erase(itPtr);
				else
					++itPtr;
			}
			FirmwareViewClosingSet().insert(instanceId);
			auto itAlive = FirmwareViewAliveMap().find(instanceId);
			if (itAlive != FirmwareViewAliveMap().end())
			{
				itAlive->second->store(false);
				FirmwareViewAliveMap().erase(itAlive);
			}
		}
	};

	BNRegisterObjectDestructionCallbacks(&callbacks);
	registered = true;
}

void BinaryNinja::InitArmv5FirmwareViewType()
{
	static Armv5FirmwareViewType type;
	BinaryViewType::Register(&type);
	g_armv5FirmwareViewType = &type;

	RegisterFirmwareViewDestructionCallbacks();
	BinaryViewType::RegisterBinaryViewInitialAnalysisCompletionEvent(OnFirmwareInitialAnalysisComplete);
	BinaryViewType::RegisterBinaryViewFinalizationEvent(OnFirmwareViewFinalization);
}

bool BinaryNinja::IsFirmwareViewAliveById(uint64_t instanceId)
{
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
	if (BNIsShutdownRequested())
		return false; // Treat as not alive during shutdown

	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	auto it = FirmwareViewAliveMap().find(instanceId);
	if (it == FirmwareViewAliveMap().end())
		return false;
	return it->second && it->second->load();
}

void BinaryNinja::StoreFirmwareFunctionSnapshot(uint64_t instanceId, const std::unordered_set<uint64_t>& snapshot)
{
	if (instanceId == 0)
		return;
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
	if (BNIsShutdownRequested())
		return;
	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	FirmwareFunctionSnapshotMap()[instanceId] = snapshot;
}

std::unordered_set<uint64_t> BinaryNinja::LoadFirmwareFunctionSnapshot(uint64_t instanceId)
{
	if (instanceId == 0)
		return {};
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
	if (BNIsShutdownRequested())
		return {};
	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	auto it = FirmwareFunctionSnapshotMap().find(instanceId);
	if (it == FirmwareFunctionSnapshotMap().end())
		return {};
	return it->second;
}

void BinaryNinja::ClearFirmwareFunctionSnapshot(uint64_t instanceId)
{
	if (instanceId == 0)
		return;
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
	if (BNIsShutdownRequested())
		return;
	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	FirmwareFunctionSnapshotMap().erase(instanceId);
}

Armv5FirmwareView::Armv5FirmwareView(BinaryView *data, bool parseOnly)
		: BinaryView("ARMv5 Firmware", data->GetFile(), data), m_parseOnly(parseOnly), m_entryPoint(0), m_endian(LittleEndian), m_addressSize(4), m_postAnalysisScansDone(false), m_seededFunctions(), m_seededUserFunctions(), m_seededDataDefines(), m_seededSymbols(), m_instanceId(0), m_fileSessionId(0), m_viewPtr(0)
{
	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.ARMv5FirmwareView");

	{
		std::lock_guard<std::mutex> lock(FirmwareViewMutex);
		m_instanceId = GetNextInstanceId()++;
		if (GetFile())
			m_fileSessionId = GetFile()->GetSessionId();
		m_viewPtr = reinterpret_cast<uintptr_t>(GetObject());

		if (!m_parseOnly && m_viewPtr != 0)
		{
			FirmwareViewClosingSet().erase(m_instanceId);
			FirmwareViewScanCancelSet().erase(m_instanceId);
			FirmwareViewMap()[m_instanceId] = this;
			FirmwareViewPointerToInstanceMap()[m_viewPtr] = m_instanceId;
			if (m_fileSessionId != 0)
				FirmwareFileSessionMap()[m_fileSessionId] = m_instanceId;
			// Create alive token for background jobs to reference without holding view pointers
			FirmwareViewAliveMap()[m_instanceId] = std::make_shared<std::atomic<bool>>(true);

			m_logger->LogInfo("FirmwareView ctor: instanceId=%llx parseOnly=%d ptr=0x%llx",
				(unsigned long long)m_instanceId, m_parseOnly, (unsigned long long)m_viewPtr);
		}
		else
		{
			m_logger->LogInfo("FirmwareView ctor: instanceId=%llx parseOnly=%d (not tracking)",
				(unsigned long long)m_instanceId, m_parseOnly);
		}
	}
}

Armv5FirmwareView::~Armv5FirmwareView()
{
	if (ShouldSkipLifetimeTracking())
		return;
	if (m_instanceId != 0)
	{
		std::lock_guard<std::mutex> lock(FirmwareViewMutex);

		auto it = FirmwareViewMap().find(m_instanceId);
		if (it != FirmwareViewMap().end())
			FirmwareViewMap().erase(it);
		if (m_fileSessionId != 0)
		{
			auto itFile = FirmwareFileSessionMap().find(m_fileSessionId);
			if (itFile != FirmwareFileSessionMap().end() && itFile->second == m_instanceId)
				FirmwareFileSessionMap().erase(itFile);
		}

		// Mark alive token false and remove it so jobs know the view is gone.
		auto itAlive = FirmwareViewAliveMap().find(m_instanceId);
		if (itAlive != FirmwareViewAliveMap().end())
		{
			itAlive->second->store(false);
			FirmwareViewAliveMap().erase(itAlive);
		}
		
		if (m_viewPtr != 0)
		{
			auto itPtr = FirmwareViewPointerToInstanceMap().find(m_viewPtr);
			if (itPtr != FirmwareViewPointerToInstanceMap().end() && itPtr->second == m_instanceId)
				FirmwareViewPointerToInstanceMap().erase(itPtr);
		}
		FirmwareFunctionSnapshotMap().erase(m_instanceId);
	}
}

uint64_t Armv5FirmwareView::PerformGetEntryPoint() const
{
	return m_entryPoint;
}

BNEndianness Armv5FirmwareView::PerformGetDefaultEndianness() const
{
	return m_endian;
}

size_t Armv5FirmwareView::PerformGetAddressSize() const
{
	return m_addressSize;
}

bool Armv5FirmwareView::Init()
{
	uint64_t length = GetParentView()->GetLength();

	uint64_t imageBase = 0;
	bool imageBaseFromUser = false;

	// Get load settings if available
	Ref<Settings> settings = GetLoadSettings(GetTypeName());
	if (settings && settings->Contains(Armv5Settings::kImageBase))
	{
		imageBase = settings->Get<uint64_t>(Armv5Settings::kImageBase, this);
		imageBaseFromUser = (imageBase != 0);
	}

	FirmwareSettings fwSettings = LoadFirmwareSettings(settings, this, FirmwareSettingsMode::Init);
	const FirmwareScanTuning &tuning = fwSettings.tuning;
	(void)tuning;

	// Emit a single consolidated settings line to make log triage reproducible.
	if (fwSettings.enableVerboseLogging)
		LogFirmwareSettingsSummary(m_logger, fwSettings);

	// Handle platform override from settings
	if (settings && settings->Contains(Armv5Settings::kPlatform))
	{
		Ref<Platform> platformOverride =
				Platform::GetByName(settings->Get<string>(Armv5Settings::kPlatform, this));
		if (platformOverride)
		{
			m_plat = platformOverride;
			m_arch = m_plat->GetArchitecture();
		}
	}
	else
	{
		// Default to ARMv5 platform
		m_plat = Platform::GetByName("armv5");
		m_arch = Architecture::GetByName("armv5");
	}

	if (!m_arch)
	{
		m_logger->LogError("ARMv5 architecture not found");
		return false;
	}

	// Auto-detect image base from vector table if not specified by user
	if (!imageBaseFromUser)
	{
		uint64_t detectedBase = DetectImageBaseFromVectorTable(GetParentView());
		if (detectedBase != 0)
		{
			imageBase = detectedBase;
			m_logger->LogInfo("Auto-detected image base: 0x%llx", (unsigned long long)imageBase);
		}
	}

	// Create binary reader for parsing
	BinaryReader reader(GetParentView());
	reader.SetEndianness(m_endian);

	DataBuffer fileBuf;
	const uint8_t *fileData = nullptr;
	uint64_t fileDataLen = 0;

	if (length > 0)
	{
		uint64_t bufferLen = (length < kMaxBufferedLength) ? length : kMaxBufferedLength;
		if (bufferLen > 0)
		{
			fileBuf = GetParentView()->ReadBuffer(0, bufferLen);
			if (fileBuf.GetLength() > 0)
			{
				fileData = static_cast<const uint8_t *>(fileBuf.GetData());
				fileDataLen = fileBuf.GetLength();
			}
		}
	}

	// Determine whether the vector table entries are code-like instructions or raw pointers.
	bool vectorIsCode = true;
	if (length >= 0x20)
	{
		auto isLdrPcLiteral = [](uint32_t instr) -> bool {
			return ((instr & 0x0FFFF000u) == 0x059FF000u) || ((instr & 0x0FFFF000u) == 0x051FF000u);
		};
		auto isBranchImm = [](uint32_t instr) -> bool {
			return (instr & 0x0E000000u) == 0x0A000000u;
		};
		uint32_t codeLike = 0;
		for (uint64_t i = 0; i < 8; i++)
		{
			uint32_t instr = 0;
			if (!ReadU32At(reader, fileData, fileDataLen, m_endian, i * 4, instr, length))
				continue;
			if (isLdrPcLiteral(instr) || isBranchImm(instr))
				codeLike++;
		}
		// Require a majority of entries to look like instructions.
		vectorIsCode = (codeLike >= 4);
	}

	// Add a single segment covering the entire file
	AddAutoSegment(imageBase, length, 0, length, SegmentExecutable | SegmentReadable);

	// Add sections:
	// Vector table (0x00-0x1F): code
	// Vector literal pool (0x20-0x3F): data
	// Rest: code
	if (length >= 0x20)
		AddAutoSection("vectors", imageBase, 0x20,
			vectorIsCode ? ReadOnlyCodeSectionSemantics : ReadOnlyDataSectionSemantics);
	if (length >= 0x40)
	{
		AddAutoSection("vector_ptrs", imageBase + 0x20, 0x20, ReadOnlyDataSectionSemantics);
		if (length > 0x40)
			AddAutoSection("code", imageBase + 0x40, length - 0x40, ReadOnlyCodeSectionSemantics);
	}
	else if (length > 0x20)
	{
		// If the file is oddly short, conservatively label remaining bytes as code.
		AddAutoSection("code", imageBase + 0x20, length - 0x20, ReadOnlyCodeSectionSemantics);
	}

	if (m_arch && m_plat)
	{
		SetDefaultArchitecture(m_arch);
		SetDefaultPlatform(m_plat);
	}

	// Disable core pointer sweep if requested to avoid excessive false positives on raw firmware blobs.
	if (fwSettings.disablePointerSweep)
		Settings::Instance()->Set("analysis.pointerSweep.autorun", false, this);
	else
		Settings::Instance()->Set("analysis.pointerSweep.autorun", true, this);

	// Partial linear sweep option: leave auto linear sweep enabled but limit it to faster tier
	if (fwSettings.enablePartialLinearSweep)
	{
		Settings::Instance()->Set("triage.linearSweep", "full", this);
		Settings::Instance()->Set("analysis.linearSweep.autorun", true, this);
		Settings::Instance()->Set("analysis.linearSweep.controlFlowGraph", false, this);
		Settings::Instance()->Set("analysis.signatureMatcher.autorun", false, this);
	}
	else if (fwSettings.disableLinearSweep)
	{
		Settings::Instance()->Set("analysis.linearSweep.autorun", false, this);
		Settings::Instance()->Set("analysis.linearSweep.controlFlowGraph", false, this);
		Settings::Instance()->Set("triage.linearSweep", "none", this);
	}

	// Allow normal function analysis - the ARMv5 plugin controls function creation
	// through the unified recognizer to prevent excessive auto-discovery

	// ARMv5 views need string typing to be handled by the firmware scan workflow
	// The analysis completion callbacks will handle this on background threads

	// Standard ARM exception vector names and handler names
	const char *vectorNames[] = {
			"vec_reset",
			"vec_undef",
			"vec_swi",
			"vec_prefetch_abort",
			"vec_data_abort",
			"vec_reserved",
			"vec_irq",
			"vec_fiq"};

	const char *handlerNames[] = {
			"reset_handler",
			"undef_handler",
			"swi_handler",
			"prefetch_abort_handler",
			"data_abort_handler",
			"reserved_handler",
			"irq_handler",
			"fiq_handler"};

	// Track resolved handler addresses (absolute VAs)
	uint64_t handlerAddrs[8] = {0};

	try
	{
		// First pass: resolve all handler addresses from vector table
		for (int i = 0; i < 8; i++)
		{
			uint64_t vectorOffset = static_cast<uint64_t>(i) * 4;
			uint64_t vectorAddr = imageBase + vectorOffset;

			// Define symbol for the vector entry (it's code, not data)
			DefineAutoSymbol(new Symbol(FunctionSymbol, vectorNames[i], vectorAddr, GlobalBinding));

			// Seed vector entry as a function so it gets disassembled
			if (!m_parseOnly)
			{
				m_seededFunctions.insert(vectorAddr);
				m_seededUserFunctions.insert(vectorAddr);
			}

			// Resolve the handler address (may return relative offset or absolute VA depending on table)
			uint64_t handlerAddr = ResolveVectorEntry(
					reader, fileData, fileDataLen, m_endian, vectorOffset, imageBase, length);

			if (handlerAddr != 0)
			{
				// If it looks like a file-relative offset, convert to VA
				if (handlerAddr < length)
					handlerAddrs[i] = imageBase + handlerAddr;
				else
					handlerAddrs[i] = handlerAddr;

				m_logger->LogDebug(
						"Vector %d (%s): handler at 0x%llx",
						i, vectorNames[i], (unsigned long long)handlerAddrs[i]);
			}
		}

		// If we have LDR PC vectors, they use a literal pointer table after the vectors.
		// Define the pointer table entries as data.
		uint32_t firstInstr = 0;
		ReadU32At(reader, fileData, fileDataLen, m_endian, 0, firstInstr, length);

		const bool firstIsLdrPc =
				((firstInstr & 0xFFFFF000) == 0xE59FF000) || ((firstInstr & 0xFFFFF000) == 0xE51FF000);

		if (firstIsLdrPc)
		{
			for (int i = 0; i < 8; i++)
			{
				uint32_t vecInstr = 0;
				ReadU32At(reader, fileData, fileDataLen, m_endian, static_cast<uint64_t>(i) * 4, vecInstr, length);

				const bool isLdrPc =
						((vecInstr & 0xFFFFF000) == 0xE59FF000) || ((vecInstr & 0xFFFFF000) == 0xE51FF000);

				if (!isLdrPc)
					continue;

				// Mirror ResolveVectorEntry's PC-relative semantics
				uint32_t vecOffset = vecInstr & 0xFFF;
				uint64_t pcBase = (static_cast<uint64_t>(i) * 4) + 8;
				const bool add = (vecInstr & (1u << 23)) != 0;

				uint64_t ptrOffset = 0;
				if (add)
				{
					ptrOffset = pcBase + vecOffset;
				}
				else
				{
					if (vecOffset > pcBase)
						continue;
					ptrOffset = pcBase - vecOffset;
				}

				uint64_t ptrAddr = imageBase + ptrOffset;

				if (!m_parseOnly)
				{
					// Define as pointer to code using UserDataVariable to prevent BN treating as code
					Ref<Type> ptrType = Type::PointerType(m_arch, Type::VoidType());
					m_seededDataDefines.push_back({ptrAddr, ptrType, true});

					string ptrName = string(handlerNames[i]) + "_ptr";
					m_seededSymbols.push_back(new Symbol(DataSymbol, ptrName, ptrAddr, GlobalBinding));
				}
			}
		}
	}
	catch (ReadException &e)
	{
		m_logger->LogWarn("Failed to fully parse vector table: %s", e.what());
	}

	// Set entry point from reset handler
	m_entryPoint = handlerAddrs[0];
	if (m_entryPoint == 0)
		m_entryPoint = imageBase;
	if (!IsValidFunctionStart(Ref<BinaryView>(this), m_plat, m_entryPoint))
	{
		m_logger->LogWarn("Entry point invalid at 0x%llx, falling back to image base",
			(unsigned long long)m_entryPoint);
		m_entryPoint = imageBase;
	}

	m_logger->LogDebug("Entry point: 0x%llx", (unsigned long long)m_entryPoint);

	// Finished for parse-only mode
	if (m_parseOnly)
		return true;

	// Collect vector table entries and handler functions for analysis
	if (m_plat)
	{
		std::set<uint64_t> seededFunctions;

		// Collect resolved handler functions for analysis (deferred)
		for (int i = 0; i < 8; i++)
		{
			if (handlerAddrs[i] == 0)
				continue;

			if (handlerAddrs[i] >= imageBase && handlerAddrs[i] < imageBase + length)
			{
				seededFunctions.insert(handlerAddrs[i]);
				m_seededUserFunctions.insert(handlerAddrs[i]);
				m_seededSymbols.push_back(
						new Symbol(FunctionSymbol, handlerNames[i], handlerAddrs[i], GlobalBinding));

				m_logger->LogDebug("Seeded handler function: %s at 0x%llx",
													 handlerNames[i], (unsigned long long)handlerAddrs[i]);
			}
		}

		// Defer entry point function creation to post-analysis scan job
		if (m_entryPoint >= imageBase && m_entryPoint < imageBase + length)
		{
			seededFunctions.insert(m_entryPoint);
			m_seededUserFunctions.insert(m_entryPoint);
		}


		// Timing helper for firmware-specific analysis passes (only logs when verbose enabled)
		auto timePass = [&](const char *label, auto &&fn)
		{
			if (!fwSettings.enableVerboseLogging)
			{
				fn();
				return;
			}

			auto start = std::chrono::steady_clock::now();
			fn();
			double seconds = std::chrono::duration_cast<std::chrono::duration<double>>(
													 std::chrono::steady_clock::now() - start)
													 .count();
			m_logger->LogInfo("Firmware analysis timing: %s took %.3f s", label, seconds);
		};

		// Analyze MMU configuration to discover memory regions
		timePass("MMU analysis", [&]()
						 { AnalyzeMMUConfiguration(
									 Ref<BinaryView>(this), reader, fileData, fileDataLen, m_endian, imageBase, length, m_logger); });

		if (!fwSettings.skipFirmwareScans && fwSettings.enableVerboseLogging)
			m_logger->LogInfo("Firmware scans scheduled via module workflow activity");

		if (!seededFunctions.empty())
			m_seededFunctions.insert(seededFunctions.begin(), seededFunctions.end());

		// Ensure vector/handler entry points exist even if post-analysis scans are skipped.
		if (!m_seededUserFunctions.empty())
		{
			Ref<Architecture> baseArch = m_arch;
			for (uint64_t addr : m_seededUserFunctions)
			{
				uint64_t funcAddr = addr;
				Ref<Platform> targetPlat = m_plat;

				// Respect Thumb bit via associated architecture mapping
				if (baseArch)
				{
					Ref<Architecture> targetArch = baseArch->GetAssociatedArchitectureByAddress(funcAddr);
					if (targetArch && targetArch != baseArch)
					{
						Ref<Platform> related = m_plat->GetRelatedPlatform(targetArch);
						if (related)
							targetPlat = related;
					}
				}

				if (funcAddr < imageBase || funcAddr >= imageBase + length)
				{
					m_logger->LogWarn("Seeded function outside view: 0x%llx",
														(unsigned long long)funcAddr);
					continue;
				}
				if (!IsValidFunctionStart(Ref<BinaryView>(this), targetPlat, funcAddr))
				{
					m_logger->LogWarn("Seeded function invalid at 0x%llx", (unsigned long long)funcAddr);
					continue;
				}

				Ref<Function> func = GetAnalysisFunction(targetPlat.GetPtr(), funcAddr);
				if (!func)
					func = CreateUserFunction(targetPlat.GetPtr(), funcAddr);

				if (!func)
				{
					AddFunctionForAnalysis(targetPlat.GetPtr(), funcAddr, true);
					m_logger->LogWarn("Seeded function: CreateUserFunction failed, added for analysis at 0x%llx",
														(unsigned long long)funcAddr);
				}
			}
		}
	}

	return true;
}

void Armv5FirmwareView::RunFirmwareWorkflowScans(Ref<BinaryView> viewRef)
{
	if (!GetObject())
		return;
	if (BNIsShutdownRequested())
		return;
	if (m_instanceId == 0)
		return;
	if (IsFirmwareViewClosingById(m_instanceId))
		return;
	if (m_parseOnly)
		return;
	if (!TryBeginWorkflowScans())
		return;

	// Pass through the Ref<> from workflow callback - do NOT create new Ref<> from this
	ScheduleArmv5FirmwareScanJob(viewRef);
}

bool Armv5FirmwareView::TryBeginWorkflowScans()
{
	if (m_postAnalysisScansDone)
		return false;
	m_postAnalysisScansDone = true;
	return true;
}

const std::set<uint64_t> &Armv5FirmwareView::GetSeededFunctions() const
{
	return m_seededFunctions;
}

const std::set<uint64_t> &Armv5FirmwareView::GetSeededUserFunctions() const
{
	return m_seededUserFunctions;
}

const std::vector<FirmwareScanDataDefine> &Armv5FirmwareView::GetSeededDataDefines() const
{
	return m_seededDataDefines;
}

const std::vector<BinaryNinja::Ref<BinaryNinja::Symbol>> &Armv5FirmwareView::GetSeededSymbols() const
{
	return m_seededSymbols;
}

void BinaryNinja::RunArmv5FirmwareWorkflowScans(const Ref<BinaryView> &view)
{
	if (!view || !view->GetObject())
		return;
	if (view->GetTypeName() != "ARMv5 Firmware")
		return;
	if (Armv5Settings::PluginConfig::Get().AreAllScansDisabled())
		return;

	// dynamic_cast may fail if view is a wrapper from analysis context
	Armv5FirmwareView *firmwareView = dynamic_cast<Armv5FirmwareView *>(view.GetPtr());
	if (!firmwareView)
	{
		InstanceId instanceId = GetInstanceIdFromView(view.GetPtr());
		if (instanceId == 0 || IsFirmwareViewClosingById(instanceId) || !IsFirmwareViewAliveById(instanceId))
			return;
		firmwareView = GetFirmwareViewForInstanceId(instanceId);
		if (!firmwareView)
			return;
	}

	// Pass through the Ref<> from workflow callback - do NOT create new Ref<> from raw pointer
	firmwareView->RunFirmwareWorkflowScans(view);
}

bool BinaryNinja::IsFirmwareViewClosing(const BinaryView *view)
{
	if (!view)
		return true;
	if (!view->GetObject())
		return true;

	InstanceId instanceId = GetInstanceIdFromView(view);
	if (instanceId == 0)
		return true;

	return IsFirmwareViewClosingById(instanceId);
}

bool BinaryNinja::IsFirmwareViewClosingById(uint64_t instanceId)
{
	if (instanceId == 0)
		return true;
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
	if (BNIsShutdownRequested())
		return true; // Treat as closing during shutdown

	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	auto &closing = FirmwareViewClosingSet();
	bool isClosing = closing.find(instanceId) != closing.end();
	if (isClosing)
	{
		auto logger = LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareView");
		if (logger)
			logger->LogInfo("IsFirmwareViewClosingById: instanceId=%llx is closing", (unsigned long long)instanceId);
	}
	return isClosing;
}

bool BinaryNinja::IsFirmwareViewScanCancelled(const BinaryView *view)
{
	if (!view)
		return true;

	InstanceId instanceId = GetInstanceIdFromView(view);
	if (instanceId == 0)
		return true;

	return IsFirmwareViewScanCancelledById(instanceId);
}

bool BinaryNinja::IsFirmwareViewScanCancelledById(uint64_t instanceId)
{
	if (instanceId == 0)
		return true;
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
	if (BNIsShutdownRequested())
		return true; // Treat as cancelled during shutdown

	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	auto &cancelled = FirmwareViewScanCancelSet();
	return cancelled.find(instanceId) != cancelled.end();
}

void BinaryNinja::SetFirmwareViewScanCancelled(uint64_t instanceId, bool cancelled)
{
	if (instanceId == 0)
		return;
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
	if (BNIsShutdownRequested())
		return;

	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	auto &set = FirmwareViewScanCancelSet();
	if (cancelled)
		set.insert(instanceId);
	else
		set.erase(instanceId);
}

Armv5FirmwareView* BinaryNinja::GetFirmwareViewForInstanceId(uint64_t instanceId)
{
	if (instanceId == 0)
		return nullptr;
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
	if (BNIsShutdownRequested())
		return nullptr;

	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	auto itAlive = FirmwareViewAliveMap().find(instanceId);
	if (itAlive == FirmwareViewAliveMap().end() || !itAlive->second->load())
		return nullptr;
	auto it = FirmwareViewMap().find(instanceId);
	if (it == FirmwareViewMap().end())
		return nullptr;

	return it->second;
}

Armv5FirmwareView* BinaryNinja::GetFirmwareViewForFileSessionId(uint64_t fileSessionId)
{
	if (fileSessionId == 0)
		return nullptr;
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
	if (BNIsShutdownRequested())
		return nullptr;

	std::lock_guard<std::mutex> lock(FirmwareViewMutex);
	auto itFile = FirmwareFileSessionMap().find(fileSessionId);
	if (itFile == FirmwareFileSessionMap().end())
		return nullptr;
	auto itAlive = FirmwareViewAliveMap().find(itFile->second);
	if (itAlive == FirmwareViewAliveMap().end() || !itAlive->second->load())
		return nullptr;
	if (FirmwareViewClosingSet().find(itFile->second) != FirmwareViewClosingSet().end())
		return nullptr;
	auto it = FirmwareViewMap().find(itFile->second);
	if (it == FirmwareViewMap().end())
		return nullptr;
	return it->second;
}

Armv5FirmwareViewType::Armv5FirmwareViewType()
		: BinaryViewType("ARMv5 Firmware", "ARMv5 Firmware")
{
	m_logger = LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareViewType");
}

Ref<BinaryView> Armv5FirmwareViewType::Create(BinaryView *data)
{
	try
	{
		return new Armv5FirmwareView(data);
	}
	catch (std::exception &e)
	{
		m_logger->LogErrorForException(
				e, "%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}

Ref<BinaryView> Armv5FirmwareViewType::Parse(BinaryView *data)
{
	try
	{
		return new Armv5FirmwareView(data, true);
	}
	catch (std::exception &e)
	{
		m_logger->LogErrorForException(
				e, "%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}

bool Armv5FirmwareViewType::IsTypeValidForData(BinaryView *data)
{
	// Need at least 32 bytes for vector table + some code to analyze
	if (data->GetLength() < 64)
		return false;

	DataBuffer buf = data->ReadBuffer(0, 32);
	if (buf.GetLength() < 32)
		return false;

	const uint32_t *words = (const uint32_t *)buf.GetData();

	// Step 1: Check for ARM vector table pattern
	int vectorCount = 0;
	for (int i = 0; i < 8; i++)
	{
		uint32_t instr = words[i];

		// LDR PC, [PC, #imm] - 0xE59FF0xx or 0xE51FF0xx
		if ((instr & 0xFFFFF000) == 0xE59FF000 || (instr & 0xFFFFF000) == 0xE51FF000)
		{
			vectorCount++;
			continue;
		}

		// B (branch) instruction: 0xEAxxxxxx
		if ((instr & 0xFF000000) == 0xEA000000)
		{
			vectorCount++;
			continue;
		}
	}

	// Require at least 4 valid vector table entries
	if (vectorCount < 4)
		return false;

	// Step 2: Use our disassembler to verify instructions are valid ARMv5
	size_t scanSize = std::min((size_t)4096, (size_t)data->GetLength());
	DataBuffer codeBuf = data->ReadBuffer(0, scanSize);
	if (codeBuf.GetLength() < scanSize)
		return false;

	const uint32_t *code = (const uint32_t *)codeBuf.GetData();
	size_t numWords = scanSize / 4;

	// Learn pointer-looking high bytes from the vector pointer table (0x20-0x3F).
	bool pointerHighByte[256] = {false};
	if (numWords >= (0x40 / 4))
	{
		for (size_t j = (0x20 / 4); j < (0x40 / 4) && j < numWords; j++)
		{
			uint32_t w = code[j];
			if (w == 0)
				continue;
			if ((w & 0x3) == 0)
				pointerHighByte[(uint8_t)(w >> 24)] = true;
		}
	}

	int validInstructions = 0;
	int unknownInstructions = 0;

	for (size_t i = 0; i < numWords; i++)
	{
		uint32_t instr = code[i];
		uint64_t offset = static_cast<uint64_t>(i) * 4;

		// Skip vector pointer table (0x20-0x3F)
		if (offset >= 0x20 && offset < 0x40)
			continue;

		// Skip obvious data
		if (instr == 0 || (instr & 0xFFFF0000) == 0)
			continue;

		// Skip pointer-looking values based on learned high byte
		if (pointerHighByte[(uint8_t)(instr >> 24)])
			continue;

		armv5::Instruction decoded;
		if (armv5::armv5_decompose(instr, &decoded, (uint32_t)(i * 4), 0) == 0)
			validInstructions++;
		else
			unknownInstructions++;
	}

	int totalNonZero = validInstructions + unknownInstructions;
	if (totalNonZero < 10)
	{
		m_logger->LogDebug("Too few non-zero words to determine architecture");
		return false;
	}

	float validRatio = (float)validInstructions / totalNonZero;
	m_logger->LogDebug("ARMv5 detection: %d valid, %d unknown, ratio %.2f",
										 validInstructions, unknownInstructions, validRatio);

	if (validRatio < 0.70f)
	{
		m_logger->LogDebug("Low valid instruction ratio (%.2f) - likely not ARMv5", validRatio);
		return false;
	}

	m_logger->LogDebug("ARMv5 Firmware detected: %d vector entries, %.0f%% valid ARMv5 instructions",
										 vectorCount, validRatio * 100);
	return true;
}

bool Armv5FirmwareViewType::IsForceLoadable()
{
	// Allow users to manually select this view type in "Open with Options"
	return true;
}

Ref<Settings> Armv5FirmwareViewType::GetLoadSettingsForData(BinaryView *data)
{
	Ref<BinaryView> viewRef = Parse(data);
	if (!viewRef || !viewRef->Init())
	{
		m_logger->LogDebug("Parse failed, using default load settings");
		viewRef = data;
	}

	Ref<Settings> settings = GetDefaultLoadSettingsForData(viewRef);

	RegisterFirmwareSettings(settings);

	// Allow overriding image base and platform
	vector<string> overrides = {Armv5Settings::kImageBase, Armv5Settings::kPlatform};
	for (const auto &overrideKey : overrides)
	{
		if (settings->Contains(overrideKey))
			settings->UpdateProperty(overrideKey, "readOnly", false);
	}

	// Auto-detect image base from vector table if the addresses are absolute
	uint64_t detectedBase = DetectImageBaseFromVectorTable(data);
	if (detectedBase != 0 && settings->Contains(Armv5Settings::kImageBase))
	{
		settings->Set(Armv5Settings::kImageBase, detectedBase, viewRef);
		m_logger->LogInfo("Auto-detected image base: 0x%llx", (unsigned long long)detectedBase);
	}

	return settings;
}