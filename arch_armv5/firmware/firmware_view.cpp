/*
 * ARMv5 Firmware BinaryViewType
 *
 * Custom BinaryViewType for bare metal ARM firmware detection.
 * Detects ARM binaries by looking for vector table patterns at offset 0.
 */

#include "firmware_internal.h"
#include "firmware_view.h"
#include "firmware_scan_job.h"
#include "firmware_settings.h"

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

static constexpr uint64_t kMaxBufferedLength = 64ULL * 1024 * 1024;

static Armv5FirmwareViewType *g_armv5FirmwareViewType = nullptr;

static bool ShouldSkipLifetimeTracking()
{
	// Don't check shutdown - rely on destruction callbacks to clean up properly
	// Destruction callbacks are called when objects are destroyed, which happens during shutdown
	return false;
}

// Use global static mutex like KernelCacheController/SharedCacheController
// Global statics are safe to use during shutdown (destroyed after main() exits)
static std::mutex FirmwareViewMutex;

using InstanceId = uint64_t;

static InstanceId &GetNextInstanceId()
{
	static InstanceId id = 1;
	return id;
}

static std::unordered_set<InstanceId> &FirmwareViewClosingSet()
{
	static auto *set = new std::unordered_set<InstanceId>();
	return *set;
}

static std::unordered_set<InstanceId> &FirmwareViewScanCancelSet()
{
	static auto *set = new std::unordered_set<InstanceId>();
	return *set;
}

static std::unordered_map<InstanceId, Armv5FirmwareView*> &FirmwareViewMap()
{
	static auto *map = new std::unordered_map<InstanceId, Armv5FirmwareView*>();
	return *map;
}

static std::unordered_map<uint64_t, InstanceId> &FirmwareFileSessionMap()
{
	static auto *map = new std::unordered_map<uint64_t, InstanceId>();
	return *map;
}

static std::unordered_map<uintptr_t, InstanceId> &FirmwareViewPointerToInstanceMap()
{
	static auto *map = new std::unordered_map<uintptr_t, InstanceId>();
	return *map;
}

static std::unordered_map<InstanceId, std::unordered_set<uint64_t>> &FirmwareFunctionSnapshotMap()
{
	static auto *map = new std::unordered_map<InstanceId, std::unordered_set<uint64_t>>();
	return *map;
}

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

static bool IsValidFunctionStart(const Ref<BinaryView>& view, const Ref<Platform>& platform, uint64_t addr)
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
	if (enforceExecutable && !view->IsOffsetExecutable(checkAddr))
		return false;
	DataBuffer buf = view->ReadBuffer(checkAddr, arch->GetMaxInstructionLength());
	if (buf.GetLength() == 0)
		return false;
	if (buf.GetLength() >= 4)
	{
		const uint8_t* bytes = static_cast<const uint8_t*>(buf.GetData());
		const bool allZero = bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0;
		const bool allFF = bytes[0] == 0xFF && bytes[1] == 0xFF && bytes[2] == 0xFF && bytes[3] == 0xFF;
		if (allZero || allFF)
			return false;
	}
	InstructionInfo info;
	if (!arch->GetInstructionInfo(static_cast<const uint8_t*>(buf.GetData()), checkAddr, buf.GetLength(), info))
		return false;
	return info.length != 0;
}

// Track a small alive token per view instance that background tasks can use to
// determine whether the view is still alive without touching view pointers.
static std::unordered_map<InstanceId, std::shared_ptr<std::atomic<bool>>> &FirmwareViewAliveMap()
{
	static auto *map = new std::unordered_map<InstanceId, std::shared_ptr<std::atomic<bool>>>();
	return *map;
}

// Don't track BackgroundTask - let the detached thread manage it (like EFI resolver).
// The thread checks for cancellation via ShouldCancel() which checks BNIsShutdownRequested()
// and IsFirmwareViewClosingById(). During shutdown, we just let the task be dropped.

InstanceId BinaryNinja::GetInstanceIdFromView(const BinaryView *view)
{
	if (!view)
		return 0;
	
	// If it's our own view type, we can just get the ID safely
	const Armv5FirmwareView* fwView = dynamic_cast<const Armv5FirmwareView*>(view);
	if (fwView)
		return fwView->GetInstanceId();
	
	// Fallback to lookup via object pointer if it's a wrapper view.
	// NOTE: This is susceptible to pointer reuse if not handled carefully,
	// but we only track real views in the map.
	if (!view->GetObject())
		return 0;
	// During shutdown, don't access static objects (mutex, maps) - they may be destroyed
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