/*
 * ARMv5 Firmware BinaryViewType
 *
 * Custom BinaryViewType for bare metal ARM firmware detection.
 * Detects ARM binaries by looking for vector table patterns at offset 0.
 */

#include "firmware_internal.h"
#include "firmware_settings.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;
using namespace BinaryNinja;
using namespace armv5;

static constexpr uint64_t kMaxBufferedLength = 64ULL * 1024 * 1024;

static Armv5FirmwareViewType* g_armv5FirmwareViewType = nullptr;
static std::mutex& FirmwareViewMutex()
{
	static std::mutex* mutex = new std::mutex();
	return *mutex;
}

static std::unordered_map<BNBinaryView*, Armv5FirmwareView*>& FirmwareViewMap()
{
	static auto* map = new std::unordered_map<BNBinaryView*, Armv5FirmwareView*>();
	return *map;
}


void BinaryNinja::InitArmv5FirmwareViewType()
{
	static Armv5FirmwareViewType type;
	BinaryViewType::Register(&type);
	g_armv5FirmwareViewType = &type;
}


// NOTE: We previously had a BinaryDataNotification to auto-apply the irq-handler
// calling convention to exception handlers. This was removed because:
// 1. No other architecture plugins do this - it's non-standard behavior
// 2. It adds complexity (notification lifecycle management, mutex, etc.)
// 3. The handler functions are already named (irq_handler, fiq_handler, etc.)
//    so users can easily identify them and apply conventions manually if needed
// 4. Auto-applying could interfere with user preferences or cause issues if
//    vector table detection is incorrect


Armv5FirmwareView::Armv5FirmwareView(BinaryView* data, bool parseOnly): BinaryView("ARMv5 Firmware", data->GetFile(), data),
	m_parseOnly(parseOnly),
	m_entryPoint(0),
	m_endian(LittleEndian),
	m_addressSize(4),
	m_postAnalysisScansDone(false)
{
	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.ARMv5FirmwareView");
	{
		std::lock_guard<std::mutex> lock(FirmwareViewMutex());
		FirmwareViewMap()[GetObject()] = this;
	}
}


Armv5FirmwareView::~Armv5FirmwareView()
{
	{
		std::lock_guard<std::mutex> lock(FirmwareViewMutex());
		auto& map = FirmwareViewMap();
		auto it = map.find(GetObject());
		if (it != map.end() && it->second == this)
			map.erase(it);
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
	if (settings && settings->Contains(FirmwareSettingKeys::kImageBase))
	{
		imageBase = settings->Get<uint64_t>(FirmwareSettingKeys::kImageBase, this);
		imageBaseFromUser = (imageBase != 0);
	}

	FirmwareSettings fwSettings = LoadFirmwareSettings(settings, this, FirmwareSettingsMode::Init);
	const FirmwareScanTuning& tuning = fwSettings.tuning;

	// Emit a single consolidated settings line to make log triage reproducible.
	// This mirrors the effective values after defaults + user overrides are applied.
	if (fwSettings.enableVerboseLogging)
		LogFirmwareSettingsSummary(m_logger, fwSettings);

	// Handle platform override from settings
	if (settings && settings->Contains(FirmwareSettingKeys::kPlatform))
	{
		Ref<Platform> platformOverride = Platform::GetByName(settings->Get<string>(FirmwareSettingKeys::kPlatform, this));
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
	const uint8_t* fileData = nullptr;
	uint64_t fileDataLen = 0;
	if (length > 0)
	{
		uint64_t bufferLen = (length < kMaxBufferedLength) ? length : kMaxBufferedLength;
		if (bufferLen > 0)
		{
			fileBuf = GetParentView()->ReadBuffer(0, bufferLen);
			if (fileBuf.GetLength() > 0)
			{
				fileData = static_cast<const uint8_t*>(fileBuf.GetData());
				fileDataLen = fileBuf.GetLength();
			}
		}
	}

	// Add a single segment covering the entire file
	AddAutoSegment(imageBase, length, 0, length,
		SegmentExecutable | SegmentReadable);

	// Add sections
	// Vector table (0x00-0x1F): code (contains branch/load instructions)
	// Vector literal pool (0x20-0x3F): data (contains handler addresses)
	// Rest: mark as code to follow core Binary Ninja view behavior (linear sweep + RD)
	AddAutoSection("vectors", imageBase, 0x20, ReadOnlyCodeSectionSemantics);
	AddAutoSection("vector_ptrs", imageBase + 0x20, 0x20, ReadOnlyDataSectionSemantics);
	AddAutoSection("code", imageBase + 0x40, length - 0x40, ReadOnlyCodeSectionSemantics);

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

	// Parse vector table and resolve handler addresses
	// (reader already created above for image base detection)

	// Standard ARM exception vector names and handler names
	const char* vectorNames[] = {
		"vec_reset",
		"vec_undef",
		"vec_swi",
		"vec_prefetch_abort",
		"vec_data_abort",
		"vec_reserved",
		"vec_irq",
		"vec_fiq"
	};

	const char* handlerNames[] = {
		"reset_handler",
		"undef_handler",
		"swi_handler",
		"prefetch_abort_handler",
		"data_abort_handler",
		"reserved_handler",
		"irq_handler",
		"fiq_handler"
	};

	// Track resolved handler addresses to avoid duplicates
	uint64_t handlerAddrs[8] = {0};

	try
	{
		// First pass: resolve all handler addresses from vector table
		for (int i = 0; i < 8; i++)
		{
			uint64_t vectorOffset = i * 4;
			uint64_t vectorAddr = imageBase + vectorOffset;

			// Define symbol for the vector entry (it's code, not data)
			DefineAutoSymbol(new Symbol(FunctionSymbol, vectorNames[i], vectorAddr, GlobalBinding));

			// Resolve the handler address
			uint64_t handlerAddr = ResolveVectorEntry(reader, fileData, fileDataLen, m_endian,
				vectorOffset, imageBase, length);
			if (handlerAddr != 0)
			{
				// Store for later - add imageBase if it looks like a relative address
				// (addresses less than length are likely file-relative)
				if (handlerAddr < length)
					handlerAddrs[i] = imageBase + handlerAddr;
				else
					handlerAddrs[i] = handlerAddr;

				m_logger->LogDebug("Vector %d (%s): handler at 0x%llx",
					i, vectorNames[i], (unsigned long long)handlerAddrs[i]);
			}
		}

		// Check if we have LDR PC vectors - they use a pointer table after the vectors
		// Define the pointer table entries as data
		uint32_t firstInstr = 0;
		ReadU32At(reader, fileData, fileDataLen, m_endian, 0, firstInstr, length);
		if ((firstInstr & 0xFFFFF000) == 0xE59FF000)
		{
			// LDR PC style - there's a pointer table
			// Define pointer table entries as void* data
			for (int i = 0; i < 8; i++)
			{
				// Calculate where this vector's pointer should be
				// Each vector is at offset i*4, PC is i*4+8, so pointer is at i*4+8+offset
				uint32_t vecInstr = 0;
				ReadU32At(reader, fileData, fileDataLen, m_endian, i * 4, vecInstr, length);
				if ((vecInstr & 0xFFFFF000) == 0xE59FF000)
				{
					uint32_t vecOffset = vecInstr & 0xFFF;
					uint64_t ptrOffset = (i * 4) + 8 + vecOffset;
					uint64_t ptrAddr = imageBase + ptrOffset;

					// Define as pointer to code using UserDataVariable to prevent
					// Binary Ninja from treating this area as code
					Ref<Type> ptrType = Type::PointerType(m_arch, Type::VoidType());
					DefineUserDataVariable(ptrAddr, ptrType);

					string ptrName = string(handlerNames[i]) + "_ptr";
					DefineAutoSymbol(new Symbol(DataSymbol, ptrName, ptrAddr, GlobalBinding));
				}
			}
		}
	}
	catch (ReadException& e)
	{
		m_logger->LogWarn("Failed to fully parse vector table: %s", e.what());
	}

	// Set entry point from reset handler
	m_entryPoint = handlerAddrs[0];
	if (m_entryPoint == 0)
		m_entryPoint = imageBase;

	m_logger->LogDebug("Entry point: 0x%llx", (unsigned long long)m_entryPoint);

	// Finished for parse only mode
	if (m_parseOnly)
		return true;

	// Add vector table entries and handler functions for analysis
	if (m_plat)
	{
		std::set<uint64_t> seededFunctions;

		// Add vector table entries as functions (they contain LDR PC or B instructions)
		for (int i = 0; i < 8; i++)
		{
			uint64_t vectorAddr = imageBase + (i * 4);
			if (AddFunctionForAnalysis(m_plat, vectorAddr, false))
				seededFunctions.insert(vectorAddr);
		}

		// Add resolved handler functions
		for (int i = 0; i < 8; i++)
		{
			if (handlerAddrs[i] != 0 && handlerAddrs[i] >= imageBase && handlerAddrs[i] < imageBase + length)
			{
				if (AddFunctionForAnalysis(m_plat, handlerAddrs[i], false))
					seededFunctions.insert(handlerAddrs[i]);
				DefineAutoSymbol(new Symbol(FunctionSymbol, handlerNames[i], handlerAddrs[i], GlobalBinding));

				m_logger->LogDebug("Added handler function: %s at 0x%llx",
					handlerNames[i], (unsigned long long)handlerAddrs[i]);
			}
		}

		// Add reset handler as entry point
		if (m_entryPoint != 0)
		{
			AddEntryPointForAnalysis(m_plat, m_entryPoint);
		}

		// Special handling for IRQ/FIQ handlers that use MMIO vector tables
		// These typically have a pattern:
		//   push {r0-r5}        ; save scratch registers
		//   mov r0, #0xXX000000 ; load MMIO base address
		//   ldr pc, [r0, #imm]  ; jump through MMIO vector table
		//   <cleanup code>      ; ISR returns here for cleanup
		// We need to mark the instruction after the LDR PC as a function entry
		// since the ISR will return there via interrupt return mechanism
		try
		{
			// Check IRQ handler (vector 6) and FIQ handler (vector 7)
			for (int vecIdx = 6; vecIdx <= 7; vecIdx++)
			{
				if (handlerAddrs[vecIdx] == 0 || handlerAddrs[vecIdx] < imageBase)
					continue;

				uint64_t handlerOffset = handlerAddrs[vecIdx] - imageBase;
				if (handlerOffset + 16 > length)
					continue;

				// Scan the first few instructions of the handler for LDR PC pattern
				for (int instrIdx = 0; instrIdx < 4; instrIdx++)
				{
					uint32_t instr = 0;
					ReadU32At(reader, fileData, fileDataLen, m_endian, handlerOffset + (instrIdx * 4), instr, length);

					// LDR PC, [Rn, #imm] - jump through MMIO vector
					// Encoding: cond 0101 U0W1 Rn 1111 imm12 (W=0, L=1, Rd=PC)
					// Common forms: 0xE59xF0xx (add) or 0xE51xF0xx (sub)
					if ((instr & 0x0F50F000) == 0x0510F000 && (instr & 0xF0000000) == 0xE0000000)
					{
						// Found LDR PC - the next instruction is the cleanup entry
						uint64_t cleanupAddr = handlerAddrs[vecIdx] + ((instrIdx + 1) * 4);

						// Verify cleanup address is within the image
						if (cleanupAddr >= imageBase && cleanupAddr < imageBase + length)
						{
							if (AddFunctionForAnalysis(m_plat, cleanupAddr, false))
								seededFunctions.insert(cleanupAddr);

							const char* cleanupName = (vecIdx == 6) ? "irq_return" : "fiq_return";
							DefineAutoSymbol(new Symbol(FunctionSymbol, cleanupName, cleanupAddr, GlobalBinding));

							m_logger->LogDebug("Added %s cleanup function at 0x%llx",
								cleanupName, (unsigned long long)cleanupAddr);
						}
						break;  // Found the LDR PC, move to next handler
					}
				}
			}
		}
		catch (ReadException&)
		{
			// Ignore read errors during IRQ/FIQ cleanup scan
		}

		// Analyze MMU configuration to discover memory regions
		/*
		 * Timing helper for firmware-specific analysis passes.
		 * This only emits logs when verbose firmware logging is enabled, so we can
		 * pinpoint slow phases without spamming normal runs.
		 */
		auto timePass = [&](const char* label, auto&& fn)
		{
			if (!fwSettings.enableVerboseLogging)
			{
				fn();
				return;
			}

			auto start = std::chrono::steady_clock::now();
			fn();
			double seconds = std::chrono::duration_cast<std::chrono::duration<double>>(
				std::chrono::steady_clock::now() - start).count();
			m_logger->LogInfo("Firmware analysis timing: %s took %.3f s", label, seconds);
		};

		timePass("MMU analysis", [&]()
		{
			AnalyzeMMUConfiguration(this, reader, fileData, fileDataLen, m_endian, imageBase, length, m_logger);
		});

		if (!fwSettings.skipFirmwareScans && fwSettings.enableVerboseLogging)
		{
			m_logger->LogInfo("Firmware scans scheduled via module workflow activity");
		}

		if (!seededFunctions.empty())
			m_seededFunctions.insert(seededFunctions.begin(), seededFunctions.end());

		// NOTE: Exception handlers are named (irq_handler, fiq_handler, etc.) but we
		// don't auto-apply the irq-handler calling convention. Users can apply it
		// manually if needed. This follows the pattern of other architecture plugins.
	}

	return true;
}

void Armv5FirmwareView::RunFirmwareWorkflowScans()
{
	if (AnalysisIsAborted())
		return;
	BNAnalysisState state = GetAnalysisInfo().state;
	if (state == InitialState || state == HoldState)
		return;
	if (m_postAnalysisScansDone)
	{
		m_logger->LogInfo("Firmware workflow scan: skipped (already done)");
		return;
	}
	m_postAnalysisScansDone = true;

	if (m_parseOnly)
	{
		m_logger->LogInfo("Firmware workflow scan: skipped (parse-only view)");
		return;
	}

	if (!m_plat || !m_arch)
	{
		m_logger->LogInfo("Firmware workflow scan: skipped (missing platform/arch)");
		return;
	}
	if (AnalysisIsAborted())
	{
		m_logger->LogInfo("Firmware workflow scan: skipped (analysis aborted)");
		return;
	}

	const char* disableScans = getenv("BN_ARMV5_FIRMWARE_DISABLE_SCANS");
	if (disableScans && disableScans[0] != '\0')
		m_logger->LogInfo("Firmware workflow env override: BN_ARMV5_FIRMWARE_DISABLE_SCANS=%s", disableScans);
	const char* disableActions = getenv("BN_ARMV5_FIRMWARE_DISABLE_ACTIONS");
	if (disableActions && disableActions[0] != '\0')
		m_logger->LogInfo("Firmware workflow env override: BN_ARMV5_FIRMWARE_DISABLE_ACTIONS=%s", disableActions);

	m_logger->LogInfo("Firmware workflow scan: start");

	uint64_t length = GetLength();
	if (!length)
		return;

	/*
	 * Mirror the firmware scan settings used during Init(), but run them here
	 * as a workflow activity so we can align with Binary Ninja's analysis pipeline.
	 */
	Ref<Settings> settings = GetLoadSettings(GetTypeName());
	FirmwareSettings fwSettings = LoadFirmwareSettings(settings, this, FirmwareSettingsMode::Workflow);
	const FirmwareScanTuning& tuning = fwSettings.tuning;

	if (fwSettings.skipFirmwareScans)
	{
		m_logger->LogInfo("Firmware workflow scan skipped (skipFirmwareScans enabled)");
		return;
	}

	if (AnalysisIsAborted())
	{
		m_logger->LogInfo("Firmware workflow scan skipped (analysis aborted)");
		return;
	}

	uint64_t imageBase = GetStart();
	uint64_t bufferLen = (length < kMaxBufferedLength) ? length : kMaxBufferedLength;
	DataBuffer fileBuf = GetParentView()->ReadBuffer(0, bufferLen);
	const uint8_t* fileData = static_cast<const uint8_t*>(fileBuf.GetData());
	uint64_t fileDataLen = fileBuf.GetLength();
	if (!fileData || fileDataLen == 0)
		return;

	BinaryReader reader(GetParentView());
	reader.SetEndianness(m_endian);

	std::set<uint64_t> seededFunctions = m_seededFunctions;

	auto timePass = [&](const char* label, auto&& fn)
	{
		if (!fwSettings.enableVerboseLogging)
		{
			fn();
			return;
		}

		auto start = std::chrono::steady_clock::now();
		fn();
		double seconds = std::chrono::duration_cast<std::chrono::duration<double>>(
			std::chrono::steady_clock::now() - start).count();
		m_logger->LogInfo("Firmware workflow timing: %s took %.3f s", label, seconds);
	};

	if (fwSettings.enableLiteralPoolTyping)
	{
		FirmwareScanContext scanCtx{reader, fileData, fileDataLen, m_endian, imageBase, length,
			m_arch, m_plat, m_logger, fwSettings.enableVerboseLogging, this};
		timePass("Literal pool typing", [&]()
		{
			TypeLiteralPoolEntries(scanCtx);
		});
		if (fwSettings.enableClearAutoDataOnCodeRefs)
		{
			timePass("Clear auto data on code refs", [&]()
			{
				ClearAutoDataOnCodeReferences(scanCtx);
			});
		}
	}

	if (fwSettings.enablePrologueScan)
	{
		Ref<Architecture> thumbArch = Architecture::GetByName("armv5t");
		timePass("Function prologue scan", [&]()
		{
			ScanForFunctionPrologues(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_arch, thumbArch, m_plat, m_logger, fwSettings.enableVerboseLogging, tuning, &seededFunctions);
		});
	}

	if (fwSettings.enableClearAutoDataOnCodeRefs)
	{
		FirmwareScanContext scanCtx{reader, fileData, fileDataLen, m_endian, imageBase, length,
			m_arch, m_plat, m_logger, fwSettings.enableVerboseLogging, this};
		timePass("Clear auto data in function entry blocks", [&]()
		{
			ClearAutoDataInFunctionEntryBlocks(scanCtx, &seededFunctions);
		});
	}

	if (fwSettings.enableCallTargetScan)
	{
		timePass("Call target scan", [&]()
		{
			ScanForCallTargets(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_plat, m_logger, fwSettings.enableVerboseLogging, tuning, &seededFunctions);
		});
	}

	std::set<uint64_t> addedFunctions;
	if (fwSettings.enablePointerTargetScan)
	{
		timePass("Pointer target scan", [&]()
		{
			ScanForPointerTargets(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_plat, m_logger, fwSettings.enableVerboseLogging, tuning, &addedFunctions);
		});
	}

	if (fwSettings.enableOrphanCodeScan)
	{
		timePass("Orphan code block scan", [&]()
		{
			ScanForOrphanCodeBlocks(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_plat, m_logger, fwSettings.enableVerboseLogging, tuning, fwSettings.orphanMinValidInstr,
				fwSettings.orphanMinBodyInstr, fwSettings.orphanMinSpacingBytes, fwSettings.orphanMaxPerPage,
				fwSettings.orphanRequirePrologue, &addedFunctions);
		});
	}

	if (!addedFunctions.empty())
		seededFunctions.insert(addedFunctions.begin(), addedFunctions.end());

	if (fwSettings.enableClearAutoDataOnCodeRefs && !addedFunctions.empty())
	{
		FirmwareScanContext scanCtx{reader, fileData, fileDataLen, m_endian, imageBase, length,
			m_arch, m_plat, m_logger, fwSettings.enableVerboseLogging, this};
		timePass("Clear auto data in new function entry blocks", [&]()
		{
			ClearAutoDataInFunctionEntryBlocks(scanCtx, &addedFunctions);
		});
	}

	if (fwSettings.enableInvalidFunctionCleanup)
	{
		std::set<uint64_t> protectedStarts = seededFunctions;
		timePass("Cleanup invalid functions", [&]()
		{
			CleanupInvalidFunctions(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_logger, fwSettings.enableVerboseLogging, tuning, fwSettings.cleanupMaxSizeBytes,
				fwSettings.cleanupRequireZeroRefs, fwSettings.cleanupRequirePcWriteStart, m_entryPoint, protectedStarts);
		});
	}
	m_logger->LogInfo("Firmware workflow scan: done");
}

void BinaryNinja::RunArmv5FirmwareWorkflowScans(const Ref<BinaryView>& view)
{
	auto logger = LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareView");
	if (!view)
	{
		if (logger)
			logger->LogInfo("Firmware workflow scan: no BinaryView");
		return;
	}
	if (view->GetTypeName() != "ARMv5 Firmware")
	{
		if (logger)
			logger->LogInfo("Firmware workflow scan: wrong view type %s", view->GetTypeName().c_str());
		return;
	}
	Armv5FirmwareView* firmwareView = nullptr;
	Ref<BinaryView> viewRef;
	{
		std::lock_guard<std::mutex> lock(FirmwareViewMutex());
		auto& map = FirmwareViewMap();
		auto it = map.find(view->GetObject());
		if (it != map.end())
		{
			firmwareView = it->second;
			viewRef = firmwareView;
		}
	}
	if (!firmwareView)
	{
		if (logger)
			logger->LogInfo("Firmware workflow scan: view map lookup failed");
		return;
	}
	firmwareView->RunFirmwareWorkflowScans();
}


Armv5FirmwareViewType::Armv5FirmwareViewType(): BinaryViewType("ARMv5 Firmware", "ARMv5 Firmware")
{
	m_logger = LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareViewType");
}


Ref<BinaryView> Armv5FirmwareViewType::Create(BinaryView* data)
{
	try
	{
		return new Armv5FirmwareView(data);
	}
	catch (std::exception& e)
	{
		m_logger->LogErrorForException(
			e, "%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


Ref<BinaryView> Armv5FirmwareViewType::Parse(BinaryView* data)
{
	try
	{
		return new Armv5FirmwareView(data, true);
	}
	catch (std::exception& e)
	{
		m_logger->LogErrorForException(
			e, "%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


bool Armv5FirmwareViewType::IsTypeValidForData(BinaryView* data)
{
	// Need at least 32 bytes for vector table + some code to analyze
	if (data->GetLength() < 64)
		return false;

	DataBuffer buf = data->ReadBuffer(0, 32);
	if (buf.GetLength() < 32)
		return false;

	const uint32_t* words = (const uint32_t*)buf.GetData();

	// Step 1: Check for ARM vector table pattern
	int vectorCount = 0;
	for (int i = 0; i < 8; i++)
	{
		uint32_t instr = words[i];

		// LDR PC, [PC, #imm] - 0xE59FF0xx
		if ((instr & 0xFFFFF000) == 0xE59FF000)
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
	// This is positive detection - we check that our disassembler can decode the code
	size_t scanSize = std::min((size_t)4096, (size_t)data->GetLength());
	DataBuffer codeBuf = data->ReadBuffer(0, scanSize);
	if (codeBuf.GetLength() < scanSize)
		return false;

	const uint32_t* code = (const uint32_t*)codeBuf.GetData();
	size_t numWords = scanSize / 4;

// Build a cheap heuristic for "pointer-looking" words by learning the high byte(s)
// used in the vector pointer table (0x20-0x3F). Those entries are addresses, not instructions.
bool pointerHighByte[256] = {false};
if (numWords >= (0x40 / 4))
{
	for (size_t j = (0x20 / 4); j < (0x40 / 4) && j < numWords; j++)
	{
		uint32_t w = code[j];
		if (w == 0)
			continue;
		// Most pointers are word-aligned; use that to avoid learning noise from constants.
		if ((w & 0x3) == 0)
			pointerHighByte[(uint8_t)(w >> 24)] = true;
	}
}

	int validInstructions = 0;
	int unknownInstructions = 0;

	for (size_t i = 0; i < numWords; i++)
	{
		uint32_t instr = code[i];
		uint64_t offset = i * 4;

		// Skip the vector pointer table area (0x20-0x3F) - these are addresses, not instructions
		if (offset >= 0x20 && offset < 0x40)
			continue;

		// Skip obvious data (zeros, small constants)
		if (instr == 0 || (instr & 0xFFFF0000) == 0)
			continue;

		// Skip values that look like addresses (pointers in literal pools).
// Rather than hard-coding an address range, use the high-byte(s) we observed in the vector pointer table.
if (pointerHighByte[(uint8_t)(instr >> 24)])
	continue;

		// Try to decode with our ARMv5 disassembler (little endian)
		armv5::Instruction decoded;
		if (armv5::armv5_decompose(instr, &decoded, (uint32_t)(i * 4), 0) == 0)
		{
			// Successfully decoded as valid ARMv5
			validInstructions++;
		}
		else
		{
			// Our disassembler couldn't decode it - might be ARMv6/v7 or data
			unknownInstructions++;
		}
	}

	// Require a good ratio of valid ARMv5 instructions
	// Allow some unknowns since there's data mixed in with code
	int totalNonZero = validInstructions + unknownInstructions;
	if (totalNonZero < 10)
	{
		m_logger->LogDebug("Too few non-zero words to determine architecture");
		return false;
	}

	float validRatio = (float)validInstructions / totalNonZero;
	m_logger->LogDebug("ARMv5 detection: %d valid, %d unknown, ratio %.2f",
		validInstructions, unknownInstructions, validRatio);

	// Require at least 70% of non-data words to be valid ARMv5 instructions
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
	// even though IsTypeValidForData returns false
	return true;
}


Ref<Settings> Armv5FirmwareViewType::GetLoadSettingsForData(BinaryView* data)
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
	vector<string> overrides = {FirmwareSettingKeys::kImageBase, FirmwareSettingKeys::kPlatform};
	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}

	// Auto-detect image base from vector table if the addresses are absolute
	uint64_t detectedBase = DetectImageBaseFromVectorTable(data);
	if (detectedBase != 0 && settings->Contains(FirmwareSettingKeys::kImageBase))
	{
		settings->Set(FirmwareSettingKeys::kImageBase, detectedBase, viewRef);
		m_logger->LogInfo("Auto-detected image base: 0x%llx", (unsigned long long)detectedBase);
	}

	return settings;
}
