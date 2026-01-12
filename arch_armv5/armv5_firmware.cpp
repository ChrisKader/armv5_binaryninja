/*
 * ARMv5 Firmware BinaryViewType
 *
 * Custom BinaryViewType for bare metal ARM firmware detection.
 * Detects ARM binaries by looking for vector table patterns at offset 0.
 */

#include "armv5_firmware.h"
#include "armv5_disasm/armv5.h"
#include <set>
#include <unordered_map>
#include <mutex>
#include <map>
#include <unordered_map>
#include <cstring>
#include <chrono>

#include <cstdint>
using namespace std;
using namespace BinaryNinja;
using namespace armv5;


static inline uint32_t Swap32(uint32_t value)
{
	return ((value & 0xff000000) >> 24) |
		((value & 0x00ff0000) >> 8) |
		((value & 0x0000ff00) << 8) |
		((value & 0x000000ff) << 24);
}

static constexpr uint64_t kMaxBufferedLength = 64ULL * 1024 * 1024;

// Tuning parameters for firmware scan heuristics (content-based validation).
struct FirmwareScanTuning
{
	uint32_t minValidInstr = 2;   // Minimum consecutive valid ARM instructions
	uint32_t minBodyInstr = 1;    // Minimum valid instructions after the prologue
	uint32_t maxLiteralRun = 2;   // Max consecutive LDR literal instructions
	uint32_t minPointerRun = 3;  // Minimum consecutive pointers to treat as table (conservative by default)
	bool scanRawPointerTables = true;  // Scan raw data for pointer tables
	bool requirePointerTableCodeRefs = true;  // Require code refs into pointer tables to avoid runaway false positives
	bool allowPointerTablesInCode = false;  // Allow raw pointer tables inside code semantics
	bool requireCallInFunction = false;  // Require call targets to be inside existing functions
};

// Context for firmware analysis scans - avoids passing many parameters
struct FirmwareScanContext
{
	BinaryReader& reader;
	const uint8_t* data;
	uint64_t dataLen;
	BNEndianness endian;
	uint64_t imageBase;
	uint64_t length;
	Ref<Architecture> arch;
	Ref<Platform> plat;
	Ref<Logger> logger;
	bool verboseLog;
	BinaryView* view;

	uint64_t ImageEnd() const { return imageBase + length; }
};

static bool HasExplicitCodeSemantics(BinaryView* view)
{
	auto sections = view->GetSections();
	for (auto& section : sections)
	{
		if (section->GetSemantics() == ReadOnlyCodeSectionSemantics)
			return true;
	}
	return false;
}

static inline bool IsPaddingWord(uint32_t word)
{
	return (word == 0) || (word == 0xFFFFFFFF) || (word == 0xE1A00000);
}

// Detect PC-relative literal loads (LDR Rt, [PC, #imm]) using instruction bits.
static inline bool IsLdrLiteral(uint32_t instr)
{
	// bits[27:26]=01, bit25=0 (imm), bit20=1 (L), Rn=PC (0b1111)
	return (instr & 0x0E1F0000) == 0x041F0000;
}

static inline bool IsJumpTableDispatchInstruction(uint32_t instr)
{
	// LDR PC, [PC, #imm] (PC-relative indirect jump)
	if ((instr & 0x0F7FF000) == 0x051FF000)
		return true;

	// ADD PC, PC, Rn (computed jump used by switch tables)
	if ((instr & 0x0FFFF010) == 0x008FF000)
		return true;

	return false;
}

static bool IsPcWriteInstruction(const Instruction& instr)
{
	// Direct branches
	switch (instr.operation)
	{
	case ARMV5_B:
	case ARMV5_BL:
	case ARMV5_BLX:
	case ARMV5_BX:
		return true;
	default:
		break;
	}

	// LDR PC, [...]
	if (instr.operation == ARMV5_LDR &&
		instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
		return true;

	// POP/LDM with PC in reg list
	if (instr.operation == ARMV5_POP || instr.operation == ARMV5_LDM ||
		instr.operation == ARMV5_LDMIA || instr.operation == ARMV5_LDMIB ||
		instr.operation == ARMV5_LDMDA || instr.operation == ARMV5_LDMDB)
	{
		for (int i = 0; i < MAX_OPERANDS; i++)
		{
			if (instr.operands[i].cls == NONE)
				break;
			if (instr.operands[i].cls == REG_LIST)
			{
				if (instr.operands[i].imm & (1U << REG_PC))
					return true;
				break;
			}
		}
	}

	// Data-processing writing to PC
	switch (instr.operation)
	{
	case ARMV5_ADC:
	case ARMV5_ADCS:
	case ARMV5_ADD:
	case ARMV5_ADDS:
	case ARMV5_AND:
	case ARMV5_ANDS:
	case ARMV5_ASR:
	case ARMV5_ASRS:
	case ARMV5_BIC:
	case ARMV5_BICS:
	case ARMV5_EOR:
	case ARMV5_EORS:
	case ARMV5_LSL:
	case ARMV5_LSLS:
	case ARMV5_LSR:
	case ARMV5_LSRS:
	case ARMV5_MVN:
	case ARMV5_MVNS:
	case ARMV5_ORR:
	case ARMV5_ORRS:
	case ARMV5_ROR:
	case ARMV5_RORS:
	case ARMV5_RSB:
	case ARMV5_RSBS:
	case ARMV5_RSC:
	case ARMV5_SBC:
	case ARMV5_SBCS:
	case ARMV5_SUB:
	case ARMV5_SUBS:
	case ARMV5_MOV:
	case ARMV5_MOVS:
		if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
			return true;
		break;
	default:
		break;
	}

	return false;
}

static bool IsLikelyFunctionBoundary(const uint8_t* data, uint64_t dataLen, BNEndianness endian,
	uint64_t imageBase, uint64_t length, uint64_t addr)
{
	// Treat the start of the code region as a boundary.
	if (addr <= imageBase + 0x40)
		return true;
	if (addr < imageBase + 4)
		return true;

	uint64_t prevAddr = addr - 4;
	if (prevAddr < imageBase || prevAddr + 4 > imageBase + length)
		return false;

	uint64_t prevOff = prevAddr - imageBase;
	if (prevOff + 4 > dataLen)
		return false;

	uint32_t prevWord = 0;
	memcpy(&prevWord, data + prevOff, sizeof(prevWord));
	if (endian == BigEndian)
		prevWord = Swap32(prevWord);

	// Padding or erased data implies a boundary.
	if (IsPaddingWord(prevWord))
		return true;

	armv5::Instruction decoded;
	memset(&decoded, 0, sizeof(decoded));
	if (armv5::armv5_decompose(prevWord, &decoded, (uint32_t)prevAddr, (uint32_t)(endian == BigEndian)) != 0)
		return true;

	// Only treat unconditional PC writes as hard boundaries.
	if (UNCONDITIONAL(decoded.cond) && IsPcWriteInstruction(decoded))
		return true;

	return false;
}

static bool IsAllowedPcWriteStart(const Instruction& instr)
{
	// Allow unconditional/conditional branch thunks and BL/BLX/BX.
	switch (instr.operation)
	{
	case ARMV5_B:
	case ARMV5_BL:
	case ARMV5_BLX:
	case ARMV5_BX:
		return true;
	default:
		break;
	}

	// Allow literal veneer style: LDR PC, [PC, #imm] (no register index)
	if (instr.operation == ARMV5_LDR &&
		instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
	{
		const InstructionOperand& mem = instr.operands[1];
		if ((mem.cls == MEM_IMM || mem.cls == MEM_PRE_IDX) &&
			(mem.reg == REG_PC) && !mem.flags.offsetRegUsed)
			return true;
	}

	return false;
}

static bool ValidateFirmwareFunctionCandidate(BinaryView* view, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t imageBase, uint64_t length, uint64_t addr,
	const FirmwareScanTuning& tuning, bool requireBodyInstr, bool allowPcWriteStart)
{
	uint64_t imageEnd = imageBase + length;
	if (addr < imageBase || addr + 4 > imageEnd)
		return false;
	if (addr & 3)
		return false;

	// Avoid defining functions on typed data when available.
	DataVariable dataVar;
	if (view->GetDataVariableAtAddress(addr, dataVar) && (dataVar.address == addr))
		return false;

	// Align candidate validation with core analysis by using the architecture's
	// GetInstructionInfo callback. This applies the same IsLikelyData heuristics
	// and undefined/unpredictable filtering the core uses when accepting code.
	Ref<Architecture> arch = view->GetDefaultArchitecture();
	if (!arch)
		arch = Architecture::GetByName("armv5");
	if (!arch)
		return false;

	uint64_t offset = addr - imageBase;
	if (offset + 4 > dataLen)
		return false;

	uint32_t minValid = (tuning.minValidInstr > 0) ? tuning.minValidInstr : 1;
	uint32_t minBody = tuning.minBodyInstr;
	uint32_t window = minValid;
	if (requireBodyInstr)
	{
		uint32_t needed = 1 + minBody;
		if (needed > window)
			window = needed;
	}

	uint32_t validCount = 0;
	uint32_t bodyCount = 0;
	uint32_t literalRun = 0;
	uint32_t paddingRun = 0;

	for (uint32_t i = 0; i < window; i++)
	{
		uint64_t curOff = offset + (uint64_t)i * 4;
		if (curOff + 4 > dataLen)
			return false;

		uint32_t instr = 0;
		memcpy(&instr, data + curOff, sizeof(instr));
		if (endian == BigEndian)
			instr = Swap32(instr);

		if (i == 0 && IsPaddingWord(instr))
			return false;

		// Treat consecutive padding words as data, not code.
		if (IsPaddingWord(instr))
		{
			paddingRun++;
			if (paddingRun >= 2)
				return false;
			continue;
		}
		else
		{
			paddingRun = 0;
		}

		InstructionInfo info;
		size_t maxLen = 4;
		if (!arch->GetInstructionInfo(data + curOff, addr + i * 4, maxLen, info))
			return false;
		if (info.length != 4)
			return false;

		armv5::Instruction decoded;
		memset(&decoded, 0, sizeof(decoded));
		if (armv5::armv5_decompose(instr, &decoded, (uint32_t)(addr + i * 4), (uint32_t)(endian == BigEndian)) != 0)
			return false;

		if (i == 0 && IsPcWriteInstruction(decoded))
		{
			if (!allowPcWriteStart || !IsAllowedPcWriteStart(decoded))
				return false;
		}

		validCount++;
		if (i > 0)
			bodyCount++;

		if (IsLdrLiteral(instr))
			literalRun++;
		else
			literalRun = 0;

		if (literalRun > tuning.maxLiteralRun)
			return false;

		// Reject candidates that immediately branch/jump outside the binary image.
		// This prevents core analysis from chasing invalid targets and reading past EOF.
		if ((instr & 0x0E000000) == 0x0A000000)
		{
			int32_t imm24 = (int32_t)(instr & 0x00FFFFFF);
			if (imm24 & 0x00800000)
				imm24 |= 0xFF000000;
			int64_t target = (int64_t)(addr + (i * 4) + 8) + ((int64_t)imm24 << 2);
			if (target < (int64_t)imageBase || target >= (int64_t)(imageBase + length))
				return false;
		}

		// LDR PC, [PC, #imm] should reference a literal inside the image.
		if ((instr & 0x0F7FF000) == 0x051FF000)
		{
			uint32_t imm12 = instr & 0xFFF;
			bool add = (instr & 0x00800000) != 0;
			uint64_t litAddr = add ? (addr + (i * 4) + 8 + imm12) : (addr + (i * 4) + 8 - imm12);
			if (litAddr < imageBase || (litAddr + 4) > (imageBase + length))
				return false;
		}
	}

	if (validCount < minValid)
		return false;
	if (requireBodyInstr && (bodyCount < minBody))
		return false;

	return true;
}

static bool ReadU32At(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t offset, uint32_t& out, uint64_t length)
{
	// Prevent out-of-bounds reads against the underlying BinaryView.
	if (length != 0 && offset + 4 > length)
	{
		out = 0;
		return false;
	}
	if (data && offset + 4 <= dataLen)
	{
		memcpy(&out, data + offset, sizeof(out));
		if (endian == BigEndian)
			out = Swap32(out);
		return true;
	}
	reader.Seek(offset);
	try
	{
		out = reader.Read32();
		return true;
	}
	catch (...)
	{
		out = 0;
		return false;
	}
}

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


// Helper to auto-detect image base from vector table
// Returns detected image base, or 0 if not detectable
//
// The vector table contains absolute addresses to handlers. If we can find where
// a handler is in the file, we can calculate: imageBase = handlerAddr - fileOffset
static uint64_t DetectImageBaseFromVectorTable(BinaryView* data)
{
	uint64_t length = data->GetLength();
	if (length < 0x40)
		return 0;

	DataBuffer buf = data->ReadBuffer(0, 0x40);
	if (buf.GetLength() < 0x40)
		return 0;

	const uint32_t* words = (const uint32_t*)buf.GetData();

	// Scan all 8 vectors for LDR PC, [PC, #imm] patterns with absolute addresses.
	// Some binaries (like U-Boot) use B (branch) for reset vector but LDR PC for others.
	// We need at least one LDR PC vector with an absolute address to detect the base.
	uint64_t minHandlerAddr = UINT64_MAX;
	int ldrPcCount = 0;

	for (int i = 0; i < 8; i++)
	{
		uint32_t vecInstr = words[i];
		if ((vecInstr & 0xFFFFF000) == 0xE59FF000)
		{
			uint32_t offset = vecInstr & 0xFFF;
			uint64_t ptr = (i * 4) + 8 + offset;
			if (ptr + 4 <= length)
			{
				DataBuffer handlerBuf = data->ReadBuffer(ptr, 4);
				if (handlerBuf.GetLength() >= 4)
				{
					uint32_t addr = *(const uint32_t*)handlerBuf.GetData();
					addr &= ~1u;
					// Only consider addresses that are absolute (>= file length)
					// Skip file-relative addresses like 0x40
					if (addr >= length)
					{
						ldrPcCount++;
						if (addr < minHandlerAddr)
							minHandlerAddr = addr;
					}
				}
			}
		}
	}

	// Need at least one LDR PC vector with an absolute address
	if (ldrPcCount == 0 || minHandlerAddr == UINT64_MAX)
		return 0;

	// The minimum handler address tells us the earliest code location.
	// The image base is: handlerAddr - (file offset of that handler)
	//
	// We need to figure out where in the file the minimum handler is.
	// The minimum handler is likely the one closest to the start of the file.
	// Since all handlers should be within the file (when adjusted by base),
	// we can try different base values and find one where all handlers map
	// to valid file offsets.
	//
	// Strategy: Try common alignments (4KB, 64KB, 1MB, 16MB) and find the
	// largest alignment where all handlers map to valid file offsets.

	auto validateBase = [&](uint64_t base) -> bool {
		for (int i = 0; i < 8; i++)
		{
			uint32_t vecInstr = words[i];
			if ((vecInstr & 0xFFFFF000) == 0xE59FF000)
			{
				uint32_t offset = vecInstr & 0xFFF;
				uint64_t ptr = (i * 4) + 8 + offset;
				if (ptr + 4 <= length)
				{
					DataBuffer handlerBuf = data->ReadBuffer(ptr, 4);
					if (handlerBuf.GetLength() >= 4)
					{
						uint32_t addr = *(const uint32_t*)handlerBuf.GetData();
						addr &= ~1u;
						// Skip file-relative addresses
						if (addr < length)
							continue;
						if (addr < base)
							return false;
						uint64_t fileOffset = addr - base;
						if (fileOffset >= length)
							return false;
					}
				}
			}
		}
		return true;
	};

	// Try common alignment boundaries from largest to smallest
	// The correct base should be the one that puts all handlers within the file
	uint64_t alignments[] = { 0x1000000, 0x100000, 0x10000, 0x1000 };  // 16MB, 1MB, 64KB, 4KB

	for (uint64_t align : alignments)
	{
		uint64_t base = minHandlerAddr & ~(align - 1);
		if (validateBase(base))
			return base;
	}

	// Fallback: just use the minimum handler rounded down to 4KB
	return minHandlerAddr & ~0xFFFULL;
}


// Memory region structure for MMU analysis
struct MemRegion {
	uint64_t virtBase;
	uint64_t physBase;
	uint64_t size;
	bool readable;
	bool writable;
	bool executable;
	bool cacheable;
	bool bufferable;
	const char* type;
};

static bool LooksLikeReturnThunk(const uint8_t* data, uint64_t dataLen, BNEndianness endian,
	uint64_t imageBase, uint64_t length, uint64_t addr)
{
	if (addr < imageBase || addr + 4 > imageBase + length)
		return false;
	uint64_t offset = addr - imageBase;
	const uint32_t maxInstrs = 6;

	for (uint32_t i = 0; i < maxInstrs; i++)
	{
		uint64_t cur = offset + (uint64_t)i * 4;
		if (cur + 4 > dataLen)
			return false;
		uint32_t word = 0;
		memcpy(&word, data + cur, sizeof(word));
		if (endian == BigEndian)
			word = Swap32(word);

		if (word == 0xE1A00000 || word == 0x00000000 || word == 0xFFFFFFFF)
			continue;

		armv5::Instruction instr;
		memset(&instr, 0, sizeof(instr));
		if (armv5::armv5_decompose(word, &instr, (uint32_t)cur, 0) != 0)
			return false;

		if ((instr.cond != armv5::COND_AL) && (instr.cond != armv5::COND_NV))
			return false;

		if (instr.operation == armv5::ARMV5_BX &&
			instr.operands[0].cls == armv5::REG && instr.operands[0].reg == armv5::REG_LR)
			return true;

		if (instr.operation == armv5::ARMV5_MOV &&
			instr.operands[0].cls == armv5::REG && instr.operands[0].reg == armv5::REG_PC &&
			instr.operands[1].cls == armv5::REG && instr.operands[1].reg == armv5::REG_LR)
			return true;

		if (instr.operation == armv5::ARMV5_POP || instr.operation == armv5::ARMV5_LDM ||
			instr.operation == armv5::ARMV5_LDMIA || instr.operation == armv5::ARMV5_LDMIB ||
			instr.operation == armv5::ARMV5_LDMDA || instr.operation == armv5::ARMV5_LDMDB)
		{
			for (int op = 0; op < MAX_OPERANDS; op++)
			{
				if (instr.operands[op].cls == armv5::NONE)
					break;
				if (instr.operands[op].cls == armv5::REG_LIST &&
					(instr.operands[op].imm & (1U << armv5::REG_PC)))
					return true;
			}
		}

		return false;
	}

	return false;
}


/*
 * Scan for ARM function prologues and add them as entry points.
 *
 * This provides more accurate function detection than Binary Ninja's generic
 * linear sweep, which over-detects due to ARM's dense instruction encoding.
 *
 * Detected ARM function prologues:
 *
 * Pattern 1: STMFD/PUSH sp!, {..., lr} with 2+ registers including lr
 *   Encoding: 0xE92D4xxx where reglist includes lr
 *   Example: push {r4, lr} = 0xE92D4010
 *
 * Pattern 1b: STMFD/PUSH sp!, {r0-r3, ip, lr} with 3+ scratch registers only
 *   Encoding: 0xE92D4xxx where reglist has 3+ regs but no r4-r11
 *   Example: push {r0, r1, r2, lr} = 0xE92D4007
 *   Common for wrapper/thunk functions that save args before a call
 *
 * Pattern 2: STMFD/PUSH sp!, {rX, lr} with 2 registers
 *   Encoding: 0xE92D40xx where popcount(reglist) == 2
 *   Common for small leaf functions that only need one callee-saved register
 *
 * Pattern 3: MOV ip, sp followed by STMFD with fp and lr
 *   Encoding: 0xE1A0C00D followed by 0xE92Dxxxx with bits 11 and 14 set
 *   Classic APCS frame pointer setup prologue
 *
 * Pattern 4: STR lr, [sp, #-4]! followed by SUB sp, sp, #imm
 *   Encoding: 0xE52DE004 followed by 0xE24DD0xx
 *   Common for small leaf functions and for stack frame allocation
 *
 * Pattern 5: MRS Rx, CPSR (when preceded by a boundary instruction)
 *   Encoding: 0xE10Fx000 (MRS Rd, CPSR)
 *   Interrupt enable/disable utility functions
 *   Only detected when immediately following a return or unconditional branch
 *
 * Pattern 6: MOV/MVN Rd, #imm followed by BX LR (short return-value function)
 *   Encoding: 0xE3A0xxxx or 0xE3E0xxxx followed by 0xE12FFF1E
 *   Example: mov r0, #0 + bx lr (return 0 function)
 *   Only detected when preceded by a boundary instruction
 *
 * Pattern 7: MCR/MRC (coprocessor access) when preceded by a boundary instruction
 *   Encoding: 0xEE....10 (MCR) or 0xEE....10 (MRC)
 *   System register accessor functions (CP15, etc.)
 *   Only detected when immediately following a boundary instruction
 *
 * NOT detected (high false positive rate):
 *   - Single-instruction stack adjustments or literal loads
 *   - Thumb prologues (0xB5xx appears frequently in ARM literals)
 *
 * Returns the number of function prologues found.
 */
static size_t ScanForFunctionPrologues(BinaryView* view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	Ref<Architecture> armArch, Ref<Architecture> thumbArch, Ref<Platform> plat, Ref<Logger> logger,
	bool verboseLog, const FirmwareScanTuning& tuning, std::set<uint64_t>* seededFunctions)
{
	size_t prologuesFound = 0;
	size_t totalWords = 0;
	size_t codeWords = 0;
	size_t prologueHits = 0;
	size_t addedCount = 0;
	size_t skippedExisting = 0;
	size_t skippedNonCode = 0;
	size_t skippedInvalidCandidate = 0;

	bool enforceCodeSemantics = HasExplicitCodeSemantics(view);

	// Minimum offset to start scanning (skip vector table area)
	uint64_t startOffset = 0x40;
	uint64_t scanLen = (dataLen < length) ? dataLen : length;
	if (scanLen <= startOffset)
		return 0;

	// Track addresses we've already added to avoid duplicates
	std::set<uint64_t> addedAddrs;

	// Helper to add a function if not already added
	auto addFunction = [&](uint64_t funcAddr, bool requireBodyInstr) {
		if (addedAddrs.find(funcAddr) == addedAddrs.end())
		{
			if (!view->GetAnalysisFunctionsContainingAddress(funcAddr).empty())
			{
				skippedExisting++;
				return;
			}
			if (!ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
				funcAddr, tuning, requireBodyInstr, false))
			{
				skippedInvalidCandidate++;
				return;
			}
			if (view->AddFunctionForAnalysis(plat, funcAddr, true))
			{
				if (seededFunctions)
					seededFunctions->insert(funcAddr);
				addedCount++;
			}
			addedAddrs.insert(funcAddr);
			prologuesFound++;
		}
	};

	logger->LogInfo("Prologue scan: Scanning for function prologues in %llu bytes",
		(unsigned long long)(length - startOffset));

	// Track the previous instruction for boundary-based patterns
	uint32_t prevInstr = 0;
	uint32_t prevPrevInstr = 0;

	// Scan for ARM prologues (4-byte aligned)
	for (uint64_t offset = startOffset; offset + 4 <= scanLen; offset += 4)
	{
		totalWords++;
		uint64_t instrAddr = imageBase + offset;
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(instrAddr))
		{
			skippedNonCode++;
			prevPrevInstr = 0;
			prevInstr = 0;
			continue;
		}
		codeWords++;

		uint32_t instr = 0;
		if (offset + 4 <= dataLen)
		{
			memcpy(&instr, data + offset, sizeof(instr));
			if (endian == BigEndian)
				instr = Swap32(instr);
		}

		bool isPrologue = false;
		bool requireBodyInstr = true;

		auto isReturnInstr = [](uint32_t ins) -> bool {
			// BX Rn = 0xE12FFF1x (BX LR = 0xE12FFF1E)
			if ((ins & 0x0FFFFFF0) == 0x012FFF10)
				return true;
			// MOV PC, LR = 0xE1A0F00E
			if (ins == 0xE1A0F00E)
				return true;
			// LDMFD sp!, {..., pc} = 0xE8BD8xxx (POP with pc)
			if ((ins & 0xFFFF0000) == 0xE8BD0000 && (ins & 0x8000))
				return true;
			// LDMFD Rn!, {..., pc} = 0xE8B.8xxx (more general POP with pc)
			if ((ins & 0x0FFF0000) == 0x08B00000 && (ins & 0x8000))
				return true;
			return false;
		};

		auto isBoundaryInstr = [&](uint32_t ins) -> bool {
			if (isReturnInstr(ins))
				return true;
			// Unconditional B = 0xEAxxxxxx
			if ((ins & 0xFF000000) == 0xEA000000)
				return true;
			return false;
		};

		auto isValidArmInstruction = [&](uint32_t ins, uint64_t addr) -> bool {
			armv5::Instruction decoded;
			memset(&decoded, 0, sizeof(decoded));
			return armv5::armv5_decompose(ins, &decoded, (uint32_t)addr, 0) == 0;
		};

		auto readWordAt = [&](uint64_t wordOffset, uint32_t& outWord) -> bool {
			if (wordOffset + 4 > dataLen)
				return false;
			memcpy(&outWord, data + wordOffset, sizeof(outWord));
			if (endian == BigEndian)
				outWord = Swap32(outWord);
			return true;
		};

		auto boundaryBefore = [&](uint64_t currOffset) -> bool {
			if (currOffset == startOffset)
				return true;
			int checked = 0;
			uint64_t off = currOffset;
			while (off >= 4 && checked < 8)
			{
				uint32_t w = 0;
				if (!readWordAt(off - 4, w))
					return false;
				if (IsPaddingWord(w))
				{
					off -= 4;
					checked++;
					continue;
				}
				return isBoundaryInstr(w);
			}
			return false;
		};

		auto hasReturnSoon = [&](uint64_t currOffset) -> bool {
			for (int i = 1; i <= 4; i++)
			{
				uint64_t off = currOffset + (uint64_t)i * 4;
				uint32_t w = 0;
				if (!readWordAt(off, w))
					return false;
				if (!isValidArmInstruction(w, off))
					return false;
				if (isReturnInstr(w))
					return true;
			}
			return false;
		};

		bool prevIsBoundary = boundaryBefore(offset);

		// Pattern 1: STMFD/STMDB/PUSH sp!, {..., lr} with 2+ registers
		// Encoding: cond 100 P U S W L Rn reglist
		// STMFD sp! = 1001 0010 1101 xxxx = 0xE92Dxxxx
		// Must have LR (bit 14) in register list
		if ((instr & 0xFFFF0000) == 0xE92D0000 && (instr & 0x4000) != 0)
		{
			uint32_t reglist = instr & 0xFFFF;
			int regCount = __builtin_popcount(reglist);
			if (regCount >= 2 && prevIsBoundary)
				isPrologue = true;
		}

		// Pattern 3: MOV ip, sp followed by STMFD with fp and lr
		// This is the classic APCS prologue
		// Very reliable as the two-instruction sequence is unlikely to appear in data
		if (instr == 0xE1A0C00D && prevIsBoundary)
		{
			if (offset + 8 <= dataLen)
			{
				uint32_t nextInstr = 0;
				memcpy(&nextInstr, data + offset + 4, sizeof(nextInstr));
				if (endian == BigEndian)
					nextInstr = Swap32(nextInstr);

				// STMDB sp!, {..., fp, ..., lr} = 0xE92D0800 | 0x4000
				if ((nextInstr & 0xFFFF0000) == 0xE92D0000 &&
					(nextInstr & 0x4800) == 0x4800)  // both fp (bit 11) and lr (bit 14)
					isPrologue = true;
			}
		}

		// Pattern 4: STR lr, [sp, #-4]! followed by SUB sp, sp, #imm
		// Encoding: 0xE52DE004 followed by 0xE24DD0xx
		if (instr == 0xE52DE004 && prevIsBoundary)
		{
			if (offset + 8 <= dataLen)
			{
				uint32_t nextInstr = 0;
				memcpy(&nextInstr, data + offset + 4, sizeof(nextInstr));
				if (endian == BigEndian)
					nextInstr = Swap32(nextInstr);

				if ((nextInstr & 0xFFFFF000) == 0xE24DD000)
					isPrologue = true;
			}
		}

		// Pattern 5: MRS Rx, CPSR when preceded by a return instruction
		// These are small interrupt enable/disable utility functions
		// Encoding: cond 0001 0 R 00 1111 Rd 0000 0000 0000
		// MRS Rd, CPSR = 0xE10F0000 | (Rd << 12)
		// Mask: 0x0FBF0FFF (ignore condition and Rd)
		if ((instr & 0x0FBF0FFF) == 0x010F0000)
		{
			if (prevIsBoundary && hasReturnSoon(offset))
			{
				isPrologue = true;
				requireBodyInstr = false;
			}
		}

		// Pattern 6: MOV/MVN Rd, #imm followed by BX LR (short return-value function)
		// These are small functions that just return a constant value
		// Very reliable as we verify both the MOV/MVN and the following BX LR
		// Only detected when preceded by a return (function boundary)
		if ((instr & 0x0FE00000) == 0x03A00000 || (instr & 0x0FE00000) == 0x03E00000)
		{
			if (prevIsBoundary && offset + 8 <= dataLen)
			{
				// Check if followed by BX LR
				uint32_t nextInstr = 0;
				memcpy(&nextInstr, data + offset + 4, sizeof(nextInstr));
				if (endian == BigEndian)
					nextInstr = Swap32(nextInstr);

				// BX LR = 0xE12FFF1E (or conditional)
				if ((nextInstr & 0x0FFFFFFF) == 0x012FFF1E)
				{
					isPrologue = true;
					requireBodyInstr = false;
				}
			}
		}

		// Pattern 7: MCR/MRC (coprocessor access) when preceded by a return
		// These are small system register accessor functions
		// MCR: cond 1110 opc1 0 CRn Rt coproc opc2 1 CRm
		// MRC: cond 1110 opc1 1 CRn Rt coproc opc2 1 CRm
		// Mask: check for 0xEE......1. pattern
		if ((instr & 0x0F000010) == 0x0E000010)
		{
			if (prevIsBoundary && hasReturnSoon(offset))
			{
				isPrologue = true;
				requireBodyInstr = false;
			}
		}

		if (isPrologue)
		{
			prologueHits++;
			addFunction(imageBase + offset, requireBodyInstr);
		}

		// Remember this instruction for next iteration
		prevPrevInstr = prevInstr;
		prevInstr = instr;
	}

	// NOTE: Thumb prologue scanning is disabled for now.
	// The TI-Nspire firmware is primarily ARM code, and scanning for Thumb
	// prologues creates many false positives because:
	// 1. 0xB5xx patterns appear frequently in ARM data/literals
	// 2. Without proper mode switching analysis, we can't reliably identify
	//    which regions are actually Thumb code
	//
	// Thumb functions will still be discovered via BX/BLX calls from ARM code
	// that set the Thumb bit in the target address.

	logger->LogInfo("Prologue scan: Found %zu function prologues", prologuesFound);
	if (verboseLog)
	{
		logger->LogInfo(
			"Prologue scan detail: scanned=%zu code=%zu prologue_hits=%zu added=%zu skipped_existing=%zu "
			"skipped_noncode=%zu skipped_invalid_candidate=%zu",
			totalWords, codeWords, prologueHits, addedCount, skippedExisting, skippedNonCode,
			skippedInvalidCandidate);
	}
	return prologuesFound;
}


/*
 * Scan for BL, BLX, and LDR PC call targets to discover additional functions.
 *
 * This complements prologue scanning by finding functions that are called
 * but might not have recognizable prologues (e.g., hand-written assembly,
 * optimized leaf functions, Thumb code).
 * To reduce false positives, only callsites within discovered functions
 * are considered.
 *
 * Detected patterns:
 *
 * Pattern 1: BL imm (ARM branch-and-link)
 *   Encoding: cond 1011 imm24
 *   Example: BL 0x1000 = 0xEBxxxxxx
 *   The 24-bit signed offset is shifted left 2 and added to PC+8
 *
 * Pattern 2: BLX imm (ARM to Thumb call)
 *   Encoding: 1111 101 H imm24
 *   Example: BLX 0x1001 = 0xFAxxxxxx or 0xFBxxxxxx
 *   Target has Thumb bit set (bit 0 = 1)
 *
 * Pattern 3: LDR PC, [PC, #imm] (indirect jump via literal pool)
 *   Encoding: cond 0101 1001 1111 Rd imm12
 *   Example: LDR PC, [PC, #0x10] = 0xE59FFxxx
 *   Loads a function address from a nearby literal pool entry
 *
 * Returns the number of call targets found.
 */
static size_t ScanForCallTargets(BinaryView* view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	Ref<Platform> plat, Ref<Logger> logger, bool verboseLog, const FirmwareScanTuning& tuning,
	std::set<uint64_t>* seededFunctions)
{
	size_t targetsFound = 0;
	uint64_t scanLen = (dataLen < length) ? dataLen : length;
	size_t totalInstrs = 0;
	size_t codeInstrs = 0;
	size_t inFunctionInstrs = 0;
	size_t nonFunctionInstrs = 0;
	size_t skippedNonCode = 0;
	size_t skippedNotInFunction = 0;
	size_t skippedPrevNotCode = 0;
	size_t blMatches = 0;
	size_t ldrMatches = 0;
	size_t addedCount = 0;
	size_t skipLdrPcInFunction = 0;
	size_t skipBlIntraFunction = 0;
	size_t skipBlNonFuncBoundary = 0;
	size_t skipMisaligned = 0;
	size_t skipOutOfBounds = 0;
	size_t skipNonCodeTarget = 0;
	size_t skipNonBoundary = 0;
	size_t skipExistingTarget = 0;
	size_t skipReturnThunk = 0;
	size_t skipInvalidTarget = 0;
	size_t skipDuplicate = 0;
	size_t skipInvalidCandidate = 0;

	// Track addresses we've already added to avoid duplicates
	std::set<uint64_t> addedAddrs;
	bool enforceCodeSemantics = HasExplicitCodeSemantics(view);

	// Helper to add a function if not already added and target is valid
	auto addFunction = [&](uint64_t funcAddr, const char* source, bool requireBoundary) {
		// For ARM mode, addresses must be 4-byte aligned.
		// Strip any Thumb bit and reject misaligned addresses.
		uint64_t alignedAddr = funcAddr & ~3ULL;
		if (funcAddr & 3)
		{
			skipMisaligned++;
			return;
		}

		// Must be within image bounds
		if (alignedAddr < imageBase || alignedAddr >= imageBase + length)
		{
			skipOutOfBounds++;
			return;
		}

		// Only add functions in code semantics (standard BN behavior)
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(alignedAddr))
		{
			skipNonCodeTarget++;
			return;
		}

		// Reject targets that are not at a likely function boundary.
		if (requireBoundary && !IsLikelyFunctionBoundary(data, dataLen, endian, imageBase, length, alignedAddr))
		{
			skipNonBoundary++;
			return;
		}

		if (!view->GetAnalysisFunctionsContainingAddress(alignedAddr).empty())
		{
			skipExistingTarget++;
			return;
		}

		if (LooksLikeReturnThunk(data, dataLen, endian, imageBase, length, alignedAddr))
		{
			skipReturnThunk++;
			return;
		}

		// Validate target looks like valid ARM code
		uint64_t offset = alignedAddr - imageBase;
		if (offset + 4 <= dataLen)
		{
			uint32_t targetInstr = 0;
			memcpy(&targetInstr, data + offset, sizeof(targetInstr));
			if (endian == BigEndian)
				targetInstr = Swap32(targetInstr);

			// Skip if target is all zeros (BSS/uninitialized data)
			if (targetInstr == 0)
			{
				skipInvalidTarget++;
				return;
			}

			// Skip if target is all 0xFF (erased flash)
			if (targetInstr == 0xFFFFFFFF)
			{
				skipInvalidTarget++;
				return;
			}

			// In ARMv5, condition code 0b1111 (0xFxxxxxxx) is mostly undefined
			// except for a few specific encodings. Most valid ARM code uses
			// condition codes 0x0-0xE. Skip obvious non-code.
			uint32_t cond = (targetInstr >> 28) & 0xF;
			if (cond == 0xF)
			{
				// Only a few 0xF instructions are valid in ARMv5:
				// - BLX imm (0xFAxxxxxx, 0xFBxxxxxx)
				// - PLD (0xF55FF000 pattern)
				// Most other 0xFxxxxxxx patterns are undefined
				uint32_t op = (targetInstr >> 24) & 0xFF;
				if (op != 0xFA && op != 0xFB)
				{
					skipInvalidTarget++;
					return;  // Likely data, not code
				}
			}

			// Additional heuristic: very unlikely instruction patterns
			// ANDEQ r0, r0, r0 with random high bits often indicates data
			if ((targetInstr & 0x0FFFFFFF) == 0x00000000 && cond != 0xE)
			{
				skipInvalidTarget++;
				return;
			}
		}

		// Call-targets should start with real code, not a PC-write stub. Requiring
		// a body instruction and disallowing PC-write starts avoids seeding functions
		// that the core later merges or deletes as mid-function labels.
		if (!ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
			alignedAddr, tuning, true, false))
		{
			skipInvalidCandidate++;
			return;
		}

		if (addedAddrs.find(alignedAddr) == addedAddrs.end())
		{
			if (view->AddFunctionForAnalysis(plat, alignedAddr, true))
			{
				if (seededFunctions)
					seededFunctions->insert(alignedAddr);
				addedCount++;
			}
			addedAddrs.insert(alignedAddr);
			targetsFound++;
		}
		else
		{
			skipDuplicate++;
		}
	};

	// Helper to check if an instruction looks like valid ARM code
	// Returns true if the instruction has a valid condition code and
	// doesn't match common literal pool patterns
	auto isLikelyCode = [&](uint32_t instr) -> bool {
		uint32_t cond = (instr >> 28) & 0xF;

		// Condition 0xF is mostly undefined in ARMv5
		if (cond == 0xF)
		{
			uint32_t op = (instr >> 24) & 0xFF;
			if (op != 0xFA && op != 0xFB)  // Only BLX is valid
				return false;
		}

		// All zeros or all ones is data
		if (instr == 0 || instr == 0xFFFFFFFF)
			return false;

		// Check for address-like patterns (literal pool entries)
		uint32_t highByte = (instr >> 24) & 0xFF;
		if ((highByte == 0x10 || highByte == 0x11 || highByte == 0x12 ||
		     highByte == 0x13 || highByte == 0xA4) && (instr & 0x3) == 0)
			return false;  // Likely an aligned address

		return true;
	};

	// Track previous instruction for context checking
	uint32_t prevInstr = 0;

	// Skip vector table and pointer table regions
	uint64_t startOffset = 0x40;

	// Scan for ARM call instructions (4-byte aligned)
	for (uint64_t offset = startOffset; offset + 4 <= scanLen; offset += 4)
	{
		totalInstrs++;
		uint32_t instr = 0;
		if (offset + 4 <= dataLen)
		{
			memcpy(&instr, data + offset, sizeof(instr));
			if (endian == BigEndian)
				instr = Swap32(instr);
		}

		uint64_t instrAddr = imageBase + offset;
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(instrAddr))
		{
			skippedNonCode++;
			prevInstr = 0;
			continue;
		}
		codeInstrs++;
		auto callsiteFuncs = view->GetAnalysisFunctionsContainingAddress(instrAddr);
		bool inFunction = !callsiteFuncs.empty();
		if (!inFunction)
		{
			nonFunctionInstrs++;
			if (tuning.requireCallInFunction)
			{
				skippedNotInFunction++;
				prevInstr = 0;
				continue;
			}
		}
		else
		{
			inFunctionInstrs++;
		}

		// Pattern 1: BL imm (ARM branch-and-link)
		// Encoding: cond 1011 imm24 where cond != 1111
		// Mask: 0x0F000000, value: 0x0B000000
		if ((instr & 0x0F000000) == 0x0B000000 && (instr & 0xF0000000) != 0xF0000000)
		{
			// Only trust BL if the previous instruction also looks like code
			// This filters out BL-like patterns in literal pools
			if (offset >= 4 && isLikelyCode(prevInstr))
			{
				blMatches++;
				// Extract 24-bit signed offset, shift left 2, add to PC+8
				int32_t imm24 = instr & 0x00FFFFFF;
				// Sign-extend from 24 bits
				if (imm24 & 0x00800000)
					imm24 |= 0xFF000000;
				int32_t offset_bytes = imm24 << 2;
				uint64_t target = instrAddr + 8 + offset_bytes;
				uint64_t alignedTarget = target & ~3ULL;

				// If the BL is inside a function and the target is also inside that
				// same function, it's almost certainly an internal label (PIC, thunk).
				if (inFunction)
				{
					auto targetFuncs = view->GetAnalysisFunctionsContainingAddress(alignedTarget);
					bool intraFunction = false;
					for (const auto& cf : callsiteFuncs)
					{
						if (!cf)
							continue;
						for (const auto& tf : targetFuncs)
						{
							if (tf && (tf->GetStart() == cf->GetStart()))
							{
								intraFunction = true;
								break;
							}
						}
						if (intraFunction)
							break;
					}
					if (intraFunction)
					{
						skipBlIntraFunction++;
						prevInstr = instr;
						continue;
					}
				}
				// BL targets are likely real function starts.
				addFunction(target, "BL", false);
			}
			else
			{
				skippedPrevNotCode++;
			}
		}

		// Pattern 2: BLX imm (ARM to Thumb call)
		// Encoding: 1111 101 H imm24
		// H bit (bit 24) adds 2 to the offset for Thumb alignment
		// NOTE: For ARMv5 firmware with no Thumb code, we skip BLX entirely
		// since it shouldn't exist in pure ARM binaries
		// if ((instr & 0xFE000000) == 0xFA000000) { ... }

		// Pattern 3: LDR PC, [PC, #imm] (indirect jump via literal pool)
		// Encoding: cond 0101 U001 1111 1111 imm12
		// U bit (bit 23) indicates add/subtract
		// Example: LDR PC, [PC, #0x10] = 0xE59FF010
		if ((instr & 0x0F7FF000) == 0x051FF000)
		{
			// LDR PC is commonly used for jump tables inside functions; those
			// targets are *not* function entry points. Only treat LDR PC as a
			// potential function target when the dispatch itself is outside any
			// existing function (e.g., a veneer in standalone code).
			if (!view->GetAnalysisFunctionsContainingAddress(instrAddr).empty())
			{
				skipLdrPcInFunction++;
				prevInstr = instr;
				continue;
			}

			// Only trust LDR PC if preceded by valid code
			if (offset >= 4 && isLikelyCode(prevInstr))
			{
				ldrMatches++;
				uint32_t imm12 = instr & 0xFFF;
				bool add = (instr & 0x00800000) != 0;
				// PC reads as instrAddr + 8 in ARM mode
				uint64_t litPoolAddr = add ? (instrAddr + 8 + imm12) : (instrAddr + 8 - imm12);

				// Read the literal pool entry
				if (litPoolAddr >= imageBase && litPoolAddr + 4 <= imageBase + length)
				{
					uint64_t litPoolOffset = litPoolAddr - imageBase;
					if (litPoolOffset + 4 <= dataLen)
					{
						uint32_t target = 0;
						memcpy(&target, data + litPoolOffset, sizeof(target));
						if (endian == BigEndian)
							target = Swap32(target);

						// Add as function (preserving Thumb bit if present)
						// Indirect branches are common for jump tables; require a boundary.
						addFunction(target, "LDR PC", true);
					}
				}
			}
			else
			{
				skippedPrevNotCode++;
			}
		}

		// Remember this instruction for next iteration
		prevInstr = instr;
	}

	logger->LogInfo("Call target scan: Found %zu call targets", targetsFound);
	if (verboseLog)
	{
		logger->LogInfo(
			"Call target scan detail: scanned=%zu code=%zu in_func=%zu non_func=%zu bl=%zu ldr_pc=%zu added=%zu "
			"skip_noncode=%zu skip_not_in_func=%zu skip_prev_not_code=%zu skip_misaligned=%zu "
			"skip_oob=%zu skip_noncode_target=%zu skip_non_boundary=%zu skip_existing=%zu skip_return_thunk=%zu skip_ldr_pc_in_func=%zu "
			"skip_bl_intra_func=%zu skip_bl_nonfunc_boundary=%zu "
			"skip_invalid_target=%zu skip_duplicate=%zu skip_invalid_candidate=%zu",
			totalInstrs, codeInstrs, inFunctionInstrs, nonFunctionInstrs, blMatches, ldrMatches, addedCount,
			skippedNonCode, skippedNotInFunction, skippedPrevNotCode, skipMisaligned,
			skipOutOfBounds, skipNonCodeTarget, skipNonBoundary, skipExistingTarget, skipReturnThunk, skipLdrPcInFunction,
			skipBlIntraFunction, skipBlNonFuncBoundary,
			skipInvalidTarget, skipDuplicate, skipInvalidCandidate);
	}
	return targetsFound;
}

/*
 * Scan for 32-bit pointers that reference executable code and add them as functions.
 *
 * This discovers entry points referenced via data tables. To reduce false
 * positives, only data variables that are referenced from code are considered.
 *
 * Returns the number of pointer targets found.
 */
static size_t ScanForPointerTargets(BinaryView* view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	Ref<Platform> plat, Ref<Logger> logger, bool verboseLog, const FirmwareScanTuning& tuning,
	std::set<uint64_t>* seededFunctions)
{
	size_t targetsFound = 0;
	std::set<uint64_t> addedAddrs;
	size_t dataVarCount = 0;
	size_t withCodeRefs = 0;
	size_t pointerTyped = 0;
	size_t addedCount = 0;
	size_t skipNonCodeTarget = 0;
	size_t skipOutOfBounds = 0;
	size_t skipMisaligned = 0;
	size_t skipExistingTarget = 0;
	size_t skipReturnThunk = 0;
	size_t skipInvalidTarget = 0;
	size_t skipNotPointerType = 0;
	size_t skipInvalidCandidate = 0;
	size_t skipJumpTableRefs = 0;
	size_t skipNonBoundary = 0;
	size_t rawWordScanned = 0;
	size_t rawRunsFound = 0;
	size_t rawRunsWithRefs = 0;
	size_t rawRunsNoRefs = 0;
	size_t rawRunsAllowedNoRefs = 0;
	size_t rawAddedCount = 0;
	size_t rawSkipInFunction = 0;
	size_t rawSkipInvalidTarget = 0;
	size_t rawSkipJumpTableRefs = 0;

	uint64_t imageEnd = imageBase + length;
	uint8_t minHigh = (uint8_t)(imageBase >> 24);
	uint8_t maxHigh = (uint8_t)((imageEnd - 1) >> 24);
	bool enforceCodeSemantics = HasExplicitCodeSemantics(view);

	auto addFunction = [&](uint64_t funcAddr) {
		uint64_t alignedAddr = funcAddr & ~3ULL;
		if (funcAddr & 3)
		{
			skipMisaligned++;
			return;
		}
		if (alignedAddr < imageBase || alignedAddr >= imageEnd)
		{
			skipOutOfBounds++;
			return;
		}
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(alignedAddr))
		{
			skipNonCodeTarget++;
			return;
		}
		if (!IsLikelyFunctionBoundary(data, dataLen, endian, imageBase, length, alignedAddr))
		{
			skipNonBoundary++;
			return;
		}
		if (!view->GetAnalysisFunctionsContainingAddress(alignedAddr).empty())
		{
			skipExistingTarget++;
			return;
		}
		if (LooksLikeReturnThunk(data, dataLen, endian, imageBase, length, alignedAddr))
		{
			skipReturnThunk++;
			return;
		}
		// Pointer targets should also look like real function entries; avoid
		// PC-write stubs and require a body instruction to reduce false starts.
		if (!ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
			alignedAddr, tuning, true, false))
		{
			skipInvalidCandidate++;
			return;
		}
		if (addedAddrs.find(alignedAddr) != addedAddrs.end())
			return;
		if (view->AddFunctionForAnalysis(plat, alignedAddr, true))
		{
			if (seededFunctions)
				seededFunctions->insert(alignedAddr);
			addedCount++;
		}
		addedAddrs.insert(alignedAddr);
		targetsFound++;
	};

	auto isValidTarget = [&](uint64_t targetAddr, bool countInvalid) -> bool {
		if (targetAddr < imageBase || targetAddr + 4 > imageEnd)
			return false;
		uint64_t targetOffset = targetAddr - imageBase;
		if (targetOffset + 4 > dataLen)
			return false;
		uint32_t targetInstr = 0;
		memcpy(&targetInstr, data + targetOffset, sizeof(targetInstr));
		if (endian == BigEndian)
			targetInstr = Swap32(targetInstr);
		if (targetInstr == 0 || targetInstr == 0xFFFFFFFF)
		{
			if (countInvalid)
				skipInvalidTarget++;
			return false;
		}
		uint32_t cond = (targetInstr >> 28) & 0xF;
		if (cond == 0xF)
		{
			uint32_t op = (targetInstr >> 24) & 0xFF;
			if (op != 0xFA && op != 0xFB)
			{
				if (countInvalid)
					skipInvalidTarget++;
				return false;
			}
		}
		armv5::Instruction decoded;
		memset(&decoded, 0, sizeof(decoded));
		if (armv5::armv5_decompose(targetInstr, &decoded, (uint32_t)targetOffset, 0) != 0)
		{
			if (countInvalid)
				skipInvalidTarget++;
			return false;
		}
		return true;
	};

	auto readInstrAt = [&](uint64_t addr, uint32_t& outInstr) -> bool {
		if (addr < imageBase || addr + 4 > imageEnd)
			return false;
		uint64_t off = addr - imageBase;
		if (off + 4 > dataLen)
			return false;
		memcpy(&outInstr, data + off, sizeof(outInstr));
		if (endian == BigEndian)
			outInstr = Swap32(outInstr);
		return true;
	};

	auto hasOnlyJumpTableRefs = [&](uint64_t addr) -> bool {
		auto refs = view->GetCodeReferences(addr);
		if (refs.empty())
			return false;
		for (const auto& ref : refs)
		{
			uint32_t instr = 0;
			if (!readInstrAt(ref.addr, instr))
				return false;
			if (!IsJumpTableDispatchInstruction(instr))
				return false;
		}
		return true;
	};

	// Only consider data variables that are referenced from code.
	auto dataVars = view->GetDataVariables();
	for (const auto& entry : dataVars)
	{
		dataVarCount++;
		uint64_t locationAddr = entry.first;
		const DataVariable& dataVar = entry.second;
		if (locationAddr < imageBase + 0x40)
			continue;
		if (locationAddr + 4 > imageEnd)
			continue;
		if (enforceCodeSemantics && view->IsOffsetCodeSemantics(locationAddr))
			continue;

		if (view->GetCodeReferences(locationAddr).empty())
			continue;

		// If all code refs are jump-table dispatches, these pointers are case labels,
		// not function entry points. Skip to avoid adding mid-function functions.
		if (hasOnlyJumpTableRefs(locationAddr))
		{
			skipJumpTableRefs++;
			continue;
		}
		withCodeRefs++;
		if (dataVar.type.GetValue())
		{
			Ref<Type> varType = dataVar.type.GetValue();
			if (varType && varType->GetClass() != PointerTypeClass)
			{
				if (varType->GetClass() != ArrayTypeClass)
				{
					skipNotPointerType++;
					continue;
				}
				Ref<Type> elemType = varType->GetChildType().GetValue();
				if (!elemType || elemType->GetClass() != PointerTypeClass)
				{
					skipNotPointerType++;
					continue;
				}
			}
		}
		pointerTyped++;

		uint64_t offset = locationAddr - imageBase;
		if (offset + 4 > dataLen)
			continue;

		uint32_t value = 0;
		memcpy(&value, data + offset, sizeof(value));
		if (endian == BigEndian)
			value = Swap32(value);
		if (value == 0 || value == 0xFFFFFFFF)
			continue;
		if ((value & 3) != 0)
			continue;
		if (value < imageBase || value >= imageEnd)
			continue;
		uint8_t high = (uint8_t)(value >> 24);
		if (high < minHigh || high > maxHigh)
			continue;

		if (isValidTarget(value, true))
			addFunction(value);
	}

	// Scan raw words for pointer tables to fill gaps when core pointer sweep is disabled.
	// Heuristics: require a consecutive run of valid pointers *and* at least one code reference into
	// the table so we don't treat random code bytes as pointer arrays.
	if (tuning.scanRawPointerTables && tuning.minPointerRun > 0)
	{
		const uint64_t scanStart = 0x40;
		uint32_t runLen = 0;
		uint64_t runStartOffset = 0;

		auto finalizeRun = [&](uint64_t startOffset, uint32_t count)
		{
			if (count < tuning.minPointerRun)
				return;
			rawRunsFound++;

			uint64_t tableAddr = imageBase + startOffset;
			bool hasCodeRefs = false;
			bool hasNonJumpRef = false;
			for (uint32_t i = 0; i < count; i++)
			{
				uint64_t addr = imageBase + startOffset + (uint64_t)i * 4;
				if (!view->GetCodeReferences(addr).empty())
				{
					hasCodeRefs = true;
					if (!hasOnlyJumpTableRefs(addr))
						hasNonJumpRef = true;
					if (hasNonJumpRef)
						break;
				}
			}

		if (!hasCodeRefs)
		{
			rawRunsNoRefs++;
			if (tuning.requirePointerTableCodeRefs)
				return;
			if (view->IsOffsetCodeSemantics(tableAddr) && !tuning.allowPointerTablesInCode)
				return;
			rawRunsAllowedNoRefs++;
		}
		else
		{
			if (!hasNonJumpRef)
			{
				rawSkipJumpTableRefs++;
				return;
			}
			rawRunsWithRefs++;
		}

			// Define the pointer table as data if it doesn't already exist.
			DataVariable existing;
			if (!view->GetDataVariableAtAddress(tableAddr, existing))
			{
				Ref<Type> ptrType = Type::PointerType(view->GetDefaultArchitecture(), Type::VoidType());
				Ref<Type> tableType = Type::ArrayType(ptrType, count);
				view->DefineDataVariable(tableAddr, tableType);
			}

			for (uint32_t i = 0; i < count; i++)
			{
				uint64_t addr = imageBase + startOffset + (uint64_t)i * 4;
				uint64_t offset = startOffset + (uint64_t)i * 4;
				if (offset + 4 > dataLen)
					break;

				uint32_t value = 0;
				memcpy(&value, data + offset, sizeof(value));
				if (endian == BigEndian)
					value = Swap32(value);

				if (value == 0 || value == 0xFFFFFFFF)
					continue;
				if ((value & 3) != 0)
					continue;
				if (!isValidTarget(value, false))
				{
					rawSkipInvalidTarget++;
					continue;
				}

				size_t prevAdded = addedCount;
				addFunction(value);
				if (addedCount > prevAdded)
					rawAddedCount++;
			}
		};

		for (uint64_t offset = scanStart; offset + 4 <= dataLen; offset += 4)
		{
			rawWordScanned++;
			uint64_t addr = imageBase + offset;
			if (!view->GetAnalysisFunctionsContainingAddress(addr).empty())
			{
				rawSkipInFunction++;
				if (runLen > 0)
				{
					finalizeRun(runStartOffset, runLen);
					runLen = 0;
				}
				continue;
			}

			uint32_t value = 0;
			memcpy(&value, data + offset, sizeof(value));
			if (endian == BigEndian)
				value = Swap32(value);

			if (value == 0 || value == 0xFFFFFFFF || (value & 3) != 0 ||
				value < imageBase || value >= imageEnd)
			{
				if (runLen > 0)
				{
					finalizeRun(runStartOffset, runLen);
					runLen = 0;
				}
				continue;
			}

			uint8_t high = (uint8_t)(value >> 24);
			if (high < minHigh || high > maxHigh)
			{
				if (runLen > 0)
				{
					finalizeRun(runStartOffset, runLen);
					runLen = 0;
				}
				continue;
			}

			if (!isValidTarget(value, false))
			{
				if (runLen > 0)
				{
					finalizeRun(runStartOffset, runLen);
					runLen = 0;
				}
				continue;
			}

			if (runLen == 0)
				runStartOffset = offset;
			runLen++;
		}

		if (runLen > 0)
			finalizeRun(runStartOffset, runLen);
	}

	logger->LogInfo("Pointer target scan: Found %zu pointer targets", targetsFound);
	if (verboseLog)
	{
		logger->LogInfo(
			"Pointer target scan detail: data_vars=%zu code_ref_vars=%zu pointer_typed=%zu added=%zu "
			"skip_not_pointer_type=%zu skip_misaligned=%zu skip_oob=%zu skip_noncode_target=%zu "
			"skip_non_boundary=%zu skip_existing=%zu skip_return_thunk=%zu skip_invalid_target=%zu skip_invalid_candidate=%zu "
			"skip_jump_table_refs=%zu raw_words=%zu raw_runs=%zu raw_runs_with_refs=%zu raw_runs_no_refs=%zu "
			"raw_runs_allowed_no_refs=%zu raw_added=%zu raw_skip_in_func=%zu raw_skip_invalid_target=%zu "
			"raw_skip_jump_table_refs=%zu",
			dataVarCount, withCodeRefs, pointerTyped, addedCount,
			skipNotPointerType, skipMisaligned, skipOutOfBounds, skipNonCodeTarget,
			skipNonBoundary, skipExistingTarget, skipReturnThunk, skipInvalidTarget, skipInvalidCandidate, skipJumpTableRefs,
			rawWordScanned, rawRunsFound, rawRunsWithRefs, rawRunsNoRefs, rawRunsAllowedNoRefs, rawAddedCount,
			rawSkipInFunction, rawSkipInvalidTarget, rawSkipJumpTableRefs);
	}
	return targetsFound;
}

/*
 * Scan for orphaned code blocks post-analysis.
 *
 * After core analysis completes, find basic blocks that are not yet part of
 * any function. These represent undiscovered functions that weren't captured by
 * explicit calls or prologue patterns. This is a post-analysis sweep that fills
 * gaps left by the CFG-based discovery process.
 *
 * Returns the number of orphan functions found and added.
 */
static size_t ScanForOrphanCodeBlocks(BinaryView* view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	Ref<Platform> plat, Ref<Logger> logger, bool verboseLog, const FirmwareScanTuning& tuning,
	uint32_t minValidInstr, uint32_t minBodyInstr, uint32_t minSpacingBytes, uint32_t maxPerPage,
	bool requirePrologue,
	std::set<uint64_t>* seededFunctions)
{
	size_t orphansFound = 0;
	size_t blocksScanned = 0;
	size_t orphanCandidates = 0;
	size_t addedCount = 0;
	size_t skipExisting = 0;
	size_t skipInvalidCandidate = 0;
	size_t skipProtected = 0;
	size_t skipNonBoundaryOrPrologue = 0;
	size_t skipSpacing = 0;
	size_t skipPageCap = 0;
	size_t skipPaddingRun = 0;
	size_t skipNoPrologue = 0;

	std::set<uint64_t> addedAddrs;
	bool enforceCodeSemantics = HasExplicitCodeSemantics(view);
	uint64_t lastAddedAddr = 0;
	std::unordered_map<uint64_t, uint32_t> pageCounts;

	auto isStrongPrologue = [&](uint32_t instr) -> bool {
		uint32_t cond = (instr >> 28) & 0xF;
		if (cond != 0xE)
			return false;
		if ((instr & 0xFFFF0000) != 0xE92D0000)
			return false;
		uint32_t reglist = instr & 0xFFFF;
		if (!(reglist & (1U << REG_LR)))
			return false;
		return __builtin_popcount(reglist) >= 3;
	};
	auto isWeakPrologue = [&](uint32_t instr) -> bool {
		uint32_t cond = (instr >> 28) & 0xF;
		if (cond != 0xE)
			return false;
		// STMDB/STMFD sp!, {..., lr}
		if ((instr & 0xFFFF0000) == 0xE92D0000)
		{
			uint32_t reglist = instr & 0xFFFF;
			return (reglist & (1U << REG_LR)) != 0;
		}
		// SUB sp, sp, #imm (stack allocation)
		if ((instr & 0xFFFFF000) == 0xE24DD000)
			return true;
		return false;
	};

	auto addFunction = [&](uint64_t funcAddr) {
		uint64_t alignedAddr = funcAddr & ~3ULL;
		if (alignedAddr < imageBase || alignedAddr >= imageBase + length)
			return;
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(alignedAddr))
			return;
		if (!view->GetAnalysisFunctionsContainingAddress(alignedAddr).empty())
		{
			skipExisting++;
			return;
		}
		// Protect seeded functions from being removed later
		if (seededFunctions && seededFunctions->find(alignedAddr) != seededFunctions->end())
		{
			skipProtected++;
			return;
		}
		FirmwareScanTuning orphanTuning = tuning;
		orphanTuning.minValidInstr = minValidInstr;
		orphanTuning.minBodyInstr = minBodyInstr;
		// Validate that the orphan block looks like real code
		if (!ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
			alignedAddr, orphanTuning, true, false))
		{
			skipInvalidCandidate++;
			return;
		}
		if (addedAddrs.find(alignedAddr) != addedAddrs.end())
			return;
		if (view->AddFunctionForAnalysis(plat, alignedAddr, true))
		{
			if (seededFunctions)
				seededFunctions->insert(alignedAddr);
			addedCount++;
			lastAddedAddr = alignedAddr;
			pageCounts[alignedAddr & ~0xFFFULL]++;
		}
		addedAddrs.insert(alignedAddr);
		orphansFound++;
	};

	// Collect all basic blocks from the view
	auto allFuncs = view->GetAnalysisFunctionList();
	std::set<uint64_t> coveredRanges;

	// Build a set of all addresses covered by existing functions
	for (const auto& func : allFuncs)
	{
		if (!func)
			continue;
		uint64_t funcStart = func->GetStart();
		uint64_t funcEnd = func->GetHighestAddress();
		// Mark entire function range as covered
		for (uint64_t addr = funcStart; addr <= funcEnd; addr += 4)
		{
			coveredRanges.insert(addr);
		}
	}

	// Scan for orphaned 4-byte aligned code in code semantics regions
	logger->LogInfo("Orphan code scan: Scanning for unreachable functions in %llu bytes",
		(unsigned long long)(length));

	for (uint64_t offset = 0; offset + 4 <= length; offset += 4)
	{
		uint64_t instrAddr = imageBase + offset;

		// Skip if already covered by a function
		if (coveredRanges.find(instrAddr) != coveredRanges.end())
			continue;

		// Skip if not in code semantics
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(instrAddr))
			continue;

		blocksScanned++;

		// Enforce spacing between added functions to avoid runaway growth.
		if (lastAddedAddr && (instrAddr - lastAddedAddr) < minSpacingBytes)
		{
			skipSpacing++;
			continue;
		}

		// Per-page cap to avoid flooding a single 4KB region with functions.
		uint64_t page = instrAddr & ~0xFFFULL;
		if (maxPerPage > 0)
		{
			auto it = pageCounts.find(page);
			if (it != pageCounts.end() && it->second >= maxPerPage)
			{
				skipPageCap++;
				continue;
			}
		}

		// Candidate if it looks like a boundary or a prologue.
		bool isBoundary = IsLikelyFunctionBoundary(data, dataLen, endian, imageBase, length, instrAddr);
		bool isPrologue = false;

		// Quick filter: reject regions dominated by padding/erased words.
		// This avoids ballooning candidate counts on zero-filled data.
		uint32_t paddingCount = 0;
		const uint32_t padWindow = 3;
		if (offset + (uint64_t)padWindow * 4 <= dataLen)
		{
			for (uint32_t i = 0; i < padWindow; i++)
			{
				uint32_t word = 0;
				memcpy(&word, data + offset + (uint64_t)i * 4, sizeof(word));
				if (endian == BigEndian)
					word = Swap32(word);
				if (IsPaddingWord(word))
					paddingCount++;
			}
		}
		if (paddingCount >= 2)
		{
			skipPaddingRun++;
			continue;
		}

		// Strong prologue pattern (STMFD/PUSH sp!, {..., lr} with 3+ regs)
		if (offset + 4 <= dataLen)
		{
			uint32_t instr = 0;
			memcpy(&instr, data + offset, sizeof(instr));
			if (endian == BigEndian)
				instr = Swap32(instr);
			isPrologue = isWeakPrologue(instr) || isStrongPrologue(instr);
		}

		if (requirePrologue && !isPrologue)
		{
			skipNoPrologue++;
			continue;
		}

		if (!requirePrologue && !isBoundary && !isPrologue)
		{
			skipNonBoundaryOrPrologue++;
			continue;
		}
		orphanCandidates++;
		addFunction(instrAddr);
	}

	logger->LogInfo("Orphan code scan: Found %zu orphaned functions", orphansFound);
	if (verboseLog)
	{
		logger->LogInfo(
			"Orphan code scan detail: scanned=%zu candidates=%zu added=%zu "
			"skip_existing=%zu skip_invalid_candidate=%zu skip_protected=%zu "
			"skip_non_boundary_or_prologue=%zu skip_spacing=%zu skip_page_cap=%zu "
			"skip_padding_run=%zu skip_no_prologue=%zu",
			blocksScanned, orphanCandidates, addedCount,
			skipExisting, skipInvalidCandidate, skipProtected,
			skipNonBoundaryOrPrologue, skipSpacing, skipPageCap,
			skipPaddingRun, skipNoPrologue);
	}
	return orphansFound;
}

static size_t CleanupInvalidFunctions(BinaryView* view, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t imageBase, uint64_t length, Ref<Logger> logger, bool verboseLog,
	const FirmwareScanTuning& tuning, uint32_t maxSizeBytes, bool requireZeroRefs,
	bool requirePcWriteStart, uint64_t entryPoint, const std::set<uint64_t>& protectedStarts)
{
	size_t scanned = 0;
	size_t candidates = 0;
	size_t removed = 0;
	size_t skipUser = 0;
	size_t skipTooLarge = 0;
	size_t skipHasRefs = 0;
	size_t skipProtected = 0;
	size_t skipNonPcWrite = 0;
	size_t skipValid = 0;
	size_t skipNoData = 0;

	FirmwareScanTuning cleanupTuning = tuning;
	cleanupTuning.minValidInstr = 1;
	cleanupTuning.minBodyInstr = 0;

	std::vector<Ref<Function>> toRemove;
	auto funcs = view->GetAnalysisFunctionList();
	for (const auto& func : funcs)
	{
		scanned++;
		if (!func || !func->WasAutomaticallyDiscovered())
		{
			skipUser++;
			continue;
		}

		Ref<Symbol> sym = func->GetSymbol();
		if (sym && !sym->IsAutoDefined())
		{
			skipUser++;
			continue;
		}

		uint64_t start = func->GetStart();
		if (start < imageBase || start >= imageBase + length)
			continue;
		if (start == entryPoint || protectedStarts.find(start) != protectedStarts.end())
		{
			skipProtected++;
			continue;
		}

		uint64_t sizeBytes = 0;
		Ref<Architecture> arch = func->GetArchitecture();
		if (arch)
			sizeBytes = func->GetHighestAddress() - start + arch->GetDefaultIntegerSize();
		if (maxSizeBytes > 0 && sizeBytes > maxSizeBytes)
		{
			skipTooLarge++;
			continue;
		}

		if (requireZeroRefs && !view->GetCodeReferences(start).empty())
		{
			skipHasRefs++;
			continue;
		}

		uint64_t offset = start - imageBase;
		if (offset + 4 > dataLen)
		{
			skipNoData++;
			continue;
		}

		uint32_t firstWord = 0;
		memcpy(&firstWord, data + offset, sizeof(firstWord));
		if (endian == BigEndian)
			firstWord = Swap32(firstWord);

		armv5::Instruction decoded;
		memset(&decoded, 0, sizeof(decoded));
		bool decodeOk = (armv5::armv5_decompose(firstWord, &decoded, (uint32_t)start,
			(uint32_t)(endian == BigEndian)) == 0);

		bool pcWrite = decodeOk ? IsPcWriteInstruction(decoded) : false;
		if (requirePcWriteStart && !pcWrite && decodeOk)
		{
			skipNonPcWrite++;
			continue;
		}

		candidates++;
		if (ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
			start, cleanupTuning, false, true))
		{
			skipValid++;
			continue;
		}

		toRemove.push_back(func);
	}

	for (const auto& func : toRemove)
	{
		view->RemoveAnalysisFunction(func, true);
		removed++;
	}

	logger->LogInfo("Cleanup invalid functions: removed=%zu candidates=%zu scanned=%zu",
		removed, candidates, scanned);
	if (verboseLog)
	{
		logger->LogInfo(
			"Cleanup invalid detail: skip_user=%zu skip_protected=%zu skip_too_large=%zu "
			"skip_has_refs=%zu skip_non_pc_write=%zu skip_valid=%zu skip_no_data=%zu",
			skipUser, skipProtected, skipTooLarge, skipHasRefs,
			skipNonPcWrite, skipValid, skipNoData);
	}

	return removed;
}


// Structure to hold discovered config array info
struct MMUConfigArray {
	uint64_t startAddr;    // Start address of array
	uint64_t endAddr;      // End address of array
	bool isIdentity;       // true = 4-byte identity entries, false = 8-byte VA->PA entries
	uint64_t litPoolAddr1; // Address of start pointer in literal pool
	uint64_t litPoolAddr2; // Address of end pointer in literal pool
};

// Structure to hold ROM-to-SRAM copy info for reading initialized data
struct RomToSramCopy {
	uint64_t romSrc;       // Source address in ROM
	uint64_t sramDst;      // Destination address in SRAM
	uint64_t sramEnd;      // End of SRAM destination region
	bool valid;            // Whether a valid copy was found
};

// Find ROM-to-SRAM copy operation that initializes config arrays
// Looks for pattern: ldrlo rx, [ry], #4 / strlo rx, [rz], #4 (copy loop)
// Returns info about the copy or {.valid = false} if not found
static RomToSramCopy FindRomToSramCopy(BinaryReader& reader, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t length, uint64_t aliasBase, Ref<Logger> logger)
{
	RomToSramCopy result = {0, 0, 0, false};

	if (aliasBase == 0)
		return result;

	// Scan for the characteristic LDRLO/STRLO copy loop pattern
	// ARM encoding for LDRLO Rx, [Ry], #4 (post-indexed, unsigned immediate):
	//   cond=0011 (LO/CC) 01 I=0 P=0 U=1 B=0 W=0 L=1 Rn Rd imm12=4
	//   Example: LDRLO r3, [r0], #4 = 0x34903004
	//   Mask 0x0FF00FFF (ignore cond, Rn, Rd), value 0x04900004
	// ARM encoding for STRLO:
	//   cond=0011 01 I=0 P=0 U=1 B=0 W=0 L=0 Rn Rd imm12=4
	//   Example: STRLO r3, [r1], #4 = 0x34813004
	//   Mask 0x0FF00FFF, value 0x04800004

	for (uint64_t offset = 0; offset + 8 <= length; offset += 4)
	{
		uint32_t instr1 = 0, instr2 = 0;
		ReadU32At(reader, data, dataLen, endian, offset, instr1, length);
		ReadU32At(reader, data, dataLen, endian, offset + 4, instr2, length);

		// Check for LDRLO followed by STRLO (or vice versa)
		bool isLdrLo1 = (instr1 & 0x0FF00FFF) == 0x04900004 && (instr1 & 0xF0000000) == 0x30000000;
		bool isStrLo1 = (instr1 & 0x0FF00FFF) == 0x04800004 && (instr1 & 0xF0000000) == 0x30000000;
		bool isLdrLo2 = (instr2 & 0x0FF00FFF) == 0x04900004 && (instr2 & 0xF0000000) == 0x30000000;
		bool isStrLo2 = (instr2 & 0x0FF00FFF) == 0x04800004 && (instr2 & 0xF0000000) == 0x30000000;

		if ((isLdrLo1 && isStrLo2) || (isStrLo1 && isLdrLo2))
		{
			logger->LogInfo("MMU: Found copy loop at file offset 0x%llx (LDRLO/STRLO pattern)",
				(unsigned long long)offset);

			// Scan backwards to find literal pool loads that set up the copy
			// We're looking for LDR instructions that load:
			// 1. ROM source address (small value within file)
			// 2. SRAM destination address (matches alias base)
			// 3. SRAM end address (matches alias base)

			std::vector<std::pair<uint64_t, uint32_t>> literalRefs;

			// Scan up to 64 instructions back
			for (int i = 1; i <= 64 && offset >= (uint64_t)(i * 4); i++)
			{
				uint32_t prevInstr = 0;
				ReadU32At(reader, data, dataLen, endian, offset - (i * 4), prevInstr, length);

				// LDR Rd, [PC, #imm]: 0x051F0000 (sub) or 0x059F0000 (add)
				if ((prevInstr & 0x0F7F0000) == 0x051F0000)
				{
					uint32_t imm12 = prevInstr & 0xFFF;
					bool add = (prevInstr & 0x00800000) != 0;
					uint64_t pcVal = (offset - (i * 4)) + 8;
					uint64_t litAddr = add ? (pcVal + imm12) : (pcVal - imm12);

					if (litAddr + 4 <= length)
					{
						uint32_t value = 0;
						ReadU32At(reader, data, dataLen, endian, litAddr, value, length);
						literalRefs.push_back({litAddr, value});
					}
				}
			}

			// Categorize the literal values
			// The copy pattern typically loads: ROM source, SRAM start, SRAM end
			// in consecutive literal pool entries. We look for the ROM address
			// and then the SRAM addresses that are loaded closest to it.
			uint64_t romSrc = 0;
			uint64_t romSrcLitAddr = 0;
			std::vector<std::pair<uint64_t, uint64_t>> sramAddrsWithLitAddr;  // (sram_addr, lit_pool_addr)

			for (const auto& ref : literalRefs)
			{
				uint64_t litAddr = ref.first;
				uint32_t val = ref.second;

				// ROM address: within file bounds, but not too small
				if (val < length && val > 0x1000)
				{
					romSrc = val;
					romSrcLitAddr = litAddr;
				}
				// SRAM address: matches our alias base
				else if ((val & 0xFF000000) == aliasBase)
				{
					sramAddrsWithLitAddr.push_back({val, litAddr});
				}
			}

			if (romSrc != 0 && sramAddrsWithLitAddr.size() >= 2)
			{
				// Find the SRAM addresses that are in consecutive literal pool entries
				// closest to the ROM source (they form: ROM, SRAM_start, SRAM_end)
				// The literal pool entries may be loaded in any order, so we check both directions
				uint64_t sramDst = 0, sramEnd = 0;

				for (size_t i = 0; i + 1 < sramAddrsWithLitAddr.size(); i++)
				{
					uint64_t addr1 = sramAddrsWithLitAddr[i].first;
					uint64_t lit1 = sramAddrsWithLitAddr[i].second;
					uint64_t addr2 = sramAddrsWithLitAddr[i + 1].first;
					uint64_t lit2 = sramAddrsWithLitAddr[i + 1].second;

					// Check if these are consecutive literal pool entries (either direction)
					int64_t litDiff = (int64_t)lit2 - (int64_t)lit1;
					if (litDiff != 4 && litDiff != -4)
						continue;

					// Determine which is start (smaller addr) and which is end (larger addr)
					uint64_t startAddr = (addr1 < addr2) ? addr1 : addr2;
					uint64_t endAddr = (addr1 < addr2) ? addr2 : addr1;
					uint64_t size = endAddr - startAddr;

					// Check for reasonable copy size (256 bytes to 64KB)
					if (size >= 0x100 && size <= 0x10000)
					{
						// Use this pair
						sramDst = startAddr;
						sramEnd = endAddr;
						break;  // Found a valid pair, stop searching
					}
				}

				if (sramDst != 0 && sramEnd != 0)
				{
					result.romSrc = romSrc;
					result.sramDst = sramDst;
					result.sramEnd = sramEnd;
					result.valid = true;

					logger->LogInfo("MMU: ROM-to-SRAM copy found:");
					logger->LogInfo("MMU:   ROM source:  0x%08llx", (unsigned long long)romSrc);
					logger->LogInfo("MMU:   SRAM dest:   0x%08llx - 0x%08llx",
						(unsigned long long)sramDst, (unsigned long long)sramEnd);
					logger->LogInfo("MMU:   Size:        %llu bytes", (unsigned long long)(sramEnd - sramDst));

					return result;
				}
			}
		}
	}

	return result;
}

// Read u32, using ROM copy data for SRAM addresses if available
static bool ReadU32Smart(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t addr, uint64_t aliasBase, uint64_t length,
	const RomToSramCopy& romCopy, uint32_t& out)
{
	// Check if this is an SRAM address that falls within the ROM copy range
	if (romCopy.valid && aliasBase != 0 &&
		(addr & 0xFF000000) == aliasBase &&
		addr >= romCopy.sramDst && addr < romCopy.sramEnd)
	{
		// Calculate the corresponding ROM address
		uint64_t offsetInSram = addr - romCopy.sramDst;
		uint64_t romAddr = romCopy.romSrc + offsetInSram;

		// Read from ROM instead
		return ReadU32At(reader, data, dataLen, endian, romAddr, out, length);
	}

	// For addresses within the file, read directly
	// Handle aliased addresses by stripping the high byte
	uint64_t readAddr = addr;
	if (aliasBase != 0 && (addr & 0xFF000000) == aliasBase)
	{
		readAddr = addr & 0x00FFFFFF;
	}

	return ReadU32At(reader, data, dataLen, endian, readAddr, out, length);
}

// Analyze MMU configuration to discover memory regions
// Looks for MCR p15, 0, Rx, c2, c0, 0 (write to TTBR) and parses the translation table
// When translation table is uninitialized, discovers config arrays through static analysis
static void AnalyzeMMUConfiguration(BinaryView* view, BinaryReader& reader, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length, Ref<Logger> logger)
{
	uint64_t ttbrValue = 0;
	uint64_t ttbrInstrAddr = 0;
	uint64_t mmuSetupFuncStart = 0;

	// Scan for MCR p15, 0, Rx, c2, c0, 0 instruction
	// Encoding: cond 1110 opc1[3] 0 CRn[4] Rt[4] coproc[4] opc2[3] 1 CRm[4]
	// MCR p15, 0, Rx, c2, c0, 0: 1110 1110 0000 0010 xxxx 1111 0001 0000
	// Mask: 0x0FFF0FFF, expect: 0x0E020F10
	logger->LogInfo("MMU: Scanning for TTBR write in %llu bytes", (unsigned long long)length);

	for (uint64_t offset = 0; offset + 4 <= length; offset += 4)
	{
		uint32_t instr = 0;
		ReadU32At(reader, data, dataLen, endian, offset, instr, length);

		// MCR p15, 0, Rx, c2, c0, 0 - write TTBR0
		if ((instr & 0x0FFF0FFF) == 0x0E020F10)
		{
			uint32_t rt = (instr >> 12) & 0xF;
			ttbrInstrAddr = imageBase + offset;
			logger->LogInfo("MMU: Found MCR p15, c2 at 0x%llx (file offset 0x%llx), Rt=r%u",
				(unsigned long long)ttbrInstrAddr, (unsigned long long)offset, rt);

			// Try to trace back to find the value loaded into Rt
			// Also look for function prologue to identify the MMU setup function boundaries
			// Look for LDR Rt, [PC, #imm] or MOV Rt, #imm patterns
			// Search up to 128 instructions back (covers typical MMU setup functions)
			for (int i = 1; i <= 128 && offset >= (uint64_t)(i * 4); i++)
			{
				uint32_t prevInstr = 0;
				ReadU32At(reader, data, dataLen, endian, offset - (i * 4), prevInstr, length);

				// Check for function prologue (STMFD sp!, {..., lr})
				// This helps us identify the start of the MMU setup function
				if ((prevInstr & 0xFFFF0000) == 0xE92D0000 && (prevInstr & 0x4000) != 0)
				{
					if (mmuSetupFuncStart == 0)
					{
						mmuSetupFuncStart = offset - (i * 4);
						logger->LogInfo("MMU: Found MMU setup function prologue at file offset 0x%llx",
							(unsigned long long)mmuSetupFuncStart);
					}
				}

				// LDR Rt, [PC, #imm] - check for both add and sub variants
				// Encoding: cond 01 I P U 0 W 1 Rn Rd imm12
				// LDR Rd, [PC, #imm]: xxxx 0101 U001 1111 Rd imm12
				if ((prevInstr & 0x0F7F0000) == 0x051F0000 &&
				    ((prevInstr >> 12) & 0xF) == rt)
				{
					uint32_t imm12 = prevInstr & 0xFFF;
					bool add = (prevInstr & 0x00800000) != 0;
					uint64_t pcValue = (offset - (i * 4)) + 8;
					uint64_t literalAddr = add ? (pcValue + imm12) : (pcValue - imm12);

					logger->LogInfo("MMU:   Found LDR r%u, [PC, #%s0x%x] -> literal at file offset 0x%llx (length=0x%llx)",
						rt, add ? "" : "-", imm12, (unsigned long long)literalAddr, (unsigned long long)length);

					if (literalAddr < length)
					{
						uint32_t value = 0;
						ReadU32At(reader, data, dataLen, endian, literalAddr, value, length);
						ttbrValue = value;
						logger->LogInfo("MMU: TTBR value loaded: 0x%llx from literal at 0x%llx",
							(unsigned long long)ttbrValue, (unsigned long long)literalAddr);
					}
					else
					{
						logger->LogWarn("MMU: Literal offset 0x%llx is outside file bounds (0x%llx)",
							(unsigned long long)literalAddr, (unsigned long long)length);
					}
					break;
				}

				// MOV Rt, #imm (for simple cases)
				if ((prevInstr & 0x0FEF0000) == 0x03A00000 &&
				    ((prevInstr >> 12) & 0xF) == rt)
				{
					uint32_t imm8 = prevInstr & 0xFF;
					uint32_t rotate = (prevInstr >> 8) & 0xF;
					ttbrValue = (imm8 >> (rotate * 2)) | (imm8 << (32 - rotate * 2));
					logger->LogInfo("Found TTBR write at 0x%llx, TTBR value: 0x%llx (from MOV)",
						(unsigned long long)ttbrInstrAddr, (unsigned long long)ttbrValue);
					break;
				}
			}

			// If we didn't find a value, don't give up - there might be another MCR p15, c2
			if (ttbrValue != 0)
				break;
			else
				logger->LogInfo("MMU: Could not trace TTBR value for MCR at 0x%llx, continuing scan",
					(unsigned long long)offset);
		}
	}

	// Parse the translation table if we found TTBR
	if (ttbrValue == 0)
	{
		logger->LogInfo("MMU: No TTBR write found or could not trace value, skipping MMU analysis");
		return;
	}

	// TTBR points to a 16KB aligned table with 4096 entries (one per 1MB section)
	uint64_t ttbrBase = ttbrValue & ~0x3FFFULL;  // 16KB alignment

	// Check if translation table is within our file
	// Handle physical address alias patterns dynamically:
	// - If TTBR has high bits set but low bits point within our file, it's an alias
	// - We discover the alias base from the TTBR value itself (e.g., 0xA4xxxxxx -> 0xA4000000)
	uint64_t ttbrFileOffset = 0;
	bool ttbrInFile = false;
	uint64_t ttbrVirtBase = ttbrBase;  // Virtual address for symbols
	uint64_t discoveredAliasBase = 0;  // Discovered physical address alias base (if any)

	if (ttbrBase >= imageBase && ttbrBase < imageBase + length)
	{
		ttbrFileOffset = ttbrBase - imageBase;
		ttbrInFile = true;
	}
	else
	{
		// Check if TTBR is a physical address alias
		// Pattern: TTBR has high bits set, but low 24 bits are within file
		// This handles various aliasing schemes (0xA4xxxxxx, 0x80xxxxxx, etc.)
		uint64_t ttbrLowBits = ttbrBase & 0x00FFFFFF;
		uint64_t ttbrHighBits = ttbrBase & 0xFF000000;

		if (ttbrHighBits != 0 && ttbrLowBits < length)
		{
			uint64_t aliasedAddr = imageBase + ttbrLowBits;
			logger->LogInfo("MMU: TTBR 0x%llx appears to be physical alias of 0x%llx",
				(unsigned long long)ttbrBase, (unsigned long long)aliasedAddr);

			ttbrFileOffset = ttbrLowBits;
			ttbrInFile = true;
			ttbrVirtBase = aliasedAddr;  // Use virtual address for symbols
			discoveredAliasBase = ttbrHighBits;  // Remember the alias base for later use

			logger->LogInfo("MMU: Discovered physical alias base: 0x%llx",
				(unsigned long long)discoveredAliasBase);
		}
	}

	if (!ttbrInFile || ttbrFileOffset + 0x4000 > length)
	{
		logger->LogInfo("MMU: Translation table at 0x%llx is not in file, skipping MMU parsing",
			(unsigned long long)ttbrBase);
		logger->LogInfo("MMU: Image range: 0x%llx-0x%llx, TTBR: 0x%llx",
			(unsigned long long)imageBase, (unsigned long long)(imageBase + length),
			(unsigned long long)ttbrBase);
		return;
	}

	logger->LogInfo("MMU: Parsing translation table at 0x%llx (file offset 0x%llx, virt addr 0x%llx)",
		(unsigned long long)ttbrBase, (unsigned long long)ttbrFileOffset,
		(unsigned long long)ttbrVirtBase);

	// Define the translation table as data
	Ref<Type> ttEntryType = Type::IntegerType(4, false);
	Ref<Type> ttArrayType = Type::ArrayType(ttEntryType, 4096);
	view->DefineDataVariable(ttbrVirtBase, ttArrayType);
	view->DefineAutoSymbol(new Symbol(DataSymbol, "mmu_translation_table", ttbrVirtBase, GlobalBinding));

	// Parse section descriptors and create memory regions
	// ARM section descriptor format (bits):
	// [31:20] Section base address
	// [19]    NS (Non-Secure)
	// [18]    0
	// [17]    nG (not Global)
	// [16]    S (Shareable)
	// [15]    APX (Access Permission extension)
	// [14:12] TEX (Type Extension)
	// [11:10] AP (Access Permission)
	// [9]     Implementation defined
	// [8:5]   Domain
	// [4]     XN (Execute Never)
	// [3]     C (Cacheable)
	// [2]     B (Bufferable)
	// [1:0]   Descriptor type: 00=fault, 01=coarse page table, 10=section, 11=reserved

	vector<MemRegion> regions;
	MemRegion currentRegion = {0, 0, 0, false, false, false, false, false, nullptr};

	for (uint32_t i = 0; i < 4096; i++)
	{
		uint32_t descriptor = 0;
		ReadU32At(reader, data, dataLen, endian, ttbrFileOffset + (i * 4), descriptor, length);

		uint64_t virtAddr = (uint64_t)i << 20;  // Each entry covers 1MB
		uint32_t descType = descriptor & 0x3;

		bool isValid = false;
		uint64_t physAddr = 0;
		bool readable = false, writable = false, executable = true;
		bool cacheable = false, bufferable = false;
		const char* regionType = "unknown";

		if (descType == 0x2)  // Section descriptor
		{
			isValid = true;
			physAddr = descriptor & 0xFFF00000;
			uint32_t ap = (descriptor >> 10) & 0x3;
			uint32_t apx = (descriptor >> 15) & 0x1;
			cacheable = (descriptor >> 3) & 0x1;
			bufferable = (descriptor >> 2) & 0x1;
			executable = !((descriptor >> 4) & 0x1);  // XN bit

			// Decode AP bits (simplified)
			// AP[2:0] = APX:AP[1:0]
			uint32_t fullAP = (apx << 2) | ap;
			readable = (fullAP != 0);  // Any non-zero AP allows some read
			writable = (ap == 0x3 || (ap == 0x1 && apx == 0));  // Full access

			if (cacheable && bufferable)
				regionType = "RAM (write-back)";
			else if (cacheable)
				regionType = "RAM (write-through)";
			else if (!cacheable && !bufferable)
				regionType = "MMIO/Device";
			else
				regionType = "RAM (uncached)";
		}
		else if (descType == 0x1)  // Coarse page table (we don't parse these yet)
		{
			// Could be parsed for finer-grained mappings
			regionType = "page table";
		}

		// Merge adjacent regions with same attributes
		if (isValid)
		{
			if (currentRegion.size > 0 &&
			    currentRegion.virtBase + currentRegion.size == virtAddr &&
			    currentRegion.physBase + currentRegion.size == physAddr &&
			    currentRegion.cacheable == cacheable &&
			    currentRegion.bufferable == bufferable &&
			    currentRegion.readable == readable &&
			    currentRegion.writable == writable &&
			    currentRegion.executable == executable)
			{
				// Extend current region
				currentRegion.size += 0x100000;
			}
			else
			{
				// Save current region and start new one
				if (currentRegion.size > 0)
					regions.push_back(currentRegion);

				currentRegion = {virtAddr, physAddr, 0x100000,
					readable, writable, executable, cacheable, bufferable, regionType};
			}
		}
		else if (currentRegion.size > 0)
		{
			// End of valid region
			regions.push_back(currentRegion);
			currentRegion = {0, 0, 0, false, false, false, false, false, nullptr};
		}
	}

	// Don't forget the last region
	if (currentRegion.size > 0)
		regions.push_back(currentRegion);

	if (regions.empty())
	{
		logger->LogInfo("MMU: Translation table is uninitialized (all fault entries)");
		logger->LogInfo("MMU: Discovering config arrays from MMU setup code...");

		// The translation table is empty - it gets populated at runtime from config arrays.
		// We need to find these arrays by analyzing the MMU setup function.
		//
		// Pattern: The function loads pairs of pointers (array start, array end) from
		// the literal pool, then loops through the entries to populate the translation table.
		//
		// Array types:
		// - Identity arrays (4-byte entries): VA only, PA = VA
		// - VA->PA arrays (8-byte entries): VA and PTE descriptor
		//
		// We detect the array type by examining the first entry.

		// Find ROM-to-SRAM copy operation for reading initialized config array data
		// The config arrays are stored in SRAM addresses but the binary contains ROM data
		// that gets copied to SRAM at boot. We need to read from the ROM source.
		RomToSramCopy romCopy = FindRomToSramCopy(reader, data, dataLen, endian, length,
			discoveredAliasBase, logger);

		// Collect all literal pool references in the MMU setup function area
		// Structure: {literalPoolAddr, value}
		std::vector<std::pair<uint64_t, uint32_t>> literalRefs;

		// Scan a reasonable range around the TTBR instruction
		// Use mmuSetupFuncStart if found, otherwise scan from TTBR-512 to TTBR+256
		uint64_t ttbrFileOffset = ttbrInstrAddr - imageBase;
		uint64_t scanStart = (mmuSetupFuncStart != 0) ? mmuSetupFuncStart :
			((ttbrFileOffset > 512) ? (ttbrFileOffset - 512) : 0);
		uint64_t scanEnd = (ttbrFileOffset + 512 < length) ? (ttbrFileOffset + 512) : length;

		logger->LogInfo("MMU: Scanning for literal pool refs from 0x%llx to 0x%llx",
			(unsigned long long)scanStart, (unsigned long long)scanEnd);

		for (uint64_t off = scanStart; off + 4 <= scanEnd; off += 4)
		{
			uint32_t instr = 0;
			ReadU32At(reader, data, dataLen, endian, off, instr, length);

			// LDR Rd, [PC, #imm]: collect literal pool references
			if ((instr & 0x0F7F0000) == 0x051F0000)
			{
				uint32_t imm12 = instr & 0xFFF;
				bool add = (instr & 0x00800000) != 0;
				uint64_t pcVal = off + 8;
				uint64_t litAddr = add ? (pcVal + imm12) : (pcVal - imm12);

				if (litAddr + 4 <= length)
				{
					uint32_t value = 0;
					ReadU32At(reader, data, dataLen, endian, litAddr, value, length);
					literalRefs.push_back({litAddr, value});
				}
			}
		}

		logger->LogInfo("MMU: Found %zu literal pool references", literalRefs.size());

		// Find config arrays: look for pairs of consecutive literal pool entries
		// where the values look like array bounds (addr1 < addr2, reasonable size)
		std::vector<MMUConfigArray> configArrays;

		for (size_t i = 0; i + 1 < literalRefs.size(); i++)
		{
			uint64_t litAddr1 = literalRefs[i].first;
			uint64_t litAddr2 = literalRefs[i + 1].first;
			uint32_t val1 = literalRefs[i].second;
			uint32_t val2 = literalRefs[i + 1].second;

			// Check if these are consecutive literal pool entries (4 bytes apart)
			if (litAddr2 - litAddr1 != 4)
				continue;

			// Check if values look like array bounds
			// Must be ordered (start < end) with reasonable size (< 0x1000 bytes)
			if (val1 >= val2)
				continue;

			uint32_t arraySize = val2 - val1;
			if (arraySize == 0 || arraySize > 0x1000)
				continue;

			// Validate that the array start address is within our file or ROM copy range
			// Handle physical address aliases using the discovered alias base
			bool arrayAccessible = false;

			// Check if array is in ROM copy range (preferred - has initialized data)
			if (romCopy.valid && discoveredAliasBase != 0 &&
				(val1 & 0xFF000000) == discoveredAliasBase &&
				val1 >= romCopy.sramDst && val2 <= romCopy.sramEnd)
			{
				arrayAccessible = true;
				logger->LogInfo("MMU: Config array at 0x%08x is in ROM copy range", val1);
			}
			else
			{
				// Fall back to checking if array is directly in file
				uint64_t arrayFileOffset = val1;
				if (discoveredAliasBase != 0 && (val1 & 0xFF000000) == discoveredAliasBase)
					arrayFileOffset = val1 & 0x00FFFFFF;

				if (arrayFileOffset >= imageBase && arrayFileOffset < imageBase + length)
					arrayAccessible = true;
				else if (arrayFileOffset < length)
					arrayAccessible = true;
			}

			if (!arrayAccessible)
				continue;  // Array not accessible

			// Read first few entries using ReadU32Smart to get data from ROM if needed
			uint32_t firstEntry = 0, secondEntry = 0, thirdEntry = 0;
			ReadU32Smart(reader, data, dataLen, endian, val1, discoveredAliasBase, length, romCopy, firstEntry);
			ReadU32Smart(reader, data, dataLen, endian, val1 + 4, discoveredAliasBase, length, romCopy, secondEntry);
			ReadU32Smart(reader, data, dataLen, endian, val1 + 8, discoveredAliasBase, length, romCopy, thirdEntry);

			// Check if array is uninitialized (all entries are the same value like 0x0ff59ff0)
			// This indicates the array is populated at runtime, not in the binary
			if (firstEntry == secondEntry && secondEntry == thirdEntry)
			{
				// All entries are the same - likely uninitialized
				// Skip this array unless entries look like valid descriptors
				uint32_t descType = firstEntry & 0x3;
				if (descType != 0x2 && descType != 0x1)  // Not a valid section or page table descriptor
				{
					logger->LogInfo("MMU: Skipping uninitialized array at 0x%08x (all entries = 0x%08x)",
						val1, firstEntry);
					continue;
				}
			}

			// Determine array type based on first entry
			// Identity arrays have entries that look like 0xXX000000 (1MB aligned) or
			// have low bits that look like section descriptors (0x..00012, 0x..00c12, etc.)
			// VA->PA arrays have the VA in the first word
			bool isIdentity = false;

			// Check if first entry looks like a section base + descriptor bits
			// Section base is in [31:20], descriptor bits in [19:0]
			uint32_t sectionBase = firstEntry & 0xFFF00000;
			uint32_t descBits = firstEntry & 0x000FFFFF;

			// Identity entries typically have descriptor bits like 0x00012 (cached) or 0x00c12 (device)
			// or just section base with minimal flags
			if ((descBits & 0x00003) == 0x02 ||  // Section descriptor type
			    (descBits & 0xFFFFF) < 0x100 ||  // Very low flags (likely just base)
			    (firstEntry & 0x000FFFFF) == 0)   // Just the section base
			{
				isIdentity = true;
			}

			// For identity arrays, entry count = size / 4
			// For VA->PA arrays, entry count = size / 8
			size_t entrySize = isIdentity ? 4 : 8;
			size_t entryCount = arraySize / entrySize;

			if (entryCount == 0 || entryCount > 256)
				continue;  // Unreasonable entry count

			logger->LogInfo("MMU: Found config array at 0x%08x-0x%08x (%s, %zu entries)",
				val1, val2, isIdentity ? "identity" : "VA->PA", entryCount);

			configArrays.push_back({val1, val2, isIdentity, litAddr1, litAddr2});

			// Parse the array entries and create memory regions
			// Use the original SRAM addresses (val1, val2) with ReadU32Smart to read from ROM
			for (size_t j = 0; j < entryCount; j++)
			{
				uint64_t entryAddr = val1 + (j * entrySize);
				if (entryAddr + entrySize > val2)
					break;

				uint32_t entry1 = 0, entry2 = 0;
				ReadU32Smart(reader, data, dataLen, endian, entryAddr, discoveredAliasBase, length, romCopy, entry1);
				if (!isIdentity)
					ReadU32Smart(reader, data, dataLen, endian, entryAddr + 4, discoveredAliasBase, length, romCopy, entry2);

				uint64_t virtAddr, physAddr;
				uint32_t descriptor;

				if (isIdentity)
				{
					// Identity: entry is VA (with possible descriptor bits)
					virtAddr = entry1 & 0xFFF00000;
					physAddr = virtAddr;  // Identity mapping
					descriptor = entry1 & 0x000FFFFF;
				}
				else
				{
					// VA->PA: first word is VA, second is PTE descriptor
					virtAddr = entry1 & 0xFFF00000;
					physAddr = entry2 & 0xFFF00000;
					descriptor = entry2 & 0x000FFFFF;
				}

				// Decode descriptor bits
				bool cacheable = (descriptor >> 3) & 0x1;
				bool bufferable = (descriptor >> 2) & 0x1;
				bool executable = !((descriptor >> 4) & 0x1);  // XN bit
				uint32_t ap = (descriptor >> 10) & 0x3;
				bool readable = (ap != 0);
				bool writable = (ap == 0x3);

				const char* regionType = "unknown";
				if (cacheable && bufferable)
					regionType = "RAM (cached)";
				else if (!cacheable && !bufferable)
					regionType = "MMIO";
				else if (!cacheable && bufferable)
					regionType = "RAM (write-combine)";
				else
					regionType = "RAM (uncached)";

				// Check if this region can be merged with the previous one
				bool merged = false;
				if (!regions.empty())
				{
					MemRegion& last = regions.back();
					if (last.virtBase + last.size == virtAddr &&
					    last.physBase + last.size == physAddr &&
					    last.cacheable == cacheable &&
					    last.bufferable == bufferable &&
					    last.executable == executable &&
					    last.readable == readable &&
					    last.writable == writable)
					{
						last.size += 0x100000;  // Extend by 1MB
						merged = true;
					}
				}

				if (!merged)
				{
					regions.push_back({virtAddr, physAddr, 0x100000,
						readable, writable, executable, cacheable, bufferable, regionType});
				}
			}
		}

		if (configArrays.empty() || regions.empty())
		{
			logger->LogInfo("MMU: Config arrays uninitialized in binary, searching literal pool for alias base");

			// The config arrays are populated at runtime, but we can find the alias base
			// by searching the literal pool for a 1MB-aligned value that matches the
			// TTBR's high byte pattern. For example:
			// - TTBR = 0xA4034000 -> look for 0xA4000000 in literal pool
			// - This is the uncached RAM alias base that gets ORed with addresses

			uint64_t ttbrHighByte = ttbrValue & 0xFF000000;
			uint64_t foundAliasBase = 0;

			// Search the literal pool for the alias base (e.g., 0xA4000000)
			for (const auto& ref : literalRefs)
			{
				uint32_t val = ref.second;
				// Look for 1MB-aligned value matching TTBR high byte
				if ((val & 0xFF000000) == ttbrHighByte && (val & 0x00FFFFFF) == 0)
				{
					foundAliasBase = val;
					logger->LogInfo("MMU: Found alias base 0x%08x in literal pool at 0x%llx",
						val, (unsigned long long)ref.first);
					break;
				}
			}

			// If we found the alias base, or can infer it from TTBR
			if (foundAliasBase != 0 || discoveredAliasBase != 0)
			{
				uint64_t aliasBase = foundAliasBase ? foundAliasBase : discoveredAliasBase;
				uint64_t ttbrOffset = ttbrValue & 0x00FFFFFF;

				// Infer minimum RAM size from TTBR offset + 16KB translation table
				uint64_t minRamSize = ttbrOffset + 0x4000;
				// Round up to 1MB boundary
				uint64_t ramSize = ((minRamSize + 0xFFFFF) & ~0xFFFFFULL);

				logger->LogInfo("MMU: Alias base 0x%llx -> 0x%llx (size 0x%llx)",
					(unsigned long long)aliasBase,
					(unsigned long long)imageBase, (unsigned long long)ramSize);

				// Add the physical alias region
				regions.push_back({aliasBase, imageBase, ramSize,
					true, true, true, false, false, "Physical alias"});
			}

			logger->LogInfo("MMU: Inferred %zu memory regions from literal pool analysis", regions.size());
		}
		else
		{
			logger->LogInfo("MMU: Discovered %zu config arrays, extracted %zu memory regions",
				configArrays.size(), regions.size());
		}
	}
	else
	{
		logger->LogInfo("MMU: Found %zu memory regions from translation table", regions.size());
	}

	// Deduplicate regions by virtual address (keep first occurrence)
	std::vector<MemRegion> uniqueRegions;
	std::set<uint64_t> seenVA;
	for (const auto& region : regions)
	{
		if (region.size == 0)
			continue;
		if (seenVA.find(region.virtBase) == seenVA.end())
		{
			seenVA.insert(region.virtBase);
			uniqueRegions.push_back(region);
		}
	}

	// Sort by virtual address
	std::sort(uniqueRegions.begin(), uniqueRegions.end(),
		[](const MemRegion& a, const MemRegion& b) { return a.virtBase < b.virtBase; });

	// Log what we found but don't create segments for now
	// Creating segments without backing data was causing crashes
	logger->LogInfo("MMU: Analysis complete. Found %zu memory regions:", uniqueRegions.size());
	logger->LogInfo("MMU:   %-21s  %-6s %-13s %-3s  %6s", "Address Range", "Type", "Cache", "Prm", "Size");
	logger->LogInfo("MMU:   %-21s  %-6s %-13s %-3s  %6s", "---------------------", "------", "-------------", "---", "------");
	for (const auto& region : uniqueRegions)
	{
		// Format size as human-readable
		char sizeStr[16];
		uint64_t sz = region.size;
		if (sz >= 0x100000 && (sz % 0x100000) == 0)
			snprintf(sizeStr, sizeof(sizeStr), "%lluMB", (unsigned long long)(sz / 0x100000));
		else if (sz >= 0x400 && (sz % 0x400) == 0)
			snprintf(sizeStr, sizeof(sizeStr), "%lluKB", (unsigned long long)(sz / 0x400));
		else
			snprintf(sizeStr, sizeof(sizeStr), "%lluB", (unsigned long long)sz);

		// Determine base type (RAM or MMIO) from the type string
		const char* baseType = "RAM";
		if (region.type && (strstr(region.type, "MMIO") || strstr(region.type, "Device")))
			baseType = "MMIO";

		// Determine cache policy from C and B bits
		const char* cachePolicy = "uncached";
		if (region.cacheable && region.bufferable)
			cachePolicy = "write-back";
		else if (region.cacheable && !region.bufferable)
			cachePolicy = "write-through";
		else if (!region.cacheable && region.bufferable)
			cachePolicy = "write-combine";
		// else uncached (C=0, B=0)

		logger->LogInfo("MMU:   0x%08llx-0x%08llx  %-6s %-13s %s%s%s  %6s (0x%llx)",
			(unsigned long long)region.virtBase,
			(unsigned long long)(region.virtBase + region.size - 1),
			baseType,
			cachePolicy,
			region.readable ? "R" : "-",
			region.writable ? "W" : "-",
			region.executable ? "X" : "-",
			sizeStr,
			(unsigned long long)region.size);
	}

	// TODO: Creating segments for MMIO regions without file backing causes crashes
	// Need to investigate the correct Binary Ninja API for this
}


// Helper to resolve a vector table entry to a handler address
// Returns the target address, or 0 if not resolvable
static uint64_t ResolveVectorEntry(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t vectorOffset, uint64_t imageBase, uint64_t length)
{
	uint32_t instr = 0;
	ReadU32At(reader, data, dataLen, endian, vectorOffset, instr, length);

	// LDR PC, [PC, #imm] - 0xE59FF0xx
	if ((instr & 0xFFFFF000) == 0xE59FF000)
	{
		uint32_t offset = instr & 0xFFF;
		// PC is 8 bytes ahead when executing, relative to instruction address
		uint64_t pointerAddr = vectorOffset + 8 + offset;

		if (pointerAddr + 4 <= length)
		{
			uint32_t handlerAddr = 0;
			ReadU32At(reader, data, dataLen, endian, pointerAddr, handlerAddr, length);
			// Mask off Thumb bit if present
			return handlerAddr & ~1u;
		}
	}
	// B (branch) instruction: 0xEAxxxxxx
	else if ((instr & 0xFF000000) == 0xEA000000)
	{
		int32_t offset = (instr & 0x00FFFFFF);
		// Sign extend from 24 bits
		if (offset & 0x800000)
			offset |= 0xFF000000;
		// Multiply by 4 and add 8 (PC offset), relative to instruction address
		return vectorOffset + ((int64_t)offset << 2) + 8;
	}

	return 0;
}


// Check if a value looks like an MMIO/peripheral address (outside image, high address range)
static bool IsLikelyMMIOPointer(uint32_t value, uint64_t imageBase, uint64_t imageEnd)
{
	// Must be aligned
	if ((value & 3) != 0)
		return false;

	// Inside the image - it's a code/data pointer, not MMIO
	if (value >= imageBase && value < imageEnd)
		return false;

	// Common MMIO ranges for embedded ARM systems:
	// 0x40000000+ (STM32, many ARM MCUs)
	// 0x80000000+ (SDRAM, peripherals on many SoCs)
	// 0x90000000+ (peripherals)
	// 0xA0000000+ (external memory/peripherals)
	// 0xC0000000+ (peripherals)
	// 0xD0000000+ (peripherals)
	// 0xE0000000+ (ARM Cortex-M system peripherals)
	// 0xF0000000+ (vendor peripherals)
	uint32_t highNibble = (value >> 28) & 0xF;
	return highNibble >= 4;  // 0x40000000 and above
}

// Scan for PC-relative loads and type their literal pool entries as data
// This keeps literal pools from being interpreted as code and improves display
static void TypeLiteralPoolEntries(const FirmwareScanContext& ctx)
{
	ctx.logger->LogDebug("Typing literal pool entries...");

	Ref<Type> ptrType = Type::PointerType(ctx.arch, Type::VoidType());
	Ref<Type> u32Type = Type::IntegerType(4, false);
	uint32_t entriesTyped = 0;
	uint32_t ldrPcCount = 0;
	uint32_t skippedNonCode = 0;
	uint32_t skippedInFunction = 0;
	uint32_t skippedDecodedCode = 0;
	uint32_t skippedExisting = 0;

	for (uint64_t offset = 0; offset + 4 <= ctx.length; offset += 4)
	{
		uint32_t instr = 0;
		ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, instr, ctx.length);
		uint64_t instrAddr = ctx.imageBase + offset;
		// Only type literal pools referenced from code.
		if (!ctx.view->IsOffsetCodeSemantics(instrAddr))
		{
			skippedNonCode++;
			continue;
		}

		// LDR Rd, [PC, #imm] - pattern: cond 01 0 P U 0 W 1 1111 Rd imm12
		// We want P=1, W=0 (offset addressing, no writeback), Rn=PC (1111)
		// Mask: 0x0F7F0000, expect: 0x051F0000
		if ((instr & 0x0F7F0000) == 0x051F0000)
		{
			ldrPcCount++;
			uint32_t imm12 = instr & 0xFFF;
			bool add = (instr & 0x00800000) != 0;
			uint64_t pc = offset + 8;  // PC is 8 bytes ahead
			uint64_t literalOffset = add ? (pc + imm12) : (pc - imm12);

			if (literalOffset + 4 <= ctx.length)
			{
				uint32_t value = 0;
				ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, literalOffset, value, ctx.length);

				uint64_t literalAddr = ctx.imageBase + literalOffset;
				// Avoid typing data inside discovered functions to reduce accidental code suppression.
				if (!ctx.view->GetAnalysisFunctionsContainingAddress(literalAddr).empty())
				{
					skippedInFunction++;
					continue;
				}
				if (ctx.view->IsOffsetCodeSemantics(literalAddr))
				{
					armv5::Instruction decoded;
					memset(&decoded, 0, sizeof(decoded));
					if (armv5::armv5_decompose(value, &decoded, (uint32_t)literalOffset, 0) == 0)
					{
						skippedDecodedCode++;
						continue;
					}
				}
				DataVariable existing;
				if (ctx.view->GetDataVariableAtAddress(literalAddr, existing) &&
					existing.address == literalAddr)
				{
					skippedExisting++;
					continue;
				}

				Ref<Type> entryType = u32Type;
				if (IsLikelyMMIOPointer(value, ctx.imageBase, ctx.ImageEnd()) ||
					((value & 3) == 0 && value >= ctx.imageBase && value < ctx.ImageEnd()))
					entryType = ptrType;

				ctx.view->DefineDataVariable(literalAddr, entryType);
				entriesTyped++;
			}
		}
	}

	ctx.logger->LogInfo("Typed %u literal pool entries as data", entriesTyped);
	if (ctx.verboseLog)
	{
		ctx.logger->LogInfo(
			"Literal pool typing detail: ldr_pc=%u typed=%u skipped_noncode=%u skipped_in_function=%u "
			"skipped_decoded_code=%u skipped_existing=%u",
			ldrPcCount, entriesTyped, skippedNonCode, skippedInFunction, skippedDecodedCode, skippedExisting);
	}
}

static void ClearAutoDataOnCodeReferences(const FirmwareScanContext& ctx)
{
	uint32_t cleared = 0;
	uint32_t dataVarCount = 0;
	uint32_t autoVarCount = 0;
	uint32_t withCodeRefs = 0;
	uint32_t decodeFailed = 0;
	ctx.logger->LogDebug("Clearing auto data at code-referenced addresses...");

	auto dataVars = ctx.view->GetDataVariables();
	for (const auto& entry : dataVars)
	{
		dataVarCount++;
		uint64_t addr = entry.first;
		const DataVariable& dataVar = entry.second;
		if (!dataVar.autoDiscovered || dataVar.address != addr)
			continue;
		autoVarCount++;
		if (addr < ctx.imageBase || addr + 8 > ctx.ImageEnd())
			continue;
		if (!ctx.view->IsOffsetCodeSemantics(addr))
			continue;
		if (ctx.view->GetCodeReferences(addr).empty())
			continue;
		withCodeRefs++;

		uint64_t offset = addr - ctx.imageBase;
		uint32_t word0 = 0;
		uint32_t word1 = 0;
		if (!ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, word0, ctx.length))
		{
			decodeFailed++;
			continue;
		}
		if (!ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset + 4, word1, ctx.length))
		{
			decodeFailed++;
			continue;
		}

		armv5::Instruction instr0;
		armv5::Instruction instr1;
		memset(&instr0, 0, sizeof(instr0));
		memset(&instr1, 0, sizeof(instr1));
		if (armv5::armv5_decompose(word0, &instr0, (uint32_t)offset, 0) != 0)
		{
			decodeFailed++;
			continue;
		}
		if (armv5::armv5_decompose(word1, &instr1, (uint32_t)(offset + 4), 0) != 0)
		{
			decodeFailed++;
			continue;
		}

		ctx.view->UndefineDataVariable(addr, false);
		cleared++;
	}

	ctx.logger->LogInfo("Cleared %u auto data variables at code-referenced addresses", cleared);
	if (ctx.verboseLog)
	{
		ctx.logger->LogInfo(
			"Clear auto data detail: data_vars=%u auto=%u code_ref=%u cleared=%u decode_fail=%u",
			dataVarCount, autoVarCount, withCodeRefs, cleared, decodeFailed);
	}
}

static void ClearAutoDataInFunctionEntryBlocks(const FirmwareScanContext& ctx,
	const std::set<uint64_t>* seededFunctions)
{
	uint32_t cleared = 0;
	uint32_t targetsCount = 0;
	uint32_t decodeFailed = 0;
	const size_t maxInstrs = 16;

	std::vector<uint64_t> targets;
	if (seededFunctions && !seededFunctions->empty())
	{
		targets.reserve(seededFunctions->size());
		for (auto addr : *seededFunctions)
			targets.push_back(addr);
	}
	else
	{
		auto functions = ctx.view->GetAnalysisFunctionList();
		targets.reserve(functions.size());
		for (const auto& func : functions)
		{
			if (func)
				targets.push_back(func->GetStart());
		}
	}

	for (auto startAddr : targets)
	{
		targetsCount++;
		uint64_t addr = startAddr;
		for (size_t i = 0; i < maxInstrs; i++)
		{
			if (addr + 8 > ctx.ImageEnd())
				break;
			uint64_t offset = addr - ctx.imageBase;
			uint32_t word0 = 0;
			uint32_t word1 = 0;
			if (!ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, word0, ctx.length))
			{
				decodeFailed++;
				break;
			}
			if (!ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset + 4, word1, ctx.length))
			{
				decodeFailed++;
				break;
			}

			armv5::Instruction instr0;
			armv5::Instruction instr1;
			memset(&instr0, 0, sizeof(instr0));
			memset(&instr1, 0, sizeof(instr1));
			if (armv5::armv5_decompose(word0, &instr0, (uint32_t)offset, 0) != 0)
			{
				decodeFailed++;
				break;
			}
			if (armv5::armv5_decompose(word1, &instr1, (uint32_t)(offset + 4), 0) != 0)
			{
				decodeFailed++;
				break;
			}

			DataVariable dataVar;
			if (ctx.view->GetDataVariableAtAddress(addr, dataVar) &&
				dataVar.address == addr && dataVar.autoDiscovered)
			{
				ctx.view->UndefineDataVariable(addr, false);
				cleared++;
			}

			if ((instr0.operation == armv5::ARMV5_B) &&
				(instr0.cond == armv5::COND_AL || instr0.cond == armv5::COND_NV))
				break;
			if (instr0.operation == armv5::ARMV5_BX)
				break;

			addr += 4;
		}
	}

	if (cleared)
		ctx.logger->LogInfo("Cleared %u auto data variables inside function entry blocks", cleared);
	if (ctx.verboseLog)
	{
		ctx.logger->LogInfo(
			"Entry block clear detail: targets=%u cleared=%u decode_fail=%u",
			targetsCount, cleared, decodeFailed);
	}
}

// Scan for jump tables (ADD PC, PC, Rn pattern) and mark them as uint32 arrays
// NOTE: Currently unused, kept for future IL-based jump table resolution
static void ScanForJumpTables(const FirmwareScanContext& ctx)
{
	ctx.logger->LogDebug("Scanning for jump tables...");

	Ref<Type> uint32Type = Type::IntegerType(4, false);

	for (uint64_t offset = 0; offset + 4 <= ctx.length; offset += 4)
	{
		uint32_t instr = 0;
		ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, instr, ctx.length);

		// ADD PC, PC, Rn (computed jump for switch tables)
		if ((instr & 0x0FFFF010) == 0x008FF000)
		{
			uint64_t tableBase = 0;
			uint32_t maxCases = 0;

			for (int i = 1; i <= 16 && offset >= (uint64_t)(i * 4); i++)
			{
				uint32_t scanInstr = 0;
				ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset - (i * 4), scanInstr, ctx.length);

				// ADD Rx, PC, #imm (table base calculation)
				if ((scanInstr & 0x0FFF0000) == 0x028F0000)
				{
					uint32_t imm12 = scanInstr & 0xFFF;
					uint32_t rotate = (scanInstr >> 8) & 0xF;
					uint32_t immediate = (imm12 >> (rotate * 2)) | (imm12 << (32 - rotate * 2));
					tableBase = ctx.imageBase + (offset - (i * 4)) + 8 + immediate;
				}

				// CMP Rx, #imm (bounds check)
				if ((scanInstr & 0x0FF00000) == 0x03500000 && maxCases == 0)
				{
					uint32_t imm8 = scanInstr & 0xFF;
					uint32_t rotate = (scanInstr >> 8) & 0xF;
					maxCases = ((imm8 >> (rotate * 2)) | (imm8 << (32 - rotate * 2))) + 1;
				}

				if (tableBase != 0 && maxCases > 0)
					break;
			}

			if (tableBase != 0)
			{
				if (maxCases == 0 || maxCases > 64)
					maxCases = 32;

				uint32_t validEntries = 0;
				for (uint32_t i = 0; i < maxCases; i++)
				{
					uint64_t entryFileOffset = (tableBase - ctx.imageBase) + (i * 4);
					if (entryFileOffset + 4 > ctx.length)
						break;
					uint32_t entryValue = 0;
					ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, entryFileOffset, entryValue, ctx.length);
					if (entryValue > 0x100000)
						break;
					validEntries++;
				}

				if (validEntries > 0)
				{
					Ref<Type> arrayType = Type::ArrayType(uint32Type, validEntries);
					ctx.view->DefineUserDataVariable(tableBase, arrayType);

					char symName[32];
					snprintf(symName, sizeof(symName), "switch_table_%llx",
						(unsigned long long)tableBase);
					ctx.view->DefineAutoSymbol(new Symbol(DataSymbol, symName, tableBase, LocalBinding));

					ctx.logger->LogDebug("Defined switch table at 0x%llx with %u entries",
						(unsigned long long)tableBase, validEntries);
				}
			}
		}
	}
}


bool Armv5FirmwareView::Init()
{
	uint64_t length = GetParentView()->GetLength();
	uint64_t imageBase = 0;
	bool imageBaseFromUser = false;
	/*
	 * Default to core-analysis behavior (match other Binary Ninja views), but
	 * disable pointer sweep for raw firmware blobs to avoid massive false positives.
	 */
	bool enablePrologueScan = false;
	bool enableCallTargetScan = false;
	bool enablePointerTargetScan = false;
	bool enableOrphanCodeScan = true;
	bool enableLiteralPoolTyping = false;
	bool enableClearAutoDataOnCodeRefs = false;
	bool enableVerboseLogging = false;
	bool disablePointerSweep = false;
	bool disableLinearSweep = false;
	bool enableInvalidFunctionCleanup = false;
	uint32_t cleanupMaxSizeBytes = 8;
	bool cleanupRequireZeroRefs = true;
	bool cleanupRequirePcWriteStart = true;
	uint32_t orphanMinValidInstr = 4;
	uint32_t orphanMinBodyInstr = 2;
	uint32_t orphanMinSpacingBytes = 0x80;
	uint32_t orphanMaxPerPage = 6;
	bool orphanRequirePrologue = true;
	bool enablePartialLinearSweep = true;
	bool skipFirmwareScans = true;
	FirmwareScanTuning tuning{};

	// Get load settings if available
	Ref<Settings> settings = GetLoadSettings(GetTypeName());
	if (settings && settings->Contains("loader.imageBase"))
	{
		imageBase = settings->Get<uint64_t>("loader.imageBase", this);
		imageBaseFromUser = (imageBase != 0);
	}
	if (settings)
	{
		if (settings->Contains("loader.armv5.firmware.scanPrologues"))
			enablePrologueScan = settings->Get<bool>("loader.armv5.firmware.scanPrologues", this);
		if (settings->Contains("loader.armv5.firmware.scanCallTargets"))
			enableCallTargetScan = settings->Get<bool>("loader.armv5.firmware.scanCallTargets", this);
		if (settings->Contains("loader.armv5.firmware.scanPointerTargets"))
			enablePointerTargetScan = settings->Get<bool>("loader.armv5.firmware.scanPointerTargets", this);
		if (settings->Contains("loader.armv5.firmware.scanOrphanCode"))
			enableOrphanCodeScan = settings->Get<bool>("loader.armv5.firmware.scanOrphanCode", this);
		if (settings->Contains("loader.armv5.firmware.orphanMinValidInstr"))
			orphanMinValidInstr = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.orphanMinValidInstr", this);
		if (settings->Contains("loader.armv5.firmware.orphanMinBodyInstr"))
			orphanMinBodyInstr = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.orphanMinBodyInstr", this);
		if (settings->Contains("loader.armv5.firmware.orphanMinSpacingBytes"))
			orphanMinSpacingBytes = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.orphanMinSpacingBytes", this);
		if (settings->Contains("loader.armv5.firmware.orphanMaxPerPage"))
			orphanMaxPerPage = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.orphanMaxPerPage", this);
		if (settings->Contains("loader.armv5.firmware.orphanRequirePrologue"))
			orphanRequirePrologue = settings->Get<bool>("loader.armv5.firmware.orphanRequirePrologue", this);
		if (settings->Contains("loader.armv5.firmware.partialLinearSweep"))
			enablePartialLinearSweep = settings->Get<bool>("loader.armv5.firmware.partialLinearSweep", this);
		if (settings->Contains("loader.armv5.firmware.skipFirmwareScans"))
			skipFirmwareScans = settings->Get<bool>("loader.armv5.firmware.skipFirmwareScans", this);
		if (settings->Contains("loader.armv5.firmware.typeLiteralPools"))
			enableLiteralPoolTyping = settings->Get<bool>("loader.armv5.firmware.typeLiteralPools", this);
		if (settings->Contains("loader.armv5.firmware.clearAutoDataOnCodeRefs"))
			enableClearAutoDataOnCodeRefs = settings->Get<bool>("loader.armv5.firmware.clearAutoDataOnCodeRefs", this);
		if (settings->Contains("loader.armv5.firmware.verboseLogging"))
			enableVerboseLogging = settings->Get<bool>("loader.armv5.firmware.verboseLogging", this);
		if (settings->Contains("loader.armv5.firmware.disablePointerSweep"))
			disablePointerSweep = settings->Get<bool>("loader.armv5.firmware.disablePointerSweep", this);
		if (settings->Contains("loader.armv5.firmware.disableLinearSweep"))
			disableLinearSweep = settings->Get<bool>("loader.armv5.firmware.disableLinearSweep", this);
		if (settings->Contains("loader.armv5.firmware.scanMinValidInstr"))
			tuning.minValidInstr = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.scanMinValidInstr", this);
		if (settings->Contains("loader.armv5.firmware.scanMinBodyInstr"))
			tuning.minBodyInstr = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.scanMinBodyInstr", this);
		if (settings->Contains("loader.armv5.firmware.scanMaxLiteralRun"))
			tuning.maxLiteralRun = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.scanMaxLiteralRun", this);
		if (settings->Contains("loader.armv5.firmware.scanRawPointerTables"))
			tuning.scanRawPointerTables = settings->Get<bool>("loader.armv5.firmware.scanRawPointerTables", this);
		if (settings->Contains("loader.armv5.firmware.rawPointerTableMinRun"))
			tuning.minPointerRun = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.rawPointerTableMinRun", this);
		if (settings->Contains("loader.armv5.firmware.rawPointerTableRequireCodeRefs"))
			tuning.requirePointerTableCodeRefs = settings->Get<bool>("loader.armv5.firmware.rawPointerTableRequireCodeRefs", this);
		if (settings->Contains("loader.armv5.firmware.rawPointerTableAllowInCode"))
			tuning.allowPointerTablesInCode = settings->Get<bool>("loader.armv5.firmware.rawPointerTableAllowInCode", this);
		if (settings->Contains("loader.armv5.firmware.callScanRequireInFunction"))
			tuning.requireCallInFunction = settings->Get<bool>("loader.armv5.firmware.callScanRequireInFunction", this);
		if (settings->Contains("loader.armv5.firmware.cleanupInvalidFunctions"))
			enableInvalidFunctionCleanup = settings->Get<bool>("loader.armv5.firmware.cleanupInvalidFunctions", this);
		if (settings->Contains("loader.armv5.firmware.cleanupInvalidMaxSize"))
			cleanupMaxSizeBytes = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.cleanupInvalidMaxSize", this);
		if (settings->Contains("loader.armv5.firmware.cleanupInvalidRequireZeroRefs"))
			cleanupRequireZeroRefs = settings->Get<bool>("loader.armv5.firmware.cleanupInvalidRequireZeroRefs", this);
		if (settings->Contains("loader.armv5.firmware.cleanupInvalidRequirePcWrite"))
			cleanupRequirePcWriteStart = settings->Get<bool>("loader.armv5.firmware.cleanupInvalidRequirePcWrite", this);
	}
	if (tuning.minValidInstr == 0)
		tuning.minValidInstr = 1;
	if (tuning.minPointerRun == 0)
		tuning.minPointerRun = 1;

	// Emit a single consolidated settings line to make log triage reproducible.
	// This mirrors the effective values after defaults + user overrides are applied.
	if (enableVerboseLogging)
	{
		m_logger->LogInfo(
			"Firmware settings: prologue_scan=%d call_scan=%d pointer_scan=%d orphan_scan=%d "
			"orphan_min_valid=%u orphan_min_body=%u orphan_min_spacing=0x%x orphan_max_per_page=%u "
			"orphan_require_prologue=%d partial_linear_sweep=%d skip_firmware_scans=%d "
			"raw_ptr_tables=%d raw_ptr_min_run=%u raw_ptr_require_refs=%d raw_ptr_allow_in_code=%d "
			"call_scan_require_in_func=%d disable_pointer_sweep=%d disable_linear_sweep=%d "
			"cleanup_invalid=%d cleanup_max_size=%u cleanup_zero_refs=%d cleanup_pc_write=%d "
			"type_literal_pools=%d clear_auto_data_on_code_refs=%d scan_min_valid=%u scan_min_body=%u scan_max_literal_run=%u",
			enablePrologueScan, enableCallTargetScan, enablePointerTargetScan, enableOrphanCodeScan,
			orphanMinValidInstr, orphanMinBodyInstr, orphanMinSpacingBytes, orphanMaxPerPage,
			orphanRequirePrologue, enablePartialLinearSweep, skipFirmwareScans,
			tuning.scanRawPointerTables, tuning.minPointerRun, tuning.requirePointerTableCodeRefs, tuning.allowPointerTablesInCode,
			tuning.requireCallInFunction, disablePointerSweep, disableLinearSweep,
			enableInvalidFunctionCleanup, cleanupMaxSizeBytes, cleanupRequireZeroRefs, cleanupRequirePcWriteStart,
			enableLiteralPoolTyping, enableClearAutoDataOnCodeRefs,
			tuning.minValidInstr, tuning.minBodyInstr, tuning.maxLiteralRun);
	}

	// Handle platform override from settings
	if (settings && settings->Contains("loader.platform"))
	{
		Ref<Platform> platformOverride = Platform::GetByName(settings->Get<string>("loader.platform", this));
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
	if (disablePointerSweep)
		Settings::Instance()->Set("analysis.pointerSweep.autorun", false, this);
	else
		Settings::Instance()->Set("analysis.pointerSweep.autorun", true, this);

	// Partial linear sweep option: leave auto linear sweep enabled but limit it to faster tier
	if (enablePartialLinearSweep)
	{
		Settings::Instance()->Set("triage.linearSweep", "full", this);
		Settings::Instance()->Set("analysis.linearSweep.autorun", true, this);
		Settings::Instance()->Set("analysis.linearSweep.controlFlowGraph", false, this);
		Settings::Instance()->Set("analysis.signatureMatcher.autorun", false, this);
	}
	else if (disableLinearSweep)
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
			if (!enableVerboseLogging)
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

		if (!skipFirmwareScans && enableVerboseLogging)
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

	m_logger->LogInfo("Firmware workflow scan: start");

	uint64_t length = GetLength();
	if (!length)
		return;

	/*
	 * Mirror the firmware scan settings used during Init(), but run them here
	 * as a workflow activity so we can align with Binary Ninja's analysis pipeline.
	 */
	bool enablePrologueScan = false;
	bool enableCallTargetScan = false;
	bool enablePointerTargetScan = false;
	bool enableOrphanCodeScan = true;
	bool enableLiteralPoolTyping = false;
	bool enableClearAutoDataOnCodeRefs = false;
	bool enableVerboseLogging = false;
	bool enableInvalidFunctionCleanup = false;
	uint32_t cleanupMaxSizeBytes = 8;
	bool cleanupRequireZeroRefs = true;
	bool cleanupRequirePcWriteStart = true;
	uint32_t orphanMinValidInstr = 4;
	uint32_t orphanMinBodyInstr = 2;
	uint32_t orphanMinSpacingBytes = 0x80;
	uint32_t orphanMaxPerPage = 8;
	bool orphanRequirePrologue = false;
	bool skipFirmwareScans = true;
	FirmwareScanTuning tuning{};

	Ref<Settings> settings = GetLoadSettings(GetTypeName());
	if (settings)
	{
		if (settings->Contains("loader.armv5.firmware.scanPrologues"))
			enablePrologueScan = settings->Get<bool>("loader.armv5.firmware.scanPrologues", this);
		if (settings->Contains("loader.armv5.firmware.scanCallTargets"))
			enableCallTargetScan = settings->Get<bool>("loader.armv5.firmware.scanCallTargets", this);
		if (settings->Contains("loader.armv5.firmware.scanPointerTargets"))
			enablePointerTargetScan = settings->Get<bool>("loader.armv5.firmware.scanPointerTargets", this);
		if (settings->Contains("loader.armv5.firmware.scanOrphanCode"))
			enableOrphanCodeScan = settings->Get<bool>("loader.armv5.firmware.scanOrphanCode", this);
		if (settings->Contains("loader.armv5.firmware.orphanMinValidInstr"))
			orphanMinValidInstr = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.orphanMinValidInstr", this);
		if (settings->Contains("loader.armv5.firmware.orphanMinBodyInstr"))
			orphanMinBodyInstr = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.orphanMinBodyInstr", this);
		if (settings->Contains("loader.armv5.firmware.orphanMinSpacingBytes"))
			orphanMinSpacingBytes = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.orphanMinSpacingBytes", this);
		if (settings->Contains("loader.armv5.firmware.orphanMaxPerPage"))
			orphanMaxPerPage = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.orphanMaxPerPage", this);
		if (settings->Contains("loader.armv5.firmware.orphanRequirePrologue"))
			orphanRequirePrologue = settings->Get<bool>("loader.armv5.firmware.orphanRequirePrologue", this);
		if (settings->Contains("loader.armv5.firmware.skipFirmwareScans"))
			skipFirmwareScans = settings->Get<bool>("loader.armv5.firmware.skipFirmwareScans", this);
		if (settings->Contains("loader.armv5.firmware.typeLiteralPools"))
			enableLiteralPoolTyping = settings->Get<bool>("loader.armv5.firmware.typeLiteralPools", this);
		if (settings->Contains("loader.armv5.firmware.clearAutoDataOnCodeRefs"))
			enableClearAutoDataOnCodeRefs = settings->Get<bool>("loader.armv5.firmware.clearAutoDataOnCodeRefs", this);
		if (settings->Contains("loader.armv5.firmware.verboseLogging"))
			enableVerboseLogging = settings->Get<bool>("loader.armv5.firmware.verboseLogging", this);
		if (settings->Contains("loader.armv5.firmware.scanMinValidInstr"))
			tuning.minValidInstr = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.scanMinValidInstr", this);
		if (settings->Contains("loader.armv5.firmware.scanMinBodyInstr"))
			tuning.minBodyInstr = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.scanMinBodyInstr", this);
		if (settings->Contains("loader.armv5.firmware.scanMaxLiteralRun"))
			tuning.maxLiteralRun = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.scanMaxLiteralRun", this);
		if (settings->Contains("loader.armv5.firmware.scanRawPointerTables"))
			tuning.scanRawPointerTables = settings->Get<bool>("loader.armv5.firmware.scanRawPointerTables", this);
		if (settings->Contains("loader.armv5.firmware.rawPointerTableMinRun"))
			tuning.minPointerRun = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.rawPointerTableMinRun", this);
		if (settings->Contains("loader.armv5.firmware.rawPointerTableRequireCodeRefs"))
			tuning.requirePointerTableCodeRefs = settings->Get<bool>("loader.armv5.firmware.rawPointerTableRequireCodeRefs", this);
		if (settings->Contains("loader.armv5.firmware.rawPointerTableAllowInCode"))
			tuning.allowPointerTablesInCode = settings->Get<bool>("loader.armv5.firmware.rawPointerTableAllowInCode", this);
		if (settings->Contains("loader.armv5.firmware.callScanRequireInFunction"))
			tuning.requireCallInFunction = settings->Get<bool>("loader.armv5.firmware.callScanRequireInFunction", this);
		if (settings->Contains("loader.armv5.firmware.cleanupInvalidFunctions"))
			enableInvalidFunctionCleanup = settings->Get<bool>("loader.armv5.firmware.cleanupInvalidFunctions", this);
		if (settings->Contains("loader.armv5.firmware.cleanupInvalidMaxSize"))
			cleanupMaxSizeBytes = (uint32_t)settings->Get<uint64_t>("loader.armv5.firmware.cleanupInvalidMaxSize", this);
		if (settings->Contains("loader.armv5.firmware.cleanupInvalidRequireZeroRefs"))
			cleanupRequireZeroRefs = settings->Get<bool>("loader.armv5.firmware.cleanupInvalidRequireZeroRefs", this);
		if (settings->Contains("loader.armv5.firmware.cleanupInvalidRequirePcWrite"))
			cleanupRequirePcWriteStart = settings->Get<bool>("loader.armv5.firmware.cleanupInvalidRequirePcWrite", this);
	}

	if (tuning.minValidInstr == 0)
		tuning.minValidInstr = 1;
	if (tuning.minPointerRun == 0)
		tuning.minPointerRun = 1;

	if (skipFirmwareScans)
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
		if (!enableVerboseLogging)
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

	if (enableLiteralPoolTyping)
	{
		FirmwareScanContext scanCtx{reader, fileData, fileDataLen, m_endian, imageBase, length,
			m_arch, m_plat, m_logger, enableVerboseLogging, this};
		timePass("Literal pool typing", [&]()
		{
			TypeLiteralPoolEntries(scanCtx);
		});
		if (enableClearAutoDataOnCodeRefs)
		{
			timePass("Clear auto data on code refs", [&]()
			{
				ClearAutoDataOnCodeReferences(scanCtx);
			});
		}
	}

	if (enablePrologueScan)
	{
		Ref<Architecture> thumbArch = Architecture::GetByName("armv5t");
		timePass("Function prologue scan", [&]()
		{
			ScanForFunctionPrologues(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_arch, thumbArch, m_plat, m_logger, enableVerboseLogging, tuning, &seededFunctions);
		});
	}

	if (enableClearAutoDataOnCodeRefs)
	{
		FirmwareScanContext scanCtx{reader, fileData, fileDataLen, m_endian, imageBase, length,
			m_arch, m_plat, m_logger, enableVerboseLogging, this};
		timePass("Clear auto data in function entry blocks", [&]()
		{
			ClearAutoDataInFunctionEntryBlocks(scanCtx, &seededFunctions);
		});
	}

	if (enableCallTargetScan)
	{
		timePass("Call target scan", [&]()
		{
			ScanForCallTargets(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_plat, m_logger, enableVerboseLogging, tuning, &seededFunctions);
		});
	}

	std::set<uint64_t> addedFunctions;
	if (enablePointerTargetScan)
	{
		timePass("Pointer target scan", [&]()
		{
			ScanForPointerTargets(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_plat, m_logger, enableVerboseLogging, tuning, &addedFunctions);
		});
	}

	if (enableOrphanCodeScan)
	{
		timePass("Orphan code block scan", [&]()
		{
			ScanForOrphanCodeBlocks(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_plat, m_logger, enableVerboseLogging, tuning, orphanMinValidInstr, orphanMinBodyInstr,
				orphanMinSpacingBytes, orphanMaxPerPage, orphanRequirePrologue, &addedFunctions);
		});
	}

	if (!addedFunctions.empty())
		seededFunctions.insert(addedFunctions.begin(), addedFunctions.end());

	if (enableClearAutoDataOnCodeRefs && !addedFunctions.empty())
	{
		FirmwareScanContext scanCtx{reader, fileData, fileDataLen, m_endian, imageBase, length,
			m_arch, m_plat, m_logger, enableVerboseLogging, this};
		timePass("Clear auto data in new function entry blocks", [&]()
		{
			ClearAutoDataInFunctionEntryBlocks(scanCtx, &addedFunctions);
		});
	}

	if (enableInvalidFunctionCleanup)
	{
		std::set<uint64_t> protectedStarts = seededFunctions;
		timePass("Cleanup invalid functions", [&]()
		{
			CleanupInvalidFunctions(this, fileData, fileDataLen, m_endian, imageBase, length,
				m_logger, enableVerboseLogging, tuning, cleanupMaxSizeBytes,
				cleanupRequireZeroRefs, cleanupRequirePcWriteStart, m_entryPoint, protectedStarts);
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
	{
		std::lock_guard<std::mutex> lock(FirmwareViewMutex());
		auto& map = FirmwareViewMap();
		auto it = map.find(view->GetObject());
		if (it != map.end())
			firmwareView = it->second;
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

	settings->RegisterSetting("loader.armv5.firmware.scanPrologues",
		R"({
		"title" : "Scan for function prologues",
		"type" : "boolean",
		"default" : true,
		"description" : "Discover additional function entry points by scanning for common prologue patterns."
		})");
	settings->RegisterSetting("loader.armv5.firmware.scanCallTargets",
		R"({
		"title" : "Scan for call targets",
		"type" : "boolean",
		"default" : true,
		"description" : "Discover additional function entry points from direct call and indirect branch targets."
		})");
	settings->RegisterSetting("loader.armv5.firmware.scanPointerTargets",
		R"({
		"title" : "Scan for pointer targets",
		"type" : "boolean",
		"default" : true,
		"description" : "Discover function entry points referenced by data pointers."
		})");
	settings->RegisterSetting("loader.armv5.firmware.scanOrphanCode",
		R"({
		"title" : "Scan for orphan code blocks",
		"type" : "boolean",
		"default" : true,
		"description" : "Discover unreachable functions post-analysis by finding orphaned code blocks and basic block boundaries."
		})");
	settings->RegisterSetting("loader.armv5.firmware.orphanMinValidInstr",
		R"({
		"title" : "Orphan scan min valid instructions",
		"type" : "number",
		"default" : 6,
		"min" : 1,
		"max" : 16,
		"description" : "Minimum consecutive valid ARM instructions required for an orphan code candidate."
		})");
	settings->RegisterSetting("loader.armv5.firmware.orphanMinBodyInstr",
		R"({
		"title" : "Orphan scan min body instructions",
		"type" : "number",
		"default" : 2,
		"min" : 0,
		"max" : 16,
		"description" : "Minimum valid instructions after the candidate prologue when validating orphan code."
		})");
	settings->RegisterSetting("loader.armv5.firmware.orphanMinSpacingBytes",
		R"({
		"title" : "Orphan scan min spacing bytes",
		"type" : "number",
		"default" : 128,
		"min" : 0,
		"max" : 4096,
		"description" : "Minimum spacing between orphan functions added during the post-analysis scan."
		})");
	settings->RegisterSetting("loader.armv5.firmware.orphanMaxPerPage",
		R"({
		"title" : "Orphan scan max per 4KB page",
		"type" : "number",
		"default" : 6,
		"min" : 0,
		"max" : 64,
		"description" : "Maximum orphan functions to add per 4KB page (0 disables the cap)."
		})");
	settings->RegisterSetting("loader.armv5.firmware.partialLinearSweep",
		R"({
		"title" : "Partial linear sweep",
		"type" : "boolean",
		"default" : true,
		"description" : "Enable Binary Ninja's partial linear sweep (no CFG pass) alongside the firmware scans."
		})");
	settings->RegisterSetting("loader.armv5.firmware.skipFirmwareScans",
		R"({
		"title" : "Skip firmware scans",
		"type" : "boolean",
		"default" : false,
		"description" : "Disable the firmware-specific pointer/orphan/call scans so only the core sweep runs."
		})");
	settings->RegisterSetting("loader.armv5.firmware.orphanRequirePrologue",
		R"({
		"title" : "Orphan scan require prologue",
		"type" : "boolean",
		"default" : true,
		"description" : "Require a prologue-like instruction at the candidate start to reduce false positives."
		})");
	settings->RegisterSetting("loader.armv5.firmware.scanRawPointerTables",
		R"({
		"title" : "Scan raw pointer tables",
		"type" : "boolean",
		"default" : true,
		"description" : "Scan untyped data for runs of pointers into code to recover function starts when pointer sweep is disabled."
		})");
	settings->RegisterSetting("loader.armv5.firmware.rawPointerTableMinRun",
		R"({
		"title" : "Raw pointer table min run",
		"type" : "number",
		"default" : 3,
		"min" : 1,
		"max" : 16,
		"description" : "Minimum consecutive pointers required to treat a region as a pointer table."
		})");
	settings->RegisterSetting("loader.armv5.firmware.rawPointerTableRequireCodeRefs",
		R"({
		"title" : "Raw pointer table require code refs",
		"type" : "boolean",
		"default" : true,
		"description" : "Require at least one code reference into a raw pointer table before using it."
		})");
	settings->RegisterSetting("loader.armv5.firmware.rawPointerTableAllowInCode",
		R"({
		"title" : "Raw pointer table allow in code",
		"type" : "boolean",
		"default" : false,
		"description" : "Allow raw pointer tables inside code semantics when code references are not required."
		})");
	settings->RegisterSetting("loader.armv5.firmware.callScanRequireInFunction",
		R"({
		"title" : "Call scan require in-function",
		"type" : "boolean",
		"default" : false,
		"description" : "Restrict call-target scanning to instructions already inside functions."
		})");
	settings->RegisterSetting("loader.armv5.firmware.disablePointerSweep",
		R"({
		"title" : "Disable core pointer sweep",
		"type" : "boolean",
		"default" : false,
		"description" : "Disable Binary Ninja's core pointer sweep (analysis.pointerSweep.autorun) to reduce false positives in raw firmware blobs."
		})");
	settings->RegisterSetting("loader.armv5.firmware.disableLinearSweep",
		R"({
		"title" : "Disable core linear sweep",
		"type" : "boolean",
		"default" : false,
		"description" : "Disable Binary Ninja's core linear sweep so firmware scans drive function discovery."
		})");
	settings->RegisterSetting("loader.armv5.firmware.cleanupInvalidFunctions",
		R"({
		"title" : "Cleanup invalid functions",
		"type" : "boolean",
		"default" : true,
		"description" : "Remove tiny auto-discovered functions that fail ARMv5 validation checks after analysis."
		})");
	settings->RegisterSetting("loader.armv5.firmware.cleanupInvalidMaxSize",
		R"({
		"title" : "Cleanup invalid max size",
		"type" : "number",
		"default" : 8,
		"min" : 4,
		"max" : 32,
		"description" : "Maximum size (bytes) for functions eligible for invalid cleanup."
		})");
	settings->RegisterSetting("loader.armv5.firmware.cleanupInvalidRequireZeroRefs",
		R"({
		"title" : "Cleanup invalid require zero refs",
		"type" : "boolean",
		"default" : true,
		"description" : "Only remove invalid functions with no incoming code references."
		})");
	settings->RegisterSetting("loader.armv5.firmware.cleanupInvalidRequirePcWrite",
		R"({
		"title" : "Cleanup invalid require PC write",
		"type" : "boolean",
		"default" : true,
		"description" : "Only remove invalid functions whose first instruction writes PC."
		})");
	settings->RegisterSetting("loader.armv5.firmware.typeLiteralPools",
		R"({
		"title" : "Type literal pool entries",
		"type" : "boolean",
		"default" : true,
		"description" : "Define literal pool entries as data to avoid disassembling them as code."
		})");
	settings->RegisterSetting("loader.armv5.firmware.clearAutoDataOnCodeRefs",
		R"({
		"title" : "Clear auto data on code references",
		"type" : "boolean",
		"default" : true,
		"description" : "Undefine auto-discovered data at code-referenced addresses when nearby bytes decode as valid instructions."
		})");
	settings->RegisterSetting("loader.armv5.firmware.verboseLogging",
		R"({
		"title" : "Verbose firmware analysis logging",
		"type" : "boolean",
		"default" : true,
		"description" : "Emit per-pass summary logs for firmware analysis heuristics without enabling global debug logging."
		})");
	settings->RegisterSetting("loader.armv5.firmware.scanMinValidInstr",
		R"({
		"title" : "Scan minimum valid instructions",
		"type" : "number",
		"default" : 2,
		"min" : 1,
		"max" : 16,
		"description" : "Minimum number of consecutive valid ARM instructions required to accept a firmware scan candidate."
		})");
	settings->RegisterSetting("loader.armv5.firmware.scanMinBodyInstr",
		R"({
		"title" : "Scan minimum body instructions",
		"type" : "number",
		"default" : 1,
		"min" : 0,
		"max" : 16,
		"description" : "Minimum number of valid instructions after the prologue when validating a scan candidate."
		})");
	settings->RegisterSetting("loader.armv5.firmware.scanMaxLiteralRun",
		R"({
		"title" : "Scan max literal run",
		"type" : "number",
		"default" : 2,
		"min" : 0,
		"max" : 16,
		"description" : "Maximum consecutive PC-relative literal loads allowed in the validation window."
		})");

	// Allow overriding image base and platform
	vector<string> overrides = {"loader.imageBase", "loader.platform"};
	for (const auto& override : overrides)
	{
		if (settings->Contains(override))
			settings->UpdateProperty(override, "readOnly", false);
	}

	// Auto-detect image base from vector table if the addresses are absolute
	uint64_t detectedBase = DetectImageBaseFromVectorTable(data);
	if (detectedBase != 0 && settings->Contains("loader.imageBase"))
	{
		settings->Set("loader.imageBase", detectedBase, viewRef);
		m_logger->LogInfo("Auto-detected image base: 0x%llx", (unsigned long long)detectedBase);
	}

	return settings;
}
