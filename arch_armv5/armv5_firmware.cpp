/*
 * ARMv5 Firmware BinaryViewType
 *
 * Custom BinaryViewType for bare metal ARM firmware detection.
 * Detects ARM binaries by looking for vector table patterns at offset 0.
 */

#include "armv5_firmware.h"
#include "armv5_disasm/armv5.h"
#include <set>
#include <map>
#include <cstring>

using namespace std;
using namespace BinaryNinja;


static inline uint32_t Swap32(uint32_t value)
{
	return ((value & 0xff000000) >> 24) |
		((value & 0x00ff0000) >> 8) |
		((value & 0x0000ff00) << 8) |
		((value & 0x000000ff) << 24);
}

static constexpr uint64_t kMaxBufferedLength = 64ULL * 1024 * 1024;

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
	BinaryView* view;

	uint64_t ImageEnd() const { return imageBase + length; }
};

static bool ReadU32At(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t offset, uint32_t& out)
{
	if (data && offset + 4 <= dataLen)
	{
		memcpy(&out, data + offset, sizeof(out));
		if (endian == BigEndian)
			out = Swap32(out);
		return true;
	}
	reader.Seek(offset);
	out = reader.Read32();
	return true;
}

static Armv5FirmwareViewType* g_armv5FirmwareViewType = nullptr;


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
	m_parseOnly(parseOnly), m_entryPoint(0), m_endian(LittleEndian), m_addressSize(4)
{
	CreateLogger("BinaryView");
	m_logger = CreateLogger("BinaryView.ARMv5FirmwareView");
}


Armv5FirmwareView::~Armv5FirmwareView()
{
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
	uint32_t firstInstr = words[0];

	// Check for LDR PC, [PC, #imm] pattern
	if ((firstInstr & 0xFFFFF000) != 0xE59FF000)
		return 0;

	// Read the reset handler address (vector 0 - most reliable)
	uint32_t vecOffset = firstInstr & 0xFFF;
	uint64_t ptrAddr = 8 + vecOffset;  // PC + 8 + offset

	if (ptrAddr + 4 > length)
		return 0;

	DataBuffer ptrBuf = data->ReadBuffer(ptrAddr, 4);
	if (ptrBuf.GetLength() < 4)
		return 0;

	uint32_t resetHandlerAddr = *(const uint32_t*)ptrBuf.GetData();
	resetHandlerAddr &= ~1u;  // Mask off Thumb bit

	// If the handler address is within the file length, it's already file-relative
	if (resetHandlerAddr < length)
		return 0;

	// The handler address is absolute. We need to find where in the file
	// this handler's code actually lives.
	//
	// Strategy: The vector table pointer area ends around 0x20-0x3F.
	// Code typically starts at 0x40 or later. Look for a function prologue
	// (PUSH, STMFD, etc.) starting from 0x40 and assume that's where
	// the lowest handler begins.
	//
	// A simpler approach: if all handler addresses share a common high portion,
	// that's the image base. For example:
	//   0x11217480, 0x1121bf10, 0x1121bf4c -> common prefix 0x11200000
	//
	// We'll find the minimum handler address and see how far into the file
	// it could reasonably be, then calculate the base.

	// Collect all handler addresses (only those that are absolute, i.e., >= file length)
	uint64_t minHandlerAddr = resetHandlerAddr;
	for (int i = 1; i < 8; i++)
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
					if (addr >= length && addr < minHandlerAddr)
						minHandlerAddr = addr;
				}
			}
		}
	}

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


/*
 * Scan for ARM function prologues and add them as entry points.
 *
 * This provides more accurate function detection than Binary Ninja's generic
 * linear sweep, which over-detects due to ARM's dense instruction encoding.
 *
 * Detected ARM function prologues:
 *
 * Pattern 1: STMFD/PUSH sp!, {..., lr} with 3+ registers including callee-saved
 *   Encoding: 0xE92D4xxx where reglist includes r4-r11
 *   Example: push {r4, r5, lr} = 0xE92D4030
 *
 * Pattern 1b: STMFD/PUSH sp!, {r0-r3, ip, lr} with 3+ scratch registers only
 *   Encoding: 0xE92D4xxx where reglist has 3+ regs but no r4-r11
 *   Example: push {r0, r1, r2, lr} = 0xE92D4007
 *   Common for wrapper/thunk functions that save args before a call
 *
 * Pattern 2: STMFD/PUSH sp!, {rX, lr} with 2 registers
 *   Encoding: 0xE92D40xx where popcount(reglist) == 2
 *   Example: push {r4, lr} = 0xE92D4010
 *   Common for small leaf functions that only need one callee-saved register
 *
 * Pattern 3: MOV ip, sp followed by STMFD with fp and lr
 *   Encoding: 0xE1A0C00D followed by 0xE92Dxxxx with bits 11 and 14 set
 *   Classic APCS frame pointer setup prologue
 *
 * Pattern 4: STR lr, [sp, #-4]! followed by SUB sp, sp, #imm
 *   Encoding: 0xE52DE004 followed by 0xE24DD0xx
 *   Two-instruction prologue for stack frame allocation
 *   Example: str lr, [sp, #-4]! + sub sp, sp, #0x2c
 *
 * Pattern 5: MRS Rx, CPSR (when preceded by a return instruction)
 *   Encoding: 0xE10Fx000 (MRS Rd, CPSR)
 *   Interrupt enable/disable utility functions
 *   Only detected when immediately following BX LR, MOV PC LR, or POP {..., pc}
 *
 * Pattern 6: MOV/MVN Rd, #imm followed by BX LR (short return-value function)
 *   Encoding: 0xE3A0xxxx or 0xE3E0xxxx followed by 0xE12FFF1E
 *   Example: mov r0, #0 + bx lr (return 0 function)
 *   Only detected when preceded by a return instruction (function boundary)
 *
 * Pattern 7: MCR/MRC (coprocessor access) when preceded by a return
 *   Encoding: 0xEE....10 (MCR) or 0xEE....10 (MRC)
 *   System register accessor functions (CP15, etc.)
 *   Only detected when immediately following a return instruction
 *
 * NOT detected (high false positive rate):
 *   - STR lr, [sp, #-4]! alone (appears in data as SRAM addresses 0xE52Dxxxx)
 *   - Thumb prologues (0xB5xx appears frequently in ARM literals)
 *   - MOV/LDR after return without verification (could be data)
 *
 * Returns the number of function prologues found.
 */
static size_t ScanForFunctionPrologues(BinaryView* view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	Ref<Architecture> armArch, Ref<Architecture> thumbArch, Ref<Platform> plat, Ref<Logger> logger)
{
	size_t prologuesFound = 0;

	// Minimum offset to start scanning (skip vector table area)
	uint64_t startOffset = 0x40;

	// Track addresses we've already added to avoid duplicates
	std::set<uint64_t> addedAddrs;

	// Helper to add a function if not already added
	auto addFunction = [&](uint64_t funcAddr) {
		if (addedAddrs.find(funcAddr) == addedAddrs.end())
		{
			view->AddFunctionForAnalysis(plat, funcAddr);
			addedAddrs.insert(funcAddr);
			prologuesFound++;
		}
	};

	logger->LogInfo("Prologue scan: Scanning for function prologues in %llu bytes",
		(unsigned long long)(length - startOffset));

	// Track the previous instruction for MRS detection
	uint32_t prevInstr = 0;

	// Scan for ARM prologues (4-byte aligned)
	for (uint64_t offset = startOffset; offset + 4 <= length; offset += 4)
	{
		uint32_t instr = 0;
		if (offset + 4 <= dataLen)
		{
			memcpy(&instr, data + offset, sizeof(instr));
			if (endian == BigEndian)
				instr = Swap32(instr);
		}

		bool isPrologue = false;

		// Pattern 1, 1b & 2: STMFD/STMDB/PUSH sp!, {..., lr}
		// Encoding: cond 100 P U S W L Rn reglist
		// STMFD sp! = 1001 0010 1101 xxxx = 0xE92Dxxxx
		// Must have LR (bit 14) in register list
		if ((instr & 0xFFFF0000) == 0xE92D0000 && (instr & 0x4000) != 0)
		{
			uint32_t reglist = instr & 0xFFFF;
			int regCount = __builtin_popcount(reglist);

			// Pattern 1: 3+ registers with at least one callee-saved (r4-r11)
			// This is the most common prologue pattern
			bool hasCalleeSaved = (reglist & 0x0FF0) != 0;
			if (regCount >= 3 && hasCalleeSaved)
				isPrologue = true;

			// Pattern 1b: 3+ registers with scratch only (r0-r3, ip)
			// Common for wrapper/thunk functions: push {r0, r1, r2, lr}
			// These save args before calling another function
			if (regCount >= 3 && !hasCalleeSaved)
				isPrologue = true;

			// Pattern 2: Exactly 2 registers including lr
			// Common for small leaf functions: push {r4, lr}, push {r3, lr}, etc.
			// Less restrictive - accepts any 2-register push with lr
			if (regCount == 2)
				isPrologue = true;
		}

		// Pattern 3: MOV ip, sp followed by STMFD with fp and lr
		// This is the classic APCS prologue
		// Very reliable as the two-instruction sequence is unlikely to appear in data
		if (instr == 0xE1A0C00D)
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
		// This two-instruction sequence is very reliable and won't match data
		if (instr == 0xE52DE004)
		{
			if (offset + 8 <= dataLen)
			{
				uint32_t nextInstr = 0;
				memcpy(&nextInstr, data + offset + 4, sizeof(nextInstr));
				if (endian == BigEndian)
					nextInstr = Swap32(nextInstr);

				// SUB sp, sp, #imm = 0xE24DD0xx
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
			// Check if previous instruction was a return
			bool prevIsReturn = false;

			// BX LR = 0xE12FFF1E (or conditional variants)
			if ((prevInstr & 0x0FFFFFFF) == 0x012FFF1E)
				prevIsReturn = true;

			// MOV PC, LR = 0xE1A0F00E
			if (prevInstr == 0xE1A0F00E)
				prevIsReturn = true;

			// LDMFD sp!, {..., pc} = 0xE8BD8xxx (POP with pc)
			if ((prevInstr & 0xFFFF0000) == 0xE8BD0000 && (prevInstr & 0x8000))
				prevIsReturn = true;

			if (prevIsReturn)
				isPrologue = true;
		}

		// Pattern 6: MOV/MVN Rd, #imm followed by BX LR (short return-value function)
		// These are small functions that just return a constant value
		// Very reliable as we verify both the MOV/MVN and the following BX LR
		// Only detected when preceded by a return (function boundary)
		if ((instr & 0x0FE00000) == 0x03A00000 || (instr & 0x0FE00000) == 0x03E00000)
		{
			// Check if preceded by a return
			bool prevIsReturn = false;
			if ((prevInstr & 0x0FFFFFFF) == 0x012FFF1E)
				prevIsReturn = true;
			if (prevInstr == 0xE1A0F00E)
				prevIsReturn = true;
			if ((prevInstr & 0xFFFF0000) == 0xE8BD0000 && (prevInstr & 0x8000))
				prevIsReturn = true;

			if (prevIsReturn && offset + 8 <= dataLen)
			{
				// Check if followed by BX LR
				uint32_t nextInstr = 0;
				memcpy(&nextInstr, data + offset + 4, sizeof(nextInstr));
				if (endian == BigEndian)
					nextInstr = Swap32(nextInstr);

				// BX LR = 0xE12FFF1E (or conditional)
				if ((nextInstr & 0x0FFFFFFF) == 0x012FFF1E)
					isPrologue = true;
			}
		}

		// Pattern 7: MCR/MRC (coprocessor access) when preceded by a return
		// These are small system register accessor functions
		// MCR: cond 1110 opc1 0 CRn Rt coproc opc2 1 CRm
		// MRC: cond 1110 opc1 1 CRn Rt coproc opc2 1 CRm
		// Mask: check for 0xEE......1. pattern
		if ((instr & 0x0F000010) == 0x0E000010)
		{
			// Check if preceded by a return
			bool prevIsReturn = false;
			if ((prevInstr & 0x0FFFFFFF) == 0x012FFF1E)
				prevIsReturn = true;
			if (prevInstr == 0xE1A0F00E)
				prevIsReturn = true;
			if ((prevInstr & 0xFFFF0000) == 0xE8BD0000 && (prevInstr & 0x8000))
				prevIsReturn = true;

			if (prevIsReturn)
				isPrologue = true;
		}

		if (isPrologue)
		{
			addFunction(imageBase + offset);
		}

		// Remember this instruction for next iteration
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
	return prologuesFound;
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
		ReadU32At(reader, data, dataLen, endian, offset, instr1);
		ReadU32At(reader, data, dataLen, endian, offset + 4, instr2);

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
				ReadU32At(reader, data, dataLen, endian, offset - (i * 4), prevInstr);

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
						ReadU32At(reader, data, dataLen, endian, litAddr, value);
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
	BNEndianness endian, uint64_t addr, uint64_t aliasBase, const RomToSramCopy& romCopy, uint32_t& out)
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
		return ReadU32At(reader, data, dataLen, endian, romAddr, out);
	}

	// For addresses within the file, read directly
	// Handle aliased addresses by stripping the high byte
	uint64_t readAddr = addr;
	if (aliasBase != 0 && (addr & 0xFF000000) == aliasBase)
	{
		readAddr = addr & 0x00FFFFFF;
	}

	return ReadU32At(reader, data, dataLen, endian, readAddr, out);
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
		ReadU32At(reader, data, dataLen, endian, offset, instr);

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
				ReadU32At(reader, data, dataLen, endian, offset - (i * 4), prevInstr);

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
						ReadU32At(reader, data, dataLen, endian, literalAddr, value);
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
		ReadU32At(reader, data, dataLen, endian, ttbrFileOffset + (i * 4), descriptor);

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
			ReadU32At(reader, data, dataLen, endian, off, instr);

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
					ReadU32At(reader, data, dataLen, endian, litAddr, value);
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
			ReadU32Smart(reader, data, dataLen, endian, val1, discoveredAliasBase, romCopy, firstEntry);
			ReadU32Smart(reader, data, dataLen, endian, val1 + 4, discoveredAliasBase, romCopy, secondEntry);
			ReadU32Smart(reader, data, dataLen, endian, val1 + 8, discoveredAliasBase, romCopy, thirdEntry);

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
				ReadU32Smart(reader, data, dataLen, endian, entryAddr, discoveredAliasBase, romCopy, entry1);
				if (!isIdentity)
					ReadU32Smart(reader, data, dataLen, endian, entryAddr + 4, discoveredAliasBase, romCopy, entry2);

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
	ReadU32At(reader, data, dataLen, endian, vectorOffset, instr);

	// LDR PC, [PC, #imm] - 0xE59FF0xx
	if ((instr & 0xFFFFF000) == 0xE59FF000)
	{
		uint32_t offset = instr & 0xFFF;
		// PC is 8 bytes ahead when executing, relative to instruction address
		uint64_t pointerAddr = vectorOffset + 8 + offset;

		if (pointerAddr + 4 <= length)
		{
			uint32_t handlerAddr = 0;
			ReadU32At(reader, data, dataLen, endian, pointerAddr, handlerAddr);
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

// Scan for PC-relative loads and type their literal pool entries as pointers
// This helps Binary Ninja display MMIO addresses correctly instead of as negative ints
static void TypeLiteralPoolEntries(const FirmwareScanContext& ctx)
{
	ctx.logger->LogDebug("Typing literal pool entries...");

	Ref<Type> ptrType = Type::PointerType(ctx.arch, Type::VoidType());
	uint32_t entriesTyped = 0;

	for (uint64_t offset = 0; offset + 4 <= ctx.length; offset += 4)
	{
		uint32_t instr = 0;
		ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, instr);

		// LDR Rd, [PC, #imm] - pattern: cond 01 0 P U 0 W 1 1111 Rd imm12
		// We want P=1, W=0 (offset addressing, no writeback), Rn=PC (1111)
		// Mask: 0x0F7F0000, expect: 0x051F0000
		if ((instr & 0x0F7F0000) == 0x051F0000)
		{
			uint32_t imm12 = instr & 0xFFF;
			bool add = (instr & 0x00800000) != 0;
			uint64_t pc = offset + 8;  // PC is 8 bytes ahead
			uint64_t literalOffset = add ? (pc + imm12) : (pc - imm12);

			if (literalOffset + 4 <= ctx.length)
			{
				uint32_t value = 0;
				ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, literalOffset, value);

				// If it looks like an MMIO pointer, type it as void*
				if (IsLikelyMMIOPointer(value, ctx.imageBase, ctx.ImageEnd()))
				{
					uint64_t literalAddr = ctx.imageBase + literalOffset;
					ctx.view->DefineDataVariable(literalAddr, ptrType);
					entriesTyped++;
				}
			}
		}
	}

	ctx.logger->LogInfo("Typed %u literal pool entries as pointers", entriesTyped);
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
		ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, instr);

		// ADD PC, PC, Rn (computed jump for switch tables)
		if ((instr & 0x0FFFF010) == 0x008FF000)
		{
			uint64_t tableBase = 0;
			uint32_t maxCases = 0;

			for (int i = 1; i <= 16 && offset >= (uint64_t)(i * 4); i++)
			{
				uint32_t scanInstr = 0;
				ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset - (i * 4), scanInstr);

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
					ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, entryFileOffset, entryValue);
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

	// Get load settings if available
	Ref<Settings> settings = GetLoadSettings(GetTypeName());
	if (settings && settings->Contains("loader.imageBase"))
	{
		imageBase = settings->Get<uint64_t>("loader.imageBase", this);
		imageBaseFromUser = (imageBase != 0);
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
	// Rest: DefaultSectionSemantics - rely on recursive descent from entry points
	// Using ReadOnlyCodeSectionSemantics would trigger linear sweep which creates
	// many false functions when data is embedded in code sections
	AddAutoSection("vectors", imageBase, 0x20, ReadOnlyCodeSectionSemantics);
	AddAutoSection("vector_ptrs", imageBase + 0x20, 0x20, ReadOnlyDataSectionSemantics);
	AddAutoSection("code", imageBase + 0x40, length - 0x40, DefaultSectionSemantics);

	if (m_arch && m_plat)
	{
		SetDefaultArchitecture(m_arch);
		SetDefaultPlatform(m_plat);
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
		ReadU32At(reader, fileData, fileDataLen, m_endian, 0, firstInstr);
		if ((firstInstr & 0xFFFFF000) == 0xE59FF000)
		{
			// LDR PC style - there's a pointer table
			// Define pointer table entries as void* data
			for (int i = 0; i < 8; i++)
			{
				// Calculate where this vector's pointer should be
				// Each vector is at offset i*4, PC is i*4+8, so pointer is at i*4+8+offset
				uint32_t vecInstr = 0;
				ReadU32At(reader, fileData, fileDataLen, m_endian, i * 4, vecInstr);
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
		// Add vector table entries as functions (they contain LDR PC or B instructions)
		for (int i = 0; i < 8; i++)
		{
			uint64_t vectorAddr = imageBase + (i * 4);
			AddFunctionForAnalysis(m_plat, vectorAddr);
		}

		// Add resolved handler functions
		for (int i = 0; i < 8; i++)
		{
			if (handlerAddrs[i] != 0 && handlerAddrs[i] >= imageBase && handlerAddrs[i] < imageBase + length)
			{
				AddFunctionForAnalysis(m_plat, handlerAddrs[i]);
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
					ReadU32At(reader, fileData, fileDataLen, m_endian, handlerOffset + (instrIdx * 4), instr);

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
							AddFunctionForAnalysis(m_plat, cleanupAddr);

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
		AnalyzeMMUConfiguration(this, reader, fileData, fileDataLen, m_endian, imageBase, length, m_logger);

		// Scan for reliable function prologues to seed recursive descent analysis.
		// This uses conservative patterns to minimize false positives:
		// - STMFD with 3+ registers including callee-saved regs
		// - MOV ip, sp + STMFD (APCS prologue)
		// These high-confidence entry points are then expanded via call graph traversal.
		Ref<Architecture> thumbArch = Architecture::GetByName("armv5t");
		ScanForFunctionPrologues(this, fileData, fileDataLen, m_endian, imageBase, length,
			m_arch, thumbArch, m_plat, m_logger);

		// NOTE: Exception handlers are named (irq_handler, fiq_handler, etc.) but we
		// don't auto-apply the irq-handler calling convention. Users can apply it
		// manually if needed. This follows the pattern of other architecture plugins.
	}

	return true;
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

		// Skip values that look like addresses (pointers in literal pools)
		// Common patterns: 0x10xxxxxx, 0x00xxxxxx (within typical firmware range)
		if ((instr & 0xFF000000) == 0x10000000 || (instr & 0xFFF00000) == 0x00000000)
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
