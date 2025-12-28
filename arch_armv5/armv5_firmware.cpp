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


// Analyze MMU configuration to discover memory regions
// Looks for MCR p15, 0, Rx, c2, c0, 0 (write to TTBR) and parses the translation table
static void AnalyzeMMUConfiguration(BinaryView* view, BinaryReader& reader, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length, Ref<Logger> logger)
{
	uint64_t ttbrValue = 0;
	uint64_t ttbrInstrAddr = 0;

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
			// Look for LDR Rt, [PC, #imm] or MOV Rt, #imm patterns
			// Search up to 128 instructions back (covers typical MMU setup functions)
			for (int i = 1; i <= 128 && offset >= (uint64_t)(i * 4); i++)
			{
				uint32_t prevInstr = 0;
				ReadU32At(reader, data, dataLen, endian, offset - (i * 4), prevInstr);

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
	// Handle common physical address alias patterns:
	// - 0xa4xxxxxx is often a physical alias of 0x00xxxxxx (uncached view of internal RAM)
	// - This is common on ARM926EJ-S and similar embedded processors
	uint64_t ttbrFileOffset = 0;
	bool ttbrInFile = false;
	uint64_t ttbrVirtBase = ttbrBase;  // Virtual address for symbols

	if (ttbrBase >= imageBase && ttbrBase < imageBase + length)
	{
		ttbrFileOffset = ttbrBase - imageBase;
		ttbrInFile = true;
	}
	else if ((ttbrBase & 0xFF000000) == 0xA4000000)
	{
		// Physical address alias: 0xa4xxxxxx -> 0x00xxxxxx
		uint64_t aliasedAddr = ttbrBase & 0x00FFFFFF;
		logger->LogInfo("MMU: TTBR 0x%llx appears to be physical alias of 0x%llx",
			(unsigned long long)ttbrBase, (unsigned long long)aliasedAddr);

		if (aliasedAddr >= imageBase && aliasedAddr < imageBase + length)
		{
			ttbrFileOffset = aliasedAddr - imageBase;
			ttbrInFile = true;
			ttbrVirtBase = imageBase + ttbrFileOffset;  // Use virtual address for symbols
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
		logger->LogInfo("MMU: Translation table is uninitialized (all fault/0x0FF59FF0 entries)");
		logger->LogInfo("MMU: Analyzing MMU setup code to extract memory regions...");

		// The translation table is empty - it gets populated at runtime.
		// From code analysis (see MMU.md):
		//
		// Phase 1: Entire 4GB filled with descriptor 0xXXX00032:
		//   - Strongly-ordered device memory
		//   - Execute-Never (XN=1)
		//   - No access (AP=0)
		//   - This is the "default deny" - everything inaccessible
		//
		// Phase 2: Specific regions overridden from config tables:
		//   - 0x00000c12: MMIO (Strongly-ordered, XN=1, AP=3 full access)
		//   - Other descriptors loaded from RAM tables at runtime
		//
		// Known physical address aliasing:
		//   - 0xA4xxxxxx -> 0x00xxxxxx (uncached view of internal RAM)

		// Scan for MOV instructions that set descriptor templates
		// to understand what memory types are configured
		bool foundMMIODescriptor = false;

		// Look for the 0x00000c12 descriptor (MMIO with full access)
		// Limit scan to avoid excessive processing time
		uint64_t scanLimit = (length > 0x20000) ? 0x20000 : length;
		for (uint64_t off = 0; off + 4 <= scanLimit; off += 4)
		{
			uint32_t instr = 0;
			ReadU32At(reader, data, dataLen, endian, off, instr);

			// LDR Rd, [PC, #imm]: look for descriptor loads
			if ((instr & 0x0F7F0000) == 0x051F0000)
			{
				uint32_t imm12 = instr & 0xFFF;
				bool add = (instr & 0x00800000) != 0;
				uint64_t pcVal = off + 8;
				uint64_t litAddr = add ? (pcVal + imm12) : (pcVal - imm12);

				// Ensure we can read 4 bytes from litAddr
				if (litAddr + 4 <= length)
				{
					uint32_t value = 0;
					ReadU32At(reader, data, dataLen, endian, litAddr, value);

					// Check for 0x00000c12 (MMIO descriptor)
					if (value == 0x00000c12)
					{
						foundMMIODescriptor = true;
						logger->LogInfo("MMU: Found MMIO descriptor 0x00000c12 at 0x%llx",
							(unsigned long long)litAddr);
						break;  // Found what we need, stop scanning
					}
				}
			}
		}

		// Create memory regions based on analysis
		// The ROM region (0x00000000) is already covered by our main segment

		// MMIO/Peripheral region - common on ARM926EJ-S
		// Based on descriptor 0x00000c12: Strongly-ordered, XN=1, AP=3
		if (foundMMIODescriptor)
		{
			// Standard ARM peripheral ranges
			regions.push_back({0x40000000, 0x40000000, 0x10000000,
				true, true, false, false, false, "Peripherals"});

			logger->LogInfo("MMU: Added peripheral region 0x40000000-0x4FFFFFFF");
		}

		// Physical address alias region (uncached view of internal RAM)
		// This is confirmed by the TTBR value 0xA4034000 -> 0x00034000
		regions.push_back({0xA4000000, 0x00000000, 0x01000000,
			true, true, true, false, false, "Uncached alias"});

		logger->LogInfo("MMU: Added uncached alias region 0xA4000000-0xA4FFFFFF");

		logger->LogInfo("MMU: Created %zu memory regions from code analysis", regions.size());
	}
	else
	{
		logger->LogInfo("MMU: Found %zu memory regions from translation table", regions.size());
	}

	// Log what we found but don't create segments for now
	// Creating segments without backing data was causing crashes
	logger->LogInfo("MMU: Analysis complete. Found %zu memory regions:", regions.size());
	for (const auto& region : regions)
	{
		if (region.size == 0)
			continue;

		logger->LogInfo("MMU:   0x%08llx-0x%08llx (%s) %s%s%s",
			(unsigned long long)region.virtBase,
			(unsigned long long)(region.virtBase + region.size - 1),
			region.type ? region.type : "unknown",
			region.readable ? "R" : "-",
			region.writable ? "W" : "-",
			region.executable ? "X" : "-");
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
