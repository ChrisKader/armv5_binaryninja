/*
 * ARMv5 Firmware Vector Table Helpers
 */

#include "firmware_internal.h"

using namespace std;
using namespace BinaryNinja;

// Helper to auto-detect image base from vector table
// Returns detected image base, or 0 if not detectable
//
// The vector table contains absolute addresses to handlers. If we can find where
// a handler is in the file, we can calculate: imageBase = handlerAddr - fileOffset
uint64_t DetectImageBaseFromVectorTable(BinaryView* data)
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

// Helper to resolve a vector table entry to a handler address
// Returns the target address, or 0 if not resolvable
uint64_t ResolveVectorEntry(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
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
