/*
 * ARMv5 Firmware MMU Analysis
 */

#include "firmware_internal.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

using namespace std;
using namespace BinaryNinja;

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
void AnalyzeMMUConfiguration(const Ref<BinaryView>& view, BinaryReader& reader, const uint8_t* data,
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
			ttbrInstrAddr = offset;

			logger->LogInfo("MMU: Found TTBR write at 0x%llx (MCR p15,0,R%d,c2,c0,0)",
				(unsigned long long)offset, rt);

			// We need to find the value loaded into Rt
			// Scan backwards for MOV/LDR that sets Rt
			for (int i = 1; i <= 8 && offset >= (uint64_t)(i * 4); i++)
			{
				uint32_t prevInstr = 0;
				ReadU32At(reader, data, dataLen, endian, offset - (i * 4), prevInstr, length);

				// MOV Rd, #imm: 0xE3A0xxxx (Rd in bits 15:12)
				if ((prevInstr & 0x0FEF0000) == 0x03A00000 && ((prevInstr >> 12) & 0xF) == rt)
				{
					uint32_t imm12 = prevInstr & 0xFFF;
					uint32_t rotate = (prevInstr >> 8) & 0xF;
					uint32_t imm = (imm12 >> (rotate * 2)) | (imm12 << (32 - rotate * 2));
					ttbrValue = imm;
					logger->LogInfo("MMU: TTBR value loaded via MOV: 0x%08llx",
						(unsigned long long)ttbrValue);
					break;
				}

				// LDR Rd, [PC, #imm]: 0x051F0000 (sub) or 0x059F0000 (add)
				if ((prevInstr & 0x0F7F0000) == 0x051F0000 && ((prevInstr >> 12) & 0xF) == rt)
				{
					uint32_t imm12 = prevInstr & 0xFFF;
					bool add = (prevInstr & 0x00800000) != 0;
					uint64_t pcVal = (offset - (i * 4)) + 8;
					uint64_t litAddr = add ? (pcVal + imm12) : (pcVal - imm12);

					if (litAddr + 4 <= length)
					{
						uint32_t value = 0;
						ReadU32At(reader, data, dataLen, endian, litAddr, value, length);
						ttbrValue = value;
						logger->LogInfo("MMU: TTBR value loaded via literal: 0x%08llx",
							(unsigned long long)ttbrValue);
						break;
					}
				}
			}

			// Save function start for later use (search backward for function prologue)
			// We'll look for a typical prologue pattern within 32 instructions
			for (int i = 1; i <= 32 && offset >= (uint64_t)(i * 4); i++)
			{
				uint32_t prevInstr = 0;
				ReadU32At(reader, data, dataLen, endian, offset - (i * 4), prevInstr, length);

				// Push {.., lr} or STMFD sp!, {.., lr}: 0xE92D4xxx
				if ((prevInstr & 0xFFFF0000) == 0xE92D0000 && (prevInstr & 0x4000))
				{
					mmuSetupFuncStart = offset - (i * 4);
					logger->LogInfo("MMU: Found MMU setup function start at 0x%llx",
						(unsigned long long)mmuSetupFuncStart);
					break;
				}
			}

			break;
		}
	}

	if (ttbrValue == 0)
	{
		logger->LogInfo("MMU: TTBR value not found. Skipping MMU analysis.");
		return;
	}

	// The TTBR value is the base address of the translation table
	// In many firmwares, the high byte is an alias base (e.g., 0xA0xxxxxx)
	// We'll treat the high byte as an alias if it points outside the file
	uint64_t aliasBase = 0;
	if (ttbrValue >= length)
	{
		aliasBase = ttbrValue & 0xFF000000;
		logger->LogInfo("MMU: Using alias base 0x%08llx", (unsigned long long)aliasBase);
	}

	// Find ROM-to-SRAM copy info to read initialized config arrays
	RomToSramCopy romCopy = FindRomToSramCopy(reader, data, dataLen, endian, length, aliasBase, logger);

	// Read translation table entries (coarse page table)
	// Each entry is 4 bytes, with 4096 entries covering 4GB
	uint64_t tableBase = ttbrValue & ~0x3FFF;  // TTBR aligns to 16KB

	logger->LogInfo("MMU: Translation table base = 0x%08llx", (unsigned long long)tableBase);

	// Read the table entries and detect if it's initialized
	// If uninitialized (all zeros or all ones), use config arrays
	bool allZero = true;
	bool allOnes = true;
	uint32_t firstEntries[16] = {0};

	for (int i = 0; i < 16; i++)
	{
		uint32_t entry = 0;
		if (!ReadU32Smart(reader, data, dataLen, endian, tableBase + (i * 4),
			aliasBase, length, romCopy, entry))
			break;

		firstEntries[i] = entry;
		if (entry != 0)
			allZero = false;
		if (entry != 0xFFFFFFFF)
			allOnes = false;
	}

	if (allZero || allOnes)
	{
		logger->LogInfo("MMU: Translation table appears uninitialized (%s)",
			allZero ? "all zeros" : "all ones");

		// Try to find config arrays in the MMU setup function
		std::vector<MMUConfigArray> configArrays;

		// Scan around the MMU setup function (or around TTBR write if no prologue found)
		uint64_t scanStart = (mmuSetupFuncStart != 0) ? mmuSetupFuncStart : ttbrInstrAddr - 0x100;
		uint64_t scanEnd = ttbrInstrAddr + 0x100;

		if (scanStart < 0)
			scanStart = 0;
		if (scanEnd > length)
			scanEnd = length;

		logger->LogInfo("MMU: Scanning 0x%llx - 0x%llx for config arrays",
			(unsigned long long)scanStart, (unsigned long long)scanEnd);

		// Look for LDR instructions that load start/end pointers from literal pool
		for (uint64_t offset = scanStart; offset + 4 <= scanEnd; offset += 4)
		{
			uint32_t instr = 0;
			ReadU32At(reader, data, dataLen, endian, offset, instr, length);

			// LDR Rd, [PC, #imm]: 0x051F0000 (sub) or 0x059F0000 (add)
			if ((instr & 0x0F7F0000) == 0x051F0000)
			{
				uint32_t imm12 = instr & 0xFFF;
				bool add = (instr & 0x00800000) != 0;
				uint64_t pcVal = offset + 8;
				uint64_t litAddr = add ? (pcVal + imm12) : (pcVal - imm12);

				if (litAddr + 4 <= length)
				{
					uint32_t value = 0;
					ReadU32At(reader, data, dataLen, endian, litAddr, value, length);

					// Look for pairs of LDR instructions that load start and end pointers
					// We'll look ahead for another LDR within the next 5 instructions
					for (int i = 1; i <= 5 && offset + (i * 4) + 4 <= scanEnd; i++)
					{
						uint32_t nextInstr = 0;
						ReadU32At(reader, data, dataLen, endian, offset + (i * 4), nextInstr, length);

						if ((nextInstr & 0x0F7F0000) == 0x051F0000)
						{
							uint32_t imm12b = nextInstr & 0xFFF;
							bool addb = (nextInstr & 0x00800000) != 0;
							uint64_t pcValb = offset + (i * 4) + 8;
							uint64_t litAddrb = addb ? (pcValb + imm12b) : (pcValb - imm12b);

							if (litAddrb + 4 <= length)
							{
								uint32_t valueb = 0;
								ReadU32At(reader, data, dataLen, endian, litAddrb, valueb, length);

								// Check if these look like start/end pointers for a config array
								// Start should be < end and within reasonable bounds
								if (value < valueb && (valueb - value) <= 0x10000)
								{
									// Determine if it's identity or VA->PA mapping
									bool isIdentity = ((valueb - value) % 4 == 0);

									MMUConfigArray arr;
									arr.startAddr = value;
									arr.endAddr = valueb;
									arr.isIdentity = isIdentity;
									arr.litPoolAddr1 = litAddr;
									arr.litPoolAddr2 = litAddrb;
									configArrays.push_back(arr);

									logger->LogInfo("MMU: Found config array at 0x%llx-0x%llx (%s)",
										(unsigned long long)value, (unsigned long long)valueb,
										isIdentity ? "identity" : "VA->PA");
								}
							}
						}
					}
				}
			}
		}

		if (configArrays.empty())
		{
			logger->LogInfo("MMU: No config arrays found. Skipping MMU analysis.");
			return;
		}

		// Parse the config arrays to create memory regions
		vector<MemRegion> regions;
		MemRegion currentRegion = {0, 0, 0, false, false, false, false, false, nullptr};

		for (const auto& arr : configArrays)
		{
			uint64_t entrySize = arr.isIdentity ? 4 : 8;
			uint64_t entryCount = (arr.endAddr - arr.startAddr) / entrySize;

			logger->LogInfo("MMU: Parsing config array with %llu entries", (unsigned long long)entryCount);

			for (uint64_t i = 0; i < entryCount; i++)
			{
				uint64_t entryAddr = arr.startAddr + (i * entrySize);
				uint32_t va = 0, pa = 0, flags = 0;

				if (arr.isIdentity)
				{
					// Identity mapping: entry is VA/PA and flags in upper bits
					if (!ReadU32Smart(reader, data, dataLen, endian, entryAddr,
						aliasBase, length, romCopy, va))
						break;
					pa = va & 0xFFFFF000;
					flags = va & 0xFFF;
					va = va & 0xFFFFF000;
				}
				else
				{
					// VA->PA mapping: 8-byte entries (VA, PA+flags)
					if (!ReadU32Smart(reader, data, dataLen, endian, entryAddr,
						aliasBase, length, romCopy, va))
						break;
					if (!ReadU32Smart(reader, data, dataLen, endian, entryAddr + 4,
						aliasBase, length, romCopy, pa))
						break;
					flags = pa & 0xFFF;
					pa = pa & 0xFFFFF000;
					va = va & 0xFFFFF000;
				}

				// Parse flags
				bool readable = (flags & 0x01) != 0;
				bool writable = (flags & 0x02) != 0;
				bool executable = (flags & 0x04) != 0;
				bool cacheable = (flags & 0x08) != 0;
				bool bufferable = (flags & 0x10) != 0;
				const char* type = (flags & 0x20) ? "MMIO" : "RAM";

				// Combine contiguous regions with same attributes
				if (currentRegion.size == 0)
				{
					currentRegion = {va, pa, 0x1000, readable, writable, executable,
						cacheable, bufferable, type};
				}
				else if (va == currentRegion.virtBase + currentRegion.size &&
					pa == currentRegion.physBase + currentRegion.size &&
					readable == currentRegion.readable && writable == currentRegion.writable &&
					executable == currentRegion.executable && cacheable == currentRegion.cacheable &&
					bufferable == currentRegion.bufferable && strcmp(type, currentRegion.type) == 0)
				{
					currentRegion.size += 0x1000;
				}
				else
				{
					regions.push_back(currentRegion);
					currentRegion = {va, pa, 0x1000, readable, writable, executable,
						cacheable, bufferable, type};
				}
			}

			// Add the last region
			if (currentRegion.size > 0)
				regions.push_back(currentRegion);
		}

		// Merge regions with same physical base and attributes
		std::vector<MemRegion> uniqueRegions;
		std::sort(regions.begin(), regions.end(),
			[](const MemRegion& a, const MemRegion& b) { return a.virtBase < b.virtBase; });

		for (const auto& region : regions)
		{
			if (!uniqueRegions.empty())
			{
				MemRegion& last = uniqueRegions.back();
				if (region.virtBase == last.virtBase + last.size &&
					region.physBase == last.physBase + last.size &&
					region.readable == last.readable && region.writable == last.writable &&
					region.executable == last.executable && region.cacheable == last.cacheable &&
					region.bufferable == last.bufferable && strcmp(region.type, last.type) == 0)
				{
					last.size += region.size;
					continue;
				}
			}
			uniqueRegions.push_back(region);
		}

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
}
