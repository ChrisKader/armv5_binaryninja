/*
 * ARMv5 Firmware MMU Analysis
 */

#include "firmware_internal.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
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

// Address mapping for resolving CPU addresses to file offsets
struct AddrMapping {
	uint64_t cpuBase;
	uint64_t fileBase;
	uint64_t size;
	const char* name;
	bool fallback;
};

enum class MapEntryKind
{
	Identity4,
	VaPa8,
};

enum class MapGranularity
{
	Page4K,
	Section1M,
};

struct MapFormat
{
	MapEntryKind kind;
	MapGranularity gran;
	uint32_t knownFlagMask; // which bits we consider “flags”
	uint32_t alignMask;			// address alignment mask
	uint32_t pageSize;			// 0x1000 or 0x100000
};

struct MapStats
{
	size_t samples = 0;
	size_t ok = 0;
	size_t aligned = 0;
	size_t strideHits = 0;
	uint32_t dominantStride = 0;
	size_t uniqueFlags = 0;
	uint32_t minVA = 0;
	uint32_t maxVA = 0;
	bool haveVA = false;
	double score = 0.0;
};

// Address resolver for mixed raw/aliased/blob firmware layouts
struct AddressResolver {
	uint64_t fileLen = 0;
	std::vector<AddrMapping> maps;

	void Add(uint64_t cpuBase, uint64_t fileBase, uint64_t size, const char* name, bool fallback = false)
	{
		if (size == 0)
			return;
		if (fileBase >= fileLen)
			return;
		if (fileBase + size > fileLen)
			size = fileLen - fileBase;
		maps.push_back({cpuBase, fileBase, size, name, fallback});
	}

	bool CpuToFile(uint64_t cpuAddr, uint64_t& outFileOff, bool allowFallback = true) const
	{
		for (const auto& m : maps)
		{
			if (m.fallback)
				continue;
			if (cpuAddr >= m.cpuBase && cpuAddr < m.cpuBase + m.size)
			{
				outFileOff = m.fileBase + (cpuAddr - m.cpuBase);
				return true;
			}
		}

		if (!allowFallback)
			return false;

		for (const auto& m : maps)
		{
			if (!m.fallback)
				continue;
			if (cpuAddr >= m.cpuBase && cpuAddr < m.cpuBase + m.size)
			{
				outFileOff = m.fileBase + (cpuAddr - m.cpuBase);
				return true;
			}
		}
		return false;
	}

	bool FileToCpu(uint64_t fileOff, uint64_t& outCpuAddr, bool allowFallback = true) const
	{
		for (const auto& m : maps)
		{
			if (m.fallback)
				continue;
			if (fileOff >= m.fileBase && fileOff < m.fileBase + m.size)
			{
				outCpuAddr = m.cpuBase + (fileOff - m.fileBase);
				return true;
			}
		}

		if (!allowFallback)
			return false;

		for (const auto& m : maps)
		{
			if (!m.fallback)
				continue;
			if (fileOff >= m.fileBase && fileOff < m.fileBase + m.size)
			{
				outCpuAddr = m.cpuBase + (fileOff - m.fileBase);
				return true;
			}
		}
		return false;
	}
};

// Forward declaration (used by mapping helpers before definition)
static bool ReadU32Resolved(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, const AddressResolver& resolver, uint64_t addr, const RomToSramCopy& romCopy,
	uint64_t length, uint32_t& out);

static uint32_t MaskForGran(MapGranularity g)
{
	return (g == MapGranularity::Section1M) ? 0xFFF00000u : 0xFFFFF000u;
}

static uint32_t PageSizeForGran(MapGranularity g)
{
	return (g == MapGranularity::Section1M) ? 0x100000u : 0x1000u;
}

static bool ReadEntry(const AddressResolver &resolver, BinaryReader &reader,
											const uint8_t *data, uint64_t dataLen, BNEndianness endian,
											const RomToSramCopy &romCopy, uint64_t length,
											uint64_t addr, MapEntryKind kind, uint32_t &outA, uint32_t &outB)
{
	outA = outB = 0;
	if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, addr, romCopy, length, outA))
		return false;
	if (kind == MapEntryKind::VaPa8)
	{
		if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, addr + 4, romCopy, length, outB))
			return false;
	}
	return true;
}

static MapStats ScoreFormat(const AddressResolver &resolver, BinaryReader &reader,
														const uint8_t *data, uint64_t dataLen, BNEndianness endian,
														const RomToSramCopy &romCopy, uint64_t length,
														uint64_t startAddr, uint64_t endAddr,
														MapEntryKind kind, MapGranularity gran,
														uint32_t flagMask, size_t maxSamples = 256)
{
	MapStats st;
	uint64_t entrySize = (kind == MapEntryKind::Identity4) ? 4 : 8;
	uint64_t count = (endAddr > startAddr) ? (endAddr - startAddr) / entrySize : 0;
	if (count == 0)
		return st;

	uint32_t addrMask = MaskForGran(gran);
	uint32_t pageSize = PageSizeForGran(gran);

	std::map<uint32_t, size_t> strideFreq;
	std::map<uint32_t, size_t> flagFreq;

	uint32_t prevVA = 0;
	bool havePrev = false;

	size_t samples = std::min<uint64_t>(count, maxSamples);
	for (size_t i = 0; i < samples; i++)
	{
		uint64_t ea = startAddr + i * entrySize;
		uint32_t w0 = 0, w1 = 0;
		if (!ReadEntry(resolver, reader, data, dataLen, endian, romCopy, length, ea, kind, w0, w1))
			break;

		uint32_t vaRaw = w0;
		uint32_t paRaw = (kind == MapEntryKind::VaPa8) ? w1 : w0;

		uint32_t va = vaRaw & addrMask;
		uint32_t pa = paRaw & addrMask;
		uint32_t flags = paRaw & flagMask; // for Identity4 you can also use vaRaw & flagMask; pick one and stay consistent

		st.samples++;
		if (!st.haveVA)
		{
			st.minVA = va;
			st.maxVA = va;
			st.haveVA = true;
		}
		else
		{
			if (va < st.minVA)
				st.minVA = va;
			if (va > st.maxVA)
				st.maxVA = va;
		}

		bool vaAligned = ((va & (pageSize - 1)) == 0);
		bool paAligned = ((pa & (pageSize - 1)) == 0);
		if (vaAligned && paAligned)
			st.aligned++;

		// “sane” entries: aligned and VA not zero (common in real maps)
		if (vaAligned && paAligned)
			st.ok++;

		flagFreq[flags]++;

		if (havePrev)
		{
			uint32_t d = va - prevVA;
			strideFreq[d]++;
		}
		prevVA = va;
		havePrev = true;
	}

	// dominant stride
	size_t best = 0;
	uint32_t bestStride = 0;
	for (auto &kv : strideFreq)
	{
		if (kv.second > best)
		{
			best = kv.second;
			bestStride = kv.first;
		}
	}
	st.dominantStride = bestStride;
	st.strideHits = best;

	st.uniqueFlags = flagFreq.size();

	// scoring: alignment + dominant stride + low flag entropy
	double alignRate = (st.samples ? (double)st.aligned / (double)st.samples : 0.0);
	double strideRate = (st.samples > 1 ? (double)st.strideHits / (double)(st.samples - 1) : 0.0);
	double flagPenalty = (st.uniqueFlags > 32) ? 0.25 : 1.0; // brutal penalty if flags explode

	st.score = (alignRate * 0.55) + (strideRate * 0.35) + (flagPenalty * 0.10);
	return st;
}

static bool ChooseBestFormat(const AddressResolver &resolver, BinaryReader &reader,
														 const uint8_t *data, uint64_t dataLen, BNEndianness endian,
														 const RomToSramCopy &romCopy, uint64_t length,
														 const MMUConfigArray &arr, MapFormat &outFmt, MapStats &outStats)
{
	// Try: Identity4 / VaPa8 x 4K / 1M
	// Flag masks: your current scheme assumes low 6 bits; keep tight to avoid treating address residue as flags.
	const uint32_t kFlagMaskTight = 0x3Fu;	// start tight
	const uint32_t kFlagMaskLoose = 0xFFFu; // fallback if needed

	struct Cand
	{
		MapEntryKind k;
		MapGranularity g;
		uint32_t fm;
	};
	Cand cands[] = {
			{MapEntryKind::VaPa8, MapGranularity::Section1M, kFlagMaskTight},
			{MapEntryKind::VaPa8, MapGranularity::Page4K, kFlagMaskTight},
			{MapEntryKind::Identity4, MapGranularity::Section1M, kFlagMaskTight},
			{MapEntryKind::Identity4, MapGranularity::Page4K, kFlagMaskTight},

			{MapEntryKind::VaPa8, MapGranularity::Section1M, kFlagMaskLoose},
			{MapEntryKind::VaPa8, MapGranularity::Page4K, kFlagMaskLoose},
			{MapEntryKind::Identity4, MapGranularity::Section1M, kFlagMaskLoose},
			{MapEntryKind::Identity4, MapGranularity::Page4K, kFlagMaskLoose},
	};

	MapStats bestSt;
	MapFormat bestFmt = {};
	double bestScore = 0.0;

	for (auto &c : cands)
	{
		uint64_t entrySize = (c.k == MapEntryKind::Identity4) ? 4 : 8;
		uint64_t len = (arr.endAddr > arr.startAddr) ? (arr.endAddr - arr.startAddr) : 0;
		if (len < entrySize * 4)
			continue;
		if ((len % entrySize) != 0)
			continue;
		uint64_t count = len / entrySize;
		if (c.g == MapGranularity::Section1M && count > 4096)
			continue;

		MapStats st = ScoreFormat(resolver, reader, data, dataLen, endian, romCopy, length,
															arr.startAddr, arr.endAddr, c.k, c.g, c.fm);

		if (st.samples < 16)
			continue;

		if (st.score > bestScore)
		{
			bestScore = st.score;
			bestSt = st;
			bestFmt.kind = c.k;
			bestFmt.gran = c.g;
			bestFmt.knownFlagMask = c.fm;
			bestFmt.alignMask = MaskForGran(c.g);
			bestFmt.pageSize = PageSizeForGran(c.g);
		}
	}

	// Hard reject unless the table looks “structured”
	// Tune thresholds as you like.
	if (bestScore < 0.60)
		return false;
	if ((double)bestSt.aligned / (double)bestSt.samples < 0.70)
		return false;
	if (bestSt.uniqueFlags > 256) // flags look like address residue
		return false;
	if (!bestSt.haveVA || bestSt.maxVA <= bestSt.minVA)
		return false;
	if (bestFmt.pageSize != 0 && (bestSt.dominantStride == 0 || (bestSt.dominantStride % bestFmt.pageSize) != 0))
		return false;

	outFmt = bestFmt;
	outStats = bestSt;
	return true;
}

static AddressResolver BuildResolver(uint64_t imageBase, uint64_t length)
{
	AddressResolver resolver;
	resolver.fileLen = length;
	resolver.Add(imageBase, 0, length, "raw");
	resolver.Add(0, 0, length, "blob0", true);
	return resolver;
}

static void AddLow24Alias(AddressResolver& resolver, uint64_t aliasBase, uint64_t length)
{
	if (aliasBase == 0)
		return;
	uint64_t size = std::min<uint64_t>(length, 0x01000000ULL);
	resolver.Add(aliasBase, 0, size, "aliasLow24");
}

// ARMv5 L1 descriptor types
static inline uint32_t L1Type(uint32_t desc) { return desc & 0x3; }

// Decode ARMv5 section access permissions (AP[11:10]) into readable/writable.
// Note: ARMv5 has no NX bit; we approximate executable == readable.
static inline void DecodeSectionAP(uint32_t desc, bool& readable, bool& writable)
{
	uint32_t ap = (desc >> 10) & 0x3;
	// Conservative mapping:
	// 00: privileged no access / (implementation-defined) -> treat as not readable
	// 01: privileged RW, user no access -> readable, writable
	// 10: privileged RW, user RO -> readable, writable (priv)
	// 11: privileged RW, user RW -> readable, writable
	readable = (ap != 0);
	writable = (ap != 0);
}

// Decode ARMv5 L2 page access permissions (AP[5:4]) into readable/writable.
static inline void DecodePageAP(uint32_t desc, bool& readable, bool& writable)
{
	uint32_t ap = (desc >> 4) & 0x3;
	readable = (ap != 0);
	writable = (ap != 0);
}

static inline void AppendRegion(std::vector<MemRegion>& outRegions, const MemRegion& region)
{
	if (!outRegions.empty())
	{
		MemRegion& last = outRegions.back();
		if (last.virtBase + last.size == region.virtBase &&
			last.physBase + last.size == region.physBase &&
			last.readable == region.readable && last.writable == region.writable &&
			last.executable == region.executable && last.cacheable == region.cacheable &&
			last.bufferable == region.bufferable && strcmp(last.type, region.type) == 0)
		{
			last.size += region.size;
			return;
		}
	}
	outRegions.push_back(region);
}

static bool ParseArmv5L2Coarse(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, const AddressResolver& resolver, uint64_t length, const RomToSramCopy& romCopy,
	uint64_t vaBase, uint32_t l1Desc, std::vector<MemRegion>& outRegions, Ref<Logger> logger)
{
	uint64_t l2Base = l1Desc & 0xFFFFFC00u; // coarse table base (1KB aligned)
	uint64_t l2FileOff = 0;
	if (!resolver.CpuToFile(l2Base, l2FileOff))
		return false;

	// Preflight: ensure the table looks like a coarse L2
	{
		size_t valid = 0;
		size_t invalid = 0;
		uint64_t idx = 0;
		while (idx < 64)
		{
			uint32_t desc = 0;
			if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, l2Base + idx * 4, romCopy, length, desc))
				break;
			uint32_t type = desc & 0x3;
			if (type == 0)
			{
				invalid++;
				idx++;
				continue;
			}
			if (type == 1)
			{
				// Large page must be replicated 16 times
				bool replOk = true;
				if (idx + 15 < 256)
				{
					for (uint64_t j = 1; j < 16; j++)
					{
						uint32_t d2 = 0;
						if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, l2Base + (idx + j) * 4, romCopy, length, d2) ||
							d2 != desc)
						{
							replOk = false;
							break;
						}
					}
				}
				if (replOk)
					valid++;
				else
					invalid++;
				idx += 16;
				continue;
			}
			// Small or extended small page
			uint32_t pa = desc & 0xFFFFF000u;
			if ((pa & 0xFFF) == 0)
				valid++;
			else
				invalid++;
			idx++;
		}
		if (valid < 8 || valid <= invalid)
			return false;
	}

	bool produced = false;
	MemRegion cur = {0, 0, 0, false, false, false, false, false, nullptr};

	for (uint64_t idx = 0; idx < 256; idx++)
	{
		uint32_t desc = 0;
		if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, l2Base + idx * 4, romCopy, length, desc))
			break;

		uint32_t type = desc & 0x3;
		if (type == 0)
			continue;

		uint64_t va = vaBase + idx * 0x1000;
		uint64_t pa = 0;
		uint64_t size = 0;
		bool readable = false, writable = false;
		DecodePageAP(desc, readable, writable);
		bool cacheable = (desc & (1u << 3)) != 0;
		bool bufferable = (desc & (1u << 2)) != 0;
		bool executable = readable;
		const char* rtype = "RAM";
		if (!cacheable && !bufferable)
			rtype = "MMIO";

		if (type == 1)
		{
			// Large page (64KB) maps 16 consecutive small-page slots
			uint64_t slot = idx & ~0xFULL;
			va = vaBase + slot * 0x1000;
			pa = desc & 0xFFFF0000u;
			size = 0x10000;
			idx += 15; // skip covered slots
		}
		else if (type == 2 || type == 3)
		{
			// Small page (4KB) or extended small page (treat as 4KB)
			pa = desc & 0xFFFFF000u;
			size = 0x1000;
		}
		else
		{
			// Tiny page (1KB) not expanded for now
			continue;
		}

		MemRegion region = {va, pa, size, readable, writable, executable, cacheable, bufferable, rtype};
		if (cur.size == 0)
		{
			cur = region;
		}
		else if (cur.virtBase + cur.size == region.virtBase &&
			cur.physBase + cur.size == region.physBase &&
			cur.readable == region.readable && cur.writable == region.writable &&
			cur.executable == region.executable && cur.cacheable == region.cacheable &&
			cur.bufferable == region.bufferable && strcmp(cur.type, region.type) == 0)
		{
			cur.size += region.size;
		}
		else
		{
			AppendRegion(outRegions, cur);
			cur = region;
		}
		produced = true;
	}

	if (cur.size)
		AppendRegion(outRegions, cur);

	if (produced)
		logger->LogDebug("MMU: Expanded coarse L2 table at 0x%08llx", (unsigned long long)l2Base);
	return produced;
}

static bool ParseArmv5L2Fine(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, const AddressResolver& resolver, uint64_t length, const RomToSramCopy& romCopy,
	uint64_t vaBase, uint32_t l1Desc, std::vector<MemRegion>& outRegions, Ref<Logger> logger)
{
	uint64_t l2Base = l1Desc & 0xFFFFF000u; // fine table base (4KB aligned)
	uint64_t l2FileOff = 0;
	if (!resolver.CpuToFile(l2Base, l2FileOff))
		return false;

	// Preflight: ensure the table looks like a fine L2
	{
		size_t valid = 0;
		size_t invalid = 0;
		uint64_t idx = 0;
		while (idx < 128)
		{
			uint32_t desc = 0;
			if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, l2Base + idx * 4, romCopy, length, desc))
				break;
			uint32_t type = desc & 0x3;
			if (type == 0)
			{
				invalid++;
				idx++;
				continue;
			}
			if (type == 1)
			{
				// Large page must be replicated 64 times
				bool replOk = true;
				if (idx + 63 < 1024)
				{
					for (uint64_t j = 1; j < 64; j++)
					{
						uint32_t d2 = 0;
						if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, l2Base + (idx + j) * 4, romCopy, length, d2) ||
							d2 != desc)
						{
							replOk = false;
							break;
						}
					}
				}
				if (replOk)
					valid++;
				else
					invalid++;
				idx += 64;
				continue;
			}
			if (type == 2)
			{
				// Small page must be replicated 4 times
				bool replOk = true;
				if (idx + 3 < 1024)
				{
					for (uint64_t j = 1; j < 4; j++)
					{
						uint32_t d2 = 0;
						if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, l2Base + (idx + j) * 4, romCopy, length, d2) ||
							d2 != desc)
						{
							replOk = false;
							break;
						}
					}
				}
				if (replOk)
					valid++;
				else
					invalid++;
				idx += 4;
				continue;
			}
			// Tiny page
			uint32_t pa = desc & 0xFFFFFC00u;
			if ((pa & 0x3FF) == 0)
				valid++;
			else
				invalid++;
			idx++;
		}
		if (valid < 16 || valid <= invalid)
			return false;
	}

	bool produced = false;
	MemRegion cur = {0, 0, 0, false, false, false, false, false, nullptr};

	for (uint64_t idx = 0; idx < 1024; idx++)
	{
		uint32_t desc = 0;
		if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, l2Base + idx * 4, romCopy, length, desc))
			break;

		uint32_t type = desc & 0x3;
		if (type == 0)
			continue;

		uint64_t va = vaBase + idx * 0x400; // 1KB slots
		uint64_t pa = 0;
		uint64_t size = 0;
		uint32_t apBits = (desc >> 4) & 0xF; // AP3..AP0
		bool readable = (apBits != 0);
		bool writable = (apBits != 0);
		bool cacheable = (desc & (1u << 3)) != 0;
		bool bufferable = (desc & (1u << 2)) != 0;
		bool executable = readable;
		const char* rtype = "RAM";
		if (!cacheable && !bufferable)
			rtype = "MMIO";

		if (type == 1)
		{
			// Large page (64KB) uses 64 consecutive entries
			uint64_t slot = idx & ~0x3FULL;
			va = vaBase + slot * 0x400;
			pa = desc & 0xFFFF0000u;
			size = 0x10000;
			idx += 63;
		}
		else if (type == 2)
		{
			// Small page (4KB) uses 4 consecutive entries
			uint64_t slot = idx & ~0x3ULL;
			va = vaBase + slot * 0x400;
			pa = desc & 0xFFFFF000u;
			size = 0x1000;
			idx += 3;
		}
		else if (type == 3)
		{
			// Tiny page (1KB)
			pa = desc & 0xFFFFFC00u;
			size = 0x400;
		}
		else
		{
			continue;
		}

		MemRegion region = {va, pa, size, readable, writable, executable, cacheable, bufferable, rtype};
		if (cur.size == 0)
		{
			cur = region;
		}
		else if (cur.virtBase + cur.size == region.virtBase &&
			cur.physBase + cur.size == region.physBase &&
			cur.readable == region.readable && cur.writable == region.writable &&
			cur.executable == region.executable && cur.cacheable == region.cacheable &&
			cur.bufferable == region.bufferable && strcmp(cur.type, region.type) == 0)
		{
			cur.size += region.size;
		}
		else
		{
			AppendRegion(outRegions, cur);
			cur = region;
		}
		produced = true;
	}

	if (cur.size)
		AppendRegion(outRegions, cur);

	if (produced)
		logger->LogDebug("MMU: Expanded fine L2 table at 0x%08llx", (unsigned long long)l2Base);
	return produced;
}

// Parse an initialized ARMv5 L1 translation table (sections + coarse tables).
// Emits a simplified set of regions (primarily 1MB sections). Returns true if any regions were produced.
static bool ParseArmv5L1Table(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, const AddressResolver& resolver, uint64_t length,
	const RomToSramCopy& romCopy, uint64_t tableBase, std::vector<MemRegion>& outRegions, Ref<Logger> logger)
{
	outRegions.clear();

	for (uint64_t idx = 0; idx < 4096; idx++)
	{
		uint64_t vaBase = idx << 20; // 1MB per entry
		uint32_t desc = 0;
		if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, tableBase + idx * 4, romCopy, length, desc))
			continue;

		uint32_t type = L1Type(desc);
		if (type == 0)
			continue; // fault

		// Section descriptor (0b10)
		if (type == 2)
		{
			bool superSection = (desc & (1u << 18)) != 0;
			uint64_t paBase = superSection ? (desc & 0xFF000000u) : (desc & 0xFFF00000u);
			bool readable = false, writable = false;
			DecodeSectionAP(desc, readable, writable);
			bool cacheable = (desc & (1u << 3)) != 0; // C
			bool bufferable = (desc & (1u << 2)) != 0; // B
			bool executable = readable; // no NX in ARMv5
			const char* rtype = "RAM";
			// Heuristic: strongly-ordered / device-ish often has C=0,B=0.
			if (!cacheable && !bufferable)
				rtype = "MMIO";

			uint64_t size = superSection ? 0x01000000 : 0x100000;
			MemRegion region = {vaBase, paBase, size, readable, writable, executable, cacheable, bufferable, rtype};
			AppendRegion(outRegions, region);
			continue;
		}

		// Coarse page table (0b01)
		if (type == 1)
		{
			size_t before = outRegions.size();
			if (!ParseArmv5L2Coarse(reader, data, dataLen, endian, resolver, length, romCopy, vaBase, desc, outRegions, logger))
			{
				bool cacheable = false;
				bool bufferable = false;
				bool readable = true;
				bool writable = true;
				bool executable = true;
				const char* rtype = "L2";
				MemRegion region = {vaBase, 0, 0x100000, readable, writable, executable, cacheable, bufferable, rtype};
				AppendRegion(outRegions, region);
			}
			else
			{
				size_t added = outRegions.size() - before;
				logger->LogDebug("MMU: L2 expanded %zu region(s) for VA 0x%08llx", added, (unsigned long long)vaBase);
			}
			continue;
		}

		// Fine page table (0b11)
		if (type == 3)
		{
			size_t before = outRegions.size();
			if (!ParseArmv5L2Fine(reader, data, dataLen, endian, resolver, length, romCopy, vaBase, desc, outRegions, logger))
			{
				bool cacheable = false;
				bool bufferable = false;
				bool readable = true;
				bool writable = true;
				bool executable = true;
				const char* rtype = "L2F";
				MemRegion region = {vaBase, 0, 0x100000, readable, writable, executable, cacheable, bufferable, rtype};
				AppendRegion(outRegions, region);
			}
			else
			{
				size_t added = outRegions.size() - before;
				logger->LogDebug("MMU: L2 fine expanded %zu region(s) for VA 0x%08llx", added, (unsigned long long)vaBase);
			}
			continue;
		}
	}

	if (outRegions.empty())
		return false;

	logger->LogInfo("MMU: Parsed initialized L1 table, produced %zu regions", outRegions.size());
	return true;
}

// Find ROM-to-SRAM copy operation that initializes config arrays
// Looks for pattern: ldrlo rx, [ry], #4 / strlo rx, [rz], #4 (copy loop)
// Returns info about the copy or {.valid = false} if not found
static RomToSramCopy FindRomToSramCopy(BinaryReader& reader, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t length, uint64_t imageBase,
	const AddressResolver& resolver, uint64_t aliasBase, Ref<Logger> logger)
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

				// ROM address: a pointer into the ROM image range (imageBase-relative)
				uint64_t offTmp = 0;
				if (((val >= imageBase) && (val < imageBase + length) &&
						resolver.CpuToFile(val, offTmp, false)) && offTmp > 0x1000)
				{
					romSrc = val;
					romSrcLitAddr = litAddr;
				}
				else if (resolver.CpuToFile(val, offTmp, false) && offTmp > 0x1000)
				{
					romSrc = val;
					romSrcLitAddr = litAddr;
				}
				// SRAM address: matches our alias base (high byte)
				else if (aliasBase != 0 && (val & 0xFF000000) == aliasBase)
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

// Read u32 via resolver, using ROM copy data for SRAM addresses if available
static bool ReadU32Resolved(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, const AddressResolver& resolver, uint64_t addr, const RomToSramCopy& romCopy,
	uint64_t length, uint32_t& out)
{
	// If this is an SRAM address that falls within the ROM->SRAM copy range, remap into ROM.
	if (romCopy.valid && addr >= romCopy.sramDst && addr < romCopy.sramEnd)
	{
		uint64_t offsetInSram = addr - romCopy.sramDst;
		uint64_t romAddr = romCopy.romSrc + offsetInSram;
		uint64_t romOff = 0;
		if (!resolver.CpuToFile(romAddr, romOff))
			return false;
		return ReadU32At(reader, data, dataLen, endian, romOff, out, length);
	}

	uint64_t fileOff = 0;
	if (!resolver.CpuToFile(addr, fileOff))
		return false;
	return ReadU32At(reader, data, dataLen, endian, fileOff, out, length);
}

static inline uint32_t DecodeImm12(uint32_t instr)
{
	uint32_t imm8 = instr & 0xFF;
	uint32_t rot = ((instr >> 8) & 0xF) * 2;
	if (rot == 0)
		return imm8;
	return (imm8 >> rot) | (imm8 << (32 - rot));
}

struct RegVal
{
	bool known = false;
	uint32_t v = 0;
};

static bool ResolveRegAt(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, const AddressResolver& resolver, uint64_t useFileOff,
	uint32_t targetReg, uint32_t& outValue, Ref<Logger> logger)
{
	const int maxBack = 96;
	uint64_t start = 0;
	if (useFileOff > static_cast<uint64_t>(maxBack * 4))
		start = useFileOff - static_cast<uint64_t>(maxBack * 4);

	RegVal regs[16] = {};

	auto getCpuPc = [&](uint64_t fileOff, uint64_t& outCpuPc) -> bool
	{
		return resolver.FileToCpu(fileOff, outCpuPc, true);
	};

	for (uint64_t off = start; off < useFileOff; off += 4)
	{
		uint32_t ins = 0;
		ReadU32At(reader, data, dataLen, endian, off, ins, resolver.fileLen);

		// MOV (register): 0x01A00000
		if ((ins & 0x0FF0FFF0) == 0x01A00000)
		{
			uint32_t rd = (ins >> 12) & 0xF;
			uint32_t rm = ins & 0xF;
			if (regs[rm].known)
			{
				regs[rd] = regs[rm];
			}
			else
			{
				regs[rd].known = false;
			}
			continue;
		}

		// MOV (imm): 0x03A00000
		if ((ins & 0x0FEF0000) == 0x03A00000)
		{
			uint32_t rd = (ins >> 12) & 0xF;
			regs[rd].known = true;
			regs[rd].v = DecodeImm12(ins);
			continue;
		}

		// ORR (imm): opcode 1100
		if ((ins & 0x0FE00000) == 0x03800000)
		{
			uint32_t rd = (ins >> 12) & 0xF;
			uint32_t rn = (ins >> 16) & 0xF;
			uint32_t opcode = (ins >> 21) & 0xF;
			if (opcode == 0xC)
			{
				if (regs[rn].known)
				{
					uint32_t imm = DecodeImm12(ins);
					regs[rd].known = true;
					regs[rd].v = regs[rn].v | imm;
				}
				else
				{
					regs[rd].known = false;
				}
				continue;
			}
		}

		// BIC (imm): opcode 1110
		if ((ins & 0x0FE00000) == 0x03C00000)
		{
			uint32_t rd = (ins >> 12) & 0xF;
			uint32_t rn = (ins >> 16) & 0xF;
			uint32_t opcode = (ins >> 21) & 0xF;
			if (opcode == 0xE)
			{
				if (regs[rn].known)
				{
					uint32_t imm = DecodeImm12(ins);
					regs[rd].known = true;
					regs[rd].v = regs[rn].v & ~imm;
				}
				else
				{
					regs[rd].known = false;
				}
				continue;
			}
		}

		// ADD/SUB (imm)
		if ((ins & 0x0FE00000) == 0x02800000 || (ins & 0x0FE00000) == 0x02400000)
		{
			uint32_t rd = (ins >> 12) & 0xF;
			uint32_t rn = (ins >> 16) & 0xF;
			uint32_t opcode = (ins >> 21) & 0xF;
			uint32_t imm = DecodeImm12(ins);

			if (opcode == 0x4)
			{
				if (rn == 15)
				{
					uint64_t cpuPc = 0;
					if (getCpuPc(off, cpuPc))
					{
						regs[rd].known = true;
						regs[rd].v = static_cast<uint32_t>(cpuPc + 8 + imm);
					}
					else
					{
						regs[rd].known = true;
						regs[rd].v = static_cast<uint32_t>(off + 8 + imm);
					}
				}
				else if (regs[rn].known)
				{
					regs[rd].known = true;
					regs[rd].v = regs[rn].v + imm;
				}
				else
				{
					regs[rd].known = false;
				}
			}
			else if (opcode == 0x2)
			{
				if (rn == 15)
				{
					uint64_t cpuPc = 0;
					if (getCpuPc(off, cpuPc))
					{
						regs[rd].known = true;
						regs[rd].v = static_cast<uint32_t>(cpuPc + 8 - imm);
					}
					else
					{
						regs[rd].known = true;
						regs[rd].v = static_cast<uint32_t>(off + 8 - imm);
					}
				}
				else if (regs[rn].known)
				{
					regs[rd].known = true;
					regs[rd].v = regs[rn].v - imm;
				}
				else
				{
					regs[rd].known = false;
				}
			}
			continue;
		}

		// LDR literal: (ins & 0x0F7F0000) == 0x051F0000
		if ((ins & 0x0F7F0000) == 0x051F0000)
		{
			uint32_t rd = (ins >> 12) & 0xF;
			uint32_t imm12 = ins & 0xFFF;
			bool add = (ins & 0x00800000) != 0;

			uint64_t cpuPc = 0;
			if (getCpuPc(off, cpuPc))
			{
				uint64_t pcVal = cpuPc + 8;
				uint64_t litCpu = add ? (pcVal + imm12) : (pcVal - imm12);

				uint32_t val = 0;
				RomToSramCopy dummy = {0, 0, 0, false};
				if (ReadU32Resolved(reader, data, dataLen, endian, resolver, litCpu, dummy, resolver.fileLen, val))
				{
					regs[rd].known = true;
					regs[rd].v = val;
				}
				else
				{
					regs[rd].known = false;
				}
			}
			else
			{
				uint64_t pcFile = off + 8;
				uint64_t litFile = add ? (pcFile + imm12) : (pcFile - imm12);
				if (litFile + 4 <= resolver.fileLen)
				{
					uint32_t val = 0;
					ReadU32At(reader, data, dataLen, endian, litFile, val, resolver.fileLen);
					regs[rd].known = true;
					regs[rd].v = val;
				}
				else
				{
					regs[rd].known = false;
				}
			}
			continue;
		}

		// Conservative invalidation for other data-processing and loads that write Rd
		uint32_t classBits = (ins >> 26) & 0x3;
		if (classBits == 0)
		{
			uint32_t opcode = (ins >> 21) & 0xF;
			if (!(opcode >= 0x8 && opcode <= 0xB))
			{
				uint32_t rd = (ins >> 12) & 0xF;
				regs[rd].known = false;
			}
		}
		else if (classBits == 1)
		{
			bool isLoad = (ins & (1u << 20)) != 0;
			if (isLoad)
			{
				uint32_t rd = (ins >> 12) & 0xF;
				regs[rd].known = false;
			}
		}
	}

	if (regs[targetReg].known)
	{
		outValue = regs[targetReg].v;
		return true;
	}

	logger->LogDebug("MMU: Failed to resolve R%d in %u-instruction window", targetReg, maxBack);
	return false;
}

static bool LooksLikeL1Table(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t offset, uint64_t length)
{
	if (offset + 0x4000 > length)
		return false;

	size_t valid = 0;
	size_t faults = 0;

	for (size_t i = 0; i < 4096; i++)
	{
		uint32_t desc = 0;
		if (!ReadU32At(reader, data, dataLen, endian, offset + (i * 4), desc, length))
			return false;

		uint32_t type = desc & 0x3;
		if (type == 0)
			faults++;
		else if (type == 1 || type == 2)
			valid++;
	}

	if (valid < 128)
		return false;
	if (faults > 4000)
		return false;
	return true;
}

// Analyze MMU configuration to discover memory regions
// Looks for MCR p15, 0, Rx, c2, c0, 0 (write to TTBR) and parses the translation table
// When translation table is uninitialized, discovers config arrays through static analysis
void AnalyzeMMUConfiguration(const Ref<BinaryView>& view, BinaryReader& reader, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length, Ref<Logger> logger)
{
	struct MMULogScope
	{
		Ref<Logger> logger;
		std::string name;
		MMULogScope(Ref<Logger> l, std::string n) : logger(l), name(std::move(n))
		{
			if (logger)
				logger->LogInfo("MMU: Begin (%s)", name.c_str());
		}
		~MMULogScope()
		{
			if (logger)
				logger->LogInfo("MMU: End (%s)", name.c_str());
		}
	};

	std::string viewName = "unknown";
	if (view && view->GetFile())
	{
		viewName = view->GetFile()->GetOriginalFilename();
		if (viewName.empty())
			viewName = view->GetFile()->GetFilename();
	}
	MMULogScope logScope(logger, viewName);

	AddressResolver resolver = BuildResolver(imageBase, length);
	std::vector<uint64_t> ttbrHits;

	// Scan for MCR p15, 0, Rx, c2, c0, 0/1 instruction
	// Encoding: cond 1110 opc1[3] 0 CRn[4] Rt[4] coproc[4] opc2[3] 1 CRm[4]
	// MCR p15, 0, Rx, c2, c0, 0: 1110 1110 0000 0010 xxxx 1111 0001 0000
	// Mask: 0x0FFF0FFF, expect: 0x0E020F10 (TTBR0), 0x0E020F30 (TTBR1)
	logger->LogInfo("MMU: Scanning for TTBR write in %llu bytes", (unsigned long long)length);

	for (uint64_t offset = 0; offset + 4 <= length; offset += 4)
	{
		uint32_t instr = 0;
		ReadU32At(reader, data, dataLen, endian, offset, instr, length);

		// MCR p15, 0, Rx, c2, c0, 0/1 - write TTBR0 or TTBR1
		// Mask: 0x0FFF0FFF
		//   TTBR0 => 0x0E020F10
		//   TTBR1 => 0x0E020F30
		uint32_t ttbrMasked = (instr & 0x0FFF0FFF);
		if (ttbrMasked == 0x0E020F10 || ttbrMasked == 0x0E020F30)
			ttbrHits.push_back(offset);
	}

	if (ttbrHits.empty())
	{
		logger->LogInfo("MMU: No TTBR writes found");
	}

	auto logL1Regions = [&](const std::vector<MemRegion>& regions)
	{
		const size_t maxLog = 128;
		logger->LogInfo("MMU: Regions: %zu (showing up to %zu)", regions.size(), maxLog);
		logger->LogInfo("MMU:   %-21s  %-6s %-13s %-3s  %6s", "Address Range", "Type", "Cache", "Prm", "Size");
		logger->LogInfo("MMU:   %-21s  %-6s %-13s %-3s  %6s", "---------------------", "------", "-------------", "---", "------");
		size_t logged = 0;
		for (const auto& region : regions)
		{
			if (logged >= maxLog)
				break;
			char sizeStr[16];
			uint64_t sz = region.size;
			if (sz >= 0x100000 && (sz % 0x100000) == 0)
				snprintf(sizeStr, sizeof(sizeStr), "%lluMB", (unsigned long long)(sz / 0x100000));
			else if (sz >= 0x400 && (sz % 0x400) == 0)
				snprintf(sizeStr, sizeof(sizeStr), "%lluKB", (unsigned long long)(sz / 0x400));
			else
				snprintf(sizeStr, sizeof(sizeStr), "%lluB", (unsigned long long)sz);

			const char* cachePolicy = "uncached";
			if (region.cacheable && region.bufferable)
				cachePolicy = "write-back";
			else if (region.cacheable && !region.bufferable)
				cachePolicy = "write-through";
			else if (!region.cacheable && region.bufferable)
				cachePolicy = "write-combine";

			logger->LogInfo("MMU:   0x%08llx-0x%08llx  %-6s %-13s %s%s%s  %6s (0x%llx)",
				(unsigned long long)region.virtBase,
				(unsigned long long)(region.virtBase + region.size - 1),
				(region.type ? region.type : "RAM"),
				cachePolicy,
				region.readable ? "R" : "-",
				region.writable ? "W" : "-",
				region.executable ? "X" : "-",
				sizeStr,
				(unsigned long long)region.size);
			logged++;
		}
		if (regions.size() > maxLog)
			logger->LogInfo("MMU:   ... %zu more region(s) not shown", regions.size() - maxLog);
	};

	auto logConfigRegions = [&](const std::vector<MemRegion>& regions)
	{
		const size_t maxLog = 128;
		logger->LogInfo("MMU: Analysis complete. Found %zu memory regions (showing up to %zu):", regions.size(), maxLog);
		logger->LogInfo("MMU:   %-21s  %-6s %-13s %-3s  %6s", "Address Range", "Type", "Cache", "Prm", "Size");
		logger->LogInfo("MMU:   %-21s  %-6s %-13s %-3s  %6s", "---------------------", "------", "-------------", "---", "------");
		size_t logged = 0;
		for (const auto& region : regions)
		{
			if (logged >= maxLog)
				break;
			char sizeStr[16];
			uint64_t sz = region.size;
			if (sz >= 0x100000 && (sz % 0x100000) == 0)
				snprintf(sizeStr, sizeof(sizeStr), "%lluMB", (unsigned long long)(sz / 0x100000));
			else if (sz >= 0x400 && (sz % 0x400) == 0)
				snprintf(sizeStr, sizeof(sizeStr), "%lluKB", (unsigned long long)(sz / 0x400));
			else
				snprintf(sizeStr, sizeof(sizeStr), "%lluB", (unsigned long long)sz);

			const char* baseType = "RAM";
			if (region.type && (strstr(region.type, "MMIO") || strstr(region.type, "Device")))
				baseType = "MMIO";

			const char* cachePolicy = "uncached";
			if (region.cacheable && region.bufferable)
				cachePolicy = "write-back";
			else if (region.cacheable && !region.bufferable)
				cachePolicy = "write-through";
			else if (!region.cacheable && region.bufferable)
				cachePolicy = "write-combine";

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
			logged++;
		}
		if (regions.size() > maxLog)
			logger->LogInfo("MMU:   ... %zu more region(s) not shown", regions.size() - maxLog);
	};

	auto findPrologue = [&](uint64_t ttbrInstrAddr) -> uint64_t
	{
		for (int i = 1; i <= 32 && ttbrInstrAddr >= (uint64_t)(i * 4); i++)
		{
			uint32_t prevInstr = 0;
			ReadU32At(reader, data, dataLen, endian, ttbrInstrAddr - (i * 4), prevInstr, length);
			if ((prevInstr & 0xFFFF0000) == 0xE92D0000 && (prevInstr & 0x4000))
				return ttbrInstrAddr - (i * 4);
		}
		return 0;
	};

	for (uint64_t ttbrInstrAddr : ttbrHits)
	{
		uint32_t instr = 0;
		ReadU32At(reader, data, dataLen, endian, ttbrInstrAddr, instr, length);
		uint32_t rt = (instr >> 12) & 0xF;

		logger->LogInfo("MMU: Found TTBR write at 0x%llx (MCR p15,0,R%d,c2,c0,0/1)",
			(unsigned long long)ttbrInstrAddr, rt);

		uint32_t ttbrRegValue = 0;
		if (!ResolveRegAt(reader, data, dataLen, endian, resolver, ttbrInstrAddr, rt, ttbrRegValue, logger))
		{
			logger->LogInfo("MMU: TTBR value not resolved at 0x%llx", (unsigned long long)ttbrInstrAddr);
			continue;
		}

		uint64_t ttbrValue = ttbrRegValue;
		uint64_t aliasBase = 0;
		uint64_t offTmp = 0;
		if (!resolver.CpuToFile(ttbrValue, offTmp, false))
		{
			aliasBase = ttbrValue & 0xFF000000ULL;
			if (aliasBase != 0)
			{
				AddLow24Alias(resolver, aliasBase, length);
				logger->LogInfo("MMU: Using alias base 0x%08llx", (unsigned long long)aliasBase);
			}
		}

		if ((ttbrValue & ~0x3FFFULL) == 0)
		{
			logger->LogInfo("MMU: TTBR resolved to small value (0x%08llx); may be flags without base",
				(unsigned long long)ttbrValue);
		}

		if (!resolver.CpuToFile(ttbrValue, offTmp, true))
		{
			logger->LogInfo("MMU: TTBR value 0x%08llx not mappable to file", (unsigned long long)ttbrValue);
			continue;
		}

		RomToSramCopy romCopy = FindRomToSramCopy(reader, data, dataLen, endian, length, imageBase,
			resolver, aliasBase, logger);

		uint64_t tableBase = ttbrValue & ~0x3FFFULL;
		logger->LogInfo("MMU: Translation table base = 0x%08llx", (unsigned long long)tableBase);

		bool allZero = true;
		bool allOnes = true;
		bool allFault = true;

		for (int i = 0; i < 16; i++)
		{
			uint32_t entry = 0;
			if (!ReadU32Resolved(reader, data, dataLen, endian, resolver,
				tableBase + (i * 4), romCopy, length, entry))
				break;

			if (entry != 0)
				allZero = false;
			if (entry != 0xFFFFFFFF)
				allOnes = false;
			if ((entry & 0x3) != 0)
				allFault = false;
		}

		bool tableLooksEmpty = allZero || allOnes || allFault;
		if (!tableLooksEmpty)
		{
			std::vector<MemRegion> regions;
			if (ParseArmv5L1Table(reader, data, dataLen, endian, resolver, length, romCopy, tableBase, regions, logger))
			{
				logL1Regions(regions);
				return;
			}
			tableLooksEmpty = true;
			logger->LogInfo("MMU: L1 parse produced no regions; treating as uninitialized");
		}

		if (!tableLooksEmpty)
			continue;

		logger->LogInfo("MMU: Translation table appears uninitialized");

		uint64_t mmuSetupFuncStart = findPrologue(ttbrInstrAddr);
		if (mmuSetupFuncStart != 0)
		{
			logger->LogInfo("MMU: Found MMU setup function start at 0x%llx",
				(unsigned long long)mmuSetupFuncStart);
		}

		std::vector<MMUConfigArray> configArrays;
		uint64_t scanStart = (mmuSetupFuncStart != 0) ? mmuSetupFuncStart : ttbrInstrAddr - 0x100;
		uint64_t scanEnd = ttbrInstrAddr + 0x100;

		if (mmuSetupFuncStart == 0 && ttbrInstrAddr < 0x100)
			scanStart = 0;
		if (scanEnd > length)
			scanEnd = length;

		logger->LogInfo("MMU: Scanning 0x%llx - 0x%llx for config arrays",
			(unsigned long long)scanStart, (unsigned long long)scanEnd);

		for (uint64_t offset = scanStart; offset + 4 <= scanEnd; offset += 4)
		{
			uint32_t instrScan = 0;
			ReadU32At(reader, data, dataLen, endian, offset, instrScan, length);

			if ((instrScan & 0x0F7F0000) == 0x051F0000)
			{
				uint32_t imm12 = instrScan & 0xFFF;
				bool add = (instrScan & 0x00800000) != 0;
				uint64_t pcVal = offset + 8;
				uint64_t litAddr = add ? (pcVal + imm12) : (pcVal - imm12);

				if (litAddr + 4 <= length)
				{
					uint32_t value = 0;
					ReadU32At(reader, data, dataLen, endian, litAddr, value, length);

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

								if (value < valueb && (valueb - value) <= 0x10000)
								{
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
			uint64_t wideStart = (ttbrInstrAddr > 0x1000) ? (ttbrInstrAddr - 0x1000) : 0;
			uint64_t wideEnd = ttbrInstrAddr + 0x1000;
			if (wideEnd > length)
				wideEnd = length;

			logger->LogInfo("MMU: No config arrays found in tight window; widening scan to 0x%llx - 0x%llx",
				(unsigned long long)wideStart, (unsigned long long)wideEnd);

			for (uint64_t offset = wideStart; offset + 4 <= wideEnd; offset += 4)
			{
				uint32_t instrScan = 0;
				ReadU32At(reader, data, dataLen, endian, offset, instrScan, length);

				if ((instrScan & 0x0F7F0000) == 0x051F0000)
				{
					uint32_t imm12 = instrScan & 0xFFF;
					bool add = (instrScan & 0x00800000) != 0;
					uint64_t pcVal = offset + 8;
					uint64_t litAddr = add ? (pcVal + imm12) : (pcVal - imm12);

					if (litAddr + 4 <= length)
					{
						uint32_t value = 0;
						ReadU32At(reader, data, dataLen, endian, litAddr, value, length);

						for (int i = 1; i <= 5 && offset + (i * 4) + 4 <= wideEnd; i++)
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

									if (value < valueb && (valueb - value) <= 0x10000)
									{
										bool isIdentity = ((valueb - value) % 4 == 0);

										MMUConfigArray arr;
										arr.startAddr = value;
										arr.endAddr = valueb;
										arr.isIdentity = isIdentity;
										arr.litPoolAddr1 = litAddr;
										arr.litPoolAddr2 = litAddrb;
										configArrays.push_back(arr);

										logger->LogInfo("MMU: Found config array at 0x%llx-0x%llx (%s) [widened scan]",
											(unsigned long long)value, (unsigned long long)valueb,
											isIdentity ? "identity" : "VA->PA");
									}
								}
							}
						}
					}
				}
			}
		}

		if (configArrays.empty())
		{
			logger->LogInfo("MMU: No config arrays found for TTBR at 0x%llx", (unsigned long long)ttbrInstrAddr);
			continue;
		}

		vector<MemRegion> regions;
		MemRegion currentRegion = {0, 0, 0, false, false, false, false, false, nullptr};

		for (const auto& arr : configArrays)
		{
			MapFormat fmt = {};
			MapStats st = {};
			if (!ChooseBestFormat(resolver, reader, data, dataLen, endian, romCopy, length, arr, fmt, st))
			{
				logger->LogInfo("MMU: Rejecting candidate array 0x%llx-0x%llx (failed preflight)",
												(unsigned long long)arr.startAddr, (unsigned long long)arr.endAddr);
				continue;
			}

			uint64_t entrySize = (fmt.kind == MapEntryKind::Identity4) ? 4 : 8;
			uint64_t entryCount = (arr.endAddr - arr.startAddr) / entrySize;
			logger->LogInfo("MMU: Using format %s %s (score=%.2f aligned=%zu/%zu stride=0x%x flags=%zu)",
											(fmt.kind == MapEntryKind::VaPa8 ? "VaPa8" : "Identity4"),
											(fmt.gran == MapGranularity::Section1M ? "1M" : "4K"),
											st.score, st.aligned, st.samples, st.dominantStride, st.uniqueFlags);
			uint64_t approxSpan = entryCount * fmt.pageSize;
			if (approxSpan > (4ull * 1024 * 1024 * 1024))
			{
				logger->LogInfo("MMU: Rejecting table: implied VA span too large (0x%llx)",
												(unsigned long long)approxSpan);
				continue;
			}

			// Cap insanity early
			if (approxSpan > (512ull * 1024 * 1024))
			{
				logger->LogInfo("MMU: Rejecting huge map: implied VA span 0x%llx",
												(unsigned long long)approxSpan);
				continue;
			}

			logger->LogInfo("MMU: Parsing config array with %llu entries", (unsigned long long)entryCount);
			currentRegion = {0, 0, 0, false, false, false, false, false, nullptr}; // IMPORTANT: reset per array
			for (uint64_t i = 0; i < entryCount; i++)
			{
				uint64_t entryAddr = arr.startAddr + i * entrySize;
				uint32_t w0 = 0, w1 = 0;
				if (!ReadEntry(resolver, reader, data, dataLen, endian, romCopy, length, entryAddr, fmt.kind, w0, w1))
					break;

				uint32_t vaRaw = w0;
				uint32_t paRaw = (fmt.kind == MapEntryKind::VaPa8) ? w1 : w0;

				uint32_t va = vaRaw & fmt.alignMask;
				uint32_t pa = paRaw & fmt.alignMask;
				uint32_t flags = paRaw & fmt.knownFlagMask;

				// Your flag decode (keep it, but now flags won’t be “address dust”)
				bool readable = (flags & 0x01) != 0;
				bool writable = (flags & 0x02) != 0;
				bool executable = (flags & 0x04) != 0;
				bool cacheable = (flags & 0x08) != 0;
				bool bufferable = (flags & 0x10) != 0;
				const char *type = (flags & 0x20) ? "MMIO" : "RAM";

				uint64_t chunk = fmt.pageSize;

				if (currentRegion.size == 0)
				{
					currentRegion = {va, pa, chunk, readable, writable, executable, cacheable, bufferable, type};
				}
				else if (va == currentRegion.virtBase + currentRegion.size &&
								 pa == currentRegion.physBase + currentRegion.size &&
								 readable == currentRegion.readable && writable == currentRegion.writable &&
								 executable == currentRegion.executable && cacheable == currentRegion.cacheable &&
								 bufferable == currentRegion.bufferable && strcmp(type, currentRegion.type) == 0)
				{
					currentRegion.size += chunk;
				}
				else
				{
					regions.push_back(currentRegion);
					currentRegion = {va, pa, chunk, readable, writable, executable, cacheable, bufferable, type};
				}
			}

			if (currentRegion.size)
				regions.push_back(currentRegion);
		}

		std::vector<MemRegion> uniqueRegions;
		std::sort(regions.begin(), regions.end(),
			[](const MemRegion& a, const MemRegion& b) { return a.virtBase < b.virtBase; });

		for (const auto& region : regions)
		{
			if (!uniqueRegions.empty())
			{
				MemRegion& last = uniqueRegions.back();
				if (region.virtBase == last.virtBase &&
					region.physBase == last.physBase &&
					region.size == last.size &&
					region.readable == last.readable && region.writable == last.writable &&
					region.executable == last.executable && region.cacheable == last.cacheable &&
					region.bufferable == last.bufferable && strcmp(region.type, last.type) == 0)
				{
					continue;
				}
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

		logConfigRegions(uniqueRegions);
		return;
	}

	if (!data)
		return;

	std::vector<uint64_t> candidates;
	for (uint64_t off = 0; off + 0x4000 <= length; off += 0x4000)
	{
		if (LooksLikeL1Table(reader, data, dataLen, endian, off, length))
			candidates.push_back(off);
	}

	if (candidates.empty())
	{
		logger->LogInfo("MMU: No L1 candidates found by structure scan");
		return;
	}

	logger->LogInfo("MMU: Found %zu L1 table candidates by structure scan", candidates.size());

	for (uint64_t off : candidates)
	{
		uint64_t cpuAddr = 0;
		if (!resolver.FileToCpu(off, cpuAddr, true))
			cpuAddr = off;

		RomToSramCopy dummy = {0, 0, 0, false};
		std::vector<MemRegion> regions;
		if (ParseArmv5L1Table(reader, data, dataLen, endian, resolver, length, dummy, cpuAddr, regions, logger))
		{
			logger->LogInfo("MMU: Using L1 table candidate at file offset 0x%llx", (unsigned long long)off);
			logL1Regions(regions);
			return;
		}
	}
}
