/*
 * ARMv5 Firmware MMU Analysis
 */

#include "firmware_internal.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <unordered_set>
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

// Walking mode for discovering TTBR/config arrays when the L1 table isn't initialized.
// Heuristic = current scan+local backsolve (fast, robust when code is straight-line)
// Emulated  = lightweight forward emulation with branch following (slower, handles CFG)
enum class MMUWalkMode
{
	Heuristic,
	Emulated,
};


static MMUWalkMode GetMMUWalkMode(const Ref<BinaryView>& view, Ref<Logger> logger)
{
	// Option 1: environment variable (works everywhere)
	//   BN_MMU_WALK=emu     -> Emulated
	//   BN_MMU_WALK=heur    -> Heuristic
	//   BN_MMU_EMU_WALK=1   -> Emulated (legacy convenience)
	const char* v = std::getenv("BN_MMU_WALK");
	if (v && *v)
	{
		std::string s(v);
		for (auto& ch : s) ch = (char)std::tolower((unsigned char)ch);
		if (s == "emu" || s == "emulated" || s == "emulate")
		{
			if (logger) logger->LogInfo("MMU: WalkMode=Emulated (BN_MMU_WALK=%s)", v);
			return MMUWalkMode::Emulated;
		}
		if (s == "heur" || s == "heuristic" || s == "scan")
		{
			if (logger) logger->LogInfo("MMU: WalkMode=Heuristic (BN_MMU_WALK=%s)", v);
			return MMUWalkMode::Heuristic;
		}
	}


	const char* v2 = std::getenv("BN_MMU_EMU_WALK");
	if (v2 && *v2 && std::strcmp(v2, "0") != 0)
	{
		if (logger) logger->LogInfo("MMU: WalkMode=Emulated (BN_MMU_EMU_WALK=%s)", v2);
		return MMUWalkMode::Emulated;
	}


	// Option 2 (future): wire to BN Settings when/if you register keys elsewhere.
	(void)view;


	return MMUWalkMode::Heuristic;
}
struct MapFormat
{
	MapEntryKind kind;
	MapGranularity gran;
	uint32_t knownFlagMask; // which bits we consider “flags”
	uint32_t alignMask;         // address alignment mask
	uint32_t pageSize;          // 0x1000 or 0x100000
	bool swapWords = false;        // VaPa8 may be stored as {PA,VA} instead of {VA,PA}
	uint64_t effectiveEndAddr = 0; // tolerate inclusive end pointers
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

// Forward declaration (used by ParseRegionDesc16 before definition below)
static inline void AppendRegion(std::vector<MemRegion>& outRegions, const MemRegion& region);

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
														MapEntryKind kind, bool swapWords, MapGranularity gran,
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
		if (kind == MapEntryKind::VaPa8 && swapWords)
		{
			// Some firmwares store entries as {PA, VA}
			vaRaw = w1;
			paRaw = w0;
		}

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
			int64_t sd = (int64_t)va - (int64_t)prevVA;
			// Only count forward, reasonably-sized strides; ignore wrap/underflow and wild jumps.
			// For real maps the stride is usually pageSize (or a small multiple) and VA is monotonic.
			uint32_t maxStride = pageSize * 16; // tolerate small gaps, but not hundreds of MB
			if (sd > 0 && (uint64_t)sd <= maxStride)
			{
				strideFreq[(uint32_t)sd]++;
			}
			else
			{
				// Track outliers by counting a 0 stride bucket (used only for scoring penalty below).
				strideFreq[0]++;
			}
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
	// strideHits is based on strideFreq; compute a rate against the number of stride observations (samples-1)
	double strideRate = (st.samples > 1 ? (double)st.strideHits / (double)(st.samples - 1) : 0.0);
	// Penalize if we saw lots of outlier strides (we stored them under stride==0)
	size_t outlierStrides = 0;
	auto itOut = strideFreq.find(0);
	if (itOut != strideFreq.end())
		outlierStrides = itOut->second;
	double outlierPenalty = 1.0;
	if (st.samples > 1)
	{
		double outlierRate = (double)outlierStrides / (double)(st.samples - 1);
		// If more than 20% of strides are outliers, heavily penalize.
		if (outlierRate > 0.20)
			outlierPenalty = 0.25;
		else if (outlierRate > 0.10)
			outlierPenalty = 0.60;
	}
	double flagPenalty = (st.uniqueFlags > 32) ? 0.25 : 1.0; // brutal penalty if flags explode

	st.score = (alignRate * 0.55) + (strideRate * 0.35) + (flagPenalty * 0.10);
	st.score *= outlierPenalty;
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
		bool swap;
	};
	Cand cands[] = {
			// Prefer VaPa8 first, try both word orders.
			{MapEntryKind::VaPa8,     MapGranularity::Section1M, kFlagMaskTight, false},
			{MapEntryKind::VaPa8,     MapGranularity::Section1M, kFlagMaskTight, true},
			{MapEntryKind::VaPa8,     MapGranularity::Page4K,    kFlagMaskTight, false},
			{MapEntryKind::VaPa8,     MapGranularity::Page4K,    kFlagMaskTight, true},
			{MapEntryKind::Identity4, MapGranularity::Section1M, kFlagMaskTight, false},
			{MapEntryKind::Identity4, MapGranularity::Page4K,    kFlagMaskTight, false},

			// Loose flag masks as fallback.
			{MapEntryKind::VaPa8,     MapGranularity::Section1M, kFlagMaskLoose, false},
			{MapEntryKind::VaPa8,     MapGranularity::Section1M, kFlagMaskLoose, true},
			{MapEntryKind::VaPa8,     MapGranularity::Page4K,    kFlagMaskLoose, false},
			{MapEntryKind::VaPa8,     MapGranularity::Page4K,    kFlagMaskLoose, true},
			{MapEntryKind::Identity4, MapGranularity::Section1M, kFlagMaskLoose, false},
			{MapEntryKind::Identity4, MapGranularity::Page4K,    kFlagMaskLoose, false},
	};

	MapStats bestSt;
	MapFormat bestFmt = {};
	double bestScore = 0.0;

	for (auto &c : cands)
	{
		uint64_t entrySize = (c.k == MapEntryKind::Identity4) ? 4 : 8;
		uint64_t baseLen = (arr.endAddr > arr.startAddr) ? (arr.endAddr - arr.startAddr) : 0;
		if (baseLen < entrySize * 4)
			continue;

		// Some firmwares store an inclusive end pointer; tolerate +4/+8 to make length divisible.
		uint64_t bestLenForCand = 0;
		MapStats bestStForCand;
		double bestScoreForCand = 0.0;

		for (uint64_t extra = 0; extra <= 8; extra += 4)
		{
			uint64_t len = baseLen + extra;
			if (len < entrySize * 4)
				continue;
			if ((len % entrySize) != 0)
				continue;

			uint64_t endAddr = arr.startAddr + len;
			uint64_t count = len / entrySize;
			if (c.g == MapGranularity::Section1M && count > 4096)
				continue;

			MapStats st = ScoreFormat(resolver, reader, data, dataLen, endian, romCopy, length,
															arr.startAddr, endAddr, c.k, c.swap, c.g, c.fm);

			// Boot ROM tables can be small; accept fewer samples.
			if (st.samples < 8)
				continue;

			if (st.score > bestScoreForCand)
			{
				bestScoreForCand = st.score;
				bestStForCand = st;
				bestLenForCand = len;
			}
		}

		if (bestLenForCand == 0)
			continue;

		MapStats st = bestStForCand;
		uint64_t endAddr = arr.startAddr + bestLenForCand;

		if (st.score > bestScore)
		{
			bestScore = st.score;
			bestSt = st;
			bestFmt.kind = c.k;
			bestFmt.gran = c.g;
			bestFmt.knownFlagMask = c.fm;
			bestFmt.alignMask = MaskForGran(c.g);
			bestFmt.pageSize = PageSizeForGran(c.g);
			bestFmt.swapWords = c.swap;
			bestFmt.effectiveEndAddr = endAddr;
		}
	}

	// Boot ROM tables can be compact/irregular; keep thresholds permissive but still structured.
	if (bestScore < 0.45)
		return false;
	if (bestSt.samples && ((double)bestSt.aligned / (double)bestSt.samples) < 0.55)
		return false;
	if (bestSt.uniqueFlags > 1024) // flags look like address residue
		return false;
	if (!bestSt.haveVA || bestSt.maxVA <= bestSt.minVA)
		return false;
	if (bestFmt.pageSize != 0)
	{
		if (bestSt.dominantStride == 0)
			return false;
		if ((bestSt.dominantStride % bestFmt.pageSize) != 0)
			return false;
		// Reject absurd gaps (these are almost always unsigned underflow / wrap or not a real map).
		uint32_t maxStride = bestFmt.pageSize * 16;
		if (bestSt.dominantStride > maxStride)
			return false;
	}

	outFmt = bestFmt;
	outStats = bestSt;
	return true;
}

// Fallback: some firmwares build MMU regions via a compact descriptor list instead of per-page/section maps.
// Common shape we see in boot ROMs: 16-byte entries {va, pa, size, flags}.
// If this parses cleanly, emit regions directly.
static bool ParseRegionDesc16(const AddressResolver &resolver, BinaryReader &reader,
                             const uint8_t *data, uint64_t dataLen, BNEndianness endian,
                             const RomToSramCopy &romCopy, uint64_t length,
                             const MMUConfigArray &arr,
                             std::vector<MemRegion> &outRegions,
                             Ref<Logger> logger)
{
	outRegions.clear();
	if (arr.endAddr <= arr.startAddr)
		return false;

	uint64_t len = arr.endAddr - arr.startAddr;
	if (len < 16 * 4) // need at least 4 entries
		return false;

	// Many firmwares store an inclusive end pointer; tolerate small misalignment by rounding down.
	uint64_t entryCount = len / 16;
	if (entryCount < 4)
		return false;

	size_t valid = 0;
	size_t total = 0;

	for (uint64_t i = 0; i < entryCount; i++)
	{
		uint64_t ea = arr.startAddr + i * 16;
		uint32_t va = 0, pa = 0, sz = 0, flags = 0;
		if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, ea + 0, romCopy, length, va))
			break;
		if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, ea + 4, romCopy, length, pa))
			break;
		if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, ea + 8, romCopy, length, sz))
			break;
		if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, ea + 12, romCopy, length, flags))
			break;

		total++;

		// Basic sanity: size must be plausible and aligned; VA/PA aligned too.
		if (sz < 0x400 || sz > (512u * 1024u * 1024u))
			continue;
		if ((sz & 0x3FFu) != 0)
			continue;
		if ((va & 0x3FFu) != 0 || (pa & 0x3FFu) != 0)
			continue;

		// Reject obviously bogus "sizes" that look like pointers (same high byte as VA/PA but huge span)
		// (keeps false-positives down on random data).
		if ((sz & 0xFF000000u) == (va & 0xFF000000u) && sz > 0x01000000u)
			continue;

		// Use the same flag decode as the per-entry map path; many firmwares reuse this bitfield.
		bool readable = (flags & 0x01) != 0;
		bool writable = (flags & 0x02) != 0;
		bool executable = (flags & 0x04) != 0;
		bool cacheable = (flags & 0x08) != 0;
		bool bufferable = (flags & 0x10) != 0;
		const char* type = (flags & 0x20) ? "MMIO" : "RAM";

		MemRegion r = {(uint64_t)va, (uint64_t)pa, (uint64_t)sz,
			readable, writable, executable, cacheable, bufferable, type};
		AppendRegion(outRegions, r);
		valid++;
	}

	if (total < 4)
		return false;

	double rate = (double)valid / (double)total;
	if (valid < 4 || rate < 0.60)
		return false;

	if (logger)
		logger->LogInfo("MMU: RegionDesc16 accepted (valid=%zu/%zu, rate=%.2f)", valid, total, rate);
	return !outRegions.empty();
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
	//   Mask 0x0FF00FFF (ignore cond, Rn, Rd), value 0x04900004
	// ARM encoding for STRLO:
	//   Mask 0x0FF00FFF, value 0x04800004

	for (uint64_t offset = 0; offset + 8 <= length; offset += 4)
	{
		uint32_t instr1 = 0, instr2 = 0;
		ReadU32At(reader, data, dataLen, endian, offset, instr1, length);
		ReadU32At(reader, data, dataLen, endian, offset + 4, instr2, length);

		bool isLdrLo1 = (instr1 & 0x0FF00FFF) == 0x04900004 && (instr1 & 0xF0000000) == 0x30000000;
		bool isStrLo1 = (instr1 & 0x0FF00FFF) == 0x04800004 && (instr1 & 0xF0000000) == 0x30000000;
		bool isLdrLo2 = (instr2 & 0x0FF00FFF) == 0x04900004 && (instr2 & 0xF0000000) == 0x30000000;
		bool isStrLo2 = (instr2 & 0x0FF00FFF) == 0x04800004 && (instr2 & 0xF0000000) == 0x30000000;

		if (!((isLdrLo1 && isStrLo2) || (isStrLo1 && isLdrLo2)))
			continue;

		logger->LogInfo("MMU: Found copy loop at file offset 0x%llx (LDRLO/STRLO pattern)",
			(unsigned long long)offset);

		// Scan backwards to find literal pool loads that set up the copy.
		// Important: literals are often a few hundred bytes before the tight loop.
		std::vector<std::pair<uint64_t, uint32_t>> literalRefs; // (lit_file_off, value)

		// Scan up to 256 instructions back (~1KB)
		for (int i = 1; i <= 256 && offset >= (uint64_t)(i * 4); i++)
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

		// Collect ROM-src candidates and SRAM (alias) candidates.
		// We do NOT assume strict consecutiveness; we search for "nearby" literal pool entries.
		std::vector<std::pair<uint64_t, uint64_t>> romCands;  // (rom_cpu, lit_off)
		std::vector<std::pair<uint64_t, uint64_t>> sramCands; // (sram_cpu, lit_off)

		for (const auto& ref : literalRefs)
		{
			uint64_t litOff = ref.first;
			uint32_t val = ref.second;

			uint64_t offTmp = 0;

			// SRAM address: matches alias base (high byte)
			if ((((uint64_t)val) & 0xFF000000ULL) == aliasBase)
			{
				sramCands.push_back({(uint64_t)val, litOff});
				continue;
			}

			// ROM-ish address: something that can map into the file.
			// Prefer non-fallback (allowFallback=false), but keep a fallback option if needed.
			if (resolver.CpuToFile((uint64_t)val, offTmp, false) && offTmp > 0x1000 && offTmp < length)
			{
				romCands.push_back({(uint64_t)val, litOff});
			}
			else if (resolver.CpuToFile((uint64_t)val, offTmp, true) && offTmp > 0x1000 && offTmp < length)
			{
				// keep these too; theyre lower priority but better than nothing
				romCands.push_back({(uint64_t)val, litOff});
			}
			else if (imageBase && (uint64_t)val >= imageBase && (uint64_t)val < (imageBase + length))
			{
				// If we have a real imageBase, accept pointers into that range even if resolver is ambiguous.
				romCands.push_back({(uint64_t)val, litOff});
			}
		}

		if (romCands.empty() || sramCands.size() < 2)
			continue;

		// Sort SRAM candidates by literal pool location so we can pick a tight "cluster".
		std::sort(sramCands.begin(), sramCands.end(),
			[](const std::pair<uint64_t, uint64_t>& a, const std::pair<uint64_t, uint64_t>& b)
			{
				return a.second < b.second;
			});

		// Pick the best local cluster of SRAM literals near the loop.
		// Rationale: firmware often has multiple SRAM pointers (start/end + related anchors) and
		// our old "best pair" heuristic could miss the true start by a few words (as seen in btrom:
		// candidates start at 0xa402f74c but we picked 0xa402f790).
		// We instead select a window in the literal pool (<= 0x80 bytes span) that contains the
		// most SRAM pointers; then we use min/max address in that window as the copy range.
		const uint64_t kMaxLitSpan = 0x80;
		const uint64_t kMinCopy = 0x100;
		const uint64_t kMaxCopy = 0x200000;

		size_t bestCount = 0;
		uint64_t bestSpan = ~0ULL;
		uint64_t bestSize = 0;
		uint64_t bestSramDst = 0;
		uint64_t bestSramEnd = 0;
		uint64_t bestLitMid = 0;

		for (size_t i = 0; i < sramCands.size(); i++)
		{
			uint64_t litFirst = sramCands[i].second;
			uint64_t litLast = litFirst;
			uint64_t minAddr = sramCands[i].first;
			uint64_t maxAddr = sramCands[i].first;
			size_t count = 1;

			for (size_t j = i + 1; j < sramCands.size(); j++)
			{
				uint64_t litJ = sramCands[j].second;
				uint64_t span = (litJ >= litFirst) ? (litJ - litFirst) : (litFirst - litJ);
				if (span > kMaxLitSpan)
					break; // sorted by lit addr; further j only increases span

				litLast = litJ;
				count++;
				minAddr = std::min<uint64_t>(minAddr, sramCands[j].first);
				maxAddr = std::max<uint64_t>(maxAddr, sramCands[j].first);
			}

			if (count < 2)
				continue;

			uint64_t startAddr = minAddr;
			uint64_t endAddr = maxAddr;
			uint64_t size = (endAddr > startAddr) ? (endAddr - startAddr) : 0;
			uint64_t span = (litLast >= litFirst) ? (litLast - litFirst) : (litFirst - litLast);

			if ((startAddr & 3) != 0 || (endAddr & 3) != 0)
				continue;
			if (size < kMinCopy || size > kMaxCopy)
				continue;

			// Score: prefer more pointers (strong signal), then larger coverage, then tighter lit span.
			bool better = false;
			if (count > bestCount)
				better = true;
			else if (count == bestCount && size > bestSize)
				better = true;
			else if (count == bestCount && size == bestSize && span < bestSpan)
				better = true;

			if (better)
			{
				bestCount = count;
				bestSpan = span;
				bestSize = size;
				bestSramDst = startAddr;
				bestSramEnd = endAddr;
				bestLitMid = (litFirst + litLast) / 2;
			}
		}

		if (bestSramDst == 0 || bestSramEnd == 0)
			continue;

		// Normalize: ensure dst < end
		if (bestSramEnd < bestSramDst)
			std::swap(bestSramDst, bestSramEnd);
		uint64_t bestRom = 0;
		uint64_t bestDist = ~0ULL;
		for (const auto& rc : romCands)
		{
			uint64_t litOff = rc.second;
			uint64_t dist = (litOff > bestLitMid) ? (litOff - bestLitMid) : (bestLitMid - litOff);
			if (dist < bestDist)
			{
				bestDist = dist;
				bestRom = rc.first;
			}
		}

		if (bestRom == 0)
			continue;

		result.romSrc = bestRom;
		result.sramDst = bestSramDst;
		result.sramEnd = bestSramEnd;
		// Some firmwares use the end pointer as inclusive; make the range robust by allowing
		// a small extension if the interval looks suspiciously tiny.
		if (result.sramEnd > result.sramDst && (result.sramEnd - result.sramDst) < 0x100)
			result.sramEnd = result.sramDst + 0x100;
		result.valid = true;

		logger->LogInfo("MMU: ROM-to-SRAM copy found:");
		logger->LogInfo("MMU:   ROM source:  0x%08llx", (unsigned long long)result.romSrc);
		logger->LogInfo("MMU:   SRAM dest:   0x%08llx - 0x%08llx",
			(unsigned long long)result.sramDst, (unsigned long long)result.sramEnd);
		logger->LogInfo("MMU:   Size:        %llu bytes", (unsigned long long)(result.sramEnd - result.sramDst));

		return result;
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



// --------------------------
// Lightweight ARMv5 forward emulation (branch-following)
// Purpose: resolve TTBR register and collect literal loads / candidate config pointers
// without requiring straight-line code.
// This is *not* a full emulator: no memory model except literal reads, no flags solving.
// Conditional branches are explored both taken and not-taken.
// --------------------------


static inline bool IsBranchImm(uint32_t ins)
{
	// ARM B/BL: bits[27:25] == 101
	return ((ins >> 25) & 0x7) == 0x5;
}


static inline uint64_t BranchTarget(uint64_t curCpuPc, uint32_t ins)
{
	// imm24 sign-extended, shifted left 2, added to PC+8 (curCpuPc is current instruction address)
	int32_t imm24 = (int32_t)(ins & 0x00FFFFFFu);
	// sign extend 24->32
	if (imm24 & 0x00800000)
		imm24 |= 0xFF000000;
	int32_t off = (imm24 << 2);
	return (uint64_t)((int64_t)(curCpuPc + 8) + (int64_t)off);
}


static inline uint32_t CondField(uint32_t ins) { return (ins >> 28) & 0xF; }
static inline bool CondAlways(uint32_t cond) { return cond == 0xE; } // AL
static inline bool CondNever(uint32_t cond) { return cond == 0xF; }  // NV (treat as never)


static inline uint64_t HashRegs(const RegVal regs[16])
{
	// Cheap hash: fold known bits and values.
	uint64_t h = 1469598103934665603ull; // FNV offset
	for (int i = 0; i < 16; i++)
	{
		uint64_t x = (uint64_t)(regs[i].known ? 0xA5A50000u : 0x5A5A0000u) | (uint64_t)regs[i].v;
		h ^= x + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
	}
	return h;
}


struct LitLoad
{
	uint64_t insFileOff = 0;
	uint64_t litCpuAddr = 0;
	uint32_t value = 0;
	uint32_t rd = 0;
};


struct EmuResult
{
	bool regResolved = false;
	uint32_t regValue = 0;
	std::vector<LitLoad> literalLoads;
};


static void EmuStepInstruction(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, const AddressResolver& resolver, uint64_t fileOff,
	RegVal regs[16], EmuResult& out, Ref<Logger> logger)
{
	uint32_t ins = 0;
	ReadU32At(reader, data, dataLen, endian, fileOff, ins, resolver.fileLen);


	auto getCpuPc = [&](uint64_t fileOff2, uint64_t& outCpuPc) -> bool
	{
		return resolver.FileToCpu(fileOff2, outCpuPc, true);
	};


	// MOV (register): 0x01A00000
	if ((ins & 0x0FF0FFF0) == 0x01A00000)
	{
		uint32_t rd = (ins >> 12) & 0xF;
		uint32_t rm = ins & 0xF;
		// If this is MOV pc, Rm, control flow is handled in ResolveRegAtEmulated.
		if (rd == 15)
			return;
		if (regs[rm].known) regs[rd] = regs[rm];
		else regs[rd].known = false;
		return;
	}


	// MOV (imm): 0x03A00000
	if ((ins & 0x0FEF0000) == 0x03A00000)
	{
		uint32_t rd = (ins >> 12) & 0xF;
		regs[rd].known = true;
		regs[rd].v = DecodeImm12(ins);
		return;
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
			else regs[rd].known = false;
			return;
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
			else regs[rd].known = false;
			return;
		}
	}


	// ADD/SUB (imm)
	if ((ins & 0x0FE00000) == 0x02800000 || (ins & 0x0FE00000) == 0x02400000)
	{
		uint32_t rd = (ins >> 12) & 0xF;
		uint32_t rn = (ins >> 16) & 0xF;
		uint32_t opcode = (ins >> 21) & 0xF;
		uint32_t imm = DecodeImm12(ins);


		if (opcode == 0x4) // ADD
		{
			if (rn == 15)
			{
				uint64_t cpuPc = 0;
				if (getCpuPc(fileOff, cpuPc)) { regs[rd].known = true; regs[rd].v = (uint32_t)(cpuPc + 8 + imm); }
				else { regs[rd].known = true; regs[rd].v = (uint32_t)(fileOff + 8 + imm); }
			}
			else if (regs[rn].known) { regs[rd].known = true; regs[rd].v = regs[rn].v + imm; }
			else regs[rd].known = false;
			return;
		}
		if (opcode == 0x2) // SUB
		{
			if (rn == 15)
			{
				uint64_t cpuPc = 0;
				if (getCpuPc(fileOff, cpuPc)) { regs[rd].known = true; regs[rd].v = (uint32_t)(cpuPc + 8 - imm); }
				else { regs[rd].known = true; regs[rd].v = (uint32_t)(fileOff + 8 - imm); }
			}
			else if (regs[rn].known) { regs[rd].known = true; regs[rd].v = regs[rn].v - imm; }
			else regs[rd].known = false;
			return;
		}
	}


	// LDR literal
	if ((ins & 0x0F7F0000) == 0x051F0000)
	{
		uint32_t rd = (ins >> 12) & 0xF;
		// If this is a load into PC, control-flow is handled in ResolveRegAtEmulated.
		if (rd == 15)
			return;
		uint32_t imm12 = ins & 0xFFF;
		bool add = (ins & 0x00800000) != 0;

		uint64_t cpuPc = 0;
		uint64_t litCpu = 0;
		uint32_t val = 0;
		RomToSramCopy dummy = {0, 0, 0, false};

		if (getCpuPc(fileOff, cpuPc))
		{
			uint64_t pcVal = cpuPc + 8;
			litCpu = add ? (pcVal + imm12) : (pcVal - imm12);
			if (ReadU32Resolved(reader, data, dataLen, endian, resolver, litCpu, dummy, resolver.fileLen, val))
			{
				regs[rd].known = true;
				regs[rd].v = val;
				out.literalLoads.push_back({fileOff, litCpu, val, rd});
			}
			else regs[rd].known = false;
		}
		else
		{
			uint64_t pcFile = fileOff + 8;
			uint64_t litFile = add ? (pcFile + imm12) : (pcFile - imm12);
			if (litFile + 4 <= resolver.fileLen && ReadU32At(reader, data, dataLen, endian, litFile, val, resolver.fileLen))
			{
				regs[rd].known = true;
				regs[rd].v = val;
				// best-effort: record litCpuAddr as file-based value if CPU mapping unknown
				out.literalLoads.push_back({fileOff, litFile, val, rd});
			}
			else regs[rd].known = false;
		}
		return;
	}


	// Conservative invalidation for other ops that write Rd (same policy as ResolveRegAt)
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


	(void)logger;
}


static bool ResolveRegAtEmulated(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, const AddressResolver& resolver,
	uint64_t startFileOff, uint64_t endFileOff,
	uint32_t targetReg, uint32_t& outValue,
	EmuResult* optResult, Ref<Logger> logger)
{
	if (startFileOff >= resolver.fileLen || endFileOff > resolver.fileLen || startFileOff >= endFileOff)
		return false;


	struct Node { uint64_t off; RegVal regs[16]; };
	std::vector<Node> work;
	work.reserve(64);


	Node n{};
	n.off = startFileOff & ~3ull;
	work.push_back(n);


	std::unordered_set<uint64_t> visited;
	visited.reserve(4096);


	const size_t kMaxStates = 20000;
	const uint64_t kMaxSpan = 0x3000; // keep bounded: function-local-ish


	EmuResult localRes;


	while (!work.empty() && visited.size() < kMaxStates)
	{
		Node cur = work.back();
		work.pop_back();


		// clamp exploration window (avoid runaway into other code)
		if (cur.off + 4 > resolver.fileLen)
			continue;
		if (cur.off > endFileOff)
			continue;
		if (cur.off > startFileOff + kMaxSpan && endFileOff <= startFileOff + kMaxSpan)
			continue;


		uint64_t h = (cur.off << 1) ^ HashRegs(cur.regs);
		if (visited.find(h) != visited.end())
			continue;
		visited.insert(h);


		if (cur.off == endFileOff)
		{
			if (cur.regs[targetReg].known)
			{
				outValue = cur.regs[targetReg].v;
				if (optResult) *optResult = localRes;
				return true;
			}
			continue;
		}


		uint32_t ins = 0;
		ReadU32At(reader, data, dataLen, endian, cur.off, ins, resolver.fileLen);

		// Indirect branch: BX Rm
		// Encoding: 0x012FFF10 | Rm (ignore cond)
		if ((ins & 0x0FFFFFF0u) == 0x012FFF10u)
		{
			uint32_t rm = ins & 0xFu;
			if (!cur.regs[rm].known)
				continue;

			uint64_t tgtCpu = (uint64_t)cur.regs[rm].v;
			uint64_t tgtFile = 0;
			if (!resolver.CpuToFile(tgtCpu, tgtFile, true))
				continue;

			Node taken = cur;
			taken.off = tgtFile & ~3ull;
			work.push_back(taken);
			continue;
		}

		// MOV pc, Rm (data-processing MOV with Rd==15)
		if ((ins & 0x0FF0FFF0u) == 0x01A00000u)
		{
			uint32_t rd = (ins >> 12) & 0xFu;
			uint32_t rm = ins & 0xFu;
			if (rd == 15)
			{
				if (!cur.regs[rm].known)
					continue;
				uint64_t tgtCpu = (uint64_t)cur.regs[rm].v;
				uint64_t tgtFile = 0;
				if (!resolver.CpuToFile(tgtCpu, tgtFile, true))
					continue;
				Node taken = cur;
				taken.off = tgtFile & ~3ull;
				work.push_back(taken);
				continue;
			}
		}

		// LDR pc, [pc, #imm] (literal load into PC)
		if ((ins & 0x0F7F0000u) == 0x051F0000u && (((ins >> 12) & 0xFu) == 15))
		{
			uint32_t imm12 = ins & 0xFFFu;
			bool add = (ins & 0x00800000u) != 0;

			uint64_t cpuPc = 0;
			if (!resolver.FileToCpu(cur.off, cpuPc, true))
				cpuPc = cur.off;

			uint64_t pcVal = cpuPc + 8;
			uint64_t litCpu = add ? (pcVal + imm12) : (pcVal - imm12);
			uint32_t val = 0;
			RomToSramCopy dummy = {0, 0, 0, false};
			if (!ReadU32Resolved(reader, data, dataLen, endian, resolver, litCpu, dummy, resolver.fileLen, val))
				continue;

			// Record the literal load for later candidate derivation.
			localRes.literalLoads.push_back({cur.off, litCpu, val, 15});

			uint64_t tgtFile = 0;
			if (!resolver.CpuToFile((uint64_t)val, tgtFile, true))
				continue;
			Node taken = cur;
			taken.off = tgtFile & ~3ull;
			work.push_back(taken);
			continue;
		}

		// Branch immediate handling (explore)
		if (IsBranchImm(ins))
		{
			uint32_t cond = CondField(ins);
			if (CondNever(cond))
			{
				// treat as no-op (rare NV in ARM state)
			}
			else
			{
				uint64_t cpuPc = 0;
				if (!resolver.FileToCpu(cur.off, cpuPc, true))
					cpuPc = cur.off;

				uint64_t tgtCpu = BranchTarget(cpuPc, ins);
				uint64_t tgtFile = 0;
				if (resolver.CpuToFile(tgtCpu, tgtFile, true))
				{
					Node taken = cur;
					taken.off = tgtFile & ~3ull;

					// BL behaves like a call: set LR to return address (next instruction) and
					// explore fallthrough regardless of condition (call-return behavior).
					bool isBL = (ins & (1u << 24)) != 0;
					if (isBL)
					{
						uint32_t lrVal = 0;
						// In ARM state, LR gets address of the next instruction (curCpuPc + 4).
						lrVal = (uint32_t)(cpuPc + 4);
						// Apply LR update to both paths.
						cur.regs[14].known = true;
						cur.regs[14].v = lrVal;
						taken.regs[14].known = true;
						taken.regs[14].v = lrVal;

						Node fall = cur;
						fall.off = cur.off + 4;
						work.push_back(fall);
					}
					else if (!CondAlways(cond))
					{
						Node fall = cur;
						fall.off = cur.off + 4;
						work.push_back(fall);
					}

					work.push_back(taken);
					continue;
				}
				else
				{
					// target not mappable -> stop this path
					continue;
				}
			}
		}


		// Normal step: execute instruction semantics, then fallthrough
		EmuStepInstruction(reader, data, dataLen, endian, resolver, cur.off, cur.regs, localRes, logger);


		Node nxt = cur;
		nxt.off = cur.off + 4;
		work.push_back(nxt);
	}


	if (logger)
		logger->LogDebug("MMU: Emu resolve failed for R%d (visited=%zu states)", targetReg, visited.size());
	if (optResult) *optResult = localRes;
	return false;
}


static void DiscoverConfigArraysFromLiteralLoads(const std::vector<LitLoad>& loads,
	std::vector<MMUConfigArray>& out, Ref<Logger> logger)
{
	out.clear();
	if (loads.empty())
		return;

	// Dedup by value, keep a representative literal pool address.
	std::map<uint32_t, uint64_t> valToLit;
	for (const auto& ll : loads)
	{
		if (valToLit.find(ll.value) == valToLit.end())
			valToLit[ll.value] = ll.litCpuAddr;
	}

	std::vector<uint32_t> vals;
	vals.reserve(valToLit.size());
	for (auto& kv : valToLit) vals.push_back(kv.first);
	std::sort(vals.begin(), vals.end());

	// Find plausible (start,end) pairs. Keep it tight to avoid junk explosion.
	const uint32_t kMaxSpan = 0x10000;
	size_t produced = 0;
	for (size_t i = 0; i < vals.size(); i++)
	{
		for (size_t j = i + 1; j < vals.size(); j++)
		{
			uint32_t a = vals[i], b = vals[j];
			uint32_t d = b - a;
			if (d == 0) continue;
			if (d > kMaxSpan) break;

			// Candidate arrays are typically 4- or 8-byte entries and aligned.
			if ((a & 0x3) != 0 || (b & 0x3) != 0)
				continue;
			if (d < 16) // too small
				continue;
			if ((d % 4) != 0)
				continue;

			MMUConfigArray arr{};
			arr.startAddr = a;
			arr.endAddr = b;
			arr.isIdentity = true; // legacy hint only; real format chosen by ChooseBestFormat
			arr.litPoolAddr1 = valToLit[a];
			arr.litPoolAddr2 = valToLit[b];
			out.push_back(arr);
			produced++;
			if (produced >= 64) // cap
				return;
		}
	}

	if (logger && !out.empty())
		logger->LogInfo("MMU: Emulated walk produced %zu candidate config arrays (literal-derived)", out.size());
}

static uint64_t InferAliasBaseFromLiteralLoads(const std::vector<LitLoad>& loads)
{
	// Heuristic: pick the most common high-byte among literal values that look like SRAM/alias pointers.
	// We ignore 0 and tiny values, and require the high byte to be non-zero.
	std::map<uint32_t, size_t> freq;
	for (const auto& ll : loads)
	{
		uint32_t v = ll.value;
		if (v == 0)
			continue;
		// Filter out small immediates/flags.
		if (v < 0x10000u)
			continue;
		uint32_t hi = v & 0xFF000000u;
		if (hi == 0)
			continue;
		freq[hi]++;
	}
	uint32_t best = 0;
	size_t bestCnt = 0;
	for (auto& kv : freq)
	{
		if (kv.second > bestCnt)
		{
			bestCnt = kv.second;
			best = kv.first;
		}
	}
	// Require at least 2 hits to avoid latching onto a single stray pointer.
	if (bestCnt < 2)
		return 0;
	return (uint64_t)best;
}
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

// Produce a compact but useful debug summary of regions, beyond the per-region listing.
static void LogRegionSummary(const std::vector<MemRegion>& regions, Ref<Logger> logger, const char* tag)
{
	if (!logger)
		return;
	if (regions.empty())
	{
		logger->LogInfo("MMU: Summary(%s): no regions", tag ? tag : "?");
		return;
	}


	uint64_t minVA = regions[0].virtBase, maxVA = regions[0].virtBase + regions[0].size;
	uint64_t minPA = regions[0].physBase, maxPA = regions[0].physBase + regions[0].size;
	uint64_t total = 0;
	uint64_t totalRam = 0, totalMmio = 0;
	size_t ramCnt = 0, mmioCnt = 0, otherCnt = 0;
	size_t rwx[8] = {0};
	size_t cacheWB = 0, cacheWT = 0, cacheWC = 0, cacheUC = 0;


	uint64_t largest = 0, smallest = ~0ull;
	MemRegion largestR = regions[0], smallestR = regions[0];


	for (const auto& r : regions)
	{
		if (r.size == 0) continue;
		minVA = std::min(minVA, r.virtBase);
		maxVA = std::max(maxVA, r.virtBase + r.size);
		minPA = std::min(minPA, r.physBase);
		maxPA = std::max(maxPA, r.physBase + r.size);
		total += r.size;


		bool isMmio = (r.type && std::strcmp(r.type, "MMIO") == 0);
		bool isRam = (r.type && std::strcmp(r.type, "RAM") == 0) || (!r.type);
		if (isMmio) { mmioCnt++; totalMmio += r.size; }
		else if (isRam) { ramCnt++; totalRam += r.size; }
		else otherCnt++;


		uint32_t idx = (r.readable ? 1 : 0) | (r.writable ? 2 : 0) | (r.executable ? 4 : 0);
		rwx[idx]++;


		// Cache policy histogram
		if (r.cacheable && r.bufferable) cacheWB++;
		else if (r.cacheable && !r.bufferable) cacheWT++;
		else if (!r.cacheable && r.bufferable) cacheWC++;
		else cacheUC++;


		if (r.size > largest) { largest = r.size; largestR = r; }
		if (r.size < smallest) { smallest = r.size; smallestR = r; }
	}


	logger->LogInfo("MMU: Summary(%s): regions=%zu VA=[0x%08llx..0x%08llx] span=0x%llx total=0x%llx",
		tag ? tag : "?", regions.size(),
		(unsigned long long)minVA, (unsigned long long)(maxVA ? (maxVA - 1) : 0),
		(unsigned long long)(maxVA - minVA),
		(unsigned long long)total);
	logger->LogInfo("MMU: Summary(%s): RAM=%zu (0x%llx) MMIO=%zu (0x%llx) other=%zu",
		tag ? tag : "?",
		ramCnt, (unsigned long long)totalRam,
		mmioCnt, (unsigned long long)totalMmio,
		otherCnt);
	logger->LogInfo("MMU: Summary(%s): cache WB=%zu WT=%zu WC=%zu UC=%zu",
		tag ? tag : "?", cacheWB, cacheWT, cacheWC, cacheUC);
	logger->LogInfo("MMU: Summary(%s): perms R=%zu RW=%zu RX=%zu RWX=%zu (and others)",
		tag ? tag : "?",
		rwx[1], rwx[3], rwx[5], rwx[7]);
	logger->LogInfo("MMU: Summary(%s): largest 0x%llx @ VA 0x%08llx type=%s; smallest 0x%llx @ VA 0x%08llx type=%s",
		tag ? tag : "?",
		(unsigned long long)largest,
		(unsigned long long)largestR.virtBase,
		largestR.type ? largestR.type : "?",
		(unsigned long long)smallest,
		(unsigned long long)smallestR.virtBase,
		smallestR.type ? smallestR.type : "?");
	(void)minPA; (void)maxPA;
}

static bool LooksLikeL1Table(BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t offset, uint64_t length)
{
	if (offset + 0x4000 > length) return false;

	size_t faults = 0, coarse = 0, fine = 0, sections = 0;
	size_t badCoarse = 0, badFine = 0;
	std::map<uint32_t, size_t> deltaFreq;

	for (size_t i = 0; i < 4096; i++)
	{
		uint32_t desc = 0;
		if (!ReadU32At(reader, data, dataLen, endian, offset + (i * 4), desc, length)) return false;
		uint32_t type = desc & 0x3;
		
		if (type==0) { faults++; continue; }
        if (type==1) { coarse++; if ((desc & 0x3FFu)!=0) badCoarse++; continue; }
        if (type==3) { fine++;   if ((desc & 0xFFFu)!=0) badFine++;   continue; }

        // section
        sections++;
        bool super = (desc & (1u<<18)) != 0;
        uint32_t pa = super ? (desc & 0xFF000000u) : (desc & 0xFFF00000u);
        uint32_t va = (uint32_t)(i << 20);
        deltaFreq[pa - va]++;
	}

	size_t valid = sections + coarse + fine;
	if (valid < 64)
		return false;
	if (faults < 128)
		return false;

	if (sections >= 32)
	{
		size_t best = 0;
		for (auto &kv : deltaFreq)
			best = std::max(best, kv.second);
		if (best < std::max<size_t>(16, sections / 4))
			return false;
	}
	else
	{
		// if no sections, only accept if many page tables & theyre aligned
		if ((coarse + fine) < 128)
			return false;
		if (coarse && badCoarse > coarse / 8)
			return false;
		if (fine && badFine > fine / 8)
			return false;
	}

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
	MMUWalkMode walkMode = GetMMUWalkMode(view, logger);
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
				bool resolved = false;
		EmuResult emuRes{};


		// Prefer emulated walk when requested; otherwise keep the existing fast backsolve.
		if (walkMode == MMUWalkMode::Emulated)
		{
			uint64_t mmuSetupFuncStart = 0;
			// keep same prologue heuristic: nearest PUSH {..,LR}
			for (int i = 1; i <= 32 && ttbrInstrAddr >= (uint64_t)(i * 4); i++)
			{
				uint32_t prevInstr = 0;
				ReadU32At(reader, data, dataLen, endian, ttbrInstrAddr - (i * 4), prevInstr, length);
				if ((prevInstr & 0xFFFF0000) == 0xE92D0000 && (prevInstr & 0x4000))
				{
					mmuSetupFuncStart = ttbrInstrAddr - (i * 4);
					break;
				}
			}

			// Prefer starting emulation from the binary entry point (often the vec_reset handler).
			// This is closer to "real" boot flow than starting from a short window before the TTBR write.
			uint64_t entryStart = 0;
			if (view)
			{
				uint64_t ep = view->GetEntryPoint();
				uint64_t epFile = 0;
				if (ep && resolver.CpuToFile(ep, epFile, true))
					entryStart = epFile & ~3ull;
				else if (ep && ep < length)
					entryStart = ep & ~3ull;
			}

			uint64_t start = 0;
			if (entryStart != 0 && entryStart < ttbrInstrAddr)
				start = entryStart;
			else if (mmuSetupFuncStart != 0)
				start = mmuSetupFuncStart;
			else
				start = (ttbrInstrAddr > 0x800) ? (ttbrInstrAddr - 0x800) : 0;

			uint64_t end = ttbrInstrAddr;

			if (logger)
				logger->LogDebug("MMU: Emu window 0x%llx - 0x%llx%s", (unsigned long long)start,
					(unsigned long long)end, (entryStart != 0 ? " (entrypoint-based)" : ""));

			resolved = ResolveRegAtEmulated(reader, data, dataLen, endian, resolver, start, end, rt, ttbrRegValue, &emuRes, logger);
			if (!resolved)
			{
				// fallback to old method (sometimes better for straight-line)
				resolved = ResolveRegAt(reader, data, dataLen, endian, resolver, ttbrInstrAddr, rt, ttbrRegValue, logger);
			}
		}
		else
		{
			resolved = ResolveRegAt(reader, data, dataLen, endian, resolver, ttbrInstrAddr, rt, ttbrRegValue, logger);
			if (!resolved)
			{
				// fallback: try emulated walk only if old method fails
				uint64_t start = (ttbrInstrAddr > 0x800) ? (ttbrInstrAddr - 0x800) : 0;
				uint64_t end = ttbrInstrAddr;
				resolved = ResolveRegAtEmulated(reader, data, dataLen, endian, resolver, start, end, rt, ttbrRegValue, nullptr, logger);
			}
		}


		if (!resolved)
		{
			logger->LogInfo("MMU: TTBR value not resolved at 0x%llx", (unsigned long long)ttbrInstrAddr);
			continue;
		}

		uint64_t ttbrValue = ttbrRegValue;
		uint64_t aliasBase = 0;
		uint64_t offTmp = 0;

		// Prefer a concrete mapping for TTBR; if it doesn't map directly, treat it as an aliased/SRAM-space pointer.
		if (!resolver.CpuToFile(ttbrValue, offTmp, false))
		{
			aliasBase = ttbrValue & 0xFF000000ULL;
			if (aliasBase != 0)
			{
				AddLow24Alias(resolver, aliasBase, length);
				logger->LogInfo("MMU: Using alias base 0x%08llx", (unsigned long long)aliasBase);
			}
		}

		// If TTBR resolves to 0 / tiny flaggy values, we can still proceed by inferring the alias base from
		// literal loads seen during emulation (these often point into SRAM where config tables live).
		if (aliasBase == 0 && !emuRes.literalLoads.empty())
		{
			uint64_t inferred = InferAliasBaseFromLiteralLoads(emuRes.literalLoads);
			if (inferred != 0)
			{
				aliasBase = inferred;
				AddLow24Alias(resolver, aliasBase, length);
				logger->LogInfo("MMU: Inferred alias base 0x%08llx from literal loads", (unsigned long long)aliasBase);
			}
		}

		if ((ttbrValue & ~0x3FFFULL) == 0)
		{
			logger->LogInfo("MMU: TTBR resolved to small value (0x%08llx); may be flags without base",
				(unsigned long long)ttbrValue);
		}

		// Find ROM->SRAM copy (used to read initialized SRAM contents). This requires a non-zero alias base.
		RomToSramCopy romCopy = FindRomToSramCopy(reader, data, dataLen, endian, length, imageBase,
			resolver, aliasBase, logger);

		uint64_t tableBase = ttbrValue & ~0x3FFFULL;
		logger->LogInfo("MMU: Translation table base = 0x%08llx", (unsigned long long)tableBase);

		// If the table base is unmappable (or zero), skip L1 parsing and go straight to config-array discovery.
		bool tableBaseMappable = false;
		if (tableBase != 0)
		{
			uint64_t tmpOff = 0;
			tableBaseMappable = resolver.CpuToFile(tableBase, tmpOff, true);
		}

		bool tableLooksEmpty = true;
		if (tableBaseMappable)
		{
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

			tableLooksEmpty = allZero || allOnes || allFault;
			if (!tableLooksEmpty)
			{
				std::vector<MemRegion> regions;
				if (ParseArmv5L1Table(reader, data, dataLen, endian, resolver, length, romCopy, tableBase, regions, logger))
				{
					LogRegionSummary(regions, logger, "L1");
					logL1Regions(regions);
					return;
				}
				tableLooksEmpty = true;
				logger->LogInfo("MMU: L1 parse produced no regions; treating as uninitialized");
			}
		}

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

		logger->LogInfo("MMU: Scanning 0x%llx - 0x%llx for config arrays (mode=%s)",
			(unsigned long long)scanStart, (unsigned long long)scanEnd,
			(walkMode == MMUWalkMode::Emulated) ? "Emulated" : "Heuristic");

				// If we have emulation results, derive candidates from literal loads first.
		// This tends to work better when the setup code has branches / multiple paths.
		if (!emuRes.literalLoads.empty())
		{
			DiscoverConfigArraysFromLiteralLoads(emuRes.literalLoads, configArrays, logger);
			for (const auto& arr : configArrays)
			{
				logger->LogInfo("MMU: Candidate config array 0x%llx-0x%llx (lit 0x%llx / 0x%llx)",
					(unsigned long long)arr.startAddr, (unsigned long long)arr.endAddr,
					(unsigned long long)arr.litPoolAddr1, (unsigned long long)arr.litPoolAddr2);
			}
		}


		// Keep existing heuristic scan as well (either as primary or fallback).
		if (configArrays.empty())
		{
			logger->LogInfo("MMU: No emulated-derived arrays; using heuristic LDR-pair scan");
		}

		for (uint64_t offset = scanStart; configArrays.empty() && offset + 4 <= scanEnd; offset += 4)
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
									// Filter out obvious junk: endpoints must live in the same meaningful address space.
									if (value == 0 || valueb == 0)
										continue;
									if (aliasBase != 0)
									{
										if ( (value  & 0xFF000000u) != (uint32_t)aliasBase ||
											 (valueb & 0xFF000000u) != (uint32_t)aliasBase )
											continue;
									}
									else if (imageBase != 0)
									{
										// If we're using a real image base, require the pair to be inside that mapped range.
										if ((uint64_t)value < imageBase || (uint64_t)value >= imageBase + length)
											continue;
										if ((uint64_t)valueb <= imageBase || (uint64_t)valueb > imageBase + length)
											continue;
									}

									uint64_t offA = 0, offB = 0;
									// Reject junk pointer pairs: require a *non-fallback* mapping (no blob0 fallback).
									if (!resolver.CpuToFile((uint64_t)value, offA, false) ||
										!resolver.CpuToFile(((uint64_t)valueb) - 4, offB, false))
										continue;
									// Also reject tiny/near-header offsets; real tables won't start at 0.
									if (offA < 0x1000 || offB < 0x1000)
										continue;
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

			for (uint64_t offset = wideStart; configArrays.empty() && offset + 4 <= wideEnd; offset += 4)
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
										// Filter out obvious junk: endpoints must live in the same meaningful address space.
										if (value == 0 || valueb == 0)
											continue;
										if (aliasBase != 0)
										{
											if ( (value  & 0xFF000000u) != (uint32_t)aliasBase ||
												 (valueb & 0xFF000000u) != (uint32_t)aliasBase )
												continue;
										}
										else if (imageBase != 0)
										{
											// If we're using a real image base, require the pair to be inside that mapped range.
											if ((uint64_t)value < imageBase || (uint64_t)value >= imageBase + length)
												continue;
											if ((uint64_t)valueb <= imageBase || (uint64_t)valueb > imageBase + length)
												continue;
										}

										uint64_t offA = 0, offB = 0;
										// Reject junk pointer pairs: require a *non-fallback* mapping (no blob0 fallback).
										if (!resolver.CpuToFile((uint64_t)value, offA, false) ||
											!resolver.CpuToFile(((uint64_t)valueb) - 4, offB, false))
											continue;
										// Also reject tiny/near-header offsets; real tables won't start at 0.
										if (offA < 0x1000 || offB < 0x1000)
											continue;
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

		// Debug summary: arrays found
		logger->LogInfo("MMU: %zu config array candidate(s) accepted for format scoring", configArrays.size());

		vector<MemRegion> regions;
		MemRegion currentRegion = {0, 0, 0, false, false, false, false, false, nullptr};

		for (const auto& arr : configArrays)
		{
			MapFormat fmt = {};
			MapStats st = {};
			if (!ChooseBestFormat(resolver, reader, data, dataLen, endian, romCopy, length, arr, fmt, st))
			{
				// Fallback: region descriptor list (va, pa, size, flags)
				std::vector<MemRegion> rd;
				if (ParseRegionDesc16(resolver, reader, data, dataLen, endian, romCopy, length, arr, rd, logger))
				{
					logger->LogInfo("MMU: Using RegionDesc16 for candidate array 0x%llx-0x%llx (%zu region(s))",
						(unsigned long long)arr.startAddr, (unsigned long long)arr.endAddr, rd.size());
					regions.insert(regions.end(), rd.begin(), rd.end());
					continue;
				}

				logger->LogInfo("MMU: Rejecting candidate array 0x%llx-0x%llx (failed preflight)",
					(unsigned long long)arr.startAddr, (unsigned long long)arr.endAddr);
				continue;
			}

			uint64_t entrySize = (fmt.kind == MapEntryKind::Identity4) ? 4 : 8;
			uint64_t effectiveEnd = (fmt.effectiveEndAddr != 0) ? fmt.effectiveEndAddr : arr.endAddr;
			uint64_t entryCount = (effectiveEnd - arr.startAddr) / entrySize;
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
			if (fmt.kind == MapEntryKind::VaPa8 && fmt.swapWords)
				logger->LogInfo("MMU:   Note: VaPa8 word order swapped (PA,VA)");
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

				// Your flag decode (keep it, but now flags wont be "address dust")
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

		LogRegionSummary(uniqueRegions, logger, "Config");
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
