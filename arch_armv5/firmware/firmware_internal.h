/*
 * ARMv5 Firmware Internal Helpers
 *
 * Shared helpers and scan declarations for firmware analysis.
 */

#pragma once

#include "binaryninjaapi.h"
#include "firmware_scan_types.h"
#include "armv5_disasm/armv5.h"

#include <cstdint>
#include <cstring>
#include <set>
#include <vector>

static inline uint32_t Swap32(uint32_t value)
{
	return ((value & 0xff000000) >> 24) |
		((value & 0x00ff0000) >> 8) |
		((value & 0x0000ff00) << 8) |
		((value & 0x000000ff) << 24);
}

static inline bool ReadU32At(BinaryNinja::BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
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
	BinaryNinja::BinaryReader& reader;
	const uint8_t* data;
	uint64_t dataLen;
	BNEndianness endian;
	uint64_t imageBase;
	uint64_t length;
	BinaryNinja::Ref<BinaryNinja::Architecture> arch;
	BinaryNinja::Ref<BinaryNinja::Platform> plat;
	BinaryNinja::Ref<BinaryNinja::Logger> logger;
	bool verboseLog;
	BinaryNinja::Ref<BinaryNinja::BinaryView> view;
	FirmwareScanPlan* plan;

	uint64_t ImageEnd() const { return imageBase + length; }
};

uint64_t DetectImageBaseFromVectorTable(BinaryNinja::BinaryView* data);
uint64_t ResolveVectorEntry(BinaryNinja::BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t vectorOffset, uint64_t imageBase, uint64_t length);

size_t ScanForFunctionPrologues(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Architecture> armArch, BinaryNinja::Ref<BinaryNinja::Architecture> thumbArch,
	BinaryNinja::Ref<BinaryNinja::Platform> plat, BinaryNinja::Ref<BinaryNinja::Logger> logger,
	bool verboseLog, const FirmwareScanTuning& tuning, std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan);

size_t ScanForCallTargets(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Platform> plat, BinaryNinja::Ref<BinaryNinja::Logger> logger, bool verboseLog,
	const FirmwareScanTuning& tuning, std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan);

size_t ScanForPointerTargets(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Platform> plat, BinaryNinja::Ref<BinaryNinja::Logger> logger, bool verboseLog,
	const FirmwareScanTuning& tuning, std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan);

size_t ScanForOrphanCodeBlocks(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Platform> plat, BinaryNinja::Ref<BinaryNinja::Logger> logger, bool verboseLog,
	const FirmwareScanTuning& tuning, uint32_t minValidInstr, uint32_t minBodyInstr, uint32_t minSpacingBytes,
	uint32_t maxPerPage, bool requirePrologue, std::set<uint64_t>* addedFunctions, FirmwareScanPlan* plan);

size_t CleanupInvalidFunctions(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t imageBase, uint64_t length, BinaryNinja::Ref<BinaryNinja::Logger> logger,
	bool verboseLog, const FirmwareScanTuning& tuning, uint32_t maxSizeBytes, bool requireZeroRefs,
	bool requirePcWriteStart, uint64_t entryPoint, const std::set<uint64_t>& protectedStarts,
	FirmwareScanPlan* plan);

void AnalyzeMMUConfiguration(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, BinaryNinja::BinaryReader& reader, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Logger> logger);

void TypeLiteralPoolEntries(const FirmwareScanContext& ctx);
void ClearAutoDataOnCodeReferences(const FirmwareScanContext& ctx);
void ClearAutoDataInFunctionEntryBlocks(const FirmwareScanContext& ctx,
	const std::set<uint64_t>* seededFunctions);
