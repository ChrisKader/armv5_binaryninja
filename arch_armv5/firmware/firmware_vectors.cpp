/*
 * ARMv5 Firmware Vector Table Helpers
 *
 * - DetectImageBaseFromVectorTable: heuristically determines an image base by scoring
 *   candidate bases against resolved vector targets.
 * - ResolveVectorEntry: resolves a single vector entry (LDR-literal or B/BL) to a
 *   handler address (VA). For LDR-literal vectors, this returns the 32-bit value
 *   found in the literal pool (preserving the Thumb bit if present).
 */

#include "firmware_internal.h"

#include <cstdint>
#include <vector>

using namespace std;
using namespace BinaryNinja;

static inline bool IsLdrPcLiteral(uint32_t instr)
{
	// Match: LDR pc, [pc, #imm12]  (U=1) or LDR pc, [pc, #-imm12] (U=0)
	// Ignore condition code (top nibble).
	// Encoding: cond 0101 1001 1111 1111 .... .... .... ....
	// Mask off cond: 0x0FFFF000 should match 0x059FF000 (add) or 0x051FF000 (sub).
	return ((instr & 0x0FFFF000u) == 0x059FF000u) || ((instr & 0x0FFFF000u) == 0x051FF000u);
}

static inline bool IsBranchImm(uint32_t instr)
{
	// Match: B/BL immediate, any condition
	// Encoding: cond 101L imm24
	// Ignore cond: bits[27:25] == 101 => (instr & 0x0E000000) == 0x0A000000
	return (instr & 0x0E000000u) == 0x0A000000u;
}

static inline int32_t SignExtend24(uint32_t imm24)
{
	// imm24 is 24-bit signed
	if (imm24 & 0x00800000u)
		return (int32_t)(imm24 | 0xFF000000u);
	return (int32_t)imm24;
}

// Resolve a vector table LDR-literal to the file offset where the handler address literal lives.
// Returns true and sets outLiteralFileOff if successful.
static bool ResolveVectorLiteralPointer(uint32_t vecInstr,
																				uint64_t vectorEntryFileOff,
																				uint64_t fileLen,
																				uint64_t &outLiteralFileOff)
{
	if (!IsLdrPcLiteral(vecInstr))
		return false;

	uint32_t imm12 = vecInstr & 0xFFFu;

	// In ARM state, PC = address_of_current_instr + 8.
	// Here vectorEntryFileOff is a file offset (vector table is at file offset 0),
	// so PC is also expressed as a file offset.
	uint64_t pc = vectorEntryFileOff + 8;
	bool add = (vecInstr & (1u << 23)) != 0; // U bit

	uint64_t literalOff = 0;
	if (add)
	{
		literalOff = pc + imm12;
	}
	else
	{
		if (imm12 > pc)
			return false;
		literalOff = pc - imm12;
	}

	if (literalOff + 4 > fileLen)
		return false;

	outLiteralFileOff = literalOff;
	return true;
}

// Read U32 little-endian safely from a BinaryView at file offset.
static bool ReadU32LE(BinaryView *data, uint64_t off, uint64_t fileLen, uint32_t &out)
{
	if (!data || off + 4 > fileLen)
		return false;

	DataBuffer b = data->ReadBuffer(off, 4);
	if (b.GetLength() < 4)
		return false;

	// BinaryNinja DataBuffer storage is raw bytes; interpret as little-endian u32.
	const uint8_t *p = (const uint8_t *)b.GetData();
	out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	return true;
}

// Try candidate base: count how many vector entries we can resolve AND map into file range.
// Return score (#mapped handlers).
static int ScoreBaseFromVectors(BinaryView *data, const uint32_t *vecWords, uint64_t fileLen, uint64_t base)
{
	int mapped = 0;

	for (int i = 0; i < 8; i++)
	{
		uint64_t vecOff = (uint64_t)i * 4;
		uint32_t instr = vecWords[i];

		// Case 1: LDR pc, [pc, +/-imm] -> literal contains handler VA (possibly with Thumb bit)
		uint64_t literalOff = 0;
		if (ResolveVectorLiteralPointer(instr, vecOff, fileLen, literalOff))
		{
			uint32_t handlerVA = 0;
			if (!ReadU32LE(data, literalOff, fileLen, handlerVA))
				continue;

			uint32_t handlerVAAligned = handlerVA & ~1u; // ignore Thumb bit for mapping
			if ((uint64_t)handlerVAAligned < base)
				continue;

			uint64_t fileOff = (uint64_t)handlerVAAligned - base;
			if (fileOff < fileLen)
				mapped++;

			continue;
		}

		// Case 2: B/BL immediate: compute target VA given assumed base mapping
		if (IsBranchImm(instr))
		{
			uint32_t imm24 = instr & 0x00FFFFFFu;
			int32_t s = SignExtend24(imm24);

			// If vector table is at file offset 0 mapped at 'base',
			// then vector entry VA = base + vecOff.
			uint64_t vectorVA = base + vecOff;

			// In ARM: target = (PC) + (s<<2), PC = addr + 8.
			uint64_t pc = vectorVA + 8;
			int64_t targetVA = (int64_t)pc + ((int64_t)s << 2);

			if (targetVA < 0)
				continue;

			uint64_t targetVAu = (uint64_t)targetVA;
			if (targetVAu < base)
				continue;

			uint64_t fileOff = targetVAu - base;
			if (fileOff < fileLen)
				mapped++;
		}
	}

	return mapped;
}

// Helper to auto-detect image base from vector table at file offset 0.
// Returns detected image base, or 0 if not detectable.
uint64_t DetectImageBaseFromVectorTable(BinaryView *data)
{
	if (!data)
		return 0;

	uint64_t length = data->GetLength();
	if (length < 0x40)
		return 0;

	DataBuffer buf = data->ReadBuffer(0, 0x40);
	if (buf.GetLength() < 0x40)
		return 0;

	const uint32_t *words = (const uint32_t *)buf.GetData();

	// Collect handler VAs resolved via LDR pc literal vectors.
	vector<uint32_t> handlerVAs;
	handlerVAs.reserve(8);

	for (int i = 0; i < 8; i++)
	{
		uint32_t vecInstr = words[i];
		uint64_t vecOff = (uint64_t)i * 4;

		uint64_t literalOff = 0;
		if (!ResolveVectorLiteralPointer(vecInstr, vecOff, length, literalOff))
			continue;

		uint32_t handlerVA = 0;
		if (!ReadU32LE(data, literalOff, length, handlerVA))
			continue;

		handlerVAs.push_back(handlerVA);
	}

	// If we can’t resolve any LDR-literal handlers, base detection is unreliable.
	if (handlerVAs.empty())
		return 0;

	// Candidate bases: derive from each handler VA rounded down to common alignments.
	static const uint64_t alignments[] = {
			0x1000000ULL, // 16MB
			0x100000ULL,	// 1MB
			0x10000ULL,		// 64KB
			0x1000ULL			// 4KB
	};

	struct Candidate
	{
		uint64_t base;
		int score;
	};

	vector<Candidate> cands;
	cands.reserve(handlerVAs.size() * (sizeof(alignments) / sizeof(alignments[0])));

	auto addCand = [&](uint64_t base)
	{
		for (auto &c : cands)
			if (c.base == base)
				return;
		int score = ScoreBaseFromVectors(data, words, length, base);
		cands.push_back({base, score});
	};

	for (uint32_t vaRaw : handlerVAs)
	{
		uint64_t va = (uint64_t)(vaRaw & ~1u); // ignore Thumb bit for base scoring
		for (uint64_t a : alignments)
		{
			uint64_t base = va & ~(a - 1);
			addCand(base);
		}
		// Extra fallback: 4KB down (redundant with alignments but harmless)
		addCand(va & ~0xFFFULL);
	}

	// Pick best candidate. Require at least 2 mapped entries to avoid pure noise.
	uint64_t bestBase = 0;
	int bestScore = 0;

	for (auto &c : cands)
	{
		if (c.score > bestScore)
		{
			bestScore = c.score;
			bestBase = c.base;
		}
	}

	if (bestScore < 2)
		return 0;

	return bestBase;
}

// Helper to resolve a vector table entry to a handler address (VA).
// Returns the target address (VA), or 0 if not resolvable.
//
// NOTE: imageBase is used for branch-vector decoding (table VA = imageBase + vectorOffset).
// For LDR-literal vectors, the literal address is computed using *file offsets* (vector table at file off 0),
// and the literal contents are returned directly (preserving Thumb bit if present).
uint64_t ResolveVectorEntry(BinaryReader &reader,
														const uint8_t *data,
														uint64_t dataLen,
														BNEndianness endian,
														uint64_t vectorOffset,
														uint64_t imageBase,
														uint64_t length)
{
	uint32_t instr = 0;
	ReadU32At(reader, data, dataLen, endian, vectorOffset, instr, length);

	// LDR PC, [PC, #imm] or LDR PC, [PC, #-imm] (any condition)
	if (IsLdrPcLiteral(instr))
	{
		uint32_t imm12 = instr & 0xFFFu;
		uint64_t pc = vectorOffset + 8; // file offset + 8 (vectorOffset is file offset)
		bool add = (instr & (1u << 23)) != 0;

		uint64_t pointerOff = 0;
		if (add)
			pointerOff = pc + imm12;
		else
		{
			if (imm12 > pc)
				return 0;
			pointerOff = pc - imm12;
		}

		if (pointerOff + 4 <= length)
		{
			uint32_t handlerAddr = 0;
			ReadU32At(reader, data, dataLen, endian, pointerOff, handlerAddr, length);

			// IMPORTANT: Preserve Thumb bit. firmware_view.cpp will use
			// GetAssociatedArchitectureByAddress() to select the correct arch/platform.
			return (uint64_t)handlerAddr;
		}
	}
	// B/BL immediate (any condition)
	else if (IsBranchImm(instr))
	{
		uint32_t imm24 = instr & 0x00FFFFFFu;
		int32_t s = SignExtend24(imm24);

		// Vector entry VA = imageBase + vectorOffset (table mapped at imageBase)
		uint64_t vectorVA = imageBase + vectorOffset;
		uint64_t pc = vectorVA + 8;
		int64_t target = (int64_t)pc + ((int64_t)s << 2);
		if (target < 0)
			return 0;
		return (uint64_t)target;
	}

	return 0;
}
