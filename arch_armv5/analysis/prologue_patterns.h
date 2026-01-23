/*
 * Enhanced Prologue/Epilogue Pattern Detection for ARMv5
 *
 * Comprehensive pattern tables for various compilers and scenarios:
 * - GCC ARM/Thumb prologues
 * - ARM Compiler (ARMCC/Keil) prologues
 * - IAR EWARM prologues
 * - Clang/LLVM prologues
 * - Interrupt handler prologues
 * - Leaf function detection
 * - Tail call detection
 */

#pragma once

#include "binaryninjaapi.h"
#include <cstdint>
#include <vector>
#include <string>

namespace Armv5Analysis
{

/**
 * Pattern match result
 */
struct PrologueMatch
{
	uint64_t address;
	bool isThumb;
	double confidence;           // 0.0 - 1.0
	std::string patternName;     // Human-readable pattern name
	std::string compiler;        // Detected/suspected compiler

	// Pattern details
	uint32_t savedRegisters;     // Bitmask of saved registers
	int32_t stackAdjustment;     // Stack pointer adjustment (negative = grow)
	bool savesLR;                // Does it save link register?
	bool savesFramePointer;      // Does it save/setup frame pointer?
	bool isInterruptHandler;     // Looks like interrupt handler?
	bool isLeafFunction;         // Appears to be a leaf function?

	// Instruction sequence length
	size_t patternLength;        // Number of instructions matched
	size_t byteLength;           // Number of bytes matched
};

/**
 * Individual pattern definition
 */
struct ProloguePattern
{
	std::string name;
	std::string compiler;
	bool isThumb;
	double baseConfidence;

	// Pattern specification - either mask-based or callback
	struct InsnPattern
	{
		uint32_t value;     // Expected value after masking
		uint32_t mask;      // Bits to check
		bool is32bit;       // For Thumb: is this a 32-bit instruction?
		bool optional;      // Can this instruction be missing?
	};
	std::vector<InsnPattern> instructions;

	// Extracted information mapping
	int lrBitPosition;          // Bit position of LR in register list (-1 = N/A)
	int fpBitPosition;          // Bit position of FP in register list (-1 = N/A)
	int reglistPosition;        // Bit offset of register list (0 = bits 0-15)
	int stackImmPosition;       // Bit offset of stack immediate
	int stackImmScale;          // Multiplier for stack immediate
};

/**
 * Epilogue pattern result
 */
struct EpilogueMatch
{
	uint64_t address;
	bool isThumb;
	double confidence;
	std::string patternName;

	bool restoresLR;
	bool restoresPC;            // Returns via PC restore (common in ARM)
	bool isConditional;         // Conditional return
	uint32_t restoredRegisters;
	int32_t stackAdjustment;

	size_t patternLength;
	size_t byteLength;
};

/**
 * Enhanced Prologue/Epilogue Pattern Matcher
 */
class PrologueMatcher
{
public:
	explicit PrologueMatcher(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

	/**
	 * Match prologue pattern at address
	 * Returns empty vector if no match, otherwise returns all matching patterns
	 * (sorted by confidence, highest first)
	 */
	std::vector<PrologueMatch> matchPrologue(uint64_t address, bool isThumb);

	/**
	 * Match epilogue pattern at address
	 */
	std::vector<EpilogueMatch> matchEpilogue(uint64_t address, bool isThumb);

	/**
	 * Get the best prologue match at address
	 */
	PrologueMatch getBestPrologueMatch(uint64_t address, bool isThumb);

	/**
	 * Scan a range for prologue patterns
	 */
	std::vector<PrologueMatch> scanForPrologues(uint64_t start, uint64_t end,
		bool scanArm = true, bool scanThumb = true, double minConfidence = 0.5);

	/**
	 * Check if address looks like a leaf function start
	 * (No prologue, but valid code that doesn't call other functions)
	 */
	bool isLikelyLeafFunction(uint64_t address, bool isThumb);

	/**
	 * Check if instruction sequence looks like an interrupt handler entry
	 */
	bool isInterruptHandlerEntry(uint64_t address, bool isThumb);

private:
	void initializePatterns();

	// ARM prologue patterns
	void addArmPatterns();
	void addArmGccPatterns();
	void addArmArmccPatterns();
	void addArmIarPatterns();
	void addArmInterruptPatterns();

	// Thumb prologue patterns
	void addThumbPatterns();
	void addThumbGccPatterns();
	void addThumbArmccPatterns();
	void addThumbIarPatterns();
	void addThumbInterruptPatterns();

	// Epilogue patterns
	void addArmEpiloguePatterns();
	void addThumbEpiloguePatterns();

	// Instruction reading
	uint32_t readArm(uint64_t address);
	uint16_t readThumb16(uint64_t address);
	uint32_t readThumb32(uint64_t address);

	// Pattern matching helpers
	bool matchPattern(uint64_t address, const ProloguePattern& pattern,
		PrologueMatch& result);
	void extractPatternInfo(const ProloguePattern& pattern, uint64_t address,
		const std::vector<uint32_t>& instructions, PrologueMatch& result);

	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;

	// Pattern tables
	std::vector<ProloguePattern> m_armPrologues;
	std::vector<ProloguePattern> m_thumbPrologues;
	std::vector<ProloguePattern> m_armEpilogues;
	std::vector<ProloguePattern> m_thumbEpilogues;
};

/**
 * Common ARM register bit positions in register lists
 */
namespace ArmRegs
{
	constexpr int R0  = 0;
	constexpr int R1  = 1;
	constexpr int R2  = 2;
	constexpr int R3  = 3;
	constexpr int R4  = 4;
	constexpr int R5  = 5;
	constexpr int R6  = 6;
	constexpr int R7  = 7;
	constexpr int R8  = 8;
	constexpr int R9  = 9;
	constexpr int R10 = 10;
	constexpr int R11 = 11;  // FP in AAPCS
	constexpr int R12 = 12;  // IP (scratch)
	constexpr int SP  = 13;
	constexpr int LR  = 14;
	constexpr int PC  = 15;

	// Common aliases
	constexpr int FP  = R11;
	constexpr int IP  = R12;

	// Register list bit masks
	constexpr uint32_t CALLEE_SAVED = (1 << R4) | (1 << R5) | (1 << R6) | (1 << R7) |
	                                  (1 << R8) | (1 << R9) | (1 << R10) | (1 << R11);
	constexpr uint32_t LR_BIT = (1 << LR);
	constexpr uint32_t PC_BIT = (1 << PC);
	constexpr uint32_t FP_BIT = (1 << FP);
	constexpr uint32_t IP_BIT = (1 << IP);
}

}  // namespace Armv5Analysis
