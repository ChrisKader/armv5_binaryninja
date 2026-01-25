/*
 * Linear Sweep Analyzer
 *
 * Implements Nucleus-style function detection via basic block grouping.
 * This approach discovers functions without relying on prologue patterns
 * by analyzing control flow structure.
 *
 * Algorithm (based on "Compiler-Agnostic Function Detection in Binaries"):
 * 1. Linear disassembly of unknown regions to build basic blocks
 * 2. Connect blocks via direct control flow (branches, fall-through)
 * 3. Group blocks by intraprocedural edges:
 *    - Conditional branches: intraprocedural (stay within function)
 *    - Calls (BL/BLX): interprocedural (cross function boundary)
 *    - Unconditional branches: potential tail calls (interprocedural)
 * 4. Each group's earliest address is a function entry candidate
 *
 * Key insight: compilers use different control flow for inter vs intra
 * procedural transfers, which reveals function boundaries.
 */

#pragma once

#include "binaryninjaapi.h"
#include "function_detector.h"

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace Armv5Analysis
{

/**
 * A basic block discovered by linear sweep
 */
struct LinearBlock
{
	uint64_t start = 0;
	uint64_t end = 0;
	bool isThumb = false;
	size_t instructionCount = 0;

	// Control flow
	std::vector<uint64_t> successors;     // Direct successors (fall-through, branches)
	std::vector<uint64_t> predecessors;   // Blocks that flow to this one
	std::vector<uint64_t> callTargets;    // BL/BLX targets (interprocedural)

	// Block properties
	bool endsWithReturn = false;
	bool endsWithCall = false;
	bool endsWithUnconditionalBranch = false;
	bool endsWithConditionalBranch = false;
	bool endsWithIndirectBranch = false;
	bool hasFallthrough = false;

	// Analysis state
	int groupId = -1;  // Which function group this block belongs to
};

/**
 * A function discovered by grouping blocks
 */
struct LinearFunction
{
	uint64_t entryPoint = 0;
	bool isThumb = false;
	std::vector<uint64_t> blockAddresses;
	size_t blockCount = 0;
	size_t instructionCount = 0;

	// Confidence factors
	bool hasMultipleBlocks = false;
	bool hasReturn = false;
	bool hasCall = false;
	bool isReferencedByCall = false;
	double confidence = 0.0;
};

/**
 * Settings for linear sweep analysis
 */
struct LinearSweepSettings
{
	// Regions to scan
	uint64_t scanStart = 0;  // 0 = use view start
	uint64_t scanEnd = 0;    // 0 = use view end

	// Instruction limits
	size_t maxInstructionsPerBlock = 1000;
	size_t maxTotalBlocks = 50000;
	size_t maxTotalInstructions = 500000;

	// Block discovery
	bool skipKnownFunctions = true;    // Don't re-disassemble known function regions
	bool skipDataRegions = true;       // Skip sections marked as data
	bool respectAlignment = true;      // Prefer aligned block starts
	uint32_t preferredAlignment = 4;   // ARM instruction alignment

	// Grouping behavior
	bool treatUnconditionalBranchAsInterprocedural = true;  // B = potential tail call
	bool treatIndirectBranchAsTerminator = true;  // Indirect = function boundary
	int64_t tailCallDistanceThreshold = 0x1000;   // Branches beyond this are likely tail calls
	bool useAdaptiveThresholds = true;            // Derive threshold from segment/section layout

	// Output filtering
	double minimumConfidence = 0.4;
	size_t minimumBlocksPerFunction = 1;
	bool requireReturnOrCall = true;  // Require return or call for single-block functions
	bool enforceAlignment = true;     // Reject misaligned function entries

	// Leaf function detection
	bool detectLeafFunctions = true;          // Allow single-block functions without return/call
	double leafFunctionMinConfidence = 0.5;   // Higher threshold for leaf candidates

	/**
	 * Apply a unified detection config, mapping to LinearSweep-specific parameters.
	 */
	void ApplyUnifiedConfig(const UnifiedDetectionConfig& config)
	{
		minimumConfidence = config.minimumScore;

		if (config.mode == DetectionMode::Aggressive)
		{
			minimumBlocksPerFunction = 1;
			requireReturnOrCall = false;
			tailCallDistanceThreshold = 0x2000;
			useAdaptiveThresholds = true;
		}
		else if (config.mode == DetectionMode::Conservative)
		{
			minimumBlocksPerFunction = 2;
			requireReturnOrCall = true;
			tailCallDistanceThreshold = 0x800;
			useAdaptiveThresholds = false;
		}
	}
};

/**
 * Statistics about linear sweep
 */
struct LinearSweepStats
{
	size_t regionsScanned = 0;
	size_t totalBytes = 0;
	size_t blocksDiscovered = 0;
	size_t groupsFormed = 0;
	size_t functionsReported = 0;
	size_t armBlocks = 0;
	size_t thumbBlocks = 0;
	size_t invalidInstructions = 0;
	double scanTimeSeconds = 0.0;
};

/**
 * Linear Sweep Analyzer
 *
 * Discovers functions by linear disassembly and basic block grouping.
 */
class LinearSweepAnalyzer
{
public:
	explicit LinearSweepAnalyzer(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

	/**
	 * Run linear sweep analysis with default settings
	 */
	std::vector<LinearFunction> analyze();

	/**
	 * Run linear sweep analysis with custom settings
	 */
	std::vector<LinearFunction> analyze(const LinearSweepSettings& settings);

	/**
	 * Get discovered blocks (for debugging/visualization)
	 */
	const std::map<uint64_t, std::unique_ptr<LinearBlock>>& getBlocks() const { return m_blocks; }

	/**
	 * Get analysis statistics
	 */
	LinearSweepStats getStats() const { return m_stats; }

	/**
	 * Set progress callback
	 */
	using ProgressCallback = std::function<bool(const std::string&, double)>;
	void setProgressCallback(ProgressCallback cb) { m_progressCallback = std::move(cb); }

	// Preset configurations
	static LinearSweepSettings DefaultSettings();
	static LinearSweepSettings AggressiveSettings();
	static LinearSweepSettings ConservativeSettings();

private:
	// Phase 1: Linear disassembly
	void scanRegions();
	void scanRegion(uint64_t start, uint64_t end, bool isThumb);
	LinearBlock* createBlock(uint64_t address, bool isThumb);
	bool disassembleBlock(LinearBlock* block);

	// Phase 2: Connect blocks
	void connectBlocks();
	void addEdge(uint64_t from, uint64_t to);

	// Phase 3: Group blocks into functions
	void groupBlocks();
	void propagateGroup(LinearBlock* block, int groupId);

	// Phase 4: Extract functions from groups
	std::vector<LinearFunction> extractFunctions();
	double calculateConfidence(const LinearFunction& func);

	// Adaptive threshold computation
	int64_t computeAdaptiveThreshold(uint64_t address) const;

	// Helper methods
	bool isValidAddress(uint64_t addr);
	bool isExecutable(uint64_t addr);
	bool isInsideKnownFunction(uint64_t addr);
	bool isDataRegion(uint64_t addr);
	uint32_t readInstruction32(uint64_t addr);
	uint16_t readInstruction16(uint64_t addr);
	bool decodeArmInstruction(uint64_t addr, uint32_t instr, LinearBlock* block);
	bool decodeThumbInstruction(uint64_t addr, LinearBlock* block);
	bool reportProgress(const std::string& message, double progress);

	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
	LinearSweepSettings m_settings;
	LinearSweepStats m_stats;

	// Block storage
	std::map<uint64_t, std::unique_ptr<LinearBlock>> m_blocks;
	std::set<uint64_t> m_knownFunctionRanges;  // Addresses inside known functions

	// Grouping
	int m_nextGroupId = 0;
	std::map<int, std::vector<LinearBlock*>> m_groups;

	// Progress
	ProgressCallback m_progressCallback;
};

}  // namespace Armv5Analysis
