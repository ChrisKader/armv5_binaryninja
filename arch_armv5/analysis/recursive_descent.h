/*
 * Recursive Descent Analyzer for ARMv5
 *
 * Explores code from entry points by following calls and branches,
 * building CFGs incrementally and validating function boundaries.
 * Supports ARM/Thumb interworking detection.
 */

#pragma once

#include "binaryninjaapi.h"
#include "cfg/control_flow_graph.h"
#include "cfg/call_graph.h"

#include <vector>
#include <map>
#include <set>
#include <queue>
#include <memory>
#include <functional>

namespace Armv5Analysis
{

/**
 * Result of analyzing a single function candidate
 */
struct AnalyzedFunction
{
	uint64_t entryPoint;
	bool isThumb;

	// CFG information
	std::unique_ptr<ControlFlowGraph> cfg;
	bool cfgValid = false;
	size_t blockCount = 0;
	size_t instructionCount = 0;
	int cyclomaticComplexity = 0;

	// Function boundary
	uint64_t startAddress = 0;     // Lowest address in function
	uint64_t endAddress = 0;       // Highest address + instruction length

	// Discovered calls (potential new functions)
	std::vector<uint64_t> callTargets;
	std::vector<uint64_t> tailCallTargets;

	// Interworking info
	bool hasArmToThumbCalls = false;
	bool hasThumbToArmCalls = false;
	std::vector<std::pair<uint64_t, uint64_t>> modeChanges;  // (callsite, target)

	// Properties
	bool hasReturn = false;
	bool hasIndirectBranch = false;
	bool hasTailCall = false;
	bool isLeaf = false;           // Makes no calls
	bool appearsRecursive = false; // Calls itself

	// Confidence score based on analysis
	double confidence = 0.0;
	std::string analysisNotes;
};

/**
 * Settings for recursive descent analysis
 */
struct RecursiveDescentSettings
{
	// Limits per function
	size_t maxBlocksPerFunction = 500;
	size_t maxInstructionsPerFunction = 10000;

	// Global limits
	size_t maxFunctionsToDiscover = 5000;
	size_t maxTotalInstructions = 500000;

	// Exploration behavior
	bool followCalls = true;               // Follow BL/BLX to discover new functions
	bool followTailCalls = true;           // Follow unconditional branches at function end
	bool detectModeChanges = true;         // Track ARM/Thumb interworking
	bool validateWithCfg = true;           // Build CFG to validate boundaries

	// Confidence thresholds
	double minConfidenceToAdd = 0.5;        // Minimum confidence to add as function
	double callTargetBonus = 0.3;           // Bonus for being a call target
	double validCfgBonus = 0.2;             // Bonus for having valid CFG
	double returnBonus = 0.2;               // Bonus for having a return

	// Entry points
	bool useEntryPoint = true;              // Start from binary entry point
	bool useExistingFunctions = true;       // Start from already-defined functions
	bool useSymbols = true;                 // Start from exported symbols
	bool useVectorTable = true;             // Start from exception handlers
};

/**
 * Progress callback for long-running analysis
 */
using ProgressCallback = std::function<bool(size_t discovered, size_t queued, const std::string& status)>;

/**
 * Recursive Descent Analyzer
 *
 * Explores code systematically from entry points, following control flow
 * to discover and validate function boundaries.
 */
class RecursiveDescentAnalyzer
{
public:
	explicit RecursiveDescentAnalyzer(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

	/**
	 * Run analysis with current settings
	 * Returns the number of functions discovered
	 */
	size_t analyze();

	/**
	 * Run analysis with custom settings
	 */
	size_t analyze(const RecursiveDescentSettings& settings);

	/**
	 * Add a specific entry point for analysis
	 */
	void addEntryPoint(uint64_t address, bool isThumb);

	/**
	 * Clear all entry points
	 */
	void clearEntryPoints();

	/**
	 * Get the analyzed functions
	 */
	const std::map<uint64_t, AnalyzedFunction>& getResults() const { return m_results; }

	/**
	 * Get a specific analyzed function
	 */
	const AnalyzedFunction* getFunction(uint64_t address) const;

	/**
	 * Apply discovered functions to the BinaryView
	 * Returns count of functions created
	 */
	size_t applyToView(double minConfidence = 0.5);

	/**
	 * Set progress callback
	 */
	void setProgressCallback(ProgressCallback callback) { m_progressCallback = callback; }

	/**
	 * Get/set settings
	 */
	const RecursiveDescentSettings& getSettings() const { return m_settings; }
	void setSettings(const RecursiveDescentSettings& settings) { m_settings = settings; }

	/**
	 * Get statistics
	 */
	struct Stats
	{
		size_t entryPointsProcessed = 0;
		size_t functionsDiscovered = 0;
		size_t totalInstructions = 0;
		size_t totalBlocks = 0;
		size_t armFunctions = 0;
		size_t thumbFunctions = 0;
		size_t interworkingCalls = 0;
		size_t failedCfgBuilds = 0;
	};

	const Stats& getStats() const { return m_stats; }

private:
	/**
	 * Collect initial entry points from binary
	 */
	void collectEntryPoints();

	/**
	 * Analyze a single entry point
	 */
	void analyzeEntryPoint(uint64_t address, bool isThumb);

	/**
	 * Build CFG and extract function properties
	 */
	bool buildAndAnalyzeCfg(AnalyzedFunction& func);

	/**
	 * Calculate confidence score for a function
	 */
	double calculateConfidence(const AnalyzedFunction& func);

	/**
	 * Check if address is in an executable segment
	 */
	bool isExecutable(uint64_t address) const;

	/**
	 * Check if address is already inside a known function
	 */
	bool isInsideKnownFunction(uint64_t address) const;

	/**
	 * Determine if target address is Thumb mode based on call instruction
	 */
	bool determineTargetMode(uint64_t callSite, uint64_t target, bool currentMode) const;

	/**
	 * Report progress to callback
	 * Returns false if analysis should be cancelled
	 */
	bool reportProgress(const std::string& status);

	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	RecursiveDescentSettings m_settings;
	Stats m_stats;

	// Work queue: (address, isThumb, fromCall)
	std::queue<std::tuple<uint64_t, bool, bool>> m_workQueue;

	// Addresses we've queued to avoid duplicates
	std::set<uint64_t> m_queued;

	// Results
	std::map<uint64_t, AnalyzedFunction> m_results;

	// Explicit entry points (added by user)
	std::vector<std::pair<uint64_t, bool>> m_explicitEntryPoints;

	// Progress callback
	ProgressCallback m_progressCallback;

	// Logger
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;

	// Interval index for O(log n) range queries
	// Each interval is (start, end) sorted by start address
	struct Interval
	{
		uint64_t start;
		uint64_t end;
		bool operator<(const Interval& other) const { return start < other.start; }
	};
	mutable std::vector<Interval> m_functionIntervals;
	mutable bool m_intervalsBuilt = false;

	/**
	 * Build or rebuild the interval index for efficient range queries
	 */
	void buildIntervalIndex() const;

	/**
	 * Check if address is inside any interval using binary search (O(log n))
	 */
	bool isInsideInterval(uint64_t address) const;
};

}  // namespace Armv5Analysis
