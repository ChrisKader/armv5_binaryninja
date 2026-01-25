/*
 * Advanced Function Detector
 *
 * Multi-heuristic function detection for ARM firmware.
 * Combines multiple detection strategies with configurable weights
 * to identify function boundaries with high accuracy.
 *
 * Innovative approaches:
 * - Score-based detection combining weak signals
 * - Negative pattern detection (anti-patterns)
 * - Compiler fingerprinting
 * - Statistical instruction analysis
 * - Cross-reference density mapping
 */

#pragma once

#include "binaryninjaapi.h"

#include <vector>
#include <string>
#include <cstdint>
#include <map>
#include <set>
#include <functional>

namespace Armv5Analysis
{

/**
 * Detection source - which heuristic found this candidate
 */
enum class DetectionSource : uint32_t
{
	// Basic patterns
	ProloguePush         = 1 << 0,   // PUSH {regs, lr}
	PrologueSubSp        = 1 << 1,   // SUB sp, sp, #imm
	PrologueMovFp        = 1 << 2,   // MOV r11, sp (frame pointer)
	PrologueStmfd        = 1 << 3,   // STMFD sp!, {regs}
	
	// Call target analysis
	BlTarget             = 1 << 4,   // Target of BL instruction
	BlxTarget            = 1 << 5,   // Target of BLX instruction
	IndirectCallTarget   = 1 << 6,   // Target of indirect call (BLX Rn)
	
	// Cross-reference analysis
	HighXrefDensity      = 1 << 7,   // Many incoming references
	PointerTableEntry    = 1 << 8,   // Referenced in pointer table
	
	// Structural analysis
	AfterUnconditionalRet = 1 << 9,  // After BX LR / POP {pc}
	AfterTailCall        = 1 << 10,  // After unconditional branch
	AlignmentBoundary    = 1 << 11,  // On 4/8/16 byte boundary
	AfterLiteralPool     = 1 << 12,  // After embedded data
	AfterPadding         = 1 << 13,  // After 0x00/0xFF padding
	
	// Exception/interrupt
	VectorTableTarget    = 1 << 14,  // Exception handler
	InterruptPrologue    = 1 << 15,  // IRQ handler pattern
	
	// Advanced patterns
	ThunkPattern         = 1 << 16,  // LDR pc, [pc, #x] thunk
	TrampolinePattern    = 1 << 17,  // Jump trampoline
	SwitchCaseHandler    = 1 << 18,  // Switch/case target
	
	// Compiler-specific
	GccPrologue          = 1 << 19,  // GCC-style prologue
	ArmccPrologue        = 1 << 20,  // ARM Compiler prologue
	IarPrologue          = 1 << 21,  // IAR EWARM prologue
	
	// RTOS patterns
	TaskEntryPattern     = 1 << 22,  // RTOS task entry
	CallbackPattern      = 1 << 23,  // Callback function signature
	
	// Statistical
	InstructionSequence  = 1 << 24,  // Common instruction patterns
	EntropyTransition    = 1 << 25,  // Data->code entropy change

	// CFG-based validation (Phase 2 - Graph Analysis)
	CfgValidated         = 1 << 26,  // Valid CFG can be built from this entry

	// Negative (reduce score)
	MidInstruction       = 1 << 27,  // In middle of instruction
	InsideFunction       = 1 << 28,  // Already inside known function
	DataRegion           = 1 << 29,  // Marked as data
	InvalidInstruction   = 1 << 30,  // Cannot decode
	UnlikelyPattern      = 1U << 31, // Anti-pattern detected
};

/**
 * A candidate function location
 */
struct FunctionCandidate
{
	uint64_t address;
	bool isThumb;
	double score;                   // Combined score (0.0 - 1.0)
	uint32_t sources;               // Bitmask of DetectionSource
	std::string description;        // Human-readable explanation

	// Detailed scores per source
	std::map<DetectionSource, double> sourceScores;

	// Anti-patterns detected
	std::vector<std::string> warnings;

	// CFG validation results (Phase 2)
	bool cfgValidated = false;
	size_t cfgBlockCount = 0;
	size_t cfgEdgeCount = 0;
	size_t cfgLoopCount = 0;
	int cfgComplexity = 0;          // Cyclomatic complexity

	// Prologue body validation results
	// For prologue-only candidates, we scan forward to validate the function body
	bool bodyValidated = false;      // True if body scan found valid function structure
	size_t bodyInstrCount = 0;       // Number of valid instructions scanned
	size_t bodyBlCalls = 0;          // Number of BL/BLX calls found in body
	bool bodyHasReturn = false;      // True if we found a return instruction
	double bodyValidationBonus = 0;  // Score boost from body validation (0.0 - 1.5)

	bool operator<(const FunctionCandidate& other) const
	{
		return score > other.score;  // Higher score = better
	}
};

/**
 * Detection mode for unified config
 */
enum class DetectionMode
{
	Default,
	Aggressive,
	Conservative,
};

/**
 * Unified detection configuration
 *
 * Provides a single source of truth for detection thresholds across
 * FunctionDetector, LinearSweepAnalyzer, and RecursiveDescentAnalyzer.
 * Each analyzer maps these unified values to its internal parameters
 * via ApplyUnifiedConfig().
 */
struct UnifiedDetectionConfig
{
	double minimumScore = 0.4;        // Single threshold for all analyzers
	double highConfidenceScore = 0.8; // Score above which candidates are high confidence
	DetectionMode mode = DetectionMode::Default;

	static UnifiedDetectionConfig Default()
	{
		return UnifiedDetectionConfig{};
	}

	static UnifiedDetectionConfig Aggressive()
	{
		UnifiedDetectionConfig c;
		c.minimumScore = 0.35;
		c.highConfidenceScore = 0.6;
		c.mode = DetectionMode::Aggressive;
		return c;
	}

	static UnifiedDetectionConfig Conservative()
	{
		UnifiedDetectionConfig c;
		c.minimumScore = 0.6;
		c.highConfidenceScore = 0.9;
		c.mode = DetectionMode::Conservative;
		return c;
	}
};

/**
 * Individual detector settings
 */
struct DetectorConfig
{
	bool enabled = true;
	double weight = 1.0;            // Weight in combined score
	double threshold = 0.5;         // Minimum score to contribute
};

/**
 * Complete detection settings
 */
struct FunctionDetectionSettings
{
	// Global settings
	double minimumScore = 0.4;      // Minimum combined score to report
	double highConfidenceScore = 0.8;
	bool scanExecutableOnly = true;
	bool respectExistingFunctions = true;
	uint32_t alignmentPreference = 4;  // Prefer 4-byte aligned
	
	// ARM/Thumb detection
	bool detectArmFunctions = true;
	bool detectThumbFunctions = true;
	bool useEntryPointHint = true;  // Use BinaryView entry for mode hint
	
	// Prologue detectors
	DetectorConfig prologuePush = {true, 1.5, 0.5};
	DetectorConfig prologueSubSp = {true, 0.8, 0.5};
	DetectorConfig prologueMovFp = {true, 0.6, 0.5};
	DetectorConfig prologueStmfd = {true, 1.2, 0.5};
	
	// Call target analysis
	DetectorConfig blTarget = {true, 2.0, 0.3};       // High weight - very reliable
	DetectorConfig blxTarget = {true, 2.0, 0.3};
	DetectorConfig indirectCallTarget = {true, 1.0, 0.4};
	
	// Cross-reference analysis
	DetectorConfig highXrefDensity = {true, 1.2, 0.5};
	DetectorConfig pointerTableEntry = {true, 1.5, 0.4};
	
	// Structural analysis
	DetectorConfig afterUnconditionalRet = {true, 1.3, 0.5};
	DetectorConfig afterTailCall = {true, 1.0, 0.5};
	DetectorConfig alignmentBoundary = {false, 0.3, 0.5};  // Disabled: bulk-adds millions of noise candidates
	DetectorConfig afterLiteralPool = {true, 1.4, 0.5};
	DetectorConfig afterPadding = {true, 1.2, 0.5};
	
	// Exception/interrupt
	DetectorConfig vectorTableTarget = {true, 2.5, 0.3};  // Very high confidence
	DetectorConfig interruptPrologue = {true, 1.5, 0.5};
	
	// Advanced patterns
	DetectorConfig thunkPattern = {true, 1.8, 0.5};
	DetectorConfig trampolinePattern = {true, 1.5, 0.5};
	DetectorConfig switchCaseHandler = {true, 1.0, 0.4};
	
	// Compiler-specific
	DetectorConfig gccPrologue = {true, 1.3, 0.5};
	DetectorConfig armccPrologue = {true, 1.3, 0.5};
	DetectorConfig iarPrologue = {true, 1.3, 0.5};
	
	// RTOS patterns
	DetectorConfig taskEntryPattern = {true, 1.5, 0.5};
	DetectorConfig callbackPattern = {true, 1.0, 0.5};
	
	// Statistical
	DetectorConfig instructionSequence = {true, 0.8, 0.5};
	DetectorConfig entropyTransition = {true, 0.7, 0.5};

	// CFG-based validation (high confidence - validates structure)
	DetectorConfig cfgValidation = {true, 2.0, 0.3};
	bool useCfgValidation = true;           // Enable CFG-based validation
	size_t cfgMaxBlocks = 200;              // Max blocks to explore per candidate
	size_t cfgMaxInstructions = 5000;       // Max instructions per candidate

	// Prologue body validation - for prologue-only candidates with low scores,
	// scan forward to find evidence of a valid function body (return instruction,
	// BL calls, valid instruction sequence). This rescues functions that have
	// valid prologues but no incoming BL calls.
	bool useBodyValidation = true;          // Enable prologue body validation
	double bodyValidationWeight = 1.5;      // Score boost when body validates
	size_t bodyValidationMaxInstrs = 128;   // Max instructions to scan forward (512 bytes ARM)
	size_t bodyValidationMinInstrs = 4;     // Minimum valid instructions for boost

	// Linear sweep (Nucleus-style basic block grouping)
	// DISABLED by default - BN's built-in linear sweep is faster and adds functions
	// incrementally. Our notification handler filters out bad functions in real-time.
	bool useLinearSweep = false;            // Disable our slow linear sweep
	double linearSweepWeight = 1.8;         // Weight for linear sweep candidates (if enabled)
	size_t linearSweepMaxBlocks = 50000;    // Max blocks for linear sweep

	// Switch table resolution
	bool useSwitchResolution = true;        // Enable switch table resolution
	double switchTargetWeight = 1.5;        // Weight for switch case targets
	size_t switchMaxTables = 1000;          // Max tables to resolve

	// Tail call analysis (stack-based)
	bool useTailCallAnalysis = true;        // Enable stack-based tail call detection
	double tailCallTargetWeight = 1.6;      // Weight for tail call targets
	size_t tailCallMaxDepth = 32;           // Max instructions to analyze per function

	// Negative weights (subtracted from score)
	double midInstructionPenalty = 1.0;
	double insideFunctionPenalty = 0.8;
	double dataRegionPenalty = 0.9;
	double invalidInstructionPenalty = 0.5;
	double unlikelyPatternPenalty = 0.3;
	double epiloguePenalty = 5.0;           // Very strong penalty for epilogue instructions (always reject)
	
	// Scanning parameters
	uint32_t maxCandidates = 0;     // 0 = no limit (all passing candidates returned)
	uint64_t scanStart = 0;         // 0 = use BinaryView start
	uint64_t scanEnd = 0;           // 0 = use BinaryView end
	bool scanInChunks = true;
	uint32_t chunkSize = 65536;
	
	// Advanced options
	bool useRecursiveDiscovery = true;   // Follow calls to find more
	bool detectCompilerStyle = true;     // Auto-detect compiler
	bool useMachineLearningRules = true; // Use ML-derived rules

	// Unified detection config (propagated to LinearSweep and RecursiveDescent)
	UnifiedDetectionConfig unifiedConfig;

	/**
	 * Apply a unified detection config, mapping it to internal settings.
	 * This updates minimumScore, highConfidenceScore, and adjusts
	 * detector weights/thresholds for aggressive or conservative modes.
	 */
	void ApplyUnifiedConfig(const UnifiedDetectionConfig& config)
	{
		unifiedConfig = config;
		minimumScore = config.minimumScore;
		highConfidenceScore = config.highConfidenceScore;

		if (config.mode == DetectionMode::Aggressive)
		{
			prologuePush.threshold = 0.3;
			blTarget.threshold = 0.2;
			afterUnconditionalRet.threshold = 0.3;
			alignmentBoundary.weight = 0.3;
			instructionSequence.weight = 1.0;
			entropyTransition.weight = 0.8;
			midInstructionPenalty = 3.0;
			// maxCandidates stays at 0 (no limit)
		}
		else if (config.mode == DetectionMode::Conservative)
		{
			prologuePush.threshold = 0.7;
			blTarget.threshold = 0.5;
			afterUnconditionalRet.threshold = 0.7;
			alignmentBoundary.weight = 0.1;
			instructionSequence.weight = 0.4;
			entropyTransition.weight = 0.3;
			midInstructionPenalty = 1.5;
			unlikelyPatternPenalty = 0.6;
		}
	}
};

/**
 * Feedback type for user corrections
 */
enum class FeedbackType
{
	Correct,        // User confirmed a detected function
	FalsePositive,  // User removed a detected function
	Missed,         // User manually added a function we missed
};

/**
 * A single feedback entry recording a user correction
 */
struct FeedbackEntry
{
	uint64_t address;
	FeedbackType type;
	uint32_t detectionSources;  // Bitmask of DetectionSource that contributed
	double originalScore;       // Score at time of detection (0 for Missed)
};

/**
 * Tracks user corrections and computes adjusted detection weights.
 *
 * Records which functions were correct, false positives, or missed,
 * then adjusts detector weights to improve future runs on the same
 * firmware family.
 */
class DetectionFeedback
{
public:
	void RecordCorrectDetection(uint64_t addr, uint32_t sources = 0, double score = 0.0);
	void RecordFalsePositive(uint64_t addr, uint32_t sources = 0, double score = 0.0);
	void RecordMissedFunction(uint64_t addr);

	const std::vector<FeedbackEntry>& GetFeedback() const { return m_entries; }
	void Clear() { m_entries.clear(); }
	bool HasFeedback() const { return !m_entries.empty(); }

	/**
	 * Compute adjusted settings based on accumulated feedback.
	 * Increases weights for sources with high correct rates,
	 * decreases weights for sources with high false-positive rates,
	 * and adjusts minimumScore based on miss/false-positive balance.
	 */
	FunctionDetectionSettings ComputeAdjustedSettings(const FunctionDetectionSettings& base) const;

	// Serialization for persistence via BN Metadata
	BinaryNinja::Ref<BinaryNinja::Metadata> ToMetadata() const;
	static DetectionFeedback FromMetadata(BinaryNinja::Ref<BinaryNinja::Metadata> md);

private:
	std::vector<FeedbackEntry> m_entries;
};

/**
 * Compiler detection result
 */
enum class DetectedCompiler
{
	Unknown,
	GCC,
	ARMCC,
	IAR,
	Clang,
	Keil,
	GreenHills,
};

/**
 * Advanced function detection engine
 */
class FunctionDetector
{
public:
	FunctionDetector(BinaryNinja::Ref<BinaryNinja::BinaryView> view);
	
	/**
	 * Run full detection with current settings
	 */
	std::vector<FunctionCandidate> Detect();
	
	/**
	 * Run detection with custom settings
	 */
	std::vector<FunctionCandidate> Detect(const FunctionDetectionSettings& settings);
	
	/**
	 * Apply candidates as functions in the BinaryView
	 */
	size_t ApplyCandidates(const std::vector<FunctionCandidate>& candidates,
		double minScore = 0.5);
	
	/**
	 * Get statistics about detection
	 */
	struct DetectionStats
	{
		size_t totalCandidates;
		size_t highConfidence;
		size_t mediumConfidence;
		size_t lowConfidence;
		size_t armFunctions;
		size_t thumbFunctions;
		size_t existingFunctions;
		size_t newFunctions;
		size_t bodyValidatedFunctions;  // Functions rescued by body validation
		DetectedCompiler detectedCompiler;
		double averageScore;
		std::map<DetectionSource, size_t> sourceContributions;
	};
	
	DetectionStats GetStats() const { return m_stats; }
	
	/**
	 * Get/set settings
	 */
	const FunctionDetectionSettings& GetSettings() const { return m_settings; }
	void SetSettings(const FunctionDetectionSettings& settings) { m_settings = settings; }
	
	/**
	 * Preset configurations
	 */
	static FunctionDetectionSettings DefaultSettings();
	static FunctionDetectionSettings AggressiveSettings();
	static FunctionDetectionSettings ConservativeSettings();
	static FunctionDetectionSettings PrologueOnlySettings();
	static FunctionDetectionSettings CallTargetOnlySettings();
	
	/**
	 * Detect compiler style from existing code
	 */
	DetectedCompiler DetectCompilerStyle();

	/**
	 * Progress callback type
	 * Parameters: (currentPhase, totalPhases, phaseName)
	 * Returns false to request cancellation
	 */
	using ProgressCallback = std::function<bool(size_t, size_t, const std::string&)>;

	/**
	 * Set progress callback for long-running detection
	 */
	void SetProgressCallback(ProgressCallback callback);

	/**
	 * Check if cancellation has been requested
	 */
	bool IsCancellationRequested() const;

private:
	// Progress reporting helper
	bool ReportProgress(size_t phase, size_t totalPhases, const std::string& phaseName);
	// Individual detector methods
	void ScanProloguePatterns(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanCallTargets(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanCrossReferences(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanStructuralPatterns(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanExceptionHandlers(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanAdvancedPatterns(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanCompilerPatterns(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanRtosPatterns(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanStatisticalPatterns(std::map<uint64_t, FunctionCandidate>& candidates);
	void ApplyNegativePatterns(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanCfgValidation(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanLinearSweep(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanSwitchTargets(std::map<uint64_t, FunctionCandidate>& candidates);
	void ScanTailCallTargets(std::map<uint64_t, FunctionCandidate>& candidates);
	
	// Helper methods
	void AddCandidate(std::map<uint64_t, FunctionCandidate>& candidates,
		uint64_t address, bool isThumb, DetectionSource source,
		double score, const std::string& description);
	bool IsValidInstruction(uint64_t address, bool thumb);
	bool IsInsideKnownFunction(uint64_t address);
	bool IsDataRegion(uint64_t address);
	bool IsValidBranchSource(uint64_t sourceAddress, bool thumb);
	bool IsEpilogueInstruction(uint64_t address, bool isThumb);
	double CalculateFinalScore(const FunctionCandidate& candidate);
	double GetConfiguredWeight(DetectionSource source) const;
	bool CheckArmPrologue(uint64_t address, uint32_t instr);
	bool CheckThumbPrologue(uint64_t address, uint16_t instr, uint16_t next);
	uint32_t ReadInstruction32(uint64_t address);
	uint16_t ReadInstruction16(uint64_t address);

	// Prologue body validation - scans forward from a prologue candidate to
	// validate it's a real function by finding a return instruction
	void ValidatePrologueBody(FunctionCandidate& candidate);
	
	// Statistical helpers
	double CalculateLocalEntropy(uint64_t address, size_t windowSize);
	size_t CountIncomingReferences(uint64_t address);
	
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	FunctionDetectionSettings m_settings;
	DetectionStats m_stats;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
	
	// Caches
	std::set<uint64_t> m_existingFunctions;
	std::set<uint64_t> m_callTargets;
	std::map<uint64_t, size_t> m_xrefCounts;

	// Cached function list (expensive to fetch repeatedly)
	std::vector<BinaryNinja::Ref<BinaryNinja::Function>> m_cachedFunctionList;
	
	// Code region boundary estimation
	uint64_t m_estimatedCodeEnd = 0;
	void EstimateCodeBoundary();

	// Bulk data cache — avoids per-instruction ReadBuffer() heap allocations
	BinaryNinja::DataBuffer m_dataCache;
	uint64_t m_dataCacheStart = 0;
	size_t m_dataCacheLen = 0;
	void InitDataCache();

	// Progress callback and phase tracking for intra-phase reporting
	ProgressCallback m_progressCallback;
	bool m_cancellationRequested = false;
	size_t m_currentPhase = 0;
	static constexpr size_t kTotalPhases = 14;
};

/**
 * Convert detection source to string
 */
const char* DetectionSourceToString(DetectionSource source);

/**
 * Convert compiler to string
 */
const char* CompilerToString(DetectedCompiler compiler);

}
