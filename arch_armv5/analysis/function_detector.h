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
	
	// Negative (reduce score)
	MidInstruction       = 1 << 26,  // In middle of instruction
	InsideFunction       = 1 << 27,  // Already inside known function
	DataRegion           = 1 << 28,  // Marked as data
	InvalidInstruction   = 1 << 29,  // Cannot decode
	UnlikelyPattern      = 1 << 30,  // Anti-pattern detected
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
	
	bool operator<(const FunctionCandidate& other) const
	{
		return score > other.score;  // Higher score = better
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
	DetectorConfig alignmentBoundary = {true, 0.3, 0.5};  // Weak signal
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
	
	// Negative weights (subtracted from score)
	double midInstructionPenalty = 1.0;
	double insideFunctionPenalty = 0.8;
	double dataRegionPenalty = 0.9;
	double invalidInstructionPenalty = 0.5;
	double unlikelyPatternPenalty = 0.3;
	
	// Scanning parameters
	uint32_t maxCandidates = 10000;
	uint64_t scanStart = 0;         // 0 = use BinaryView start
	uint64_t scanEnd = 0;           // 0 = use BinaryView end
	bool scanInChunks = true;
	uint32_t chunkSize = 65536;
	
	// Advanced options
	bool useRecursiveDiscovery = true;   // Follow calls to find more
	bool detectCompilerStyle = true;     // Auto-detect compiler
	bool useMachineLearningRules = true; // Use ML-derived rules
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

private:
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
	
	// Helper methods
	void AddCandidate(std::map<uint64_t, FunctionCandidate>& candidates,
		uint64_t address, bool isThumb, DetectionSource source,
		double score, const std::string& description);
	bool IsValidInstruction(uint64_t address, bool thumb);
	bool IsInsideKnownFunction(uint64_t address);
	bool IsDataRegion(uint64_t address);
	double CalculateFinalScore(const FunctionCandidate& candidate);
	bool CheckArmPrologue(uint64_t address, uint32_t instr);
	bool CheckThumbPrologue(uint64_t address, uint16_t instr, uint16_t next);
	uint32_t ReadInstruction32(uint64_t address);
	uint16_t ReadInstruction16(uint64_t address);
	
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
