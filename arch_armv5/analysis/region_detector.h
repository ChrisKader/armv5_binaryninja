/*
 * Region Detector
 *
 * Advanced heuristics for detecting memory regions in bare-metal firmware.
 * Uses entropy analysis, code density, alignment patterns, and ARM-specific
 * signatures to automatically identify and classify memory regions.
 */

#pragma once

#include "binaryninjaapi.h"

#include <vector>
#include <string>
#include <cstdint>

namespace Armv5Analysis
{

/**
 * Detected region types
 */
enum class RegionType
{
	Unknown,
	Code,           // Executable code
	Data,           // Read-only data
	RWData,         // Read-write data (initialized)
	BSS,            // Uninitialized data (zeros)
	LiteralPool,    // ARM literal pools
	StringTable,    // String data
	VectorTable,    // Exception vectors
	JumpTable,      // Switch/jump tables
	MMIO,           // Memory-mapped I/O
	Padding,        // Alignment padding
	Compressed,     // Compressed data (high entropy)
};

/**
 * Confidence level for detection
 */
enum class Confidence
{
	Low = 1,
	Medium = 2,
	High = 3,
	Certain = 4,
};

/**
 * A detected memory region
 */
struct DetectedRegion
{
	uint64_t start;
	uint64_t end;
	RegionType type;
	Confidence confidence;
	std::string name;
	std::string description;
	
	// Detection metrics
	double entropy;
	double codeDensity;
	double stringDensity;
	uint32_t alignment;
	
	// Suggested permissions
	bool readable;
	bool writable;
	bool executable;
	
	uint64_t size() const { return end - start; }
};

/**
 * Heuristic settings for region detection
 */
struct RegionDetectionSettings
{
	// Entropy thresholds (0.0 - 8.0 for byte entropy)
	double codeEntropyMin = 4.5;      // Code typically 5.0-6.5
	double codeEntropyMax = 7.0;
	double dataEntropyMin = 2.0;      // Data typically 3.0-5.0
	double dataEntropyMax = 6.0;
	double compressedEntropyMin = 7.5; // Compressed/encrypted > 7.5
	double paddingEntropyMax = 0.5;   // Padding (zeros/0xFF) < 0.5
	
	// Code density (valid instructions / total words)
	double minCodeDensity = 0.7;      // 70% valid ARM instructions
	double thumbCodeDensityBonus = 0.1; // Thumb code may have lower density
	
	// Size thresholds
	uint64_t minRegionSize = 64;      // Minimum region size in bytes
	uint64_t minCodeRegion = 256;     // Minimum code region
	uint64_t minDataRegion = 32;      // Minimum data region
	uint64_t paddingThreshold = 16;   // Consecutive padding bytes to detect
	
	// Alignment detection
	uint32_t preferredAlignment = 4096;  // Prefer 4KB aligned boundaries
	uint32_t minAlignment = 16;          // Minimum alignment to consider
	bool useAlignmentHints = true;       // Use alignment for boundary hints
	
	// MMIO detection
	uint64_t mmioBaseStart = 0x40000000; // Common MMIO base addresses
	uint64_t mmioBaseEnd = 0x60000000;
	bool detectMMIOPatterns = true;
	
	// ARM-specific
	bool detectLiteralPools = true;
	bool detectVectorTables = true;
	bool detectJumpTables = true;
	
	// String detection
	uint32_t minStringLength = 4;
	double minStringDensity = 0.3;    // 30% printable chars for string region
	
	// Scanning parameters
	uint32_t windowSize = 256;        // Analysis window size
	uint32_t windowStep = 64;         // Step between windows
	bool mergeAdjacentRegions = true; // Merge same-type adjacent regions
	uint32_t mergeGapThreshold = 64;  // Max gap to merge
};

/**
 * Region detection engine
 */
class RegionDetector
{
public:
	RegionDetector(BinaryNinja::Ref<BinaryNinja::BinaryView> view);
	
	/**
	 * Run detection with current settings
	 */
	std::vector<DetectedRegion> Detect();
	
	/**
	 * Run detection with custom settings
	 */
	std::vector<DetectedRegion> Detect(const RegionDetectionSettings& settings);
	
	/**
	 * Get current settings
	 */
	const RegionDetectionSettings& GetSettings() const { return m_settings; }
	
	/**
	 * Update settings
	 */
	void SetSettings(const RegionDetectionSettings& settings) { m_settings = settings; }
	
	/**
	 * Apply detected regions to the BinaryView (create segments/sections)
	 */
	void ApplyRegions(const std::vector<DetectedRegion>& regions);
	
	/**
	 * Get default settings
	 */
	static RegionDetectionSettings DefaultSettings();
	
	/**
	 * Get aggressive settings (finds more regions, may have false positives)
	 */
	static RegionDetectionSettings AggressiveSettings();
	
	/**
	 * Get conservative settings (fewer false positives)
	 */
	static RegionDetectionSettings ConservativeSettings();

private:
	// Analysis methods
	double CalculateEntropy(uint64_t start, uint64_t size);
	double CalculateCodeDensity(uint64_t start, uint64_t size);
	double CalculateStringDensity(uint64_t start, uint64_t size);
	bool IsValidArmInstruction(uint32_t instr);
	bool IsValidThumbInstruction(uint16_t instr);
	bool IsPadding(uint64_t start, uint64_t size);
	bool IsLiteralPool(uint64_t start, uint64_t size);
	bool LooksLikeMMIO(uint64_t addr);
	
	// Region classification
	RegionType ClassifyRegion(uint64_t start, uint64_t size,
		double entropy, double codeDensity, double stringDensity);
	
	// Boundary detection
	std::vector<uint64_t> FindBoundaries();
	void MergeRegions(std::vector<DetectedRegion>& regions);
	
	// Name generation
	std::string GenerateRegionName(const DetectedRegion& region, int index);
	
	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	RegionDetectionSettings m_settings;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
};

/**
 * Convert region type to string
 */
const char* RegionTypeToString(RegionType type);

/**
 * Convert confidence to string
 */
const char* ConfidenceToString(Confidence conf);

}
