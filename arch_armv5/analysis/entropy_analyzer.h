/*
 * Entropy Analyzer
 *
 * Analyzes byte entropy to identify:
 * - Encrypted sections (high entropy, near 8.0)
 * - Compressed sections (high entropy)
 * - Text/string sections (low-medium entropy)
 * - Code sections (medium entropy)
 * - Zero/padding sections (near zero entropy)
 */

#pragma once

#include "binaryninjaapi.h"
#include <cstdint>
#include <string>
#include <vector>

namespace Armv5Analysis
{

enum class EntropyRegionType
{
	Unknown,
	Code,
	Text,
	CompressedData,
	EncryptedData,
	RandomData,
	SparseData,
	ZeroPadding,
	StructuredData
};

struct EntropyRegion
{
	uint64_t address;
	size_t size;
	double entropy;          // 0.0 - 8.0 bits per byte
	double uniformity;       // How uniform the distribution is
	EntropyRegionType type;
	std::string description;
};

struct EntropyAnalysisSettings
{
	size_t blockSize = 256;          // Analysis block size
	size_t minRegionSize = 512;      // Minimum region to report
	double highEntropyThreshold = 7.5;
	double lowEntropyThreshold = 4.0;
	bool mergeAdjacentRegions = true;
	bool skipCodeSections = false;
};

struct EntropyStats
{
	size_t totalBlocks = 0;
	size_t highEntropyBlocks = 0;
	size_t lowEntropyBlocks = 0;
	double averageEntropy = 0.0;
	double maxEntropy = 0.0;
	size_t encryptedRegions = 0;
	size_t compressedRegions = 0;
};

class EntropyAnalyzer
{
public:
	explicit EntropyAnalyzer(BinaryNinja::BinaryView* view);
	
	std::vector<EntropyRegion> Analyze(const EntropyAnalysisSettings& settings = EntropyAnalysisSettings());
	const EntropyStats& GetStats() const { return m_stats; }
	
	// Get entropy for a specific block
	double CalculateEntropy(uint64_t address, size_t size);
	
	// Get entropy histogram for visualization
	std::vector<std::pair<uint64_t, double>> GetEntropyMap(size_t blockSize = 256);
	
	static const char* RegionTypeToString(EntropyRegionType type);

private:
	double calculateBlockEntropy(const uint8_t* data, size_t len);
	double calculateUniformity(const uint8_t* data, size_t len);
	EntropyRegionType classifyRegion(double entropy, double uniformity, uint64_t addr);
	void mergeRegions(std::vector<EntropyRegion>& regions);
	
	BinaryNinja::BinaryView* m_view;
	EntropyAnalysisSettings m_settings;
	EntropyStats m_stats;
};

}
