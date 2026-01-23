/*
 * Entropy Analyzer Implementation
 */

#include "entropy_analyzer.h"
#include <cmath>
#include <algorithm>

using namespace BinaryNinja;

namespace Armv5Analysis
{

// Entropy classification thresholds
namespace EntropyThresholds
{
	constexpr double kZeroPadding = 0.5;          // Below this = zero padding
	constexpr double kSparseData = 2.0;           // Below this = sparse data
	constexpr double kTextLow = 2.0;              // Text/strings lower bound
	constexpr double kTextHigh = 4.5;             // Text/strings upper bound
	constexpr double kCodeLow = 4.0;              // Code lower bound
	constexpr double kCodeHigh = 6.5;             // Code upper bound
	constexpr double kCompressed = 7.0;           // Above this = compressed
	constexpr double kRandomData = 7.5;           // Above this with uniformity = random
	constexpr double kEncrypted = 7.8;            // Above this with high uniformity = encrypted
	constexpr double kRandomUniformity = 0.8;     // Uniformity threshold for random
	constexpr double kEncryptedUniformity = 0.9;  // Uniformity threshold for encrypted
}

EntropyAnalyzer::EntropyAnalyzer(BinaryView* view) : m_view(view) {}

const char* EntropyAnalyzer::RegionTypeToString(EntropyRegionType type)
{
	switch (type)
	{
	case EntropyRegionType::Code: return "Code";
	case EntropyRegionType::Text: return "Text/Strings";
	case EntropyRegionType::CompressedData: return "Compressed";
	case EntropyRegionType::EncryptedData: return "Encrypted";
	case EntropyRegionType::RandomData: return "Random";
	case EntropyRegionType::SparseData: return "Sparse";
	case EntropyRegionType::ZeroPadding: return "Zero Padding";
	case EntropyRegionType::StructuredData: return "Structured Data";
	default: return "Unknown";
	}
}

void EntropyAnalyzer::calculateMetrics(const uint8_t* data, size_t len, double& entropy, double& uniformity)
{
	entropy = 0.0;
	uniformity = 0.0;

	if (len == 0) return;

	// Count byte frequencies (single pass)
	size_t freq[256] = {0};
	for (size_t i = 0; i < len; i++)
		freq[data[i]]++;

	// Calculate Shannon entropy and uniformity in a single loop
	double expectedFreq = static_cast<double>(len) / 256.0;
	double variance = 0.0;

	for (int i = 0; i < 256; i++)
	{
		// Entropy calculation
		if (freq[i] > 0)
		{
			double p = static_cast<double>(freq[i]) / len;
			entropy -= p * log2(p);
		}

		// Variance for uniformity
		double diff = freq[i] - expectedFreq;
		variance += diff * diff;
	}

	// Uniformity: how close to uniform random distribution
	// High uniformity = random/encrypted data
	// Low uniformity = structured data
	double maxVariance = len * len / 256.0;  // Maximum possible variance
	uniformity = 1.0 - (variance / maxVariance);
}

double EntropyAnalyzer::calculateBlockEntropy(const uint8_t* data, size_t len)
{
	double entropy, uniformity;
	calculateMetrics(data, len, entropy, uniformity);
	return entropy;  // Range: 0.0 - 8.0 bits per byte
}

double EntropyAnalyzer::calculateUniformity(const uint8_t* data, size_t len)
{
	double entropy, uniformity;
	calculateMetrics(data, len, entropy, uniformity);
	return uniformity;
}

EntropyRegionType EntropyAnalyzer::classifyRegion(double entropy, double uniformity, uint64_t addr)
{
	using namespace EntropyThresholds;

	// Very low entropy = padding or sparse
	if (entropy < kZeroPadding)
		return EntropyRegionType::ZeroPadding;

	if (entropy < kSparseData)
		return EntropyRegionType::SparseData;

	// Check if address is in executable section
	bool isExecutable = false;
	for (const auto& seg : m_view->GetSegments())
	{
		if (addr >= seg->GetStart() && addr < seg->GetEnd())
		{
			isExecutable = seg->GetFlags() & SegmentExecutable;
			break;
		}
	}

	// Very high entropy with high uniformity = encrypted/random
	if (entropy >= kEncrypted && uniformity > kEncryptedUniformity)
		return EntropyRegionType::EncryptedData;

	if (entropy >= kRandomData && uniformity > kRandomUniformity)
		return EntropyRegionType::RandomData;

	// High entropy with moderate uniformity = compressed
	if (entropy >= kCompressed)
		return EntropyRegionType::CompressedData;

	// Medium entropy
	if (entropy >= kCodeLow && entropy < kCodeHigh)
	{
		if (isExecutable)
			return EntropyRegionType::Code;
		return EntropyRegionType::StructuredData;
	}

	// Low-medium entropy = likely text/strings
	if (entropy >= kTextLow && entropy < kTextHigh)
		return EntropyRegionType::Text;

	return EntropyRegionType::Unknown;
}

void EntropyAnalyzer::mergeRegions(std::vector<EntropyRegion>& regions)
{
	if (regions.size() < 2) return;
	
	std::vector<EntropyRegion> merged;
	EntropyRegion current = regions[0];
	
	for (size_t i = 1; i < regions.size(); i++)
	{
		// Merge if same type and adjacent
		if (regions[i].type == current.type &&
			regions[i].address == current.address + current.size)
		{
			// Extend current region
			double totalSize = current.size + regions[i].size;
			current.entropy = (current.entropy * current.size + regions[i].entropy * regions[i].size) / totalSize;
			current.uniformity = (current.uniformity * current.size + regions[i].uniformity * regions[i].size) / totalSize;
			current.size = static_cast<size_t>(totalSize);
		}
		else
		{
			if (current.size >= m_settings.minRegionSize)
				merged.push_back(current);
			current = regions[i];
		}
	}
	
	if (current.size >= m_settings.minRegionSize)
		merged.push_back(current);
	
	regions = merged;
}

double EntropyAnalyzer::CalculateEntropy(uint64_t address, size_t size)
{
	DataBuffer buf = m_view->ReadBuffer(address, size);
	if (buf.GetLength() < size) return 0.0;
	return calculateBlockEntropy(static_cast<const uint8_t*>(buf.GetData()), buf.GetLength());
}

std::vector<std::pair<uint64_t, double>> EntropyAnalyzer::GetEntropyMap(size_t blockSize)
{
	std::vector<std::pair<uint64_t, double>> map;
	
	for (const auto& seg : m_view->GetSegments())
	{
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + blockSize <= end; addr += blockSize)
		{
			double entropy = CalculateEntropy(addr, blockSize);
			map.push_back({addr, entropy});
		}
	}
	
	return map;
}

std::vector<EntropyRegion> EntropyAnalyzer::Analyze(const EntropyAnalysisSettings& settings)
{
	m_settings = settings;
	m_stats = EntropyStats();
	std::vector<EntropyRegion> results;
	
	double totalEntropy = 0.0;
	
	for (const auto& seg : m_view->GetSegments())
	{
		// Optionally skip executable sections
		if (settings.skipCodeSections && (seg->GetFlags() & SegmentExecutable))
			continue;
		
		uint64_t start = seg->GetStart();
		uint64_t end = seg->GetEnd();
		
		for (uint64_t addr = start; addr + settings.blockSize <= end; addr += settings.blockSize)
		{
			DataBuffer buf = m_view->ReadBuffer(addr, settings.blockSize);
			if (buf.GetLength() < settings.blockSize) continue;
			
			const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
			double entropy, uniformity;
			calculateMetrics(data, settings.blockSize, entropy, uniformity);
			
			m_stats.totalBlocks++;
			totalEntropy += entropy;
			
			if (entropy > m_stats.maxEntropy)
				m_stats.maxEntropy = entropy;
			
			if (entropy >= settings.highEntropyThreshold)
				m_stats.highEntropyBlocks++;
			else if (entropy <= settings.lowEntropyThreshold)
				m_stats.lowEntropyBlocks++;
			
			EntropyRegionType type = classifyRegion(entropy, uniformity, addr);
			
			EntropyRegion region;
			region.address = addr;
			region.size = settings.blockSize;
			region.entropy = entropy;
			region.uniformity = uniformity;
			region.type = type;
			
			// Generate description
			switch (type)
			{
			case EntropyRegionType::EncryptedData:
				region.description = "Likely encrypted data (very high entropy, uniform distribution)";
				m_stats.encryptedRegions++;
				break;
			case EntropyRegionType::CompressedData:
				region.description = "Likely compressed data (high entropy)";
				m_stats.compressedRegions++;
				break;
			case EntropyRegionType::RandomData:
				region.description = "Random or encrypted data";
				m_stats.encryptedRegions++;
				break;
			case EntropyRegionType::ZeroPadding:
				region.description = "Zero padding or empty section";
				break;
			case EntropyRegionType::SparseData:
				region.description = "Sparse data with few unique values";
				break;
			case EntropyRegionType::Code:
				region.description = "Executable code (medium entropy)";
				break;
			case EntropyRegionType::Text:
				region.description = "Text or string data (low entropy)";
				break;
			case EntropyRegionType::StructuredData:
				region.description = "Structured data (tables, configs)";
				break;
			default:
				region.description = "Unknown content type";
				break;
			}
			
			results.push_back(region);
		}
	}
	
	if (m_stats.totalBlocks > 0)
		m_stats.averageEntropy = totalEntropy / m_stats.totalBlocks;
	
	// Merge adjacent regions of the same type
	if (settings.mergeAdjacentRegions)
		mergeRegions(results);
	
	// Filter to only interesting regions (high entropy or large)
	std::vector<EntropyRegion> filtered;
	for (const auto& r : results)
	{
		// Keep high entropy regions
		if (r.entropy >= settings.highEntropyThreshold)
			filtered.push_back(r);
		// Keep encrypted/compressed regions
		else if (r.type == EntropyRegionType::EncryptedData || 
			r.type == EntropyRegionType::CompressedData ||
			r.type == EntropyRegionType::RandomData)
			filtered.push_back(r);
		// Keep large regions of any type
		else if (r.size >= 4096)
			filtered.push_back(r);
	}
	
	// Sort by entropy (highest first)
	std::sort(filtered.begin(), filtered.end(),
		[](const EntropyRegion& a, const EntropyRegion& b) { return a.entropy > b.entropy; });
	
	return filtered;
}

}
