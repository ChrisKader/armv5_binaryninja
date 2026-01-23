/*
 * Region Detector Implementation
 */

#include "region_detector.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>
#include <set>

using namespace BinaryNinja;

namespace Armv5Analysis
{

const char* RegionTypeToString(RegionType type)
{
	switch (type)
	{
	case RegionType::Code:         return "Code";
	case RegionType::Data:         return "Data";
	case RegionType::RWData:       return "RWData";
	case RegionType::BSS:          return "BSS";
	case RegionType::LiteralPool:  return "LiteralPool";
	case RegionType::StringTable:  return "Strings";
	case RegionType::VectorTable:  return "Vectors";
	case RegionType::JumpTable:    return "JumpTable";
	case RegionType::MMIO:         return "MMIO";
	case RegionType::Padding:      return "Padding";
	case RegionType::Compressed:   return "Compressed";
	default:                       return "Unknown";
	}
}

const char* ConfidenceToString(Confidence conf)
{
	switch (conf)
	{
	case Confidence::Low:     return "Low";
	case Confidence::Medium:  return "Medium";
	case Confidence::High:    return "High";
	case Confidence::Certain: return "Certain";
	default:                  return "Unknown";
	}
}

RegionDetector::RegionDetector(Ref<BinaryView> view)
	: m_view(view)
	, m_settings(DefaultSettings())
{
	m_logger = LogRegistry::CreateLogger("RegionDetector");
}

RegionDetectionSettings RegionDetector::DefaultSettings()
{
	return RegionDetectionSettings();
}

RegionDetectionSettings RegionDetector::AggressiveSettings()
{
	RegionDetectionSettings s;
	s.minCodeDensity = 0.5;
	s.minRegionSize = 32;
	s.minCodeRegion = 64;
	s.paddingThreshold = 8;
	s.mergeGapThreshold = 128;
	s.codeEntropyMin = 4.0;
	return s;
}

RegionDetectionSettings RegionDetector::ConservativeSettings()
{
	RegionDetectionSettings s;
	s.minCodeDensity = 0.85;
	s.minRegionSize = 256;
	s.minCodeRegion = 512;
	s.paddingThreshold = 32;
	s.mergeGapThreshold = 16;
	s.codeEntropyMin = 5.0;
	return s;
}

RegionDetectionSettings RegionDetector::FirmwareSafeSettings()
{
	RegionDetectionSettings s;

	// Very high thresholds - only detect major sections
	s.minCodeDensity = 0.75;       // Slightly lower - some code has literal pools mixed in
	s.minRegionSize = 16384;       // 16KB minimum for any region
	s.minCodeRegion = 32768;       // 32KB minimum for code sections
	s.minDataRegion = 16384;       // 16KB minimum for data sections
	s.paddingThreshold = 128;      // Larger padding detection (flash erases to 0xFF)
	s.mergeGapThreshold = 65536;   // 64KB - aggressively merge same-type regions

	// Entropy ranges tuned for firmware
	s.codeEntropyMin = 4.0;        // Lower threshold - some optimized code is denser
	s.codeEntropyMax = 7.5;
	s.dataEntropyMin = 0.5;        // BSS/padding can be very low
	s.dataEntropyMax = 6.5;

	// Larger scanning window for major regions
	s.windowSize = 16384;          // 16KB window
	s.windowStep = 4096;           // 4KB step

	// Function-aware filtering enabled
	s.useFunctionAwareness = true;
	s.literalPoolMaxSize = 4096;      // Ignore data regions up to 4KB (literal pools, jump tables)
	s.minMajorDataSection = 16384;    // Only create data sections for 16KB+ regions
	s.minMajorCodeSection = 32768;    // Only create code sections for 32KB+ regions
	s.skipEmbeddedData = true;        // Skip small data regions surrounded by code
	s.embeddedDataMaxGap = 4096;      // Data within 4KB of code is "embedded"

	// Always merge adjacent regions
	s.mergeAdjacentRegions = true;

	// Prefer alignment boundaries
	s.preferredAlignment = 4096;
	s.useAlignmentHints = true;

	return s;
}

double RegionDetector::CalculateEntropy(uint64_t start, uint64_t size)
{
	if (size == 0)
		return 0.0;
	
	// Count byte frequencies
	uint64_t counts[256] = {0};
	
	DataBuffer buffer = m_view->ReadBuffer(start, size);
	if (buffer.GetLength() < size)
		return 0.0;
	
	const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());
	for (size_t i = 0; i < size; i++)
		counts[data[i]]++;
	
	// Calculate Shannon entropy
	double entropy = 0.0;
	double logSize = log2(static_cast<double>(size));
	
	for (int i = 0; i < 256; i++)
	{
		if (counts[i] > 0)
		{
			double p = static_cast<double>(counts[i]) / static_cast<double>(size);
			entropy -= p * log2(p);
		}
	}
	
	return entropy;
}

double RegionDetector::CalculateCodeDensity(uint64_t start, uint64_t size)
{
	if (size < 4)
		return 0.0;
	
	DataBuffer buffer = m_view->ReadBuffer(start, size);
	if (buffer.GetLength() < size)
		return 0.0;
	
	const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());
	
	// Check ARM mode (32-bit aligned)
	size_t armValid = 0;
	size_t armTotal = size / 4;
	
	for (size_t i = 0; i + 3 < size; i += 4)
	{
		uint32_t instr = data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24);
		if (IsValidArmInstruction(instr))
			armValid++;
	}
	
	// Check Thumb mode (16-bit aligned)
	size_t thumbValid = 0;
	size_t thumbTotal = size / 2;
	
	for (size_t i = 0; i + 1 < size; i += 2)
	{
		uint16_t instr = data[i] | (data[i+1] << 8);
		if (IsValidThumbInstruction(instr))
			thumbValid++;
	}
	
	double armDensity = armTotal > 0 ? static_cast<double>(armValid) / armTotal : 0.0;
	double thumbDensity = thumbTotal > 0 ? static_cast<double>(thumbValid) / thumbTotal : 0.0;
	
	// Return the higher of the two
	return std::max(armDensity, thumbDensity);
}

double RegionDetector::CalculateStringDensity(uint64_t start, uint64_t size)
{
	if (size == 0)
		return 0.0;
	
	DataBuffer buffer = m_view->ReadBuffer(start, size);
	if (buffer.GetLength() < size)
		return 0.0;
	
	const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());
	
	size_t printable = 0;
	size_t nullTerminators = 0;
	
	for (size_t i = 0; i < size; i++)
	{
		uint8_t c = data[i];
		if ((c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r')
			printable++;
		if (c == 0 && i > 0 && data[i-1] != 0)
			nullTerminators++;
	}
	
	// High string density = lots of printable chars + null terminators
	double density = static_cast<double>(printable) / size;
	
	// Bonus for null terminators (indicates C strings)
	if (nullTerminators > 0)
		density += 0.1 * std::min(1.0, static_cast<double>(nullTerminators) / (size / 32.0));
	
	return std::min(1.0, density);
}

bool RegionDetector::IsValidArmInstruction(uint32_t instr)
{
	// Check condition field (must not be 0b1111 for most instructions)
	uint32_t cond = (instr >> 28) & 0xF;
	
	// Unconditional instructions are valid
	if (cond == 0xF)
	{
		// Check for valid unconditional encodings
		uint32_t op1 = (instr >> 25) & 0x7;
		return (op1 == 0x5 || op1 == 0x6 || op1 == 0x7);
	}
	
	// Check for common invalid patterns
	if (instr == 0x00000000 || instr == 0xFFFFFFFF)
		return false;
	
	// Data processing instructions (bits 27:26 = 00)
	uint32_t bits27_26 = (instr >> 26) & 0x3;
	if (bits27_26 == 0)
		return true;
	
	// Load/store (bits 27:26 = 01)
	if (bits27_26 == 1)
		return true;
	
	// Load/store multiple, branch (bits 27:26 = 10)
	if (bits27_26 == 2)
		return true;
	
	// Coprocessor, SWI (bits 27:26 = 11)
	if (bits27_26 == 3)
		return true;
	
	return false;
}

bool RegionDetector::IsValidThumbInstruction(uint16_t instr)
{
	// All-zeros or all-ones are invalid
	if (instr == 0x0000 || instr == 0xFFFF)
		return false;
	
	// Check opcode patterns
	uint16_t op = (instr >> 11) & 0x1F;
	
	// Most 5-bit opcodes are valid for 16-bit Thumb
	// Invalid range: undefined encodings
	if (op == 0x1E || op == 0x1F)
	{
		// Could be 32-bit Thumb instruction prefix
		return true;
	}
	
	return true;
}

bool RegionDetector::IsPadding(uint64_t start, uint64_t size)
{
	if (size < m_settings.paddingThreshold)
		return false;

	DataBuffer buffer = m_view->ReadBuffer(start, std::min(size, (uint64_t)256));
	if (buffer.GetLength() == 0)
		return false;

	const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());
	uint8_t first = data[0];

	// Count how many bytes match the first byte
	size_t matchCount = 1;
	for (size_t i = 1; i < buffer.GetLength(); i++)
	{
		if (data[i] == first)
			matchCount++;
	}

	// If 95% or more of bytes are the same value, it's padding
	// This catches any repeated byte pattern (0x00, 0xFF, 0xFE, 0xAA, etc.)
	double repeatRatio = static_cast<double>(matchCount) / buffer.GetLength();
	if (repeatRatio >= 0.95)
		return true;

	// Also check for alternating patterns like 0x55/0xAA (sometimes used as fill)
	if (buffer.GetLength() >= 4)
	{
		uint8_t second = data[1];
		if (first != second)
		{
			size_t alternateMatch = 0;
			for (size_t i = 0; i < buffer.GetLength(); i++)
			{
				if ((i % 2 == 0 && data[i] == first) || (i % 2 == 1 && data[i] == second))
					alternateMatch++;
			}
			double alternateRatio = static_cast<double>(alternateMatch) / buffer.GetLength();
			if (alternateRatio >= 0.95)
				return true;
		}
	}

	return false;
}

bool RegionDetector::IsInsideOrNearFunction(uint64_t start, uint64_t end)
{
	if (!m_settings.useFunctionAwareness)
		return false;

	// Check if this region overlaps with or is very close to any function
	auto functions = m_view->GetAnalysisFunctionsForAddress(start);
	if (!functions.empty())
		return true;

	functions = m_view->GetAnalysisFunctionsForAddress(end - 1);
	if (!functions.empty())
		return true;

	// Check for nearby functions within the gap threshold
	uint64_t searchStart = (start > m_settings.embeddedDataMaxGap) ? start - m_settings.embeddedDataMaxGap : 0;
	uint64_t searchEnd = end + m_settings.embeddedDataMaxGap;

	auto allFunctions = m_view->GetAnalysisFunctionList();
	for (const auto& func : allFunctions)
	{
		if (!func)
			continue;

		uint64_t funcStart = func->GetStart();
		uint64_t funcEnd = funcStart;

		// Get function end from basic blocks
		for (const auto& bb : func->GetBasicBlocks())
		{
			if (bb && bb->GetEnd() > funcEnd)
				funcEnd = bb->GetEnd();
		}

		// Check if function is near our region
		if (funcEnd >= searchStart && funcStart <= searchEnd)
			return true;
	}

	return false;
}

bool RegionDetector::IsEmbeddedInCode(uint64_t start, uint64_t end)
{
	if (!m_settings.skipEmbeddedData)
		return false;

	uint64_t regionSize = end - start;

	// Large regions are not "embedded"
	if (regionSize >= m_settings.minMajorDataSection)
		return false;

	// Check if there's code before and after this region
	uint64_t checkBefore = (start > m_settings.embeddedDataMaxGap) ? start - m_settings.embeddedDataMaxGap : m_view->GetStart();
	uint64_t checkAfter = std::min(end + m_settings.embeddedDataMaxGap, m_view->GetEnd());

	// Check code density before
	double densityBefore = CalculateCodeDensity(checkBefore, start - checkBefore);

	// Check code density after
	double densityAfter = CalculateCodeDensity(end, checkAfter - end);

	// If both sides have decent code density, this is embedded data (likely literal pool)
	return (densityBefore >= 0.5 && densityAfter >= 0.5);
}

bool RegionDetector::ShouldSkipAsLiteralPool(uint64_t start, uint64_t size, RegionType type)
{
	// Only skip data-like regions
	if (type == RegionType::Code)
		return false;

	// Skip if too small to be a major section
	if (size < m_settings.literalPoolMaxSize)
	{
		// Check if it looks like a literal pool
		if (IsLiteralPool(start, size))
			return true;

		// Check if embedded in code
		if (IsEmbeddedInCode(start, start + size))
			return true;
	}

	// Skip small data regions that are near functions
	if (size < m_settings.minMajorDataSection)
	{
		if (IsInsideOrNearFunction(start, start + size))
			return true;
	}

	return false;
}

bool RegionDetector::IsLiteralPool(uint64_t start, uint64_t size)
{
	if (size < 8 || size > 1024)
		return false;

	DataBuffer buffer = m_view->ReadBuffer(start, size);
	if (buffer.GetLength() < size)
		return false;

	const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());

	// Literal pools contain mostly valid addresses
	uint64_t imageStart = m_view->GetStart();
	uint64_t imageEnd = m_view->GetEnd();

	size_t validAddrs = 0;
	size_t totalWords = size / 4;

	for (size_t i = 0; i + 3 < size; i += 4)
	{
		uint32_t val = data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24);

		// Check if it's a plausible address
		uint64_t addr = val & ~1ULL;  // Clear Thumb bit
		if (addr >= imageStart && addr < imageEnd)
			validAddrs++;

		// Also check for small constants (common in literal pools)
		if (val < 0x10000 || (val >= 0xFFFF0000))
			validAddrs++;
	}

	return totalWords > 0 && (static_cast<double>(validAddrs) / totalWords) > 0.5;
}

bool RegionDetector::LooksLikePointerTable(uint64_t start, uint64_t size)
{
	// Pointer tables are larger than literal pools and contain many valid addresses
	if (size < 16)
		return false;

	// Sample up to 256 bytes
	size_t sampleSize = std::min(size, (uint64_t)256);
	DataBuffer buffer = m_view->ReadBuffer(start, sampleSize);
	if (buffer.GetLength() < sampleSize)
		return false;

	const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());

	uint64_t imageStart = m_view->GetStart();
	uint64_t imageEnd = m_view->GetEnd();

	size_t validAddrs = 0;
	size_t totalWords = sampleSize / 4;

	for (size_t i = 0; i + 3 < sampleSize; i += 4)
	{
		uint32_t val = data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24);

		// Check if it's a plausible code/data address
		uint64_t addr = val & ~1ULL;  // Clear Thumb bit
		if (addr >= imageStart && addr < imageEnd)
		{
			validAddrs++;
		}
		// Also check for MMIO addresses (common in firmware)
		else if ((val >= 0x40000000 && val < 0x60000000) ||
		         (val >= 0xE0000000 && val < 0xF0000000))
		{
			validAddrs++;
		}
	}

	// If 40% or more of words look like valid addresses, it's a pointer table
	return totalWords > 0 && (static_cast<double>(validAddrs) / totalWords) >= 0.4;
}

bool RegionDetector::LooksLikeMMIO(uint64_t addr)
{
	if (!m_settings.detectMMIOPatterns)
		return false;
	
	// Check common MMIO base address ranges
	if (addr >= m_settings.mmioBaseStart && addr < m_settings.mmioBaseEnd)
		return true;
	
	// Check for typical peripheral base addresses
	uint64_t base = addr & 0xFFF00000ULL;
	if (base == 0x40000000 || base == 0x41000000 || base == 0x42000000 ||
		base == 0x48000000 || base == 0x49000000 ||
		base == 0x50000000 || base == 0x58000000 ||
		base == 0xE0000000 || base == 0xE0100000)
		return true;
	
	return false;
}

RegionType RegionDetector::ClassifyRegion(uint64_t start, uint64_t size,
	double entropy, double codeDensity, double stringDensity)
{
	// Check for MMIO first (address-based)
	if (LooksLikeMMIO(start))
		return RegionType::MMIO;

	// Check for padding (very low entropy, uniform bytes)
	if (entropy < m_settings.paddingEntropyMax && IsPadding(start, size))
		return RegionType::Padding;

	// Check for BSS (all zeros, no file data)
	if (entropy < 0.1)
		return RegionType::BSS;

	// Check for compressed/encrypted data (very high entropy)
	if (entropy > m_settings.compressedEntropyMin)
		return RegionType::Compressed;

	// IMPORTANT: Check for code BEFORE strings
	// Pointer tables often have bytes in the printable ASCII range (0x20-0x7F)
	// which causes them to be misclassified as strings. Code detection is more reliable.
	if (entropy >= m_settings.codeEntropyMin && entropy <= m_settings.codeEntropyMax &&
		codeDensity >= m_settings.minCodeDensity)
		return RegionType::Code;

	// Check for literal pools (pointer tables, constants)
	// Do this before string check - literal pools can look like strings
	if (m_settings.detectLiteralPools && IsLiteralPool(start, size))
		return RegionType::LiteralPool;

	// Check if this looks like a pointer table (common in ARM firmware)
	// Pointer tables have medium entropy and contain valid addresses
	if (LooksLikePointerTable(start, size))
		return RegionType::Data;  // Classify as data, not strings

	// Check for string tables - must have VERY high string density
	// AND low entropy (pure ASCII text has low entropy)
	// AND must NOT look like code or pointer tables
	if (stringDensity > m_settings.minStringDensity &&
		entropy < 5.0 &&
		codeDensity < 0.3)  // Must not look like code at all
		return RegionType::StringTable;

	// Default to data
	if (entropy >= m_settings.dataEntropyMin && entropy <= m_settings.dataEntropyMax)
		return RegionType::Data;

	return RegionType::Unknown;
}

std::vector<uint64_t> RegionDetector::FindBoundaries()
{
	std::vector<uint64_t> boundaries;
	std::set<uint64_t> functionRanges;  // Store function address ranges for quick lookup

	uint64_t start = m_view->GetStart();
	uint64_t end = m_view->GetEnd();
	uint64_t size = end - start;

	if (size == 0)
		return boundaries;

	boundaries.push_back(start);

	// Collect function boundaries if function-awareness is enabled
	// This ensures we don't split sections in the middle of functions
	std::vector<std::pair<uint64_t, uint64_t>> functionExtents;
	if (m_settings.useFunctionAwareness)
	{
		auto allFunctions = m_view->GetAnalysisFunctionList();
		m_logger->LogDebug("RegionDetector: Found %zu functions for boundary analysis", allFunctions.size());

		for (const auto& func : allFunctions)
		{
			if (!func)
				continue;

			uint64_t funcStart = func->GetStart();
			uint64_t funcEnd = funcStart;

			// Get function end from basic blocks
			for (const auto& bb : func->GetBasicBlocks())
			{
				if (bb && bb->GetEnd() > funcEnd)
					funcEnd = bb->GetEnd();
			}

			if (funcEnd > funcStart)
			{
				functionExtents.push_back({funcStart, funcEnd});
			}
		}

		// Sort function extents by start address
		std::sort(functionExtents.begin(), functionExtents.end());
	}

	// Helper lambda to check if an address is inside any function
	auto isInsideFunction = [&functionExtents](uint64_t addr) -> bool {
		for (const auto& extent : functionExtents)
		{
			if (addr > extent.first && addr < extent.second)
				return true;
			if (extent.first > addr)  // Past the point where it could match
				break;
		}
		return false;
	};

	// Helper lambda to snap an address to a nearby alignment boundary
	auto snapToAlignment = [this, start, end](uint64_t addr) -> uint64_t {
		if (!m_settings.useAlignmentHints)
			return addr;

		// Find the nearest alignment boundary within a reasonable distance
		uint32_t align = m_settings.preferredAlignment;
		uint64_t alignedDown = addr & ~(uint64_t)(align - 1);
		uint64_t alignedUp = alignedDown + align;

		// Use the closer one, but prefer staying within bounds
		uint64_t distDown = addr - alignedDown;
		uint64_t distUp = alignedUp - addr;

		if (alignedDown >= start && distDown <= m_settings.windowStep)
			return alignedDown;
		if (alignedUp < end && distUp <= m_settings.windowStep)
			return alignedUp;

		return addr;  // Don't snap if too far
	};

	// For firmware-safe mode with large windows, use a simpler approach:
	// Only add boundaries at major transitions, snapped to alignment
	if (m_settings.useFunctionAwareness && m_settings.windowSize >= 4096)
	{
		// Find code/data transitions using larger windows
		double prevCodeDensity = -1;
		for (uint64_t addr = start; addr < end; addr += m_settings.windowStep)
		{
			uint64_t windowEnd = std::min(addr + m_settings.windowSize, end);
			double codeDensity = CalculateCodeDensity(addr, windowEnd - addr);

			// Detect code/data transitions (more reliable than entropy for firmware)
			if (prevCodeDensity >= 0)
			{
				bool wasCode = prevCodeDensity >= m_settings.minCodeDensity;
				bool isCode = codeDensity >= m_settings.minCodeDensity;

				if (wasCode != isCode)
				{
					// Don't add boundary if we're inside a function
					if (!isInsideFunction(addr))
					{
						uint64_t snapped = snapToAlignment(addr);
						if (!isInsideFunction(snapped))
							boundaries.push_back(snapped);
					}
				}
			}

			prevCodeDensity = codeDensity;
		}
	}
	else
	{
		// Original entropy-based approach for other presets
		// Add aligned boundaries
		if (m_settings.useAlignmentHints)
		{
			for (uint64_t addr = start; addr < end; addr += m_settings.preferredAlignment)
			{
				uint64_t aligned = (addr + m_settings.preferredAlignment - 1) & ~(m_settings.preferredAlignment - 1);
				if (aligned > start && aligned < end && !isInsideFunction(aligned))
					boundaries.push_back(aligned);
			}
		}

		// Analyze entropy transitions
		double prevEntropy = -1;
		for (uint64_t addr = start; addr < end; addr += m_settings.windowStep)
		{
			uint64_t windowEnd = std::min(addr + m_settings.windowSize, end);
			double entropy = CalculateEntropy(addr, windowEnd - addr);

			// Detect significant entropy changes (only if not inside a function)
			if (prevEntropy >= 0 && std::abs(entropy - prevEntropy) > 1.5)
			{
				if (!isInsideFunction(addr))
				{
					uint64_t snapped = snapToAlignment(addr);
					if (!isInsideFunction(snapped))
						boundaries.push_back(snapped);
				}
			}

			prevEntropy = entropy;
		}
	}

	boundaries.push_back(end);

	// Sort and remove duplicates
	std::sort(boundaries.begin(), boundaries.end());
	boundaries.erase(std::unique(boundaries.begin(), boundaries.end()), boundaries.end());

	m_logger->LogDebug("RegionDetector: Found %zu boundary candidates", boundaries.size());

	return boundaries;
}

void RegionDetector::MergeRegions(std::vector<DetectedRegion>& regions)
{
	if (!m_settings.mergeAdjacentRegions || regions.size() < 2)
		return;

	std::vector<DetectedRegion> merged;
	DetectedRegion current = regions[0];

	for (size_t i = 1; i < regions.size(); i++)
	{
		const DetectedRegion& next = regions[i];

		// Check if we should merge
		bool canMerge = false;

		// Same type within gap threshold
		if (current.type == next.type &&
			next.start <= current.end + m_settings.mergeGapThreshold &&
			current.readable == next.readable &&
			current.writable == next.writable &&
			current.executable == next.executable)
		{
			canMerge = true;
		}

		// For firmware-safe mode, be more aggressive about merging code regions
		// Small data/unknown regions between code should be absorbed into code
		if (m_settings.useFunctionAwareness && !canMerge)
		{
			// If current is CODE and next is CODE, merge even with gap
			if (current.type == RegionType::Code && next.type == RegionType::Code)
			{
				uint64_t gap = (next.start > current.end) ? (next.start - current.end) : 0;
				// Merge code regions with gaps up to 64KB (literal pools, small data tables)
				if (gap <= 65536)
					canMerge = true;
			}

			// Absorb small non-code regions into surrounding code
			if (current.type == RegionType::Code && next.type != RegionType::Code)
			{
				uint64_t nextSize = next.end - next.start;
				// If the non-code region is small and there's more code after it, absorb it
				if (nextSize < m_settings.minMajorDataSection && i + 1 < regions.size())
				{
					const DetectedRegion& afterNext = regions[i + 1];
					if (afterNext.type == RegionType::Code)
					{
						// Extend current to include this small region
						current.end = next.end;
						continue;  // Skip adding 'next' and check afterNext
					}
				}
			}
		}

		if (canMerge)
		{
			// Extend current region
			current.end = next.end;
			current.entropy = (current.entropy + next.entropy) / 2.0;
			current.codeDensity = (current.codeDensity + next.codeDensity) / 2.0;

			// Take higher confidence
			if (static_cast<int>(next.confidence) > static_cast<int>(current.confidence))
				current.confidence = next.confidence;
		}
		else
		{
			merged.push_back(current);
			current = next;
		}
	}

	merged.push_back(current);
	regions = merged;
}

std::string RegionDetector::GenerateRegionName(const DetectedRegion& region, int index)
{
	char buf[64];
	const char* prefix = "";
	
	switch (region.type)
	{
	case RegionType::Code:        prefix = ".text"; break;
	case RegionType::Data:        prefix = ".rodata"; break;
	case RegionType::RWData:      prefix = ".data"; break;
	case RegionType::BSS:         prefix = ".bss"; break;
	case RegionType::LiteralPool: prefix = ".literal"; break;
	case RegionType::StringTable: prefix = ".strings"; break;
	case RegionType::VectorTable: prefix = ".vectors"; break;
	case RegionType::JumpTable:   prefix = ".jumptbl"; break;
	case RegionType::MMIO:        prefix = ".mmio"; break;
	case RegionType::Padding:     prefix = ".pad"; break;
	case RegionType::Compressed:  prefix = ".compressed"; break;
	default:                      prefix = ".unknown"; break;
	}
	
	if (index > 0)
		snprintf(buf, sizeof(buf), "%s.%d", prefix, index);
	else
		snprintf(buf, sizeof(buf), "%s", prefix);
	
	return buf;
}

std::vector<DetectedRegion> RegionDetector::Detect()
{
	return Detect(m_settings);
}

std::vector<DetectedRegion> RegionDetector::Detect(const RegionDetectionSettings& settings)
{
	m_settings = settings;
	std::vector<DetectedRegion> regions;
	
	uint64_t start = m_view->GetStart();
	uint64_t end = m_view->GetEnd();
	
	if (start >= end)
		return regions;
	
	m_logger->LogInfo("RegionDetector: Scanning 0x%llx - 0x%llx (window=%u, step=%u)",
		(unsigned long long)start, (unsigned long long)end,
		settings.windowSize, settings.windowStep);
	
	// Find potential boundaries
	std::vector<uint64_t> boundaries = FindBoundaries();
	
	m_logger->LogInfo("RegionDetector: Found %zu boundary candidates", boundaries.size());
	
	// Analyze regions between boundaries
	std::map<RegionType, int> typeCounts;
	
	for (size_t i = 0; i + 1 < boundaries.size(); i++)
	{
		uint64_t regionStart = boundaries[i];
		uint64_t regionEnd = boundaries[i + 1];
		uint64_t regionSize = regionEnd - regionStart;
		
		if (regionSize < settings.minRegionSize)
			continue;
		
		// Calculate metrics
		double entropy = CalculateEntropy(regionStart, regionSize);
		double codeDensity = CalculateCodeDensity(regionStart, std::min(regionSize, (uint64_t)4096));
		double stringDensity = CalculateStringDensity(regionStart, std::min(regionSize, (uint64_t)4096));
		
		// Classify
		RegionType type = ClassifyRegion(regionStart, regionSize, entropy, codeDensity, stringDensity);
		
		// Skip if too small for type
		if (type == RegionType::Code && regionSize < settings.minCodeRegion)
			continue;
		if ((type == RegionType::Data || type == RegionType::RWData) && regionSize < settings.minDataRegion)
			continue;

		// Function-aware filtering: skip small data regions that look like literal pools
		// or are embedded in code (common in ARM firmware)
		if (ShouldSkipAsLiteralPool(regionStart, regionSize, type))
		{
			m_logger->LogDebug("RegionDetector: Skipping 0x%llx (size=%llu) - likely embedded data/literal pool",
				(unsigned long long)regionStart, (unsigned long long)regionSize);
			continue;
		}

		// For firmware-safe mode, apply stricter size requirements
		if (settings.useFunctionAwareness)
		{
			if (type == RegionType::Code && regionSize < settings.minMajorCodeSection)
				continue;
			if ((type == RegionType::Data || type == RegionType::RWData || type == RegionType::LiteralPool) &&
				regionSize < settings.minMajorDataSection)
				continue;
		}

		// Determine confidence
		Confidence conf = Confidence::Medium;
		if (type == RegionType::Code && codeDensity > 0.9)
			conf = Confidence::High;
		else if (type == RegionType::Padding || type == RegionType::BSS)
			conf = Confidence::High;
		else if (type == RegionType::Unknown)
			conf = Confidence::Low;
		
		// Create region
		DetectedRegion region;
		region.start = regionStart;
		region.end = regionEnd;
		region.type = type;
		region.confidence = conf;
		region.entropy = entropy;
		region.codeDensity = codeDensity;
		region.stringDensity = stringDensity;
		
		// Determine alignment
		region.alignment = 1;
		for (uint32_t a = 4096; a >= 4; a /= 2)
		{
			if ((regionStart % a) == 0)
			{
				region.alignment = a;
				break;
			}
		}
		
		// Set permissions based on type
		region.readable = true;
		region.writable = (type == RegionType::RWData || type == RegionType::BSS || type == RegionType::MMIO);
		region.executable = (type == RegionType::Code);
		
		// Generate name
		region.name = GenerateRegionName(region, typeCounts[type]++);
		
		// Generate description
		char desc[256];
		snprintf(desc, sizeof(desc), "Entropy: %.2f, Code: %.1f%%, Strings: %.1f%%",
			entropy, codeDensity * 100, stringDensity * 100);
		region.description = desc;
		
		regions.push_back(region);
	}
	
	// Merge adjacent regions of the same type
	MergeRegions(regions);
	
	m_logger->LogInfo("RegionDetector: Detected %zu regions", regions.size());
	
	return regions;
}

void RegionDetector::ApplyRegions(const std::vector<DetectedRegion>& regions)
{
	for (const auto& region : regions)
	{
		// Build flags
		uint32_t flags = 0;
		if (region.readable)
			flags |= SegmentReadable;
		if (region.writable)
			flags |= SegmentWritable;
		if (region.executable)
			flags |= SegmentExecutable;
		
		// Check if segment already exists
		bool exists = false;
		for (const auto& seg : m_view->GetSegments())
		{
			if (seg->GetStart() == region.start && seg->GetEnd() == region.end)
			{
				exists = true;
				break;
			}
		}
		
		if (!exists)
		{
			// Determine data length (file-backed portion)
			uint64_t dataLength = region.size();
			if (region.type == RegionType::BSS || region.type == RegionType::MMIO)
				dataLength = 0;  // No file backing
			
			m_view->AddAutoSegment(region.start, region.size(), region.start, dataLength, flags);
			m_logger->LogInfo("RegionDetector: Created segment %s at 0x%llx (size=0x%llx, flags=%x)",
				region.name.c_str(), (unsigned long long)region.start,
				(unsigned long long)region.size(), flags);
		}
		
		// Create section
		m_view->AddAutoSection(region.name, region.start, region.size());
	}
}

}
