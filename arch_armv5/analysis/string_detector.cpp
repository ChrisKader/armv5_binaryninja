/*
 * String Detector Implementation
 */

#include "string_detector.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>
#include <regex>

using namespace BinaryNinja;

namespace Armv5Analysis
{

StringDetector::StringDetector(BinaryView* view)
	: m_view(view)
{
	m_stats = {};
}

const char* StringDetector::EncodingToString(StringEncoding enc)
{
	switch (enc)
	{
	case StringEncoding::ASCII: return "ASCII";
	case StringEncoding::UTF8: return "UTF-8";
	case StringEncoding::UTF16_LE: return "UTF-16 LE";
	case StringEncoding::UTF16_BE: return "UTF-16 BE";
	case StringEncoding::UTF32_LE: return "UTF-32 LE";
	case StringEncoding::Wide: return "Wide";
	default: return "Unknown";
	}
}

const char* StringDetector::CategoryToString(StringCategory cat)
{
	switch (cat)
	{
	case StringCategory::Generic: return "Generic";
	case StringCategory::ErrorMessage: return "Error";
	case StringCategory::DebugMessage: return "Debug";
	case StringCategory::FilePath: return "Path";
	case StringCategory::URL: return "URL";
	case StringCategory::Version: return "Version";
	case StringCategory::FormatString: return "Format";
	case StringCategory::Command: return "Command";
	case StringCategory::Identifier: return "Identifier";
	case StringCategory::Crypto: return "Crypto";
	case StringCategory::Hardware: return "Hardware";
	case StringCategory::RTOS: return "RTOS";
	default: return "Unknown";
	}
}

bool StringDetector::isPrintableAscii(uint8_t c) const
{
	return (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r';
}

bool StringDetector::isPrintableUtf8(const std::vector<uint8_t>& data) const
{
	size_t i = 0;
	while (i < data.size())
	{
		uint8_t c = data[i];
		
		if (c == 0)
			break;
		
		if (c < 0x80)
		{
			// ASCII
			if (!isPrintableAscii(c))
				return false;
			i++;
		}
		else if ((c & 0xE0) == 0xC0)
		{
			// 2-byte UTF-8
			if (i + 1 >= data.size() || (data[i + 1] & 0xC0) != 0x80)
				return false;
			i += 2;
		}
		else if ((c & 0xF0) == 0xE0)
		{
			// 3-byte UTF-8
			if (i + 2 >= data.size() || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80)
				return false;
			i += 3;
		}
		else if ((c & 0xF8) == 0xF0)
		{
			// 4-byte UTF-8
			if (i + 3 >= data.size() || (data[i + 1] & 0xC0) != 0x80 || 
				(data[i + 2] & 0xC0) != 0x80 || (data[i + 3] & 0xC0) != 0x80)
				return false;
			i += 4;
		}
		else
		{
			return false;
		}
	}
	return true;
}

// Calculate Shannon entropy in bits per character
double StringDetector::calculateEntropy(const std::string& str) const
{
	if (str.empty())
		return 0.0;
	
	std::map<char, size_t> freq;
	for (char c : str)
		freq[c]++;
	
	double entropy = 0.0;
	double len = static_cast<double>(str.length());
	for (const auto& [c, count] : freq)
	{
		double p = count / len;
		if (p > 0)
			entropy -= p * std::log2(p);
	}
	return entropy;
}

// Check if string has at least one word-like sequence (consecutive alpha chars)
bool StringDetector::hasWordLikeSequence(const std::string& str, size_t minWordLen) const
{
	size_t alphaRun = 0;
	for (char c : str)
	{
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
		{
			alphaRun++;
			if (alphaRun >= minWordLen)
				return true;
		}
		else
		{
			alphaRun = 0;
		}
	}
	return false;
}

// Determine if a string is likely gibberish/random data
bool StringDetector::isLikelyGibberish(const std::string& str, const StringDetectionSettings& settings) const
{
	// Must have at least one word-like sequence
	if (!hasWordLikeSequence(str, settings.minWordLength))
		return true;
	
	// High entropy suggests random/encrypted data
	double entropy = calculateEntropy(str);
	if (entropy > settings.maxEntropyBits)
		return true;
	
	// Check for excessive non-printable escape sequences in the decoded string
	size_t escapeCount = 0;
	for (size_t i = 0; i < str.length(); i++)
	{
		unsigned char c = static_cast<unsigned char>(str[i]);
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r')
			escapeCount++;
	}
	if (str.length() > 0 && static_cast<double>(escapeCount) / str.length() > 0.1)
		return true;  // More than 10% control characters
	
	return false;
}

std::string StringDetector::decodeString(const std::vector<uint8_t>& data, StringEncoding encoding) const
{
	std::string result;
	
	switch (encoding)
	{
	case StringEncoding::ASCII:
	case StringEncoding::UTF8:
		for (uint8_t c : data)
		{
			if (c == 0) break;
			result += static_cast<char>(c);
		}
		break;
		
	case StringEncoding::UTF16_LE:
		for (size_t i = 0; i + 1 < data.size(); i += 2)
		{
			uint16_t wc = data[i] | (data[i + 1] << 8);
			if (wc == 0) break;
			if (wc < 0x80)
				result += static_cast<char>(wc);
			else if (wc < 0x800)
			{
				result += static_cast<char>(0xC0 | (wc >> 6));
				result += static_cast<char>(0x80 | (wc & 0x3F));
			}
			else
			{
				result += static_cast<char>(0xE0 | (wc >> 12));
				result += static_cast<char>(0x80 | ((wc >> 6) & 0x3F));
				result += static_cast<char>(0x80 | (wc & 0x3F));
			}
		}
		break;
		
	case StringEncoding::UTF16_BE:
		for (size_t i = 0; i + 1 < data.size(); i += 2)
		{
			uint16_t wc = (data[i] << 8) | data[i + 1];
			if (wc == 0) break;
			if (wc < 0x80)
				result += static_cast<char>(wc);
			else
				result += '?';  // Simplified
		}
		break;
		
	default:
		for (uint8_t c : data)
		{
			if (c == 0) break;
			result += static_cast<char>(c);
		}
		break;
	}
	
	return result;
}

StringCategory StringDetector::categorizeString(const std::string& content, std::string& reason) const
{
	// Error messages
	static const std::regex errorRe(R"(\b(error|fail|invalid|illegal|cannot|unable|exception|fault|panic|assert|abort)\b)", std::regex::icase);
	if (std::regex_search(content, errorRe))
	{
		reason = "Contains error keywords";
		return StringCategory::ErrorMessage;
	}
	
	// Debug messages
	static const std::regex debugRe(R"(\b(debug|trace|log|info|warn|verbose|enter|exit|called)\b)", std::regex::icase);
	if (std::regex_search(content, debugRe))
	{
		reason = "Contains debug keywords";
		return StringCategory::DebugMessage;
	}
	
	// File paths
	static const std::regex pathRe(R"(^[/\\]|\.(?:c|h|cpp|txt|bin|dat|cfg|ini|log|xml|json)$|[/\\][\w.-]+[/\\])", std::regex::icase);
	if (std::regex_search(content, pathRe))
	{
		reason = "Looks like file path";
		return StringCategory::FilePath;
	}
	
	// URLs
	static const std::regex urlRe(R"(https?://|ftp://|www\.|\.com|\.org|\.net)", std::regex::icase);
	if (std::regex_search(content, urlRe))
	{
		reason = "Contains URL pattern";
		return StringCategory::URL;
	}
	
	// Version strings
	static const std::regex versionRe(R"(\b[vV]?\d+\.\d+(?:\.\d+)?(?:[-._]?\w+)?\b|build\s*\d+|version|release)", std::regex::icase);
	if (std::regex_search(content, versionRe))
	{
		reason = "Contains version pattern";
		return StringCategory::Version;
	}
	
	// Format strings
	static const std::regex formatRe(R"(%[-+0 #]*\d*(?:\.\d+)?[hlL]?[diouxXeEfFgGaAcspn%])");
	if (std::regex_search(content, formatRe))
	{
		reason = "Printf format specifiers";
		return StringCategory::FormatString;
	}
	
	// Crypto-related
	static const std::regex cryptoRe(R"(\b(aes|des|rsa|sha|md5|encrypt|decrypt|key|cipher|hash|hmac|sign|verify|cert|ssl|tls)\b)", std::regex::icase);
	if (std::regex_search(content, cryptoRe))
	{
		reason = "Crypto-related keywords";
		return StringCategory::Crypto;
	}
	
	// Hardware/register references
	static const std::regex hwRe(R"(\b(gpio|uart|spi|i2c|dma|irq|timer|clock|pll|reg|ctrl|status|addr|base)\b)", std::regex::icase);
	if (std::regex_search(content, hwRe))
	{
		reason = "Hardware/peripheral keywords";
		return StringCategory::Hardware;
	}
	
	// RTOS related
	static const std::regex rtosRe(R"(\b(task|thread|mutex|semaphore|queue|event|timer|idle|stack|priority|tcb|schedule)\b)", std::regex::icase);
	if (std::regex_search(content, rtosRe))
	{
		reason = "RTOS-related keywords";
		return StringCategory::RTOS;
	}
	
	// Command-like (all caps with underscores, or command patterns)
	static const std::regex cmdRe(R"(^[A-Z][A-Z0-9_]{2,}$|^\w+\s*[:=]\s*\w+)");
	if (std::regex_search(content, cmdRe))
	{
		reason = "Command or constant pattern";
		return StringCategory::Command;
	}
	
	reason = "";
	return StringCategory::Generic;
}

bool StringDetector::isValidString(const std::vector<uint8_t>& data, StringEncoding encoding,
	const StringDetectionSettings& settings) const
{
	if (data.empty())
		return false;
	
	size_t charCount = 0;
	size_t printableCount = 0;
	bool foundNull = false;
	
	switch (encoding)
	{
	case StringEncoding::ASCII:
	case StringEncoding::UTF8:
		for (size_t i = 0; i < data.size(); i++)
		{
			if (data[i] == 0)
			{
				foundNull = true;
				break;
			}
			charCount++;
			if (isPrintableAscii(data[i]))
				printableCount++;
		}
		break;
		
	case StringEncoding::UTF16_LE:
		for (size_t i = 0; i + 1 < data.size(); i += 2)
		{
			uint16_t wc = data[i] | (data[i + 1] << 8);
			if (wc == 0)
			{
				foundNull = true;
				break;
			}
		charCount++;
		if (wc >= 0x20 && wc < 0x7F)
			printableCount++;
		else if (wc >= 0x80)
			printableCount++;  // Extended chars are often ok
		}
		break;
		
	default:
		return false;
	}
	
	if (charCount < settings.minLength)
		return false;
	
	if (charCount > settings.maxLength)
		return false;
	
	if (settings.requireNullTerminator && !foundNull)
		return false;
	
	double printableRatio = charCount > 0 ? static_cast<double>(printableCount) / charCount : 0;
	if (printableRatio < settings.minPrintableRatio)
		return false;
	
	return true;
}

double StringDetector::calculateConfidence(const DetectedString& str, const StringDetectionSettings& settings) const
{
	double confidence = 0.5;
	
	// Length bonus (longer strings are more likely real)
	if (str.length >= 8) confidence += 0.1;
	if (str.length >= 16) confidence += 0.1;
	if (str.length >= 32) confidence += 0.05;
	
	// Has references - very strong signal
	if (str.hasXrefs) confidence += 0.25;
	
	// Null terminated
	if (str.isNullTerminated) confidence += 0.05;
	
	// Category bonus - categorized strings are more interesting
	if (str.category != StringCategory::Generic) confidence += 0.1;
	
	// Special categories get extra confidence
	if (str.category == StringCategory::ErrorMessage ||
		str.category == StringCategory::FormatString ||
		str.category == StringCategory::URL ||
		str.category == StringCategory::FilePath)
		confidence += 0.1;
	
	// In literal pool (code section) - interesting but lower confidence
	if (str.isInCode) confidence -= 0.1;
	
	return std::min(1.0, std::max(0.0, confidence));
}

bool StringDetector::isInsideExistingString(uint64_t addr) const
{
	// Binary search to find if addr falls within any existing string range
	// Ranges are sorted by start address
	if (m_existingStringRanges.empty())
		return false;

	// Find the first range where start > addr, then check the previous one
	auto it = std::upper_bound(m_existingStringRanges.begin(), m_existingStringRanges.end(),
		std::make_pair(addr, UINT64_MAX),
		[](const std::pair<uint64_t, uint64_t>& a, const std::pair<uint64_t, uint64_t>& b) {
			return a.first < b.first;
		});

	// Check if any range before or at this position contains addr
	if (it != m_existingStringRanges.begin())
	{
		--it;
		// Check if addr is within this range [start, end)
		if (addr >= it->first && addr < it->second)
			return true;
	}

	return false;
}

void StringDetector::scanRegion(uint64_t start, uint64_t end, bool isCode,
	const StringDetectionSettings& settings, std::vector<DetectedString>& results)
{
	if (start >= end)
		return;
	
	size_t regionSize = end - start;
	if (regionSize > 64 * 1024 * 1024)  // Limit to 64MB per region
		regionSize = 64 * 1024 * 1024;
	
	DataBuffer buffer = m_view->ReadBuffer(start, regionSize);
	if (buffer.GetLength() == 0)
		return;
	
	const uint8_t* data = static_cast<const uint8_t*>(buffer.GetData());
	size_t dataLen = buffer.GetLength();
	
	// Build set of function ranges to skip - ALWAYS skip inside function bodies
	// This prevents detecting "strings" that are actually decoded instructions
	std::vector<std::pair<uint64_t, uint64_t>> funcRanges;
	if (settings.skipInsideFunctions)
	{
		for (const auto& func : m_view->GetAnalysisFunctionList())
		{
			for (const auto& range : func->GetAddressRanges())
			{
				if (range.start < end && range.end > start)
					funcRanges.push_back({range.start, range.end});
			}
		}
	}
	
	auto isInsideFunction = [&](uint64_t addr) -> bool {
		// Use binary search if we have many function ranges
		for (const auto& r : funcRanges)
			if (addr >= r.first && addr < r.second)
				return true;
		return false;
	};
	
	// Sort function ranges for efficient lookup
	std::sort(funcRanges.begin(), funcRanges.end());
	
	// Scan for ASCII/UTF-8 strings
	if (settings.detectAscii || settings.detectUtf8)
	{
		size_t i = 0;
		while (i < dataLen)
		{
			uint64_t addr = start + i;
			
			// Skip if inside a defined function body - these are instructions, not strings
			if (isInsideFunction(addr))
			{
				i++;
				continue;
			}
			
			// Skip if inside an existing defined string (not just exact start address)
			if (settings.skipExisting && isInsideExistingString(addr))
			{
				i++;
				continue;
			}
			
			// Look for string start - must be a letter or common start char
			uint8_t c = data[i];
			if (!isPrintableAscii(c) || (c < 'A' && c != ' ' && c != '"' && c != '/' && c != '.' && c != '\\' && c != '[' && c != '(' && c != '%'))
			{
				i++;
				continue;
			}
			
			// Find string end
			size_t strStart = i;
			size_t printable = 0;
			size_t alphaNum = 0;
			while (i < dataLen && data[i] != 0)
			{
				if (isPrintableAscii(data[i]))
					printable++;
				if ((data[i] >= 'A' && data[i] <= 'Z') || (data[i] >= 'a' && data[i] <= 'z') || (data[i] >= '0' && data[i] <= '9'))
					alphaNum++;
				i++;
				
				if (i - strStart > settings.maxLength)
					break;
			}
			
			size_t strLen = i - strStart;
			bool nullTerm = (i < dataLen && data[i] == 0);
			
			// Require decent alphanumeric ratio to filter out garbage
			double alphaRatio = strLen > 0 ? static_cast<double>(alphaNum) / strLen : 0;
			
			if (strLen >= settings.minLength && 
				static_cast<double>(printable) / strLen >= settings.minPrintableRatio &&
				alphaRatio >= settings.minAlphanumericRatio)
			{
				if (!settings.requireNullTerminator || nullTerm)
				{
					std::vector<uint8_t> strData(data + strStart, data + strStart + strLen);
					std::string strContent = decodeString(strData, StringEncoding::ASCII);
					
					// Additional gibberish filtering
					if (isLikelyGibberish(strContent, settings))
					{
						// Skip gibberish strings
						if (nullTerm) i++;
						continue;
					}
					
					DetectedString ds;
					ds.address = start + strStart;
					ds.length = strLen;
					ds.content = strContent;
					ds.encoding = StringEncoding::ASCII;
					ds.isNullTerminated = nullTerm;
					ds.isInCode = isCode;
					ds.hasXrefs = m_referencedAddresses.count(ds.address) > 0;
					
					// Get xrefs
					auto refs = m_view->GetCodeReferences(ds.address);
					for (const auto& ref : refs)
						ds.xrefAddresses.push_back(ref.addr);
					
					// Categorize
					ds.category = categorizeString(ds.content, ds.categoryReason);
					ds.confidence = calculateConfidence(ds, settings);
					
					if (ds.confidence >= settings.minConfidence)
					{
						if (!settings.findUnreferenced || !ds.hasXrefs || settings.findUnreferenced)
						{
							results.push_back(ds);
						}
					}
				}
			}
			
			if (nullTerm) i++;  // Skip null terminator
		}
	}
	
	// Scan for UTF-16 LE strings
	if (settings.detectUtf16)
	{
		size_t i = 0;
		while (i + 1 < dataLen)
		{
			uint64_t addr = start + i;
			// Skip if inside an existing defined string
			if (settings.skipExisting && isInsideExistingString(addr))
			{
				i += 2;
				continue;
			}
			
			uint16_t wc = data[i] | (data[i + 1] << 8);
			
			// Look for ASCII range in UTF-16
			if (wc < 0x20 || wc > 0x7E)
			{
				i += 2;
				continue;
			}
			
			// Find string
			size_t strStart = i;
			size_t charCount = 0;
			while (i + 1 < dataLen)
			{
			wc = data[i] | (data[i + 1] << 8);
			if (wc == 0) break;
			if (wc >= 0x20 && wc <= 0x7E)
				charCount++;
			else if (wc >= 0x80)
				charCount++;  // Extended char
			else
				break;  // Invalid
				i += 2;
				
				if (charCount > settings.maxLength)
					break;
			}
			
			bool nullTerm = (i + 1 < dataLen && data[i] == 0 && data[i + 1] == 0);
			
			if (charCount >= settings.minLength)
			{
				if (!settings.requireNullTerminator || nullTerm)
				{
					std::vector<uint8_t> strData(data + strStart, data + i);
					
					DetectedString ds;
					ds.address = start + strStart;
					ds.length = charCount;
					ds.content = decodeString(strData, StringEncoding::UTF16_LE);
					ds.encoding = StringEncoding::UTF16_LE;
					ds.isNullTerminated = nullTerm;
					ds.isInCode = isCode;
					ds.hasXrefs = m_referencedAddresses.count(ds.address) > 0;
					
					auto refs = m_view->GetCodeReferences(ds.address);
					for (const auto& ref : refs)
						ds.xrefAddresses.push_back(ref.addr);
					
					ds.category = categorizeString(ds.content, ds.categoryReason);
					ds.confidence = calculateConfidence(ds, settings);
					
					if (ds.confidence >= settings.minConfidence)
						results.push_back(ds);
				}
			}
			
			if (nullTerm) i += 2;
		}
	}
}

std::vector<DetectedString> StringDetector::Detect(const StringDetectionSettings& settings)
{
	std::vector<DetectedString> results;
	
	// Reset stats
	m_stats = {};
	m_existingStrings.clear();
	m_existingStringRanges.clear();
	m_referencedAddresses.clear();

	// Collect existing strings with their full ranges
	if (settings.skipExisting)
	{
		for (const auto& str : m_view->GetStrings())
		{
			m_existingStrings.insert(str.start);
			// Store the range (start, end) to check for overlaps
			m_existingStringRanges.push_back({str.start, str.start + str.length});
		}
		// Sort ranges for efficient lookup
		std::sort(m_existingStringRanges.begin(), m_existingStringRanges.end());
	}
	
	// Collect referenced addresses (for unreferenced detection)
	for (const auto& func : m_view->GetAnalysisFunctionList())
	{
		// Get data refs from this function
		auto refs = func->GetCallSites();
		// Also get constant refs
	}
	
	// Build set of referenced data addresses from data variables
	for (const auto& dv : m_view->GetDataVariables())
	{
		m_referencedAddresses.insert(dv.first);
	}
	
	// Scan data sections
	if (settings.searchDataSections)
	{
		for (const auto& seg : m_view->GetSegments())
		{
			if (!(seg->GetFlags() & SegmentExecutable) && (seg->GetFlags() & SegmentReadable))
			{
				scanRegion(seg->GetStart(), seg->GetEnd(), false, settings, results);
			}
		}
	}
	
	// Scan code sections (literal pools)
	if (settings.searchCodeSections)
	{
		for (const auto& seg : m_view->GetSegments())
		{
			if (seg->GetFlags() & SegmentExecutable)
			{
				scanRegion(seg->GetStart(), seg->GetEnd(), true, settings, results);
			}
		}
	}
	
	// Sort by address
	std::sort(results.begin(), results.end(), [](const DetectedString& a, const DetectedString& b) {
		return a.address < b.address;
	});
	
	// Remove duplicates (overlapping strings)
	std::vector<DetectedString> deduped;
	uint64_t lastEnd = 0;
	for (const auto& str : results)
	{
		if (str.address >= lastEnd)
		{
			deduped.push_back(str);
			lastEnd = str.address + str.length + 1;
		}
		else if (str.confidence > deduped.back().confidence)
		{
			// Replace with higher confidence
			deduped.back() = str;
			lastEnd = str.address + str.length + 1;
		}
	}
	results = std::move(deduped);
	
	// Compute stats
	m_stats.totalFound = results.size();
	for (const auto& str : results)
	{
		if (m_existingStrings.count(str.address) == 0)
			m_stats.newStrings++;
		if (!str.hasXrefs)
			m_stats.unreferenced++;
		if (str.isInCode)
			m_stats.inLiteralPools++;
		if (str.category == StringCategory::FormatString)
			m_stats.formatStrings++;
		if (str.category != StringCategory::Generic)
			m_stats.interestingStrings++;
		
		m_stats.byEncoding[str.encoding]++;
		m_stats.byCategory[str.category]++;
	}
	
	return results;
}

}
