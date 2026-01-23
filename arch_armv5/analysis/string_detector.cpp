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

bool StringDetector::LooksLikeNullTerminatedString(const uint8_t* data, size_t len,
	size_t minLen, double minRatio)
{
	if (!data || len < 2)
		return false;

	// Helper to check if a byte is printable (including common control chars)
	auto isPrintable = [](uint8_t c) -> bool {
		return (c >= 0x20 && c <= 0x7E) || c == 0x09 || c == 0x0A || c == 0x0D;
	};

	// Check 1: Standard null-terminated string starting at this address
	// Any sequence of printable characters followed by null is likely string data
	{
		size_t nullPos = 0;
		bool foundNull = false;
		for (size_t i = 0; i < len; i++)
		{
			if (data[i] == 0x00)
			{
				nullPos = i;
				foundNull = true;
				break;
			}
		}

		if (foundNull && nullPos >= minLen)
		{
			size_t printableCount = 0;
			for (size_t i = 0; i < nullPos; i++)
			{
				if (isPrintable(data[i]))
					printableCount++;
			}

			double ratio = static_cast<double>(printableCount) / static_cast<double>(nullPos);
			// Just require high printable ratio - separator strings like "------" are valid
			if (ratio >= minRatio)
				return true;
		}
	}

	// Check 2: We're at a string table boundary (null + printable string follows)
	// This catches addresses that land at the null terminator of a previous string
	if (data[0] == 0x00 && len > 1 && isPrintable(data[1]))
	{
		// Find the null terminator of the NEXT string
		size_t nullPos = 0;
		bool foundNull = false;
		for (size_t i = 1; i < len; i++)
		{
			if (data[i] == 0x00)
			{
				nullPos = i;
				foundNull = true;
				break;
			}
		}

		// Check if the string after the leading null is valid
		if (foundNull && (nullPos - 1) >= minLen)
		{
			size_t printableCount = 0;
			for (size_t i = 1; i < nullPos; i++)
			{
				if (isPrintable(data[i]))
					printableCount++;
			}

			size_t strLen = nullPos - 1;
			double ratio = static_cast<double>(printableCount) / static_cast<double>(strLen);
			if (ratio >= minRatio)
				return true;
		}
	}

	// Check 3: Short strings (2-3 chars) that are clearly text
	// For very short strings, require 100% printable
	{
		size_t nullPos = 0;
		bool foundNull = false;
		for (size_t i = 0; i < len && i < 8; i++)
		{
			if (data[i] == 0x00)
			{
				nullPos = i;
				foundNull = true;
				break;
			}
		}

		// Short string: 2-3 printable chars followed by null
		if (foundNull && nullPos >= 2 && nullPos < minLen)
		{
			bool allPrintable = true;
			for (size_t i = 0; i < nullPos; i++)
			{
				if (!isPrintable(data[i]))
				{
					allPrintable = false;
					break;
				}
			}
			if (allPrintable)
				return true;
		}
	}

	// Check 4: Embedded in a string region - high printable ratio in first 16 bytes
	// Even without finding a null, if the data is mostly printable, it's likely string data
	{
		constexpr size_t kQuickCheck = 16;
		size_t checkLen = (len < kQuickCheck) ? len : kQuickCheck;
		size_t printableCount = 0;
		size_t nullCount = 0;

		for (size_t i = 0; i < checkLen; i++)
		{
			if (isPrintable(data[i]))
				printableCount++;
			else if (data[i] == 0x00)
				nullCount++;
		}

		// If >= 80% printable (excluding nulls) and we have at least one null, likely string data
		size_t nonNullLen = checkLen - nullCount;
		if (nonNullLen >= 4 && nullCount >= 1 && nullCount <= 4)
		{
			double ratio = static_cast<double>(printableCount) / static_cast<double>(nonNullLen);
			if (ratio >= 0.80)
				return true;
		}
	}

	return false;
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
			// For firmware, be strict: only count ASCII-range characters
			// High byte should be 0x00 for valid ASCII-as-UTF16
			if (wc >= 0x20 && wc <= 0x7E)
				printableCount++;
			// Also allow common Latin-1 supplement (accented chars) 0x00A0-0x00FF
			else if (wc >= 0x00A0 && wc <= 0x00FF)
				printableCount++;
			// Reject Private Use Area, Specials, and other suspicious ranges
			// Characters in 0xE000-0xF8FF or 0xFFF0-0xFFFF are likely garbage
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

// Check for consecutive non-printable characters (reject strings with too many in a row)
bool StringDetector::hasConsecutiveNonPrintable(const uint8_t* data, size_t len, size_t maxConsec) const
{
	size_t consecutive = 0;
	for (size_t i = 0; i < len; i++)
	{
		uint8_t c = data[i];
		if (c == 0)
			break;  // Stop at null terminator
		
		bool isPrintable = (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r';
		if (!isPrintable)
		{
			consecutive++;
			if (consecutive > maxConsec)
				return true;  // Found too many consecutive non-printable
		}
		else
		{
			consecutive = 0;
		}
	}
	return false;
}

// Check if this is an ANSI escape sequence (ESC [ ...)
bool StringDetector::isAnsiEscapeSequence(const uint8_t* data, size_t len) const
{
	// ANSI escape sequences start with ESC (0x1B) followed by '[' (0x5B)
	if (len >= 3 && data[0] == 0x1B && data[1] == 0x5B)
		return true;
	return false;
}

// Check if data looks like UTF-16 via alternating printable/null patterns
// This is a strict check to avoid false positives on binary data
bool StringDetector::looksLikeUtf16Pattern(const uint8_t* data, size_t len, bool& isLittleEndian) const
{
	// Require at least 8 bytes (4 UTF-16 characters) for reliable detection
	if (len < 8 || (len % 2) != 0)
		return false;
	
	size_t charCount = len / 2;
	
	// Check for two patterns:
	// Pattern 1 (LE): ASCII char + null byte (e.g., 'H' 0x00 'e' 0x00 'l' 0x00 'l' 0x00)
	// Pattern 2 (BE): null byte + ASCII char (e.g., 0x00 'H' 0x00 'e' 0x00 'l' 0x00 'l')
	
	size_t leAsciiCount = 0;
	size_t beAsciiCount = 0;
	size_t leAlphaNumCount = 0;
	size_t beAlphaNumCount = 0;
	size_t consecutiveLeAlphaNum = 0;
	size_t consecutiveBeAlphaNum = 0;
	size_t maxLeConsecutive = 0;
	size_t maxBeConsecutive = 0;
	
	for (size_t i = 0; i + 1 < len; i += 2)
	{
		uint8_t c1 = data[i];
		uint8_t c2 = data[i + 1];
		
		// Little-endian: c1 is the character, c2 should be null for ASCII range
		if (c2 == 0x00 && c1 >= 0x20 && c1 <= 0x7E)
		{
			leAsciiCount++;
			if ((c1 >= 'A' && c1 <= 'Z') || (c1 >= 'a' && c1 <= 'z') || (c1 >= '0' && c1 <= '9'))
			{
				leAlphaNumCount++;
				consecutiveLeAlphaNum++;
				if (consecutiveLeAlphaNum > maxLeConsecutive)
					maxLeConsecutive = consecutiveLeAlphaNum;
			}
			else
			{
				consecutiveLeAlphaNum = 0;
			}
		}
		else
		{
			consecutiveLeAlphaNum = 0;
		}
		
		// Big-endian: c1 should be null for ASCII range, c2 is the character
		if (c1 == 0x00 && c2 >= 0x20 && c2 <= 0x7E)
		{
			beAsciiCount++;
			if ((c2 >= 'A' && c2 <= 'Z') || (c2 >= 'a' && c2 <= 'z') || (c2 >= '0' && c2 <= '9'))
			{
				beAlphaNumCount++;
				consecutiveBeAlphaNum++;
				if (consecutiveBeAlphaNum > maxBeConsecutive)
					maxBeConsecutive = consecutiveBeAlphaNum;
			}
			else
			{
				consecutiveBeAlphaNum = 0;
			}
		}
		else
		{
			consecutiveBeAlphaNum = 0;
		}
	}
	
	// Strict requirements:
	// 1. At least 80% of characters must be ASCII (null + printable)
	// 2. At least 50% must be alphanumeric
	// 3. Must have at least 3 consecutive alphanumeric (a word-like sequence)
	
	double leAsciiRatio = static_cast<double>(leAsciiCount) / static_cast<double>(charCount);
	double beAsciiRatio = static_cast<double>(beAsciiCount) / static_cast<double>(charCount);
	double leAlphaRatio = static_cast<double>(leAlphaNumCount) / static_cast<double>(charCount);
	double beAlphaRatio = static_cast<double>(beAlphaNumCount) / static_cast<double>(charCount);
	
	bool leValid = (leAsciiRatio >= 0.80 && leAlphaRatio >= 0.50 && maxLeConsecutive >= 3);
	bool beValid = (beAsciiRatio >= 0.80 && beAlphaRatio >= 0.50 && maxBeConsecutive >= 3);
	
	if (leValid && leAsciiRatio >= beAsciiRatio)
	{
		isLittleEndian = true;
		return true;
	}
	if (beValid)
	{
		isLittleEndian = false;
		return true;
	}
	
	return false;
}

// Validate proper null termination based on encoding
bool StringDetector::validateNullTermination(const uint8_t* data, size_t len, StringEncoding encoding) const
{
	switch (encoding)
	{
	case StringEncoding::ASCII:
	case StringEncoding::UTF8:
		// Single null byte
		return len > 0 && data[len] == 0x00;
		
	case StringEncoding::UTF16_LE:
	case StringEncoding::UTF16_BE:
		// Two null bytes
		return len >= 2 && data[len] == 0x00 && data[len + 1] == 0x00;
		
	case StringEncoding::UTF32_LE:
		// Four null bytes
		return len >= 4 && data[len] == 0x00 && data[len + 1] == 0x00 &&
			   data[len + 2] == 0x00 && data[len + 3] == 0x00;
		
	default:
		return data[len] == 0x00;
	}
}

// Check for word-like alphanumeric sequences in raw data
bool StringDetector::hasWordLikeSequenceRaw(const uint8_t* data, size_t len, StringEncoding encoding, size_t minWordLen) const
{
	size_t consecutiveAlphaNum = 0;
	
	switch (encoding)
	{
	case StringEncoding::UTF16_LE:
		for (size_t i = 0; i + 1 < len; i += 2)
		{
			uint16_t wc = data[i] | (data[i + 1] << 8);
			if (wc == 0)
				break;
			
			if ((wc >= 'A' && wc <= 'Z') || (wc >= 'a' && wc <= 'z') || (wc >= '0' && wc <= '9'))
			{
				consecutiveAlphaNum++;
				if (consecutiveAlphaNum >= minWordLen)
					return true;
			}
			else
			{
				consecutiveAlphaNum = 0;
			}
		}
		break;
		
	case StringEncoding::UTF16_BE:
		for (size_t i = 0; i + 1 < len; i += 2)
		{
			uint16_t wc = (data[i] << 8) | data[i + 1];
			if (wc == 0)
				break;
			
			if ((wc >= 'A' && wc <= 'Z') || (wc >= 'a' && wc <= 'z') || (wc >= '0' && wc <= '9'))
			{
				consecutiveAlphaNum++;
				if (consecutiveAlphaNum >= minWordLen)
					return true;
			}
			else
			{
				consecutiveAlphaNum = 0;
			}
		}
		break;
		
	case StringEncoding::UTF32_LE:
		for (size_t i = 0; i + 3 < len; i += 4)
		{
			uint32_t wc = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);
			if (wc == 0)
				break;
			
			if ((wc >= 'A' && wc <= 'Z') || (wc >= 'a' && wc <= 'z') || (wc >= '0' && wc <= '9'))
			{
				consecutiveAlphaNum++;
				if (consecutiveAlphaNum >= minWordLen)
					return true;
			}
			else
			{
				consecutiveAlphaNum = 0;
			}
		}
		break;
		
	default:  // ASCII, UTF8
		for (size_t i = 0; i < len; i++)
		{
			uint8_t c = data[i];
			if (c == 0)
				break;
			
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
			{
				consecutiveAlphaNum++;
				if (consecutiveAlphaNum >= minWordLen)
					return true;
			}
			else
			{
				consecutiveAlphaNum = 0;
			}
		}
		break;
	}
	
	return false;
}

// Scan for pointers to detected strings and create char* data variables
void StringDetector::scanForStringPointers(const std::vector<DetectedString>& strings,
	const StringDetectionSettings& settings)
{
	if (!settings.scanStringPointers || strings.empty())
		return;
	
	// Build set of string addresses for fast lookup
	std::set<uint64_t> stringAddresses;
	for (const auto& str : strings)
		stringAddresses.insert(str.address);
	
	// Merge with existing BN strings
	for (const auto& existing : m_view->GetStrings())
		stringAddresses.insert(existing.start);
	
	uint64_t startAddr = m_view->GetStart();
	uint64_t endAddr = m_view->GetEnd();
	
	// Scan for 4-byte aligned pointers that reference strings
	for (uint64_t addr = startAddr; addr + 4 <= endAddr; addr += 4)
	{
		DataBuffer entryBuffer = m_view->ReadBuffer(addr, 4);
		if (entryBuffer.GetLength() < 4)
			continue;
		
		const uint8_t* entryData = static_cast<const uint8_t*>(entryBuffer.GetData());
		uint64_t pointedAddr = entryData[0] | (entryData[1] << 8) | (entryData[2] << 16) | (entryData[3] << 24);
		
		// Check if this points to a known string
		if (stringAddresses.count(pointedAddr) == 0)
			continue;
		
		// Check if already has a data variable
		DataVariable existingVar;
		if (m_view->GetDataVariableAtAddress(addr, existingVar))
			continue;
		
		// Create char* pointer type
		if (settings.typeStringPointers)
		{
			Ref<Type> stringPtrType = Type::PointerType(4, Type::IntegerType(1, true));  // char*
			m_view->DefineUserDataVariable(addr, stringPtrType);
			m_stats.stringPointers++;
		}
	}
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
	
	// Scan for ASCII/UTF-8 strings with enhanced validation
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
			
			// Skip null bytes
			if (data[i] == 0x00)
			{
				i++;
				continue;
			}
			
			// Look for valid string start character
			uint8_t firstByte = data[i];
			bool validStart = (firstByte >= 0x20 && firstByte <= 0x7E) ||  // Printable ASCII
				(settings.detectAnsiEscapes && firstByte == 0x1B) ||       // ESC for ANSI sequences
				(firstByte == 0x0A) || (firstByte == 0x0D);                // LF, CR
			
			if (!validStart)
			{
				i++;
				continue;
			}
			
			// Find string end (null terminator)
			size_t strStart = i;
			while (i < dataLen && data[i] != 0x00)
				i++;
			
			if (i >= dataLen)
				break;  // No null terminator found
			
			size_t strLen = i - strStart;
			i++;  // Skip the null terminator
			
			// Validate string length
			if (strLen < settings.minLength || strLen > settings.maxLength)
				continue;
			
			// Count printable and alphanumeric characters
			size_t printableCount = 0;
			size_t alphaNumCount = 0;
			bool hasConsecutiveNonPrint = false;
			size_t consecutiveNonPrint = 0;
			
			for (size_t j = 0; j < strLen; ++j)
			{
				uint8_t c = data[strStart + j];
				bool isPrint = (c >= 0x20 && c <= 0x7E);
				
				if (isPrint)
				{
					printableCount++;
					consecutiveNonPrint = 0;
				}
				else
				{
					consecutiveNonPrint++;
					if (settings.rejectConsecutiveNonPrintable && 
						consecutiveNonPrint > settings.maxConsecutiveNonPrintable)
						hasConsecutiveNonPrint = true;
				}
				
				if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
					alphaNumCount++;
			}
			
			double printableRatio = static_cast<double>(printableCount) / strLen;
			double alphaNumRatio = static_cast<double>(alphaNumCount) / strLen;
			
			// Check for ANSI escape sequence (special case with relaxed requirements)
			bool isAnsiSeq = settings.detectAnsiEscapes && isAnsiEscapeSequence(data + strStart, strLen);
			
			// Apply validation criteria
			bool passesValidation = false;
			if (isAnsiSeq && printableRatio >= 0.6)
			{
				passesValidation = true;
				m_stats.ansiSequences++;
			}
			else if (printableRatio >= settings.minPrintableRatio && 
					 alphaNumRatio >= settings.minAlphanumericRatio && 
					 !hasConsecutiveNonPrint)
			{
				passesValidation = true;
			}
			
			if (!passesValidation)
			{
				if (hasConsecutiveNonPrint)
					m_stats.rejectedConsecutive++;
				continue;
			}
			
			// Require word-like sequence (2+ consecutive alphanumeric)
			if (!hasWordLikeSequenceRaw(data + strStart, strLen, StringEncoding::ASCII, 2))
			{
				m_stats.rejectedNoWord++;
				continue;
			}
			
			// Check for UTF-16 pattern (alternating printable/null)
			bool isUtf16 = false;
			bool isLE = true;
			if (settings.detectUtf16Patterns && strLen >= 4 && (strLen % 2) == 0)
			{
				if (looksLikeUtf16Pattern(data + strStart, strLen, isLE))
				{
					isUtf16 = true;
					m_stats.utf16Patterns++;
				}
			}
			
			std::vector<uint8_t> strData(data + strStart, data + strStart + strLen);
			std::string strContent = decodeString(strData, isUtf16 ? 
				(isLE ? StringEncoding::UTF16_LE : StringEncoding::UTF16_BE) : StringEncoding::ASCII);
			
			// Additional gibberish filtering
			if (!isAnsiSeq && isLikelyGibberish(strContent, settings))
				continue;
			
			DetectedString ds;
			ds.address = start + strStart;
			ds.length = strLen;
			ds.content = strContent;
			ds.encoding = isUtf16 ? (isLE ? StringEncoding::UTF16_LE : StringEncoding::UTF16_BE) : StringEncoding::ASCII;
			ds.isNullTerminated = true;  // We found the null terminator
			ds.isInCode = isCode;
			ds.hasXrefs = m_referencedAddresses.count(ds.address) > 0;
			
			// Get xrefs
			auto refs = m_view->GetCodeReferences(ds.address);
			for (const auto& ref : refs)
				ds.xrefAddresses.push_back(ref.addr);
			
			// Categorize
			ds.category = categorizeString(ds.content, ds.categoryReason);
			ds.confidence = calculateConfidence(ds, settings);
			
			// ANSI sequences get a confidence boost
			if (isAnsiSeq)
				ds.confidence = std::min(1.0, ds.confidence + 0.1);
			
			if (ds.confidence >= settings.minConfidence)
				results.push_back(ds);
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
				// Accept ASCII printable range
				if (wc >= 0x20 && wc <= 0x7E)
					charCount++;
				// Accept Latin-1 Supplement (accented characters)
				else if (wc >= 0x00A0 && wc <= 0x00FF)
					charCount++;
				// Reject everything else (including Private Use Area, high Unicode, etc.)
				else
					break;
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
	
	// Scan for string pointers and create char* data variables
	if (settings.scanStringPointers)
	{
		scanForStringPointers(results, settings);
	}
	
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
