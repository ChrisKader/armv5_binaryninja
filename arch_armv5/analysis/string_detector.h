/*
 * String Detector
 *
 * Advanced string detection for firmware analysis.
 * Finds strings missed by standard analysis including:
 * - Unreferenced strings in data sections
 * - Embedded strings in literal pools
 * - Format strings and interesting patterns
 * - Multi-encoding support (ASCII, UTF-8, UTF-16)
 */

#pragma once

#include "binaryninjaapi.h"
#include <vector>
#include <string>
#include <set>
#include <regex>

namespace Armv5Analysis
{

enum class StringEncoding
{
	ASCII,
	UTF8,
	UTF16_LE,
	UTF16_BE,
	UTF32_LE,
	Wide
};

enum class StringCategory
{
	Generic,
	ErrorMessage,
	DebugMessage,
	FilePath,
	URL,
	Version,
	FormatString,
	Command,
	Identifier,
	Crypto,        // Crypto-related strings
	Hardware,      // Register names, peripheral references
	RTOS           // Task names, semaphore names
};

struct DetectedString
{
	uint64_t address;
	size_t length;
	std::string content;
	StringEncoding encoding;
	StringCategory category;
	double confidence;
	bool hasXrefs;
	bool isInCode;        // Found in code section (literal pool)
	bool isNullTerminated;
	std::vector<uint64_t> xrefAddresses;
	std::string categoryReason;  // Why this category was assigned
};

struct StringDetectionSettings
{
	// Length constraints
	size_t minLength = 4;
	size_t maxLength = 2000;
	
	// Content requirements
	double minPrintableRatio = 0.75;
	double minAlphanumericRatio = 0.50;  // At least 50% alphanumeric to filter gibberish
	size_t minWordLength = 3;            // Require at least one 3+ char word-like sequence
	double maxEntropyBits = 5.5;         // Entropy > 5.5 bits/char suggests random data
	bool requireNullTerminator = true;
	bool rejectConsecutiveNonPrintable = true;  // Reject strings with 2+ consecutive non-printable
	size_t maxConsecutiveNonPrintable = 1;      // Max consecutive non-printable chars allowed
	
	// Encoding options
	bool detectAscii = true;
	bool detectUtf8 = true;
	bool detectUtf16 = true;
	bool detectUtf16Patterns = true;  // Detect UTF-16 via alternating printable/null patterns
	bool detectWide = false;
	bool detectAnsiEscapes = true;    // Allow ANSI escape sequences (ESC [ ...)
	
	// Search scope
	bool searchDataSections = true;
	bool searchCodeSections = true;  // Literal pools
	bool searchUnmapped = false;
	bool findUnreferenced = true;
	bool skipInsideFunctions = true;  // ALWAYS skip strings inside defined function bodies
	
	// Pattern detection
	bool categorizeStrings = true;
	bool detectFormatStrings = true;
	bool detectPaths = true;
	bool detectUrls = true;
	bool detectVersions = true;
	bool detectCryptoStrings = true;
	
	// Filtering
	bool skipExisting = true;  // Skip already-defined strings
	double minConfidence = 0.5;
	
	// Post-processing
	bool scanStringPointers = true;   // Scan for pointers to detected strings
	bool typeStringPointers = true;   // Create char* data variables for string pointers
	bool validateNullTermination = true;  // Validate proper null termination per encoding
};

struct StringDetectionStats
{
	size_t totalFound = 0;
	size_t newStrings = 0;
	size_t unreferenced = 0;
	size_t inLiteralPools = 0;
	size_t formatStrings = 0;
	size_t interestingStrings = 0;  // Paths, URLs, versions, etc.
	size_t stringPointers = 0;      // Pointers to strings discovered
	size_t ansiSequences = 0;       // ANSI escape sequences detected
	size_t utf16Patterns = 0;       // UTF-16 strings detected via alternating patterns
	size_t rejectedConsecutive = 0; // Rejected due to consecutive non-printable
	size_t rejectedNoWord = 0;      // Rejected due to no word-like sequence
	size_t rejectedNullTerm = 0;    // Rejected due to improper null termination
	std::map<StringEncoding, size_t> byEncoding;
	std::map<StringCategory, size_t> byCategory;
};

class StringDetector
{
public:
	explicit StringDetector(BinaryNinja::BinaryView* view);
	
	std::vector<DetectedString> Detect(const StringDetectionSettings& settings);
	const StringDetectionStats& GetStats() const { return m_stats; }
	
	// Utility methods
	static const char* EncodingToString(StringEncoding enc);
	static const char* CategoryToString(StringCategory cat);

	/**
	 * Check if data looks like a null-terminated ASCII string.
	 * 
	 * This is a fast static check for use in function validation.
	 * Returns true if the data appears to be a valid C string.
	 * 
	 * @param data      Raw bytes to check
	 * @param len       Length of buffer (max bytes to scan)
	 * @param minLen    Minimum string length to consider (default 4)
	 * @param minRatio  Minimum printable ratio (default 0.75 = 75%)
	 * @return true if data looks like a null-terminated string
	 */
	static bool LooksLikeNullTerminatedString(const uint8_t* data, size_t len,
		size_t minLen = 2, double minRatio = 0.70);

private:
	bool isValidString(const std::vector<uint8_t>& data, StringEncoding encoding,
		const StringDetectionSettings& settings) const;
	double calculateConfidence(const DetectedString& str, const StringDetectionSettings& settings) const;
	StringCategory categorizeString(const std::string& content, std::string& reason) const;
	bool isPrintableAscii(uint8_t c) const;
	bool isPrintableUtf8(const std::vector<uint8_t>& data) const;
	std::string decodeString(const std::vector<uint8_t>& data, StringEncoding encoding) const;
	
	// Gibberish filtering helpers
	double calculateEntropy(const std::string& str) const;
	bool hasWordLikeSequence(const std::string& str, size_t minWordLen) const;
	bool isLikelyGibberish(const std::string& str, const StringDetectionSettings& settings) const;
	
	// Advanced detection helpers
	bool hasConsecutiveNonPrintable(const uint8_t* data, size_t len, size_t maxConsec) const;
	bool isAnsiEscapeSequence(const uint8_t* data, size_t len) const;
	bool looksLikeUtf16Pattern(const uint8_t* data, size_t len, bool& isLittleEndian) const;
	bool validateNullTermination(const uint8_t* data, size_t len, StringEncoding encoding) const;
	bool hasWordLikeSequenceRaw(const uint8_t* data, size_t len, StringEncoding encoding, size_t minWordLen) const;
	
	// String pointer scanning
	void scanForStringPointers(const std::vector<DetectedString>& strings,
		const StringDetectionSettings& settings);
	
	void scanRegion(uint64_t start, uint64_t end, bool isCode,
		const StringDetectionSettings& settings, std::vector<DetectedString>& results);
	
	BinaryNinja::BinaryView* m_view;
	StringDetectionStats m_stats;
	std::set<uint64_t> m_existingStrings;  // Start addresses for stats lookup
	std::vector<std::pair<uint64_t, uint64_t>> m_existingStringRanges;  // (start, end) ranges for overlap check
	std::set<uint64_t> m_referencedAddresses;

	bool isInsideExistingString(uint64_t addr) const;
};

}
