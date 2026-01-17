/*
 * Structure Detector
 *
 * Advanced structure and data pattern detection for firmware analysis.
 * Detects:
 * - C++ VTables (virtual function tables)
 * - Jump tables (switch statements)
 * - Function pointer tables (callbacks, handlers)
 * - Arrays (uniform data)
 * - Structs (field access patterns)
 */

#pragma once

#include "binaryninjaapi.h"
#include <vector>
#include <string>
#include <set>
#include <map>

namespace Armv5Analysis
{

enum class StructureType
{
	VTable,           // C++ virtual function table
	JumpTable,        // Switch statement table
	FunctionTable,    // Array of function pointers
	PointerArray,     // Array of data pointers
	IntegerArray,     // Array of integers
	StringTable,      // Array of string pointers
	HandlerTable,     // IRQ/callback handlers
	StructArray,      // Array of structs
	Unknown
};

struct DetectedStructure
{
	uint64_t address;
	size_t size;
	StructureType type;
	size_t elementCount;
	size_t elementSize;
	double confidence;
	std::string description;
	std::vector<uint64_t> elements;  // Individual element addresses/values
	std::vector<std::string> elementNames;  // Resolved names if available
	bool isNew;  // Not already typed
	
	// For function tables
	std::vector<uint64_t> functionTargets;
	
	// For analysis
	std::string inferredTypeName;
	std::vector<uint64_t> xrefSources;
};

struct StructureDetectionSettings
{
	// What to detect
	bool detectVtables = true;
	bool detectJumpTables = true;
	bool detectFunctionTables = true;
	bool detectPointerArrays = true;
	bool detectIntegerArrays = true;
	bool detectStructArrays = true;
	
	// Constraints
	size_t minElements = 3;
	size_t maxElements = 1000;
	size_t maxGap = 0;  // 0 = contiguous only
	
	// Analysis
	bool inferTypes = true;
	bool resolveSymbols = true;
	bool createTypes = false;  // Auto-create BN types
	
	// Filtering
	double minConfidence = 0.5;
	bool skipExisting = true;
};

struct StructureDetectionStats
{
	size_t totalFound = 0;
	size_t vtables = 0;
	size_t jumpTables = 0;
	size_t functionTables = 0;
	size_t pointerArrays = 0;
	size_t integerArrays = 0;
	size_t newStructures = 0;
	size_t totalFunctionsDiscovered = 0;
};

class StructureDetector
{
public:
	explicit StructureDetector(BinaryNinja::BinaryView* view);
	
	std::vector<DetectedStructure> Detect(const StructureDetectionSettings& settings);
	const StructureDetectionStats& GetStats() const { return m_stats; }
	
	static const char* TypeToString(StructureType type);

private:
	void scanForVtables(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results);
	void scanForJumpTables(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results);
	void scanForFunctionTables(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results);
	void scanForPointerArrays(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results);
	void scanForIntegerArrays(const StructureDetectionSettings& settings, std::vector<DetectedStructure>& results);
	
	bool isCodePointer(uint64_t value) const;
	bool isDataPointer(uint64_t value) const;
	bool isValidPointer(uint64_t value) const;
	std::string resolveSymbol(uint64_t addr) const;
	double calculateConfidence(const DetectedStructure& s, const StructureDetectionSettings& settings) const;
	
	BinaryNinja::BinaryView* m_view;
	StructureDetectionStats m_stats;
	std::set<uint64_t> m_existingTypes;
	std::set<uint64_t> m_codeRegions;
	std::set<uint64_t> m_dataRegions;
	uint64_t m_imageBase;
	uint64_t m_imageEnd;
};

}
