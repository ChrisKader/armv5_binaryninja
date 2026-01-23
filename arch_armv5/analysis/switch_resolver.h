/*
 * Switch Table Resolver
 *
 * Resolves ARM/Thumb switch tables and indirect jumps to find
 * all target addresses. This helps function detection by:
 * 1. Finding functions that are targets of switch cases
 * 2. Preventing false positives where switch targets look like function starts
 * 3. Enabling proper CFG construction through indirect branches
 *
 * Common ARM switch patterns:
 * - TBB/TBH: Thumb-2 table branch byte/halfword
 * - LDR pc, [pc, Rn, LSL #2]: Indexed jump table
 * - ADD pc, pc, Rn, LSL #2: Computed jump
 * - LDR Rm, [table + Rn]; BX Rm: Load-then-branch pattern
 */

#pragma once

#include "binaryninjaapi.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace Armv5Analysis
{

/**
 * Type of switch table detected
 */
enum class SwitchTableType
{
	Unknown,
	TBB,            // Table Branch Byte (Thumb-2)
	TBH,            // Table Branch Halfword (Thumb-2)
	LdrPcIndexed,   // LDR pc, [pc, Rn, LSL #n]
	AddPcIndexed,   // ADD pc, pc, Rn, LSL #n
	LdrBxPattern,   // LDR Rm, [table]; BX Rm
	ArmJumpTable,   // ARM-style pointer table
};

/**
 * A resolved switch table
 */
struct ResolvedSwitch
{
	uint64_t branchAddress;         // Address of the indirect branch instruction
	uint64_t tableAddress;          // Address of the jump table data
	SwitchTableType type;
	bool isThumb;

	std::vector<uint64_t> targets;  // Resolved target addresses
	size_t entryCount;              // Number of entries in table
	size_t entrySize;               // Size of each entry (1, 2, or 4 bytes)

	double confidence;              // How confident we are in this resolution
	std::string description;
};

/**
 * Settings for switch resolution
 */
struct SwitchResolverSettings
{
	// Scanning bounds
	uint64_t scanStart = 0;
	uint64_t scanEnd = 0;

	// Limits
	size_t maxTableEntries = 256;       // Max entries in a single table
	size_t maxTotalTables = 1000;       // Max tables to resolve

	// Validation
	bool validateTargets = true;        // Check that targets are valid code
	bool skipKnownSwitches = true;      // Skip already-resolved indirect branches
	double minimumConfidence = 0.5;     // Min confidence to report
};

/**
 * Switch Table Resolver
 */
class SwitchResolver
{
public:
	explicit SwitchResolver(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

	/**
	 * Find and resolve all switch tables in the binary
	 */
	std::vector<ResolvedSwitch> resolveAll();
	std::vector<ResolvedSwitch> resolveAll(const SwitchResolverSettings& settings);

	/**
	 * Try to resolve a specific indirect branch
	 */
	bool resolveAt(uint64_t address, bool isThumb, ResolvedSwitch& result);

	/**
	 * Get all unique switch targets (for function detection)
	 */
	std::set<uint64_t> getAllTargets() const;

	/**
	 * Get statistics
	 */
	struct Stats
	{
		size_t tablesFound = 0;
		size_t totalTargets = 0;
		size_t tbbTables = 0;
		size_t tbhTables = 0;
		size_t armTables = 0;
		size_t failedResolutions = 0;
	};
	Stats getStats() const { return m_stats; }

private:
	// Pattern detection
	bool detectTbbPattern(uint64_t addr, ResolvedSwitch& result);
	bool detectTbhPattern(uint64_t addr, ResolvedSwitch& result);
	bool detectArmLdrPcPattern(uint64_t addr, ResolvedSwitch& result);
	bool detectArmAddPcPattern(uint64_t addr, ResolvedSwitch& result);
	bool detectLdrBxPattern(uint64_t addr, bool isThumb, ResolvedSwitch& result);
	bool detectArmJumpTable(uint64_t addr, ResolvedSwitch& result);

	// Table reading
	std::vector<uint64_t> readByteTable(uint64_t tableAddr, uint64_t baseAddr, size_t maxEntries);
	std::vector<uint64_t> readHalfwordTable(uint64_t tableAddr, uint64_t baseAddr, size_t maxEntries);
	std::vector<uint64_t> readWordTable(uint64_t tableAddr, size_t maxEntries);

	// Validation
	bool isValidCodeTarget(uint64_t addr, bool expectThumb);
	bool isTableBounded(uint64_t tableAddr, size_t entrySize, size_t& entryCount);

	// Helpers
	uint32_t readInstruction32(uint64_t addr);
	uint16_t readInstruction16(uint64_t addr);
	uint8_t readByte(uint64_t addr);

	BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
	BinaryNinja::Ref<BinaryNinja::Logger> m_logger;
	SwitchResolverSettings m_settings;
	Stats m_stats;

	std::vector<ResolvedSwitch> m_resolved;
};

}  // namespace Armv5Analysis
