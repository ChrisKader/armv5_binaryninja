/*
 * ARMv5 Firmware Internal Helpers
 *
 * Shared helpers, types, and scan function declarations for firmware analysis.
 *
 * ============================================================================
 * FILE ORGANIZATION
 * ============================================================================
 *
 * This header is the central include for firmware analysis components:
 *
 * - FirmwareScanTuning: Tunable parameters for heuristic scans
 * - FirmwareScanContext: Bundles all context needed for scan passes
 * - Scan function declarations: Prologue, call target, pointer table scans
 * - Low-level utilities: ReadU32At, Swap32 (forwarded from armv5_utils.h)
 *
 * ============================================================================
 * SCAN TUNING PARAMETERS
 * ============================================================================
 *
 * The FirmwareScanTuning struct controls heuristic thresholds. Tuning is
 * critical for balancing:
 *   - Precision: Avoid false positive functions (noise in analysis)
 *   - Recall: Find all real functions (completeness)
 *
 * Different firmware images may need different tuning. Conservative defaults
 * prioritize precision over recall - it's easier to manually add missed
 * functions than to clean up thousands of false positives.
 *
 * ============================================================================
 * SCAN CONTEXT
 * ============================================================================
 *
 * FirmwareScanContext bundles parameters that every scan pass needs.
 * This avoids passing 10+ parameters to each function and makes it
 * easier to add new context without changing function signatures.
 *
 * IMPORTANT: The BinaryView in the context is a Ref<>. When passing
 * context to background tasks, ensure proper lifetime management.
 * See firmware_view.cpp header for lifetime management guidelines.
 */

#pragma once

#include "binaryninjaapi.h"
#include "firmware_scan_types.h"
#include "common/armv5_utils.h"

#include <cstdint>
#include <cstring>
#include <set>
#include <vector>
// Note: <algorithm> moved to .cpp files that need it (firmware_scans.cpp, etc.)

/*
 * NOTE: Swap32 and ReadU32At have been moved to common/armv5_utils.h
 * For backward compatibility, bring them into global namespace here.
 */
using armv5::Swap32;
using armv5::ReadU32At;

/*
 * ============================================================================
 * FUNCTION RANGE CACHE
 * ============================================================================
 *
 * Provides O(log n) lookup for "is address inside a function?" queries.
 * This replaces repeated GetAnalysisFunctionsContainingAddress() calls
 * which are O(n) in the number of functions.
 */

/**
 * Cache of function address ranges for fast containment queries.
 *
 * Build this once before scanning, then use Contains() for O(log n) lookups.
 * Much faster than calling GetAnalysisFunctionsContainingAddress() repeatedly.
 */
class FunctionRangeCache
{
public:
	struct Range
	{
		uint64_t start;
		uint64_t end;  // Exclusive

		bool operator<(const Range& other) const
		{
			return start < other.start;
		}
	};

	FunctionRangeCache() = default;

	/**
	 * Build the cache from a BinaryView's function list.
	 */
	void Build(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view)
	{
		m_ranges.clear();
		if (!view || !view->GetObject())
			return;

		auto funcs = view->GetAnalysisFunctionList();
		m_ranges.reserve(funcs.size());

		for (const auto& func : funcs)
		{
			if (!func)
				continue;
			uint64_t start = func->GetStart();
			uint64_t highest = func->GetHighestAddress();
			// GetHighestAddress returns the address of the last instruction
			// Add instruction size to get the exclusive end
			BinaryNinja::Ref<BinaryNinja::Architecture> arch = func->GetArchitecture();
			size_t instrSize = arch ? arch->GetDefaultIntegerSize() : 4;
			uint64_t end = (highest >= start) ? (highest + instrSize) : (start + instrSize);
			m_ranges.push_back({start, end});
		}

		// Sort ranges by start address
		std::sort(m_ranges.begin(), m_ranges.end());

		// Merge overlapping ranges
		if (m_ranges.size() > 1)
		{
			std::vector<Range> merged;
			merged.reserve(m_ranges.size());
			merged.push_back(m_ranges[0]);

			for (size_t i = 1; i < m_ranges.size(); i++)
			{
				Range& last = merged.back();
				const Range& curr = m_ranges[i];

				if (curr.start <= last.end)
				{
					// Overlapping or adjacent - merge
					if (curr.end > last.end)
						last.end = curr.end;
				}
				else
				{
					merged.push_back(curr);
				}
			}

			m_ranges = std::move(merged);
		}
	}

	/**
	 * Check if an address is inside any cached function range.
	 * O(log n) complexity.
	 */
	bool Contains(uint64_t addr) const
	{
		if (m_ranges.empty())
			return false;

		// Binary search for the range that might contain addr
		// Find the first range with start > addr, then check the previous range
		Range searchKey{addr, addr};
		auto it = std::upper_bound(m_ranges.begin(), m_ranges.end(), searchKey);

		if (it == m_ranges.begin())
			return false;  // All ranges start after addr

		--it;  // Now it points to the last range with start <= addr
		return addr >= it->start && addr < it->end;
	}

	/**
	 * Check if an address is the start of a function (not inside, but at start).
	 * O(log n) complexity.
	 */
	bool IsStart(uint64_t addr) const
	{
		if (m_ranges.empty())
			return false;

		Range searchKey{addr, addr};
		auto it = std::lower_bound(m_ranges.begin(), m_ranges.end(), searchKey);
		return it != m_ranges.end() && it->start == addr;
	}

	/**
	 * Get the number of ranges (after merging).
	 */
	size_t Size() const { return m_ranges.size(); }

	/**
	 * Clear the cache.
	 */
	void Clear() { m_ranges.clear(); }

private:
	std::vector<Range> m_ranges;
};

/*
 * ============================================================================
 * TUNING PARAMETERS
 * ============================================================================
 */

/**
 * Tuning parameters for firmware scan heuristics.
 *
 * These control the sensitivity of various scan passes. Adjust these
 * based on the characteristics of the firmware being analyzed.
 */
struct FirmwareScanTuning
{
	/*
	 * Prologue validation: require this many consecutive valid instructions
	 * after a candidate prologue before accepting it as a real function.
	 * Higher values reduce false positives but may miss small functions.
	 */
	uint32_t minValidInstr = 2;

	/*
	 * After matching a prologue pattern, require this many valid instructions
	 * in the function body. Helps reject data that accidentally matches prologues.
	 */
	uint32_t minBodyInstr = 1;

	/*
	 * Maximum consecutive LDR-from-literal-pool instructions before assuming
	 * we've hit a literal pool (data) rather than code. Literal pools often
	 * follow functions and can look like valid instructions.
	 */
	uint32_t maxLiteralRun = 2;

	/*
	 * Minimum consecutive valid code pointers to treat a region as a pointer
	 * table (vtable, callback array, etc.). Conservative to avoid false positives.
	 */
	uint32_t minPointerRun = 3;

	/*
	 * Whether to scan for pointer tables in raw data regions.
	 * Useful for finding vtables and interrupt handler tables.
	 */
	bool scanRawPointerTables = true;

	/*
	 * Require that pointer tables have code references into them.
	 * This prevents runaway false positives from sequences of addresses
	 * that happen to look like pointers but aren't used as such.
	 */
	bool requirePointerTableCodeRefs = true;

	/*
	 * Allow pointer tables inside code semantics regions.
	 * Normally disabled because embedded pointer tables in code are rare
	 * and detecting them is error-prone.
	 */
	bool allowPointerTablesInCode = false;

	/*
	 * Require BL/BLX call targets to be inside existing functions.
	 * More conservative but may miss functions only reached via indirect calls.
	 */
	bool requireCallInFunction = false;
};

/*
 * ============================================================================
 * SCAN CONTEXT
 * ============================================================================
 */

/**
 * Context for firmware analysis scans.
 *
 * Bundles all the parameters that scan passes need into a single struct.
 * This avoids functions with 10+ parameters and makes it easier to add
 * new context without changing every function signature.
 *
 * LIFETIME NOTES:
 * ---------------
 * - The BinaryReader reference must remain valid for the scan duration
 * - The data pointer may be null (forces reader-based access)
 * - The view Ref<> keeps the view alive - see firmware_view.cpp for
 *   guidance on when this is appropriate vs dangerous
 */
struct FirmwareScanContext
{
	/* Binary reader for on-demand data access */
	BinaryNinja::BinaryReader& reader;

	/* Cached binary data (nullptr if not buffered) */
	const uint8_t* data;

	/* Length of cached data buffer */
	uint64_t dataLen;

	/* Endianness of the firmware (affects instruction decoding) */
	BNEndianness endian;

	/* Virtual address of the firmware image start */
	uint64_t imageBase;

	/* Total length of the firmware image */
	uint64_t length;

	/* Architecture for instruction decoding */
	BinaryNinja::Ref<BinaryNinja::Architecture> arch;

	/* Platform for function creation */
	BinaryNinja::Ref<BinaryNinja::Platform> plat;

	/* Logger for diagnostic output */
	BinaryNinja::Ref<BinaryNinja::Logger> logger;

	/* Enable verbose logging (detailed per-instruction output) */
	bool verboseLog;

	/*
	 * The BinaryView being analyzed.
	 *
	 * WARNING: Holding a Ref<BinaryView> extends the view's lifetime.
	 * In workflow callbacks, prefer re-acquiring from AnalysisContext.
	 */
	BinaryNinja::Ref<BinaryNinja::BinaryView> view;

	/* Scan plan to populate with proposed changes */
	FirmwareScanPlan* plan;

	/* Cached function ranges for fast containment queries */
	const FunctionRangeCache* functionRangeCache;

	/* Helper: compute end address of the firmware image */
	uint64_t ImageEnd() const { return imageBase + length; }

	/**
	 * Check if an address is inside an existing function.
	 * Uses the cache if available, falls back to view query otherwise.
	 */
	bool IsInsideFunction(uint64_t addr) const
	{
		if (functionRangeCache)
			return functionRangeCache->Contains(addr);
		if (!view || !view->GetObject())
			return false;
		return !view->GetAnalysisFunctionsContainingAddress(addr).empty();
	}
};

/*
 * ============================================================================
 * SCAN FUNCTION DECLARATIONS
 * ============================================================================
 *
 * Each scan pass returns the number of items found/processed.
 * Results are accumulated in seededFunctions (output set) and plan (actions).
 */

/**
 * Detect image base address from ARM vector table.
 *
 * ARM processors expect a vector table at address 0 (or 0xFFFF0000 for high vectors).
 * This function analyzes the vector table entries to determine where the
 * firmware image expects to be loaded.
 *
 * Detection algorithm:
 * 1. Read first 8 words as potential vector entries
 * 2. For LDR PC instructions, resolve the literal pool target
 * 3. For B instructions, compute the branch target
 * 4. Determine common base address from targets
 *
 * @param data The raw binary data to analyze.
 * @return The detected image base, or 0 if detection failed.
 */
uint64_t DetectImageBaseFromVectorTable(BinaryNinja::BinaryView* data);

/**
 * Resolve a single vector table entry to its target address.
 *
 * Vector entries can be:
 * - LDR PC, [PC, #offset] - loads target from literal pool
 * - B target - direct branch to handler
 *
 * @param reader    BinaryReader for data access.
 * @param data      Cached data buffer (or nullptr).
 * @param dataLen   Length of cached data.
 * @param endian    Endianness of the data.
 * @param vectorOffset Offset of the vector entry.
 * @param imageBase Base address of the image.
 * @param length    Total length of the image.
 * @return The resolved target address, or 0 on failure.
 */
uint64_t ResolveVectorEntry(BinaryNinja::BinaryReader& reader, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t vectorOffset, uint64_t imageBase, uint64_t length);

/**
 * Scan for function prologues (PHASE 1).
 *
 * This is the most reliable function discovery pass. It scans for
 * recognizable ARM function prologue patterns:
 *
 * Common patterns detected:
 * - PUSH {r4-r7, lr}      - Thumb: save registers and link
 * - STMFD sp!, {regs, lr} - ARM: save registers to stack
 * - SUB sp, sp, #imm      - Stack frame allocation
 * - MOV ip, sp            - Frame pointer setup
 *
 * @return Number of candidate functions found.
 */
size_t ScanForFunctionPrologues(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Architecture> armArch, BinaryNinja::Ref<BinaryNinja::Architecture> thumbArch,
	BinaryNinja::Ref<BinaryNinja::Platform> plat, BinaryNinja::Ref<BinaryNinja::Logger> logger,
	bool verboseLog, const FirmwareScanTuning& tuning, uint64_t codeDataBoundary,
	std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan);

/**
 * Scan for call targets (PHASE 2).
 *
 * Iterates through the binary looking for BL/BLX instructions and
 * adds their targets as candidate functions. This discovers functions
 * that are called but don't have recognizable prologues.
 *
 * @return Number of new call targets found.
 */
size_t ScanForCallTargets(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Platform> plat, BinaryNinja::Ref<BinaryNinja::Logger> logger, bool verboseLog,
	const FirmwareScanTuning& tuning, uint64_t codeDataBoundary, std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan);

/**
 * Scan for pointer tables (PHASE 3).
 *
 * Looks for tables of consecutive pointers that reference code addresses.
 * Common in embedded firmware:
 * - Interrupt vector tables
 * - Virtual function tables (C++ or RTOS)
 * - Callback function arrays
 *
 * @return Number of pointer tables found.
 */
size_t ScanForPointerTargets(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Platform> plat, BinaryNinja::Ref<BinaryNinja::Logger> logger, bool verboseLog,
	const FirmwareScanTuning& tuning, uint64_t codeDataBoundary, std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan);

/**
 * Scan for orphan code blocks (PHASE 4).
 *
 * Uses more aggressive heuristics to find code that wasn't discovered
 * by other passes. Looks for:
 * - Valid instruction sequences in unanalyzed regions
 * - Code between known functions (gap filling)
 * - Code after literal pools
 *
 * This pass has higher false positive rates; the cleanup pass corrects mistakes.
 *
 * @param minSpacingBytes  Minimum bytes between functions to scan gap.
 * @param maxPerPage       Maximum functions to add per 4KB page (rate limiting).
 * @param requirePrologue  If true, only accept sequences starting with prologue.
 * @return Number of orphan blocks found.
 */
size_t ScanForOrphanCodeBlocks(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Platform> plat, BinaryNinja::Ref<BinaryNinja::Logger> logger, bool verboseLog,
	const FirmwareScanTuning& tuning, uint64_t codeDataBoundary, uint32_t minValidInstr, uint32_t minBodyInstr,
	uint32_t minSpacingBytes, uint32_t maxPerPage, bool requirePrologue, std::set<uint64_t>* addedFunctions, FirmwareScanPlan* plan);

/**
 * Clean up invalid functions (PHASE 5).
 *
 * Removes functions that analysis revealed to be invalid:
 * - Functions with no valid instructions
 * - Functions that are actually data (e.g., string tables)
 * - Functions that overlap with confirmed data
 *
 * @param maxSizeBytes      Maximum function size to consider for removal.
 * @param requireZeroRefs   Only remove if function has no references.
 * @param requirePcWriteStart Only remove if function doesn't start with PC write.
 * @param entryPoint        Entry point address (never remove).
 * @param protectedStarts   Set of addresses to never remove.
 * @return Number of functions removed.
 */
size_t CleanupInvalidFunctions(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t imageBase, uint64_t length, BinaryNinja::Ref<BinaryNinja::Logger> logger,
	bool verboseLog, const FirmwareScanTuning& tuning, uint32_t maxSizeBytes, bool requireZeroRefs,
	bool requirePcWriteStart, uint64_t entryPoint, const std::set<uint64_t>& protectedStarts,
	FirmwareScanPlan* plan);

/**
 * Analyze MMU configuration.
 *
 * Searches for MMU page table setup code and memory-mapped I/O regions.
 * Used to identify MMIO addresses and create appropriate segments.
 */
void AnalyzeMMUConfiguration(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view, BinaryNinja::BinaryReader& reader, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	BinaryNinja::Ref<BinaryNinja::Logger> logger);

/*
 * ============================================================================
 * POST-SCAN CLEANUP FUNCTIONS
 * ============================================================================
 */

/**
 * Type literal pool entries as pointers.
 *
 * ARM code uses PC-relative loads (LDR Rd, [PC, #offset]) to access constants
 * stored in literal pools following functions. This function finds these
 * pools and defines the entries as proper data types (pointers, etc.).
 */
void TypeLiteralPoolEntries(const FirmwareScanContext& ctx);

/**
 * Clear auto-defined data that conflicts with code references.
 *
 * Sometimes analysis creates data variables at addresses that are actually
 * code targets. This function removes such conflicts.
 */
void ClearAutoDataOnCodeReferences(const FirmwareScanContext& ctx);

/**
 * Clear auto-defined data in function entry blocks.
 *
 * Removes data variables that overlap with the entry block of seeded
 * functions. This fixes cases where data was defined before the function
 * was recognized.
 */
void ClearAutoDataInFunctionEntryBlocks(const FirmwareScanContext& ctx,
	const std::set<uint64_t>* seededFunctions);

/**
 * Re-enable analysis for important functions that have analysis suppressed.
 *
 * Finds seeded functions and complex functions that have analysis suppressed
 * and re-enables their analysis for proper reverse engineering.
 */
void ReEnableAnalysisForImportantFunctions(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view,
	const BinaryNinja::Ref<BinaryNinja::Logger>& logger);

/**
 * Re-enable analysis for functions that have analysis suppressed.
 *
 * Finds all functions that have analysis suppressed and re-enables their
 * analysis to resolve "analysis disabled" alerts.
 */
void ReEnableAnalysisForSuppressedFunctions(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view,
	const BinaryNinja::Ref<BinaryNinja::Logger>& logger);

/**
 * Post-analysis cleanup to fix incomplete function analysis caused by
 * incorrectly marked __noreturn functions.
 *
 * Looks for functions with unreachable code after their analyzed end
 * and forces re-analysis to complete the function boundaries.
 */
void PostAnalysisCleanup(const BinaryNinja::Ref<BinaryNinja::BinaryView>& view,
	const BinaryNinja::Ref<BinaryNinja::Logger>& logger);
