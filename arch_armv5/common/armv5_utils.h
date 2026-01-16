/*
 * ARMv5 Shared Utilities
 *
 * This header consolidates utility functions that are used across multiple
 * components of the ARMv5 plugin. Previously, these functions were duplicated
 * in several files, leading to maintenance burden and potential inconsistencies.
 *
 * DESIGN NOTES:
 * -------------
 * 1. All functions here are designed to be safe for use from any context
 *    (architecture callbacks, firmware scans, workflow activities, etc.)
 *
 * 2. Functions that take BinaryView references use const Ref<>& to avoid
 *    incrementing reference counts unnecessarily. This is particularly important
 *    in workflow callbacks where reference management is critical.
 *
 * 3. Optional logging parameters allow detailed debugging without affecting
 *    performance when logging is disabled.
 *
 * CONSOLIDATION HISTORY:
 * ----------------------
 * - IsValidFunctionStart: was duplicated in armv5_architecture.cpp,
 *   firmware_view.cpp, and firmware_scans.cpp
 * - GetOperandCount: was duplicated in armv5_architecture.cpp and il.cpp
 * - GetNextFunctionAfterAddress: was in armv5_architecture.cpp
 */

#pragma once

#include "binaryninjaapi.h"
#include "armv5_disasm/armv5.h"

namespace armv5 {

/*
 * ============================================================================
 * FUNCTION VALIDATION UTILITIES
 * ============================================================================
 *
 * These functions help determine whether a given address is a valid location
 * for a function to start. This is crucial for firmware analysis where we
 * scan for functions without the benefit of symbol tables or debug info.
 */

/**
 * Check if an address is a valid location for a function to start.
 *
 * This function performs a comprehensive set of checks to determine whether
 * an address could plausibly be the start of a function. It is used during
 * firmware analysis to validate candidate function addresses discovered
 * through prologue scanning, call target analysis, or pointer table parsing.
 *
 * VALIDATION CHECKS PERFORMED:
 * ----------------------------
 * 1. View validity: Ensures the BinaryView object is valid and not destroyed
 * 2. Architecture: Gets architecture from platform or falls back to view default
 * 3. Alignment: Aligns address to instruction boundary (important for Thumb)
 * 4. Offset validity: Address must be within the binary's valid range
 * 5. File backing: Address must be backed by actual file data (not just mapped)
 * 6. Code semantics: If sections exist, address must be in a code section
 * 7. Data variable conflict: Address must not already be defined as data
 * 8. Executable: If segments exist, address must be in an executable segment
 * 9. Null/padding check: Rejects addresses pointing to all-zero or all-0xFF bytes
 * 10. Instruction validity: Must be able to decode a valid instruction
 *
 * WHY THESE CHECKS MATTER:
 * ------------------------
 * Firmware binaries often have:
 * - Large regions of padding (0x00 or 0xFF) between code sections
 * - Data tables embedded in code regions
 * - Vector tables with pointers that look like code addresses
 *
 * Without these checks, naive function discovery would create thousands
 * of false positive functions in padding regions.
 *
 * PERFORMANCE NOTES:
 * ------------------
 * This function may perform I/O (reading from the binary) and should not
 * be called in tight loops without consideration. For bulk validation,
 * consider caching the data buffer and using lower-level checks.
 *
 * @param view     The BinaryView to check against. Passed by const reference
 *                 to avoid reference count manipulation.
 * @param platform Platform to use for architecture lookup. May be nullptr,
 *                 in which case the view's default architecture is used.
 * @param addr     The address to validate.
 * @param logger   Optional logger for debug output. Pass nullptr to disable.
 * @param label    Optional label prefix for log messages (e.g., "prologue scan").
 *
 * @return true if the address passes all validation checks, false otherwise.
 */
[[nodiscard]] inline bool IsValidFunctionStart(
	const BinaryNinja::Ref<BinaryNinja::BinaryView>& view,
	const BinaryNinja::Ref<BinaryNinja::Platform>& platform,
	uint64_t addr,
	BinaryNinja::Logger* logger,
	const char* label)
{
	using namespace BinaryNinja;

	/* Check 1: View must be valid and not destroyed */
	if (!view || !view->GetObject())
		return false;

	/* Check 2: Get architecture from platform or view default */
	Ref<Architecture> arch = platform ? platform->GetArchitecture() : view->GetDefaultArchitecture();
	if (!arch)
		return false;

	/*
	 * Determine enforcement policy based on binary structure.
	 *
	 * For raw firmware with no segments/sections, we can't enforce
	 * executable/code semantics because everything is in one blob.
	 * For ELF/structured binaries, we should respect section flags.
	 */
	const bool enforceExecutable = !view->GetSegments().empty();
	const bool enforceCodeSemantics = !view->GetSections().empty();

	/* Check 3: Align to instruction boundary (ARM=4, Thumb=2) */
	uint64_t checkAddr = addr;
	const size_t align = arch->GetInstructionAlignment();
	if (align > 1)
		checkAddr &= ~(static_cast<uint64_t>(align) - 1);

	/* Check 4: Must be within valid address range */
	if (!view->IsValidOffset(checkAddr))
		return false;

	/* Check 5: Must be backed by actual file data */
	if (!view->IsOffsetBackedByFile(checkAddr))
		return false;

	/* Check 6: If we have sections, respect code semantics */
	if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(checkAddr))
		return false;

	/* Check 7: Must not conflict with existing data variable */
	DataVariable dataVar;
	if (view->GetDataVariableAtAddress(checkAddr, dataVar) && (dataVar.address == checkAddr))
		return false;

	/* Check 8: If we have segments, must be executable */
	if (enforceExecutable && !view->IsOffsetExecutable(checkAddr))
		return false;

	/* Check 9 & 10: Read instruction bytes and validate */
	DataBuffer buf = view->ReadBuffer(checkAddr, arch->GetMaxInstructionLength());
	if (buf.GetLength() == 0)
		return false;

	/*
	 * Reject obvious padding patterns.
	 * Firmware often has large regions of 0x00 or 0xFF between sections.
	 * These decode as valid ARM instructions (ANDEQ r0,r0,r0 for 0x00000000)
	 * but are clearly not real code.
	 */
	if (buf.GetLength() >= 4)
	{
		const uint8_t* bytes = static_cast<const uint8_t*>(buf.GetData());
		const bool allZero = bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0;
		const bool allFF = bytes[0] == 0xFF && bytes[1] == 0xFF && bytes[2] == 0xFF && bytes[3] == 0xFF;
		if (allZero || allFF)
			return false;
	}

	/* Check 10: Must decode to a valid instruction */
	InstructionInfo info;
	if (!arch->GetInstructionInfo(static_cast<const uint8_t*>(buf.GetData()), checkAddr, buf.GetLength(), info))
	{
		if (logger && label)
			logger->LogDebug("%s: no instruction at 0x%llx", label, (unsigned long long)checkAddr);
		return false;
	}

	return info.length != 0;
}

/**
 * Simplified overload of IsValidFunctionStart without logging.
 *
 * This is a convenience wrapper for call sites that don't need diagnostic
 * logging. It simply forwards to the full version with nullptr logger.
 *
 * @param view     The BinaryView to check against.
 * @param platform Platform to use for architecture lookup.
 * @param addr     The address to validate.
 *
 * @return true if the address passes all validation checks.
 */
[[nodiscard]] inline bool IsValidFunctionStart(
	const BinaryNinja::Ref<BinaryNinja::BinaryView>& view,
	const BinaryNinja::Ref<BinaryNinja::Platform>& platform,
	uint64_t addr)
{
	return IsValidFunctionStart(view, platform, addr, nullptr, nullptr);
}

/**
 * Find the next function after a given address.
 *
 * Searches for the next function that starts at or after the given address.
 * This is useful for determining function boundaries and for iterating
 * through functions in address order.
 *
 * @param data      The BinaryView to search.
 * @param platform  Platform to use for function lookup.
 * @param address   The address to search from.
 * @param nextFunc  Output: Reference to the found function, or nullptr.
 *
 * @return true if a function was found, false otherwise.
 */
[[nodiscard]] inline bool GetNextFunctionAfterAddress(
	BinaryNinja::Ref<BinaryNinja::BinaryView> data,
	BinaryNinja::Ref<BinaryNinja::Platform> platform,
	uint64_t address,
	BinaryNinja::Ref<BinaryNinja::Function>& nextFunc)
{
	uint64_t nextFuncAddr = data->GetNextFunctionStartAfterAddress(address);
	nextFunc = data->GetAnalysisFunction(platform, nextFuncAddr);
	return nextFunc != nullptr;
}


/*
 * ============================================================================
 * INSTRUCTION UTILITIES
 * ============================================================================
 *
 * Helper functions for working with decoded ARM instructions.
 */

/**
 * Count the number of valid operands in a decoded instruction.
 *
 * ARM instructions have a variable number of operands (0-6). The Instruction
 * struct has a fixed-size operands array, with unused entries marked with
 * cls == NONE. This function counts the actual number of valid operands.
 *
 * USAGE EXAMPLE:
 * --------------
 *   Instruction instr;
 *   armv5_decompose(opcode, &instr, addr, 0);
 *   int count = GetOperandCount(instr);
 *   for (int i = 0; i < count; i++) {
 *       // Process instr.operands[i]
 *   }
 *
 * @param instr The decoded instruction to examine.
 *
 * @return The number of valid operands (0 to MAX_OPERANDS).
 */
[[nodiscard]] constexpr inline int GetOperandCount(const Instruction& instr) noexcept
{
	for (int i = 0; i < MAX_OPERANDS; i++)
	{
		if (instr.operands[i].cls == NONE)
			return i;
	}
	return MAX_OPERANDS;
}


/*
 * ============================================================================
 * BINARY DATA UTILITIES
 * ============================================================================
 *
 * Low-level utilities for reading binary data with proper endianness handling.
 */

/**
 * Byte-swap a 32-bit value (for endianness conversion).
 *
 * @param value The value to swap.
 * @return The byte-swapped value.
 */
[[nodiscard]] constexpr inline uint32_t Swap32(uint32_t value) noexcept
{
	return ((value & 0xff000000) >> 24) |
	       ((value & 0x00ff0000) >> 8) |
	       ((value & 0x0000ff00) << 8) |
	       ((value & 0x000000ff) << 24);
}

/**
 * Read a 32-bit value from binary data with proper endianness handling.
 *
 * This function attempts to read from a cached data buffer first for
 * performance, falling back to the BinaryReader for unbuffered access.
 * This dual approach is important for firmware analysis where we often
 * have the entire binary buffered in memory.
 *
 * @param reader   BinaryReader positioned in the binary (fallback source).
 * @param data     Pointer to cached data buffer, or nullptr if not buffered.
 * @param dataLen  Length of the cached data buffer.
 * @param endian   Endianness of the data.
 * @param offset   Offset to read from.
 * @param out      Output: The read value.
 * @param length   Total length of the binary (for bounds checking).
 *
 * @return true if the read succeeded, false on bounds error or I/O error.
 */
/*
 * NOTE: This function intentionally does NOT have [[nodiscard]].
 * Many call sites don't check the return value, which should be
 * fixed in a future cleanup pass. See ISSUES.md.
 */
inline bool ReadU32At(
	BinaryNinja::BinaryReader& reader,
	const uint8_t* data,
	uint64_t dataLen,
	BNEndianness endian,
	uint64_t offset,
	uint32_t& out,
	uint64_t length)
{
	/* Bounds check against the total length */
	if (length != 0 && offset + 4 > length)
	{
		out = 0;
		return false;
	}

	/* Try buffered read first (fast path) */
	if (data && offset + 4 <= dataLen)
	{
		memcpy(&out, data + offset, sizeof(out));
		if (endian == BigEndian)
			out = Swap32(out);
		return true;
	}

	/* Fall back to BinaryReader (slow path) */
	reader.Seek(offset);
	try
	{
		out = reader.Read32();
		return true;
	}
	catch (...)
	{
		out = 0;
		return false;
	}
}

} /* namespace armv5 */
