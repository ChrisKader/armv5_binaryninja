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
#include "analysis/string_detector.h"

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

	/* Check 2: Get architecture, accounting for Thumb bit in address */
	Ref<Architecture> arch = platform ? platform->GetArchitecture() : view->GetDefaultArchitecture();
	if (!arch)
		return false;

	/*
	 * If address has Thumb bit (bit 0) set, resolve to the associated
	 * architecture (which should be Thumb). This handles cases where
	 * callers pass the default ARM platform but the address is Thumb.
	 */
	uint64_t tempAddr = addr;
	Ref<Architecture> resolvedArch = arch->GetAssociatedArchitectureByAddress(tempAddr);
	if (resolvedArch)
		arch = resolvedArch;

	/*
	 * Determine enforcement policy based on binary structure.
	 *
	 * For raw firmware with no segments/sections, we can't enforce
	 * executable/code semantics because everything is in one blob.
	 * For ELF/structured binaries, we should respect section flags.
	 */
	const bool enforceExecutable = !view->GetSegments().empty();
	const bool enforceCodeSemantics = !view->GetSections().empty();

	/*
	 * Check 3: Handle ARM/Thumb addressing and alignment
	 *
	 * ARM uses bit 0 to indicate Thumb mode in branch targets:
	 * - Bit 0 = 1: Thumb mode, actual address is addr & ~1
	 * - Bit 0 = 0: ARM mode (for ARM architecture) or Thumb (for Thumb architecture)
	 *
	 * Alignment enforcement based on platform architecture:
	 * - ARM architecture (alignment=4): must be 4-byte aligned, no Thumb bit
	 * - Thumb architecture (alignment=2): must be 2-byte aligned after clearing Thumb bit
	 */
	const size_t archAlign = arch->GetInstructionAlignment();
	uint64_t checkAddr = addr;

	if (archAlign == 4)
	{
		// ARM architecture: reject if Thumb bit is set or not 4-byte aligned
		if (addr & 3)
		{
			if (logger && label)
				logger->LogDebug("%s: misaligned ARM address 0x%llx (requires 4-byte alignment)",
					label, (unsigned long long)addr);
			return false;
		}
	}
	else if (archAlign == 2)
	{
		// Thumb architecture: clear Thumb bit, check 2-byte alignment
		checkAddr = addr & ~1ULL;
		if (checkAddr & 1)  // Should never happen but be safe
		{
			if (logger && label)
				logger->LogDebug("%s: misaligned Thumb address 0x%llx",
					label, (unsigned long long)addr);
			return false;
		}
	}
	else
	{
		// Unknown alignment, just clear bit 0 and continue
		checkAddr = addr & ~1ULL;
	}

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

	/*
	 * Check 7b: Must not be inside a string detected by Binary Ninja.
	 *
	 * BN's string analysis may have found strings at this address but not
	 * yet typed them as data variables. We check GetStringAtAddress() directly
	 * to catch these cases and prevent creating functions inside string data.
	 */
	BNStringReference strRef;
	if (view->GetStringAtAddress(checkAddr, strRef) && strRef.length > 0)
	{
		if (logger && label)
			logger->LogDebug("%s: address 0x%llx is inside string at 0x%llx (len=%zu)",
				label, (unsigned long long)checkAddr, (unsigned long long)strRef.start,
				strRef.length);
		return false;
	}

	/* Check 8: If we have segments, must be executable */
	if (enforceExecutable && !view->IsOffsetExecutable(checkAddr))
		return false;

	/*
	 * Check 9: Validate multiple consecutive instructions.
	 *
	 * A valid function should have multiple valid instructions in a row.
	 * Checking just the first instruction isn't enough - data can accidentally
	 * decode to a single valid instruction. By requiring 3+ valid instructions,
	 * we dramatically reduce false positives from string/data regions.
	 */
	constexpr size_t kMinValidInstructions = 3;
	constexpr size_t kMaxBytesToCheck = 16;  // Check up to 4 ARM instructions
	
	DataBuffer buf = view->ReadBuffer(checkAddr, kMaxBytesToCheck);
	if (buf.GetLength() < 4)
		return false;

	const uint8_t* bytes = static_cast<const uint8_t*>(buf.GetData());

	/*
	 * Check 9b: Reject addresses that look like null-terminated ASCII string data.
	 *
	 * String regions often decode as valid but nonsensical ARM instructions
	 * (e.g., "syst" = 0x73797374 = ldrbvc r7, [r3], #-0x973).
	 * Uses the centralized StringDetector logic for consistency.
	 */
	{
		constexpr size_t kMaxStringSearch = 256;
		DataBuffer strBuf = view->ReadBuffer(checkAddr, kMaxStringSearch);
		// Use permissive settings: minLen=2, minRatio=70% to catch more string patterns
		if (Armv5Analysis::StringDetector::LooksLikeNullTerminatedString(
				static_cast<const uint8_t*>(strBuf.GetData()), strBuf.GetLength(), 2, 0.70))
		{
			if (logger && label)
				logger->LogDebug("%s: address 0x%llx looks like null-terminated string",
					label, (unsigned long long)checkAddr);
			return false;
		}
	}

	size_t offset = 0;
	size_t validCount = 0;
	
	while (offset + 4 <= buf.GetLength() && validCount < kMinValidInstructions)
	{
		/*
		 * Reject obvious padding patterns.
		 * Firmware often has large regions of 0x00 or 0xFF between sections.
		 */
		const uint8_t* instrBytes = bytes + offset;
		const bool allZero = instrBytes[0] == 0 && instrBytes[1] == 0 && 
		                     instrBytes[2] == 0 && instrBytes[3] == 0;
		const bool allFF = instrBytes[0] == 0xFF && instrBytes[1] == 0xFF && 
		                   instrBytes[2] == 0xFF && instrBytes[3] == 0xFF;
		if (allZero || allFF)
		{
			if (logger && label)
				logger->LogDebug("%s: padding at 0x%llx+%zu", label, (unsigned long long)checkAddr, offset);
			return false;
		}

		/* Try to decode the instruction */
		InstructionInfo info;
		if (!arch->GetInstructionInfo(instrBytes, checkAddr + offset, buf.GetLength() - offset, info))
		{
			if (logger && label)
				logger->LogDebug("%s: invalid instruction at 0x%llx+%zu", label, (unsigned long long)checkAddr, offset);
			return false;
		}
		
		if (info.length == 0)
		{
			if (logger && label)
				logger->LogDebug("%s: zero-length instruction at 0x%llx+%zu", label, (unsigned long long)checkAddr, offset);
			return false;
		}

		validCount++;
		offset += info.length;
		
		/* Stop if we hit an unconditional branch/return - function might be very short */
		for (size_t i = 0; i < info.branchCount; i++)
		{
			if (info.branchType[i] == UnconditionalBranch ||
			    info.branchType[i] == FunctionReturn)
			{
				/* Accept short functions that end with branch/return */
				if (validCount >= 1)
					return true;
			}
		}
	}

	return validCount >= kMinValidInstructions;
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
