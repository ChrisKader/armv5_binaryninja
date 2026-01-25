/*
 * Code/Data Classifier Utilities
 *
 * Shared heuristics for distinguishing code from data in ARMv5 binaries.
 * These functions are used by FunctionDetector, LinearSweepAnalyzer, and
 * RecursiveDescentAnalyzer to avoid duplicated logic.
 *
 * All functions are header-only inlines for zero-overhead integration.
 */

#pragma once

#include "binaryninjaapi.h"

#include <cstdint>
#include <cstring>

namespace Armv5Analysis
{
namespace CodeDataClassifier
{

/**
 * Check if a byte buffer looks like a null-terminated ASCII string.
 *
 * @param data         Pointer to the data to check
 * @param len          Length of the data buffer
 * @param minPrintable Minimum number of printable characters to qualify (default 10)
 * @return true if the data looks like an ASCII string region
 */
[[nodiscard]] inline bool LooksLikeAsciiString(
	const uint8_t* data, size_t len, size_t minPrintable = 10)
{
	if (!data || len < minPrintable)
		return false;

	int printableCount = 0;
	bool hasNull = false;

	for (size_t i = 0; i < len; i++)
	{
		if (data[i] == 0)
			hasNull = true;
		else if ((data[i] >= 0x20 && data[i] < 0x7F) ||
		         data[i] == '\n' || data[i] == '\r' || data[i] == '\t')
			printableCount++;
	}

	return static_cast<size_t>(printableCount) >= minPrintable && hasNull;
}

/**
 * Check if a byte buffer looks like a pointer table.
 *
 * Scans for consecutive 4-byte-aligned values that fall within the binary's
 * address range. Common in vector tables, vtables, and jump tables.
 *
 * @param data        Pointer to the data to check
 * @param len         Length of the data buffer (must be >= minPointers * 4)
 * @param viewStart   Start address of the binary view
 * @param viewEnd     End address of the binary view
 * @param minPointers Minimum consecutive pointer-like values to qualify (default 4)
 * @return true if the data looks like a pointer table
 */
[[nodiscard]] inline bool LooksLikePointerTable(
	const uint8_t* data, size_t len,
	uint64_t viewStart, uint64_t viewEnd,
	size_t minPointers = 4)
{
	if (!data || len < minPointers * 4)
		return false;

	int ptrCount = 0;
	for (size_t i = 0; i + 4 <= len; i += 4)
	{
		uint32_t val = 0;
		memcpy(&val, data + i, 4);
		if (val >= viewStart && val < viewEnd && (val & 3) == 0)
			ptrCount++;
	}

	return static_cast<size_t>(ptrCount) >= minPointers;
}

/**
 * Comprehensive check for whether an address is in a data region.
 *
 * Consolidates checks from segment flags, section semantics, data variables,
 * string detection, and raw-firmware heuristics (ASCII strings, pointer tables).
 *
 * @param view    The BinaryView to check against
 * @param address The address to classify
 * @return true if the address appears to be in a data region
 */
[[nodiscard]] inline bool IsDataRegion(
	const BinaryNinja::Ref<BinaryNinja::BinaryView>& view,
	uint64_t address)
{
	using namespace BinaryNinja;

	// Check if in a non-executable segment
	auto seg = view->GetSegmentAt(address);
	if (seg && !(seg->GetFlags() & SegmentExecutable))
		return true;

	// Check if address is not backed by file data
	if (!view->IsOffsetBackedByFile(address))
		return true;

	// Check if sections exist and this address lacks code semantics
	if (!view->GetSections().empty() && !view->IsOffsetCodeSemantics(address))
		return true;

	// Check if address is inside an existing data variable
	DataVariable dataVar;
	if (view->GetDataVariableAtAddress(address, dataVar))
	{
		uint64_t dataEnd = dataVar.address;
		if (dataVar.type.GetValue())
			dataEnd = dataVar.address + dataVar.type.GetValue()->GetWidth();
		if (address >= dataVar.address && address < dataEnd)
			return true;
	}

	// Check if address is inside a BN-detected string
	BNStringReference strRef;
	if (view->GetStringAtAddress(address, strRef) && strRef.length > 0)
		return true;

	// For raw firmware without segments, use heuristics
	if (view->GetSegments().empty())
	{
		DataBuffer buf = view->ReadBuffer(address, 16);
		if (buf.GetLength() >= 16)
		{
			const uint8_t* bytes = static_cast<const uint8_t*>(buf.GetData());

			if (LooksLikeAsciiString(bytes, 16))
				return true;

			if (LooksLikePointerTable(bytes, 16, view->GetStart(), view->GetEnd()))
				return true;
		}
	}

	return false;
}

}  // namespace CodeDataClassifier
}  // namespace Armv5Analysis
