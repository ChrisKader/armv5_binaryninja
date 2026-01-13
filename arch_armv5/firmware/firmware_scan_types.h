/*
 * ARMv5 Firmware Scan Types
 *
 * Shared scan plan structures used by firmware analysis.
 */

#pragma once

#include "binaryninjaapi.h"

#include <cstdint>
#include <vector>

struct FirmwareScanDataDefine
{
	uint64_t address;
	BinaryNinja::Ref<BinaryNinja::Type> type;
	bool user = false;
};

struct FirmwareScanPlan
{
	std::vector<uint64_t> addFunctions;
	std::vector<uint64_t> addUserFunctions;
	std::vector<uint64_t> removeFunctions;
	std::vector<FirmwareScanDataDefine> defineData;
	std::vector<uint64_t> undefineData;
	std::vector<BinaryNinja::Ref<BinaryNinja::Symbol>> defineSymbols;

	void Clear()
	{
		addFunctions.clear();
		addUserFunctions.clear();
		removeFunctions.clear();
		defineData.clear();
		undefineData.clear();
		defineSymbols.clear();
	}
};
