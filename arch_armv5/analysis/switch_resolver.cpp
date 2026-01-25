/*
 * Switch Table Resolver - Implementation
 */

#include "switch_resolver.h"

#include <algorithm>

using namespace BinaryNinja;

namespace Armv5Analysis
{

SwitchResolver::SwitchResolver(Ref<BinaryView> view)
	: m_view(view)
	, m_settings()
{
	m_logger = LogRegistry::CreateLogger("ARMv5.SwitchResolver");
}

std::vector<ResolvedSwitch> SwitchResolver::resolveAll()
{
	return resolveAll(m_settings);
}

std::vector<ResolvedSwitch> SwitchResolver::resolveAll(const SwitchResolverSettings& settings)
{
	m_settings = settings;
	m_resolved.clear();
	m_stats = Stats{};

	uint64_t start = settings.scanStart ? settings.scanStart : m_view->GetStart();
	uint64_t end = settings.scanEnd ? settings.scanEnd : m_view->GetEnd();

	m_logger->LogDebug("SwitchResolver: Scanning for switch tables in [0x%llx, 0x%llx)",
		(unsigned long long)start, (unsigned long long)end);

	// Scan for Thumb-2 TBB/TBH patterns
	for (uint64_t addr = start; addr + 4 <= end; addr += 2)
	{
		if (m_resolved.size() >= settings.maxTotalTables)
			break;

		ResolvedSwitch result;

		// Check for TBB (E8D0F000 pattern with variations)
		if (detectTbbPattern(addr, result))
		{
			if (result.confidence >= settings.minimumConfidence)
			{
				m_resolved.push_back(result);
				m_stats.tablesFound++;
				m_stats.tbbTables++;
				m_stats.totalTargets += result.targets.size();
			}
			continue;
		}

		// Check for TBH
		if (detectTbhPattern(addr, result))
		{
			if (result.confidence >= settings.minimumConfidence)
			{
				m_resolved.push_back(result);
				m_stats.tablesFound++;
				m_stats.tbhTables++;
				m_stats.totalTargets += result.targets.size();
			}
			continue;
		}
	}

	// Scan for ARM switch patterns (4-byte aligned)
	for (uint64_t addr = (start + 3) & ~3ULL; addr + 4 <= end; addr += 4)
	{
		if (m_resolved.size() >= settings.maxTotalTables)
			break;

		ResolvedSwitch result;

		// LDR pc, [pc, Rn, LSL #2]
		if (detectArmLdrPcPattern(addr, result))
		{
			if (result.confidence >= settings.minimumConfidence)
			{
				m_resolved.push_back(result);
				m_stats.tablesFound++;
				m_stats.armTables++;
				m_stats.totalTargets += result.targets.size();
			}
			continue;
		}

		// ADD pc, pc, Rn, LSL #2
		if (detectArmAddPcPattern(addr, result))
		{
			if (result.confidence >= settings.minimumConfidence)
			{
				m_resolved.push_back(result);
				m_stats.tablesFound++;
				m_stats.armTables++;
				m_stats.totalTargets += result.targets.size();
			}
			continue;
		}

		// ARM jump table (sequence of pointers)
		if (detectArmJumpTable(addr, result))
		{
			if (result.confidence >= settings.minimumConfidence)
			{
				m_resolved.push_back(result);
				m_stats.tablesFound++;
				m_stats.armTables++;
				m_stats.totalTargets += result.targets.size();
			}
			continue;
		}
	}

	m_logger->LogInfo("SwitchResolver: Found %zu switch tables with %zu total targets",
		m_stats.tablesFound, m_stats.totalTargets);

	return m_resolved;
}

bool SwitchResolver::resolveAt(uint64_t address, bool isThumb, ResolvedSwitch& result)
{
	if (isThumb)
	{
		if (detectTbbPattern(address, result))
			return true;
		if (detectTbhPattern(address, result))
			return true;
	}
	else
	{
		if (detectArmLdrPcPattern(address, result))
			return true;
		if (detectArmAddPcPattern(address, result))
			return true;
		if (detectArmJumpTable(address, result))
			return true;
	}

	return false;
}

std::set<uint64_t> SwitchResolver::getAllTargets() const
{
	std::set<uint64_t> targets;
	for (const auto& sw : m_resolved)
	{
		for (uint64_t target : sw.targets)
		{
			targets.insert(target & ~1ULL);  // Clear Thumb bit for address
		}
	}
	return targets;
}

// ============================================================================
// Pattern Detection - Thumb-2 TBB
// ============================================================================

bool SwitchResolver::detectTbbPattern(uint64_t addr, ResolvedSwitch& result)
{
	// TBB [Rn, Rm] - Table Branch Byte
	// Encoding: 1110 1000 1101 nnnn 1111 0000 0000 mmmm
	// E8Dn F00m

	uint16_t hw1 = readInstruction16(addr);
	uint16_t hw2 = readInstruction16(addr + 2);
	uint32_t instr = ((uint32_t)hw1 << 16) | hw2;

	// Check for TBB pattern
	if ((instr & 0xFFF0FFF0) != 0xE8D0F000)
		return false;

	uint32_t rn = (instr >> 16) & 0xF;
	uint32_t rm = instr & 0xF;

	// Most common: TBB [pc, Rm] where table immediately follows
	if (rn != 15)
		return false;  // We only handle PC-relative tables for now

	result.branchAddress = addr;
	result.isThumb = true;
	result.type = SwitchTableType::TBB;
	result.entrySize = 1;

	// Table starts after the TBB instruction
	// TBB is 4 bytes, so table is at addr + 4
	result.tableAddress = addr + 4;

	// Read table entries
	// Base address for TBB is PC + 4 (after the TBB instruction)
	uint64_t baseAddr = addr + 4;
	result.targets = readByteTable(result.tableAddress, baseAddr, m_settings.maxTableEntries);
	result.entryCount = result.targets.size();

	if (result.targets.size() < 2)
		return false;  // Need at least 2 entries for a valid switch

	result.confidence = 0.9;
	result.description = "TBB [pc, Rm] with " + std::to_string(result.entryCount) + " entries";

	return true;
}

// ============================================================================
// Pattern Detection - Thumb-2 TBH
// ============================================================================

bool SwitchResolver::detectTbhPattern(uint64_t addr, ResolvedSwitch& result)
{
	// TBH [Rn, Rm, LSL #1] - Table Branch Halfword
	// Encoding: 1110 1000 1101 nnnn 1111 0000 0001 mmmm
	// E8Dn F01m

	uint16_t hw1 = readInstruction16(addr);
	uint16_t hw2 = readInstruction16(addr + 2);
	uint32_t instr = ((uint32_t)hw1 << 16) | hw2;

	// Check for TBH pattern
	if ((instr & 0xFFF0FFF0) != 0xE8D0F010)
		return false;

	uint32_t rn = (instr >> 16) & 0xF;
	uint32_t rm = instr & 0xF;

	if (rn != 15)
		return false;  // Only handle PC-relative

	result.branchAddress = addr;
	result.isThumb = true;
	result.type = SwitchTableType::TBH;
	result.entrySize = 2;

	// Table starts after the TBH instruction
	result.tableAddress = addr + 4;

	// Read table entries (halfword offsets, doubled)
	uint64_t baseAddr = addr + 4;
	result.targets = readHalfwordTable(result.tableAddress, baseAddr, m_settings.maxTableEntries);
	result.entryCount = result.targets.size();

	if (result.targets.size() < 2)
		return false;

	result.confidence = 0.9;
	result.description = "TBH [pc, Rm, LSL #1] with " + std::to_string(result.entryCount) + " entries";

	return true;
}

// ============================================================================
// Pattern Detection - ARM LDR pc, [pc, Rn, LSL #2]
// ============================================================================

bool SwitchResolver::detectArmLdrPcPattern(uint64_t addr, ResolvedSwitch& result)
{
	uint32_t instr = readInstruction32(addr);
	uint32_t cond = (instr >> 28) & 0xF;

	// LDR pc, [pc, Rn, LSL #2]
	// Encoding: cond 0111 1001 1111 1111 ssss s000 mmmm
	// Where ssss s = 00010 for LSL #2

	if ((instr & 0x0FFFFF00) != 0x079FF100)
		return false;

	// Must be unconditional or always
	if (cond != 0xE && cond != 0xF)
		return false;

	result.branchAddress = addr;
	result.isThumb = false;
	result.type = SwitchTableType::LdrPcIndexed;
	result.entrySize = 4;

	// Table is at PC + 8 (ARM pipeline)
	result.tableAddress = addr + 8;

	// Read word table
	result.targets = readWordTable(result.tableAddress, m_settings.maxTableEntries);
	result.entryCount = result.targets.size();

	if (result.targets.size() < 2)
		return false;

	result.confidence = 0.85;
	result.description = "LDR pc, [pc, Rn, LSL #2] with " + std::to_string(result.entryCount) + " entries";

	return true;
}

// ============================================================================
// Pattern Detection - ARM ADD pc, pc, Rn, LSL #2
// ============================================================================

bool SwitchResolver::detectArmAddPcPattern(uint64_t addr, ResolvedSwitch& result)
{
	uint32_t instr = readInstruction32(addr);
	uint32_t cond = (instr >> 28) & 0xF;

	// ADD pc, pc, Rn, LSL #2
	// Encoding: cond 0000 1000 1111 1111 0001 0000 mmmm

	if ((instr & 0x0FFFFFF0) != 0x008FF100)
		return false;

	if (cond != 0xE)
		return false;

	result.branchAddress = addr;
	result.isThumb = false;
	result.type = SwitchTableType::AddPcIndexed;
	result.entrySize = 4;

	// With ADD pc, pc, Rn, LSL #2, targets are PC + 8 + Rn*4
	// So each "entry" is a 4-byte offset from the base
	// The "table" conceptually starts at PC+8
	result.tableAddress = addr + 8;

	// For ADD pattern, we can't easily read a table - targets are computed
	// We look for a sequence of branch instructions following
	std::vector<uint64_t> targets;
	for (size_t i = 0; i < m_settings.maxTableEntries; i++)
	{
		uint64_t targetAddr = addr + 8 + i * 4;
		uint32_t targetInstr = readInstruction32(targetAddr);

		// Each slot should be a B instruction
		if ((targetInstr & 0x0F000000) != 0x0A000000)
			break;

		// Decode branch target
		int32_t offset = targetInstr & 0x00FFFFFF;
		if (offset & 0x00800000)
			offset |= 0xFF000000;
		uint64_t dest = targetAddr + 8 + (offset << 2);

		targets.push_back(dest);
	}

	result.targets = targets;
	result.entryCount = targets.size();

	if (targets.size() < 2)
		return false;

	result.confidence = 0.7;
	result.description = "ADD pc, pc, Rn, LSL #2 with " + std::to_string(result.entryCount) + " cases";

	return true;
}

// ============================================================================
// Pattern Detection - ARM Jump Table (pointer array)
// ============================================================================

bool SwitchResolver::detectArmJumpTable(uint64_t addr, ResolvedSwitch& result)
{
	// Look for a sequence of valid code pointers that could be a jump table
	// This is used after a LDR pc, [Rn, Rm, LSL #2] or similar

	// First check if there's an indirect branch instruction before this
	uint32_t prevInstr = 0;
	if (addr >= 8)
	{
		prevInstr = readInstruction32(addr - 4);
	}

	// Look for LDR pc, [Rn, Rm, LSL #2] pattern before
	bool hasIndirectBranch = (prevInstr & 0x0F700010) == 0x07100000 &&
	                         ((prevInstr >> 12) & 0xF) == 15;

	if (!hasIndirectBranch)
		return false;  // Only resolve tables that follow an indirect branch

	result.branchAddress = addr - 4;
	result.isThumb = false;
	result.type = SwitchTableType::ArmJumpTable;
	result.tableAddress = addr;
	result.entrySize = 4;

	// Read pointer table
	result.targets = readWordTable(addr, m_settings.maxTableEntries);
	result.entryCount = result.targets.size();

	if (result.targets.size() < 2)
		return false;

	result.confidence = 0.6;
	result.description = "ARM pointer table with " + std::to_string(result.entryCount) + " entries";

	return true;
}

// ============================================================================
// Table Reading
// ============================================================================

std::vector<uint64_t> SwitchResolver::readByteTable(uint64_t tableAddr, uint64_t baseAddr,
	size_t maxEntries)
{
	std::vector<uint64_t> targets;

	uint64_t codeEnd = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();

	for (size_t i = 0; i < maxEntries; i++)
	{
		uint8_t offset = readByte(tableAddr + i);

		// TBB: target = PC + offset * 2
		uint64_t target = baseAddr + offset * 2;

		// Validate target is within bounds and looks like code
		if (target < baseAddr || target >= codeEnd)
			break;

		if (m_settings.validateTargets && !isValidCodeTarget(target, true))
		{
			// Allow a few invalid entries (could be alignment padding)
			if (offset == 0)
				continue;
			break;
		}

		targets.push_back(target | 1);  // Mark as Thumb
	}

	return targets;
}

std::vector<uint64_t> SwitchResolver::readHalfwordTable(uint64_t tableAddr, uint64_t baseAddr,
	size_t maxEntries)
{
	std::vector<uint64_t> targets;

	uint64_t codeEnd = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();

	for (size_t i = 0; i < maxEntries; i++)
	{
		uint16_t offset = readInstruction16(tableAddr + i * 2);

		// TBH: target = PC + offset * 2
		uint64_t target = baseAddr + offset * 2;

		if (target < baseAddr || target >= codeEnd)
			break;

		if (m_settings.validateTargets && !isValidCodeTarget(target, true))
			break;

		targets.push_back(target | 1);
	}

	return targets;
}

std::vector<uint64_t> SwitchResolver::readWordTable(uint64_t tableAddr, size_t maxEntries)
{
	std::vector<uint64_t> targets;

	uint64_t codeStart = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t codeEnd = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();

	for (size_t i = 0; i < maxEntries; i++)
	{
		uint32_t ptr = readInstruction32(tableAddr + i * 4);

		// Check if this looks like a valid code pointer
		uint64_t target = ptr & ~1ULL;
		bool isThumb = ptr & 1;

		if (target < codeStart || target >= codeEnd)
			break;

		if (m_settings.validateTargets && !isValidCodeTarget(target, isThumb))
			break;

		targets.push_back(ptr);
	}

	return targets;
}

// ============================================================================
// Validation
// ============================================================================

bool SwitchResolver::isValidCodeTarget(uint64_t addr, bool expectThumb)
{
	if (!m_view->IsValidOffset(addr))
		return false;

	// Check if it's executable (or assume yes for raw binaries)
	if (!m_view->GetSegments().empty() && !m_view->IsOffsetExecutable(addr))
		return false;

	// Try to decode an instruction
	if (expectThumb)
	{
		uint16_t instr = readInstruction16(addr);
		// Check for obviously invalid patterns
		if (instr == 0x0000 || instr == 0xFFFF)
			return false;
		// Could add more validation
	}
	else
	{
		uint32_t instr = readInstruction32(addr);
		if (instr == 0x00000000 || instr == 0xFFFFFFFF)
			return false;
		// Check for undefined instruction patterns
		uint32_t opcode = (instr >> 25) & 0x7;
		if (opcode == 0x3 && (instr & (1 << 4)))
			return false;  // Undefined
	}

	return true;
}

bool SwitchResolver::isTableBounded(uint64_t tableAddr, size_t entrySize, size_t& entryCount)
{
	// Try to determine table bounds by looking for termination
	entryCount = 0;

	uint64_t codeEnd = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();

	for (size_t i = 0; i < m_settings.maxTableEntries; i++)
	{
		uint64_t entryAddr = tableAddr + i * entrySize;
		if (entryAddr >= codeEnd)
			break;

		// Check if we've hit code (indicates end of table)
		// This is heuristic - look for instruction patterns
		if (entrySize == 4)
		{
			uint32_t val = readInstruction32(entryAddr);
			// Check if this looks like an instruction vs a pointer
			// ARM instructions often have condition codes in top nibble
			uint32_t cond = (val >> 28) & 0xF;
			if (cond <= 0xE && ((val & 0x0FFFFFF0) != 0))
			{
				// Might be an instruction, check common patterns
				// This is very heuristic
			}
		}

		entryCount++;
	}

	return entryCount > 0;
}

// ============================================================================
// Helpers
// ============================================================================

uint32_t SwitchResolver::readInstruction32(uint64_t addr)
{
	DataBuffer buf = m_view->ReadBuffer(addr, 4);
	if (buf.GetLength() < 4)
		return 0;

	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	if (m_view->GetDefaultEndianness() == LittleEndian)
		return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
	else
		return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

uint16_t SwitchResolver::readInstruction16(uint64_t addr)
{
	DataBuffer buf = m_view->ReadBuffer(addr, 2);
	if (buf.GetLength() < 2)
		return 0;

	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	if (m_view->GetDefaultEndianness() == LittleEndian)
		return data[0] | (data[1] << 8);
	else
		return (data[0] << 8) | data[1];
}

uint8_t SwitchResolver::readByte(uint64_t addr)
{
	DataBuffer buf = m_view->ReadBuffer(addr, 1);
	if (buf.GetLength() < 1)
		return 0;

	return static_cast<const uint8_t*>(buf.GetData())[0];
}

}  // namespace Armv5Analysis
