/*
 * Linear Sweep Analyzer - Implementation
 *
 * Nucleus-style function detection via basic block grouping.
 */

#include "linear_sweep.h"

#include <algorithm>
#include <chrono>
#include <queue>

using namespace BinaryNinja;

namespace Armv5Analysis
{

// ============================================================================
// Constructor and Presets
// ============================================================================

LinearSweepAnalyzer::LinearSweepAnalyzer(Ref<BinaryView> view)
	: m_view(view)
	, m_settings(DefaultSettings())
{
	m_logger = LogRegistry::CreateLogger("LinearSweepAnalyzer");
}

LinearSweepSettings LinearSweepAnalyzer::DefaultSettings()
{
	return LinearSweepSettings();
}

LinearSweepSettings LinearSweepAnalyzer::AggressiveSettings()
{
	LinearSweepSettings s;
	s.minimumConfidence = 0.2;
	s.minimumBlocksPerFunction = 1;
	s.requireReturnOrCall = false;
	s.tailCallDistanceThreshold = 0x2000;  // More lenient tail call detection
	return s;
}

LinearSweepSettings LinearSweepAnalyzer::ConservativeSettings()
{
	LinearSweepSettings s;
	s.minimumConfidence = 0.5;
	s.minimumBlocksPerFunction = 2;
	s.requireReturnOrCall = true;
	s.tailCallDistanceThreshold = 0x800;
	return s;
}

// ============================================================================
// Main Analysis Entry Points
// ============================================================================

std::vector<LinearFunction> LinearSweepAnalyzer::analyze()
{
	return analyze(m_settings);
}

std::vector<LinearFunction> LinearSweepAnalyzer::analyze(const LinearSweepSettings& settings)
{
	m_settings = settings;
	m_blocks.clear();
	m_groups.clear();
	m_knownFunctionRanges.clear();
	m_nextGroupId = 0;
	m_stats = LinearSweepStats{};

	auto startTime = std::chrono::steady_clock::now();

	reportProgress("Starting linear sweep...", 0.0);

	// Phase 1: Linear disassembly
	reportProgress("Phase 1: Linear disassembly...", 0.1);
	scanRegions();

	if (m_blocks.empty())
	{
		m_logger->LogInfo("Linear sweep: no blocks discovered");
		return {};
	}

	// Phase 2: Connect blocks
	reportProgress("Phase 2: Connecting blocks...", 0.4);
	connectBlocks();

	// Phase 3: Group blocks into functions
	reportProgress("Phase 3: Grouping blocks...", 0.6);
	groupBlocks();

	// Phase 4: Extract functions
	reportProgress("Phase 4: Extracting functions...", 0.8);
	auto functions = extractFunctions();

	auto endTime = std::chrono::steady_clock::now();
	m_stats.scanTimeSeconds = std::chrono::duration<double>(endTime - startTime).count();

	reportProgress("Linear sweep complete", 1.0);

	m_logger->LogInfo("Linear sweep: %zu blocks, %zu groups, %zu functions (%.2fs)",
		m_stats.blocksDiscovered, m_stats.groupsFormed, m_stats.functionsReported,
		m_stats.scanTimeSeconds);

	return functions;
}

// ============================================================================
// Phase 1: Linear Disassembly
// ============================================================================

void LinearSweepAnalyzer::scanRegions()
{
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();

	// Build known function ranges if skipping
	if (m_settings.skipKnownFunctions)
	{
		for (auto& func : m_view->GetAnalysisFunctionList())
		{
			uint64_t funcStart = func->GetStart();
			// Mark a range around the function start
			// We'll check individual addresses against actual basic blocks
			for (auto& bb : func->GetBasicBlocks())
			{
				for (uint64_t addr = bb->GetStart(); addr < bb->GetEnd(); addr++)
				{
					m_knownFunctionRanges.insert(addr);
				}
			}
		}
	}

	// Determine initial mode from entry point or existing functions
	bool defaultThumb = false;
	uint64_t entryPoint = m_view->GetEntryPoint();
	if (entryPoint & 1)
		defaultThumb = true;
	else
	{
		// Check existing functions for predominant mode
		int armCount = 0, thumbCount = 0;
		for (auto& func : m_view->GetAnalysisFunctionList())
		{
			auto arch = func->GetArchitecture();
			if (arch)
			{
				std::string name = arch->GetName();
				if (name.find('t') != std::string::npos || name.find("thumb") != std::string::npos)
					thumbCount++;
				else
					armCount++;
			}
		}
		defaultThumb = thumbCount > armCount;
	}

	// Scan the region
	m_stats.regionsScanned = 1;
	m_stats.totalBytes = end - start;

	scanRegion(start, end, defaultThumb);
}

void LinearSweepAnalyzer::scanRegion(uint64_t start, uint64_t end, bool isThumb)
{
	uint64_t addr = start;
	size_t step = isThumb ? 2 : 4;

	// Align to instruction boundary
	if (m_settings.respectAlignment)
	{
		uint64_t align = isThumb ? 2 : 4;
		addr = (addr + align - 1) & ~(align - 1);
	}

	while (addr < end)
	{
		// Check limits
		if (m_blocks.size() >= m_settings.maxTotalBlocks)
		{
			m_logger->LogDebug("Linear sweep: block limit reached");
			break;
		}

		// Skip if already have a block here
		if (m_blocks.count(addr))
		{
			addr += step;
			continue;
		}

		// Skip if inside known function
		if (m_settings.skipKnownFunctions && isInsideKnownFunction(addr))
		{
			addr += step;
			continue;
		}

		// Skip if data region
		if (m_settings.skipDataRegions && isDataRegion(addr))
		{
			addr += step;
			continue;
		}

		// Try to create and disassemble a block
		LinearBlock* block = createBlock(addr, isThumb);
		if (block && disassembleBlock(block))
		{
			m_stats.blocksDiscovered++;
			if (isThumb)
				m_stats.thumbBlocks++;
			else
				m_stats.armBlocks++;

			// Next address is after this block
			addr = block->end;
		}
		else
		{
			// Failed to create block, move on
			if (block)
			{
				m_blocks.erase(addr);
			}
			m_stats.invalidInstructions++;
			addr += step;
		}
	}
}

LinearBlock* LinearSweepAnalyzer::createBlock(uint64_t address, bool isThumb)
{
	auto block = std::make_unique<LinearBlock>();
	block->start = address;
	block->end = address;
	block->isThumb = isThumb;

	auto* ptr = block.get();
	m_blocks[address] = std::move(block);
	return ptr;
}

bool LinearSweepAnalyzer::disassembleBlock(LinearBlock* block)
{
	uint64_t addr = block->start;
	bool isThumb = block->isThumb;
	size_t instrCount = 0;

	while (instrCount < m_settings.maxInstructionsPerBlock)
	{
		// Check if we've hit another block
		if (addr != block->start && m_blocks.count(addr))
		{
			// Fall through to existing block
			block->successors.push_back(addr);
			block->hasFallthrough = true;
			break;
		}

		// Read and decode instruction
		bool terminated = false;

		if (!isThumb)
		{
			uint32_t instr = readInstruction32(addr);
			if (instr == 0 || instr == 0xFFFFFFFF)
			{
				// Likely data, terminate
				break;
			}

			if (!decodeArmInstruction(addr, instr, block))
			{
				// Invalid instruction
				if (instrCount == 0)
					return false;  // Can't start with invalid
				break;
			}

			addr += 4;
			instrCount++;

			terminated = block->endsWithReturn || block->endsWithUnconditionalBranch ||
			             block->endsWithIndirectBranch;
		}
		else
		{
			if (!decodeThumbInstruction(addr, block))
			{
				if (instrCount == 0)
					return false;
				break;
			}

			// Thumb instructions can be 2 or 4 bytes
			// For simplicity, advance by what was decoded
			// The decode function updates block state
			uint16_t hw1 = readInstruction16(addr);
			bool is32bit = ((hw1 & 0xF800) == 0xE800) || ((hw1 & 0xF800) == 0xF000) ||
			               ((hw1 & 0xF800) == 0xF800);
			addr += is32bit ? 4 : 2;
			instrCount++;

			terminated = block->endsWithReturn || block->endsWithUnconditionalBranch ||
			             block->endsWithIndirectBranch;
		}

		if (terminated)
			break;
	}

	block->end = addr;
	block->instructionCount = instrCount;

	return instrCount > 0;
}

bool LinearSweepAnalyzer::decodeArmInstruction(uint64_t addr, uint32_t instr, LinearBlock* block)
{
	uint32_t cond = (instr >> 28) & 0xF;

	// Unconditional instructions (cond = 0xF)
	if (cond == 0xF)
	{
		// BLX <label> - Unconditional call with mode switch
		if ((instr & 0xFE000000) == 0xFA000000)
		{
			int32_t offset = instr & 0x00FFFFFF;
			if (offset & 0x00800000)
				offset |= 0xFF000000;
			offset = (offset << 2) + ((instr >> 23) & 2) + 8;
			uint64_t target = addr + offset;

			block->callTargets.push_back(target | 1);  // Mark as Thumb target
			block->endsWithCall = true;
			// BLX doesn't terminate - falls through
			block->hasFallthrough = true;
			block->successors.push_back(addr + 4);
			return true;
		}
	}

	// Skip never-execute condition
	if (cond == 0xF)
		return true;  // Valid but does nothing

	// Unconditional (AL) vs conditional
	bool isUnconditional = (cond == 0xE);

	// BX Rm - Branch and exchange
	if ((instr & 0x0FFFFFF0) == 0x012FFF10)
	{
		uint32_t rm = instr & 0xF;
		if (rm == 14)
		{
			// BX LR = return
			block->endsWithReturn = true;
		}
		else
		{
			// BX to register = indirect branch
			block->endsWithIndirectBranch = true;
		}
		return true;
	}

	// BLX Rm - Branch with link and exchange to register
	if ((instr & 0x0FFFFFF0) == 0x012FFF30)
	{
		// Indirect call
		block->endsWithCall = true;
		block->hasFallthrough = true;
		block->successors.push_back(addr + 4);
		return true;
	}

	// B <label> - Branch
	if ((instr & 0x0F000000) == 0x0A000000)
	{
		int32_t offset = instr & 0x00FFFFFF;
		if (offset & 0x00800000)
			offset |= 0xFF000000;
		offset = (offset << 2) + 8;
		uint64_t target = addr + offset;

		block->successors.push_back(target);

		if (isUnconditional)
		{
			block->endsWithUnconditionalBranch = true;
		}
		else
		{
			block->endsWithConditionalBranch = true;
			block->hasFallthrough = true;
			block->successors.push_back(addr + 4);
		}
		return true;
	}

	// BL <label> - Branch with link (call)
	if ((instr & 0x0F000000) == 0x0B000000)
	{
		int32_t offset = instr & 0x00FFFFFF;
		if (offset & 0x00800000)
			offset |= 0xFF000000;
		offset = (offset << 2) + 8;
		uint64_t target = addr + offset;

		block->callTargets.push_back(target);
		block->endsWithCall = true;
		block->hasFallthrough = true;
		block->successors.push_back(addr + 4);
		return true;
	}

	// MOV pc, lr - Return
	if ((instr & 0x0FFFFFFF) == 0x01A0F00E && isUnconditional)
	{
		block->endsWithReturn = true;
		return true;
	}

	// LDM/POP with PC - Return
	// Pattern: LDMFD sp!, {..., pc} or LDMFD sp!, {..., pc}^
	// Encoding: cond 100 P U S W 1 1101 reglist where reglist includes bit 15 (pc)
	// 0x08BD0000 = LDMIA sp!, write-back, load (no S bit)
	// 0x08FD0000 = LDMIA sp!, write-back, load, user mode (S bit set - exception return)
	// Mask out S bit (bit 22) with 0x0FBF0000 to catch both variants
	if ((instr & 0x0FBF0000) == 0x08BD0000 && (instr & (1 << 15)))
	{
		if (isUnconditional)
			block->endsWithReturn = true;
		else
		{
			block->hasFallthrough = true;
			block->successors.push_back(addr + 4);
		}
		return true;
	}

	// LDR pc, [...] - Indirect branch or return
	if ((instr & 0x0F10F000) == 0x0510F000)
	{
		// Load to PC
		uint32_t rn = (instr >> 16) & 0xF;
		if (rn == 13)
		{
			// LDR pc, [sp, ...] - likely return
			block->endsWithReturn = true;
		}
		else if (rn == 15)
		{
			// LDR pc, [pc, #offset] - jump table or thunk
			block->endsWithIndirectBranch = true;
		}
		else
		{
			block->endsWithIndirectBranch = true;
		}
		return true;
	}

	// MOV pc, Rm or ADD pc, ... - Indirect branch
	if (((instr & 0x0FEF0010) == 0x01A0F000) ||  // MOV pc, Rm
	    ((instr & 0x0FEF0010) == 0x008F0000))     // ADD pc, ...
	{
		block->endsWithIndirectBranch = true;
		return true;
	}

	// Default: not a terminator, instruction continues
	return true;
}

bool LinearSweepAnalyzer::decodeThumbInstruction(uint64_t addr, LinearBlock* block)
{
	uint16_t hw1 = readInstruction16(addr);

	// Check for 32-bit Thumb-2 instruction
	bool is32bit = ((hw1 & 0xF800) == 0xE800) || ((hw1 & 0xF800) == 0xF000) ||
	               ((hw1 & 0xF800) == 0xF800);

	if (is32bit)
	{
		uint16_t hw2 = readInstruction16(addr + 2);
		uint32_t instr = ((uint32_t)hw1 << 16) | hw2;

		// BL <label> - 32-bit Thumb call
		if ((instr & 0xF800D000) == 0xF000D000)
		{
			// Decode BL offset
			int32_t s = (instr >> 26) & 1;
			int32_t j1 = (instr >> 13) & 1;
			int32_t j2 = (instr >> 11) & 1;
			int32_t imm10 = (instr >> 16) & 0x3FF;
			int32_t imm11 = instr & 0x7FF;

			int32_t i1 = ~(j1 ^ s) & 1;
			int32_t i2 = ~(j2 ^ s) & 1;

			int32_t offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
			if (s)
				offset |= 0xFE000000;  // Sign extend

			uint64_t target = (addr + 4 + offset) | 1;  // Thumb target

			block->callTargets.push_back(target);
			block->endsWithCall = true;
			block->hasFallthrough = true;
			block->successors.push_back(addr + 4);
			return true;
		}

		// B.W <label> - 32-bit Thumb unconditional branch
		if ((instr & 0xF800D000) == 0xF0009000)
		{
			// Decode B.W offset (similar to BL)
			int32_t s = (instr >> 26) & 1;
			int32_t j1 = (instr >> 13) & 1;
			int32_t j2 = (instr >> 11) & 1;
			int32_t imm10 = (instr >> 16) & 0x3FF;
			int32_t imm11 = instr & 0x7FF;

			int32_t i1 = ~(j1 ^ s) & 1;
			int32_t i2 = ~(j2 ^ s) & 1;

			int32_t offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
			if (s)
				offset |= 0xFE000000;

			uint64_t target = (addr + 4 + offset) | 1;

			block->successors.push_back(target & ~1ULL);
			block->endsWithUnconditionalBranch = true;
			return true;
		}

		// B<cond>.W - 32-bit conditional branch
		if ((instr & 0xF800D000) == 0xF0008000)
		{
			int32_t s = (instr >> 26) & 1;
			int32_t j1 = (instr >> 13) & 1;
			int32_t j2 = (instr >> 11) & 1;
			int32_t imm6 = (instr >> 16) & 0x3F;
			int32_t imm11 = instr & 0x7FF;

			int32_t offset = (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1);
			if (s)
				offset |= 0xFFE00000;

			uint64_t target = (addr + 4 + offset);

			block->successors.push_back(target);
			block->successors.push_back(addr + 4);
			block->endsWithConditionalBranch = true;
			block->hasFallthrough = true;
			return true;
		}

		// POP.W with PC
		if ((instr & 0xFFFF8000) == 0xE8BD8000)
		{
			block->endsWithReturn = true;
			return true;
		}
	}
	else
	{
		// 16-bit Thumb instruction

		// B<cond> - Conditional branch (8-bit offset)
		if ((hw1 & 0xF000) == 0xD000 && ((hw1 >> 8) & 0xF) < 0xE)
		{
			int8_t offset = hw1 & 0xFF;
			uint64_t target = addr + 4 + (offset << 1);

			block->successors.push_back(target);
			block->successors.push_back(addr + 2);
			block->endsWithConditionalBranch = true;
			block->hasFallthrough = true;
			return true;
		}

		// B - Unconditional branch (11-bit offset)
		if ((hw1 & 0xF800) == 0xE000)
		{
			int32_t offset = hw1 & 0x7FF;
			if (offset & 0x400)
				offset |= 0xFFFFF800;  // Sign extend
			uint64_t target = addr + 4 + (offset << 1);

			block->successors.push_back(target);
			block->endsWithUnconditionalBranch = true;
			return true;
		}

		// BX Rm
		if ((hw1 & 0xFF80) == 0x4700)
		{
			uint32_t rm = (hw1 >> 3) & 0xF;
			if (rm == 14)
			{
				block->endsWithReturn = true;
			}
			else
			{
				block->endsWithIndirectBranch = true;
			}
			return true;
		}

		// BLX Rm
		if ((hw1 & 0xFF80) == 0x4780)
		{
			block->endsWithCall = true;
			block->hasFallthrough = true;
			block->successors.push_back(addr + 2);
			return true;
		}

		// POP with PC
		if ((hw1 & 0xFE00) == 0xBC00 && (hw1 & 0x0100))
		{
			block->endsWithReturn = true;
			return true;
		}

		// MOV pc, Rm (rare in Thumb)
		if ((hw1 & 0xFF87) == 0x4687)
		{
			block->endsWithIndirectBranch = true;
			return true;
		}
	}

	// Default: valid instruction, not a terminator
	return true;
}

// ============================================================================
// Phase 2: Connect Blocks
// ============================================================================

void LinearSweepAnalyzer::connectBlocks()
{
	// Build predecessor lists from successor lists
	for (auto& [addr, block] : m_blocks)
	{
		for (uint64_t succ : block->successors)
		{
			auto it = m_blocks.find(succ);
			if (it != m_blocks.end())
			{
				it->second->predecessors.push_back(addr);
			}
		}
	}
}

// ============================================================================
// Phase 3: Group Blocks into Functions
// ============================================================================

void LinearSweepAnalyzer::groupBlocks()
{
	// Key insight from Nucleus paper:
	// - Conditional branches are intraprocedural (stay within function)
	// - Calls are interprocedural (cross function boundary)
	// - Unconditional branches might be tail calls (interprocedural) or just jumps

	// Start with each block ungrouped (groupId = -1)
	// Propagate groups through intraprocedural edges

	for (auto& [addr, block] : m_blocks)
	{
		if (block->groupId >= 0)
			continue;  // Already grouped

		// Start a new group from this block
		int groupId = m_nextGroupId++;
		propagateGroup(block.get(), groupId);
	}

	// Collect groups
	for (auto& [addr, block] : m_blocks)
	{
		if (block->groupId >= 0)
		{
			m_groups[block->groupId].push_back(block.get());
		}
	}

	m_stats.groupsFormed = m_groups.size();
}

void LinearSweepAnalyzer::propagateGroup(LinearBlock* block, int groupId)
{
	if (block->groupId >= 0)
		return;  // Already assigned

	block->groupId = groupId;

	// Propagate through intraprocedural edges

	// Follow conditional branches (definitely intraprocedural)
	if (block->endsWithConditionalBranch)
	{
		for (uint64_t succ : block->successors)
		{
			auto it = m_blocks.find(succ);
			if (it != m_blocks.end())
			{
				propagateGroup(it->second.get(), groupId);
			}
		}
	}

	// Follow fall-through (definitely intraprocedural)
	if (block->hasFallthrough)
	{
		for (uint64_t succ : block->successors)
		{
			auto it = m_blocks.find(succ);
			if (it != m_blocks.end())
			{
				propagateGroup(it->second.get(), groupId);
			}
		}
	}

	// Unconditional branches: check if likely tail call
	if (block->endsWithUnconditionalBranch && !block->successors.empty())
	{
		uint64_t target = block->successors[0];
		int64_t distance = static_cast<int64_t>(target) - static_cast<int64_t>(block->start);

		// If branch is within threshold, treat as intraprocedural
		if (!m_settings.treatUnconditionalBranchAsInterprocedural ||
		    std::abs(distance) <= m_settings.tailCallDistanceThreshold)
		{
			auto it = m_blocks.find(target);
			if (it != m_blocks.end())
			{
				propagateGroup(it->second.get(), groupId);
			}
		}
		// Otherwise, treat as tail call (interprocedural) - don't propagate
	}

	// Also propagate to predecessors that flow to us
	for (uint64_t pred : block->predecessors)
	{
		auto it = m_blocks.find(pred);
		if (it != m_blocks.end())
		{
			LinearBlock* predBlock = it->second.get();
			// Only propagate if predecessor flows to us via intraprocedural edge
			if (predBlock->endsWithConditionalBranch || predBlock->hasFallthrough)
			{
				propagateGroup(predBlock, groupId);
			}
		}
	}
}

// ============================================================================
// Phase 4: Extract Functions from Groups
// ============================================================================

std::vector<LinearFunction> LinearSweepAnalyzer::extractFunctions()
{
	std::vector<LinearFunction> functions;

	for (auto& [groupId, blocks] : m_groups)
	{
		if (blocks.empty())
			continue;

		// Find entry point (earliest address in group)
		std::sort(blocks.begin(), blocks.end(),
			[](const LinearBlock* a, const LinearBlock* b) { return a->start < b->start; });

		LinearFunction func;
		func.entryPoint = blocks[0]->start;
		func.isThumb = blocks[0]->isThumb;
		func.blockCount = blocks.size();

		for (const LinearBlock* block : blocks)
		{
			func.blockAddresses.push_back(block->start);
			func.instructionCount += block->instructionCount;

			if (block->endsWithReturn)
				func.hasReturn = true;
			if (block->endsWithCall || !block->callTargets.empty())
				func.hasCall = true;
		}

		func.hasMultipleBlocks = func.blockCount > 1;

		// Check if this function is referenced by a call from another group
		for (const LinearBlock* block : blocks)
		{
			if (block->start == func.entryPoint)
			{
				// Check if any call targets point here
				for (auto& [addr, otherBlock] : m_blocks)
				{
					if (otherBlock->groupId != groupId)
					{
						for (uint64_t callTarget : otherBlock->callTargets)
						{
							if ((callTarget & ~1ULL) == func.entryPoint)
							{
								func.isReferencedByCall = true;
								break;
							}
						}
					}
					if (func.isReferencedByCall)
						break;
				}
				break;
			}
		}

		// Calculate confidence
		func.confidence = calculateConfidence(func);

		// Apply filters

		// Enforce alignment: ARM must be 4-byte aligned, Thumb must be 2-byte aligned
		if (m_settings.enforceAlignment)
		{
			bool misaligned = false;
			if (!func.isThumb && (func.entryPoint & 3))
				misaligned = true;
			if (func.isThumb && (func.entryPoint & 1))
				misaligned = true;
			if (misaligned)
				continue;  // Skip misaligned functions
		}

		if (func.confidence < m_settings.minimumConfidence)
			continue;

		if (func.blockCount < m_settings.minimumBlocksPerFunction)
			continue;

		// For single-block functions, require either a return or a call
		// Multi-block functions have structural evidence of being functions
		if (m_settings.requireReturnOrCall && func.blockCount == 1 && !func.hasReturn && !func.hasCall)
			continue;

		functions.push_back(std::move(func));
	}

	// Sort by entry point
	std::sort(functions.begin(), functions.end(),
		[](const LinearFunction& a, const LinearFunction& b) {
			return a.entryPoint < b.entryPoint;
		});

	m_stats.functionsReported = functions.size();
	return functions;
}

double LinearSweepAnalyzer::calculateConfidence(const LinearFunction& func)
{
	double score = 0.3;  // Base score

	// Multiple blocks is strong evidence
	if (func.hasMultipleBlocks)
		score += 0.2;

	// Having a return is good
	if (func.hasReturn)
		score += 0.2;

	// Making calls is evidence of real function
	if (func.hasCall)
		score += 0.1;

	// Being called by others is very strong evidence
	if (func.isReferencedByCall)
		score += 0.3;

	// More instructions = more confidence
	if (func.instructionCount >= 5)
		score += 0.1;
	if (func.instructionCount >= 20)
		score += 0.1;

	return std::min(1.0, score);
}

// ============================================================================
// Helper Methods
// ============================================================================

bool LinearSweepAnalyzer::isValidAddress(uint64_t addr)
{
	return m_view->IsValidOffset(addr);
}

bool LinearSweepAnalyzer::isExecutable(uint64_t addr)
{
	// If no segments, assume everything is executable (raw binary)
	if (m_view->GetSegments().empty())
		return m_view->IsValidOffset(addr);

	return m_view->IsOffsetExecutable(addr);
}

bool LinearSweepAnalyzer::isInsideKnownFunction(uint64_t addr)
{
	return m_knownFunctionRanges.count(addr) > 0;
}

bool LinearSweepAnalyzer::isDataRegion(uint64_t addr)
{
	// Check if explicitly marked as data
	DataVariable var;
	if (m_view->GetDataVariableAtAddress(addr, var))
		return true;

	// Check section semantics
	if (!m_view->GetSections().empty() && !m_view->IsOffsetCodeSemantics(addr))
		return true;
	
	// For raw firmware without sections, use heuristics to detect data
	if (m_view->GetSections().empty())
	{
		// Check if this looks like ASCII string data
		DataBuffer buf = m_view->ReadBuffer(addr, 16);
		if (buf.GetLength() >= 16)
		{
			const uint8_t* bytes = static_cast<const uint8_t*>(buf.GetData());
			int printableCount = 0;
			bool hasNull = false;
			for (size_t i = 0; i < 16; i++)
			{
				if (bytes[i] == 0)
					hasNull = true;
				else if ((bytes[i] >= 0x20 && bytes[i] < 0x7F) || bytes[i] == '\n' || bytes[i] == '\r' || bytes[i] == '\t')
					printableCount++;
			}
			// If mostly printable ASCII with at least one null, likely a string region
			if (printableCount >= 10 && hasNull)
				return true;
		}
	}

	return false;
}

uint32_t LinearSweepAnalyzer::readInstruction32(uint64_t addr)
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

uint16_t LinearSweepAnalyzer::readInstruction16(uint64_t addr)
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

bool LinearSweepAnalyzer::reportProgress(const std::string& message, double progress)
{
	if (m_progressCallback)
		return m_progressCallback(message, progress);
	return true;
}

}  // namespace Armv5Analysis
