/*
 * Enhanced Prologue/Epilogue Pattern Detection - Implementation
 */

#include "prologue_patterns.h"

#include <algorithm>

using namespace BinaryNinja;

namespace Armv5Analysis
{

PrologueMatcher::PrologueMatcher(Ref<BinaryView> view)
	: m_view(view)
{
	initializePatterns();
}

void PrologueMatcher::initializePatterns()
{
	addArmPatterns();
	addThumbPatterns();
	addArmEpiloguePatterns();
	addThumbEpiloguePatterns();
}

// ============================================================================
// ARM Prologue Patterns
// ============================================================================

void PrologueMatcher::addArmPatterns()
{
	addArmGccPatterns();
	addArmArmccPatterns();
	addArmIarPatterns();
	addArmInterruptPatterns();
}

void PrologueMatcher::addArmGccPatterns()
{
	// GCC Pattern 1: PUSH {regs, lr} + SUB sp, sp, #imm
	// Very common for non-leaf functions with local variables
	{
		ProloguePattern p;
		p.name = "GCC PUSH+SUB";
		p.compiler = "GCC";
		p.isThumb = false;
		p.baseConfidence = 0.9;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = -1;
		p.reglistPosition = 0;
		p.stackImmPosition = 0;
		p.stackImmScale = 1;

		// PUSH {regs, lr} = STMDB sp!, {regs} with LR
		// Encoding: cond 1001 0010 1101 reglist
		p.instructions.push_back({0x092D0000, 0x0FFF0000, false, false});
		// SUB sp, sp, #imm
		// Encoding: cond 0010 0100 1101 1101 imm12
		p.instructions.push_back({0x024DD000, 0x0FFF0000, false, true});

		m_armPrologues.push_back(p);
	}

	// GCC Pattern 2: PUSH {regs, lr} only (small functions)
	{
		ProloguePattern p;
		p.name = "GCC PUSH only";
		p.compiler = "GCC";
		p.isThumb = false;
		p.baseConfidence = 0.8;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = -1;
		p.reglistPosition = 0;

		p.instructions.push_back({0x092D0000, 0x0FFF0000, false, false});

		m_armPrologues.push_back(p);
	}

	// GCC Pattern 3: STR lr, [sp, #-4]! + SUB sp, sp, #imm
	// Single register save followed by stack allocation
	{
		ProloguePattern p;
		p.name = "GCC STR LR+SUB";
		p.compiler = "GCC";
		p.isThumb = false;
		p.baseConfidence = 0.75;
		p.lrBitPosition = -1;
		p.fpBitPosition = -1;

		// STR lr, [sp, #-4]!
		// Encoding: cond 0101 0010 0 1101 1110 0000 0000 0100
		p.instructions.push_back({0x052DE004, 0x0FFFFFFF, false, false});
		// SUB sp, sp, #imm
		p.instructions.push_back({0x024DD000, 0x0FFF0000, false, false});

		m_armPrologues.push_back(p);
	}

	// GCC Pattern 4: MOV ip, sp + PUSH {fp, ip, lr, pc}
	// Full stack frame setup
	{
		ProloguePattern p;
		p.name = "GCC full frame";
		p.compiler = "GCC";
		p.isThumb = false;
		p.baseConfidence = 0.95;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = ArmRegs::FP;

		// MOV ip, sp
		// Encoding: cond 0001 1010 0000 1100 0000 0000 1101
		p.instructions.push_back({0x01A0C00D, 0x0FFFFFFF, false, false});
		// PUSH {fp, ip, lr, pc} or subset
		p.instructions.push_back({0x092D0000, 0x0FFF0000, false, false});

		m_armPrologues.push_back(p);
	}
}

void PrologueMatcher::addArmArmccPatterns()
{
	// ARMCC Pattern 1: STMFD sp!, {regs, lr} with ip
	// ARMCC often includes r12 (ip) in the save list
	{
		ProloguePattern p;
		p.name = "ARMCC STMFD with IP";
		p.compiler = "ARMCC";
		p.isThumb = false;
		p.baseConfidence = 0.85;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = -1;
		p.reglistPosition = 0;

		// STMFD sp!, {regs} with r12 and lr
		p.instructions.push_back({0x092D5000, 0x0FFF5000, false, false});

		m_armPrologues.push_back(p);
	}

	// ARMCC Pattern 2: MOV ip, sp + STMFD sp!, {fp, ip, lr, pc} + SUB fp, ip, #4
	{
		ProloguePattern p;
		p.name = "ARMCC full frame";
		p.compiler = "ARMCC";
		p.isThumb = false;
		p.baseConfidence = 0.95;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = ArmRegs::FP;

		// MOV ip, sp
		p.instructions.push_back({0x01A0C00D, 0x0FFFFFFF, false, false});
		// STMFD sp!, {fp, ip, lr, pc}
		p.instructions.push_back({0x092DD800, 0x0FFFFFFF, false, false});
		// SUB fp, ip, #4
		p.instructions.push_back({0x024CB004, 0x0FFFFFFF, false, true});

		m_armPrologues.push_back(p);
	}
}

void PrologueMatcher::addArmIarPatterns()
{
	// IAR Pattern 1: Similar to GCC, PUSH + SUB
	{
		ProloguePattern p;
		p.name = "IAR PUSH+SUB";
		p.compiler = "IAR";
		p.isThumb = false;
		p.baseConfidence = 0.85;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = -1;
		p.reglistPosition = 0;

		p.instructions.push_back({0x092D0000, 0x0FFF0000, false, false});
		p.instructions.push_back({0x024DD000, 0x0FFF0000, false, true});

		m_armPrologues.push_back(p);
	}
}

void PrologueMatcher::addArmInterruptPatterns()
{
	// IRQ Handler Pattern 1: SUB lr, lr, #4 + STMFD sp!, {regs, lr}
	// Adjusts return address and saves context
	{
		ProloguePattern p;
		p.name = "IRQ handler";
		p.compiler = "any";
		p.isThumb = false;
		p.baseConfidence = 0.9;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = -1;

		// SUB lr, lr, #4
		p.instructions.push_back({0xE24EE004, 0xFFFFFFFF, false, false});
		// STMFD sp!, {regs, lr}
		p.instructions.push_back({0xE92D0000, 0xFFFF0000, false, false});

		m_armPrologues.push_back(p);
	}

	// FIQ Handler Pattern: Similar but may use different registers
	{
		ProloguePattern p;
		p.name = "FIQ handler";
		p.compiler = "any";
		p.isThumb = false;
		p.baseConfidence = 0.85;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = -1;

		// SUB lr, lr, #4
		p.instructions.push_back({0xE24EE004, 0xFFFFFFFF, false, false});
		// STMFD sp!, {regs} - FIQ has banked r8-r14
		p.instructions.push_back({0xE92D0000, 0xFFFF0000, false, false});

		m_armPrologues.push_back(p);
	}

	// SVC Handler Pattern
	{
		ProloguePattern p;
		p.name = "SVC handler";
		p.compiler = "any";
		p.isThumb = false;
		p.baseConfidence = 0.8;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = -1;

		// STMFD sp!, {regs, lr}^ (user mode registers)
		p.instructions.push_back({0xE96D0000, 0xFFFF0000, false, false});

		m_armPrologues.push_back(p);
	}
}

// ============================================================================
// Thumb Prologue Patterns
// ============================================================================

void PrologueMatcher::addThumbPatterns()
{
	addThumbGccPatterns();
	addThumbArmccPatterns();
	addThumbIarPatterns();
	addThumbInterruptPatterns();
}

void PrologueMatcher::addThumbGccPatterns()
{
	// Thumb Pattern 1: PUSH {regs, lr}
	// Encoding: 1011 0 10 M reglist8 (M = push LR)
	{
		ProloguePattern p;
		p.name = "Thumb PUSH LR";
		p.compiler = "GCC";
		p.isThumb = true;
		p.baseConfidence = 0.85;
		p.lrBitPosition = 8;  // Bit 8 in PUSH encoding is LR
		p.fpBitPosition = -1;
		p.reglistPosition = 0;

		// PUSH {regs, lr} with LR bit set
		p.instructions.push_back({0xB500, 0xFF00, false, false});

		m_thumbPrologues.push_back(p);
	}

	// Thumb Pattern 2: PUSH {regs, lr} + SUB sp, #imm
	{
		ProloguePattern p;
		p.name = "Thumb PUSH+SUB";
		p.compiler = "GCC";
		p.isThumb = true;
		p.baseConfidence = 0.9;
		p.lrBitPosition = 8;
		p.fpBitPosition = -1;

		// PUSH {regs, lr}
		p.instructions.push_back({0xB500, 0xFF00, false, false});
		// SUB sp, #imm7*4
		// Encoding: 1011 0000 1 imm7
		p.instructions.push_back({0xB080, 0xFF80, false, false});

		m_thumbPrologues.push_back(p);
	}

	// Thumb Pattern 3: PUSH {regs, lr} + MOV r7, sp (frame pointer)
	{
		ProloguePattern p;
		p.name = "Thumb PUSH+FP";
		p.compiler = "GCC";
		p.isThumb = true;
		p.baseConfidence = 0.9;
		p.lrBitPosition = 8;
		p.fpBitPosition = 7;  // r7 is Thumb FP

		// PUSH {regs, lr}
		p.instructions.push_back({0xB500, 0xFF00, false, false});
		// MOV r7, sp
		// Encoding: 0100 0110 0 1101 111 = 0x466F
		p.instructions.push_back({0x466F, 0xFFFF, false, true});

		m_thumbPrologues.push_back(p);
	}

	// Thumb-2 Pattern 1: PUSH.W {regs, lr}
	// 32-bit Thumb encoding
	{
		ProloguePattern p;
		p.name = "Thumb-2 PUSH.W";
		p.compiler = "GCC";
		p.isThumb = true;
		p.baseConfidence = 0.85;
		p.lrBitPosition = ArmRegs::LR;  // Standard register list
		p.fpBitPosition = -1;
		p.reglistPosition = 0;

		// PUSH.W {regs}
		// First halfword: 1110 1001 0010 1101 = 0xE92D
		// Second halfword: 0 M 0 reglist13 where M = LR
		p.instructions.push_back({0xE92D0000, 0xFFFF0000, true, false});

		m_thumbPrologues.push_back(p);
	}

	// Thumb-2 Pattern 2: PUSH.W + SUB.W sp, sp, #imm
	{
		ProloguePattern p;
		p.name = "Thumb-2 PUSH+SUB.W";
		p.compiler = "GCC";
		p.isThumb = true;
		p.baseConfidence = 0.9;
		p.lrBitPosition = ArmRegs::LR;
		p.fpBitPosition = -1;

		// PUSH.W
		p.instructions.push_back({0xE92D0000, 0xFFFF0000, true, false});
		// SUB.W sp, sp, #imm
		// Encoding: 1111 0 i 0 1101 0 1101 0 imm3 1101 imm8
		p.instructions.push_back({0xF1AD0D00, 0xFBEF8F00, true, true});

		m_thumbPrologues.push_back(p);
	}
}

void PrologueMatcher::addThumbArmccPatterns()
{
	// ARMCC Thumb patterns are similar to GCC
	// but may use different register conventions
	{
		ProloguePattern p;
		p.name = "ARMCC Thumb PUSH";
		p.compiler = "ARMCC";
		p.isThumb = true;
		p.baseConfidence = 0.8;
		p.lrBitPosition = 8;
		p.fpBitPosition = -1;

		p.instructions.push_back({0xB500, 0xFF00, false, false});

		m_thumbPrologues.push_back(p);
	}
}

void PrologueMatcher::addThumbIarPatterns()
{
	// IAR Thumb patterns
	{
		ProloguePattern p;
		p.name = "IAR Thumb PUSH";
		p.compiler = "IAR";
		p.isThumb = true;
		p.baseConfidence = 0.8;
		p.lrBitPosition = 8;
		p.fpBitPosition = -1;

		p.instructions.push_back({0xB500, 0xFF00, false, false});

		m_thumbPrologues.push_back(p);
	}
}

void PrologueMatcher::addThumbInterruptPatterns()
{
	// Cortex-M interrupt handler - hardware saves context
	// Handler starts with normal code (no special prologue)
	// But we can detect by looking for specific patterns

	// Pattern: PUSH {regs} + MRS r0, PSR (reading status)
	{
		ProloguePattern p;
		p.name = "Cortex-M IRQ with PSR";
		p.compiler = "any";
		p.isThumb = true;
		p.baseConfidence = 0.85;
		p.lrBitPosition = 8;
		p.fpBitPosition = -1;

		// PUSH {regs, lr}
		p.instructions.push_back({0xB500, 0xFF00, false, false});
		// MRS r0, xPSR (various forms)
		p.instructions.push_back({0xF3EF8000, 0xFFEF8000, true, true});

		m_thumbPrologues.push_back(p);
	}
}

// ============================================================================
// Epilogue Patterns
// ============================================================================

void PrologueMatcher::addArmEpiloguePatterns()
{
	// ARM POP {regs, pc}
	{
		ProloguePattern p;
		p.name = "ARM POP PC";
		p.compiler = "any";
		p.isThumb = false;
		p.baseConfidence = 0.9;
		p.lrBitPosition = -1;
		p.fpBitPosition = -1;

		// LDMFD sp!, {regs, pc}
		// Encoding: cond 1000 1011 1101 reglist with PC
		p.instructions.push_back({0x08BD8000, 0x0FFF8000, false, false});

		m_armEpilogues.push_back(p);
	}

	// ARM BX LR
	{
		ProloguePattern p;
		p.name = "ARM BX LR";
		p.compiler = "any";
		p.isThumb = false;
		p.baseConfidence = 0.85;
		p.lrBitPosition = -1;
		p.fpBitPosition = -1;

		// BX lr
		// Encoding: cond 0001 0010 1111 1111 1111 0001 1110
		p.instructions.push_back({0x012FFF1E, 0x0FFFFFFF, false, false});

		m_armEpilogues.push_back(p);
	}

	// ARM MOV pc, lr
	{
		ProloguePattern p;
		p.name = "ARM MOV PC,LR";
		p.compiler = "any";
		p.isThumb = false;
		p.baseConfidence = 0.8;
		p.lrBitPosition = -1;
		p.fpBitPosition = -1;

		// MOV pc, lr
		// Encoding: cond 0001 1010 0000 1111 0000 0000 1110
		p.instructions.push_back({0x01A0F00E, 0x0FFFFFFF, false, false});

		m_armEpilogues.push_back(p);
	}
}

void PrologueMatcher::addThumbEpiloguePatterns()
{
	// Thumb POP {regs, pc}
	{
		ProloguePattern p;
		p.name = "Thumb POP PC";
		p.compiler = "any";
		p.isThumb = true;
		p.baseConfidence = 0.9;
		p.lrBitPosition = -1;
		p.fpBitPosition = -1;

		// POP {regs, pc}
		// Encoding: 1011 1 10 P reglist8 where P = pop PC
		p.instructions.push_back({0xBD00, 0xFF00, false, false});

		m_thumbEpilogues.push_back(p);
	}

	// Thumb BX LR
	{
		ProloguePattern p;
		p.name = "Thumb BX LR";
		p.compiler = "any";
		p.isThumb = true;
		p.baseConfidence = 0.85;
		p.lrBitPosition = -1;
		p.fpBitPosition = -1;

		// BX lr
		// Encoding: 0100 0111 0 1110 000 = 0x4770
		p.instructions.push_back({0x4770, 0xFFFF, false, false});

		m_thumbEpilogues.push_back(p);
	}

	// Thumb-2 POP.W {regs, pc}
	{
		ProloguePattern p;
		p.name = "Thumb-2 POP.W PC";
		p.compiler = "any";
		p.isThumb = true;
		p.baseConfidence = 0.9;
		p.lrBitPosition = -1;
		p.fpBitPosition = -1;

		// POP.W {regs, pc}
		// First halfword: 1110 1000 1011 1101 = 0xE8BD
		// Second halfword: reglist with PC bit set
		p.instructions.push_back({0xE8BD8000, 0xFFFF8000, true, false});

		m_thumbEpilogues.push_back(p);
	}
}

// ============================================================================
// Instruction Reading
// ============================================================================

uint32_t PrologueMatcher::readArm(uint64_t address)
{
	DataBuffer buf = m_view->ReadBuffer(address, 4);
	if (buf.GetLength() < 4)
		return 0;

	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

uint16_t PrologueMatcher::readThumb16(uint64_t address)
{
	DataBuffer buf = m_view->ReadBuffer(address, 2);
	if (buf.GetLength() < 2)
		return 0;

	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	return data[0] | (data[1] << 8);
}

uint32_t PrologueMatcher::readThumb32(uint64_t address)
{
	DataBuffer buf = m_view->ReadBuffer(address, 4);
	if (buf.GetLength() < 4)
		return 0;

	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	// Thumb-2 32-bit instructions are stored as two halfwords
	uint16_t hw1 = data[0] | (data[1] << 8);
	uint16_t hw2 = data[2] | (data[3] << 8);
	return (hw1 << 16) | hw2;
}

// ============================================================================
// Pattern Matching
// ============================================================================

bool PrologueMatcher::matchPattern(uint64_t address, const ProloguePattern& pattern,
	PrologueMatch& result)
{
	uint64_t addr = address;
	std::vector<uint32_t> matchedInstructions;

	for (size_t i = 0; i < pattern.instructions.size(); i++)
	{
		const auto& insn = pattern.instructions[i];
		uint32_t value;
		size_t size;

		if (pattern.isThumb)
		{
			if (insn.is32bit)
			{
				value = readThumb32(addr);
				size = 4;
			}
			else
			{
				value = readThumb16(addr);
				size = 2;
			}
		}
		else
		{
			value = readArm(addr);
			size = 4;
		}

		// Check if value matches pattern
		if ((value & insn.mask) != insn.value)
		{
			if (!insn.optional)
				return false;
			// Skip optional instruction and continue
			continue;
		}

		matchedInstructions.push_back(value);
		addr += size;
	}

	// Pattern matched, fill in result
	result.address = address;
	result.isThumb = pattern.isThumb;
	result.confidence = pattern.baseConfidence;
	result.patternName = pattern.name;
	result.compiler = pattern.compiler;
	result.patternLength = matchedInstructions.size();
	result.byteLength = addr - address;

	// Extract register information
	extractPatternInfo(pattern, address, matchedInstructions, result);

	return true;
}

void PrologueMatcher::extractPatternInfo(const ProloguePattern& pattern, uint64_t address,
	const std::vector<uint32_t>& instructions, PrologueMatch& result)
{
	result.savedRegisters = 0;
	result.stackAdjustment = 0;
	result.savesLR = false;
	result.savesFramePointer = false;
	result.isInterruptHandler = (pattern.name.find("IRQ") != std::string::npos ||
	                             pattern.name.find("FIQ") != std::string::npos ||
	                             pattern.name.find("SVC") != std::string::npos ||
	                             pattern.name.find("handler") != std::string::npos);
	result.isLeafFunction = false;

	if (instructions.empty())
		return;

	uint32_t firstInsn = instructions[0];

	// Extract register list if applicable
	if (pattern.reglistPosition >= 0)
	{
		if (pattern.isThumb && !pattern.instructions[0].is32bit)
		{
			// Thumb 16-bit PUSH: lower 8 bits are register list, bit 8 is LR
			result.savedRegisters = firstInsn & 0xFF;
			if (firstInsn & 0x100)
			{
				result.savesLR = true;
				result.savedRegisters |= ArmRegs::LR_BIT;
			}
		}
		else
		{
			// ARM or Thumb-2: lower 16 bits are register list
			result.savedRegisters = firstInsn & 0xFFFF;
			if (pattern.lrBitPosition >= 0)
			{
				result.savesLR = (result.savedRegisters & (1 << pattern.lrBitPosition)) != 0;
			}
		}
	}

	// Check for frame pointer
	if (pattern.fpBitPosition >= 0)
	{
		if (result.savedRegisters & (1 << pattern.fpBitPosition))
			result.savesFramePointer = true;
	}

	// Look for stack adjustment in second instruction
	if (instructions.size() >= 2)
	{
		uint32_t secondInsn = instructions[1];

		if (pattern.isThumb)
		{
			// SUB sp, #imm7*4
			if ((secondInsn & 0xFF80) == 0xB080)
			{
				result.stackAdjustment = -static_cast<int32_t>((secondInsn & 0x7F) * 4);
			}
		}
		else
		{
			// ARM SUB sp, sp, #imm
			if ((secondInsn & 0x0FFF0000) == 0x024DD000)
			{
				uint32_t imm12 = secondInsn & 0xFFF;
				// ARM modified immediate encoding
				uint32_t rot = (imm12 >> 8) * 2;
				uint32_t value = imm12 & 0xFF;
				result.stackAdjustment = -static_cast<int32_t>((value >> rot) | (value << (32 - rot)));
			}
		}
	}

	// Adjust confidence based on what we found
	if (result.savesLR)
		result.confidence += 0.05;

	int regCount = __builtin_popcount(result.savedRegisters);
	if (regCount >= 4)
		result.confidence += 0.05;
	if (regCount >= 6)
		result.confidence += 0.05;

	// Clamp confidence
	result.confidence = std::min(1.0, result.confidence);
}

std::vector<PrologueMatch> PrologueMatcher::matchPrologue(uint64_t address, bool isThumb)
{
	std::vector<PrologueMatch> matches;
	const auto& patterns = isThumb ? m_thumbPrologues : m_armPrologues;

	for (const auto& pattern : patterns)
	{
		PrologueMatch result;
		if (matchPattern(address, pattern, result))
		{
			matches.push_back(result);
		}
	}

	// Sort by confidence (highest first)
	std::sort(matches.begin(), matches.end(),
		[](const PrologueMatch& a, const PrologueMatch& b) {
			return a.confidence > b.confidence;
		});

	return matches;
}

std::vector<EpilogueMatch> PrologueMatcher::matchEpilogue(uint64_t address, bool isThumb)
{
	std::vector<EpilogueMatch> matches;
	const auto& patterns = isThumb ? m_thumbEpilogues : m_armEpilogues;

	for (const auto& pattern : patterns)
	{
		PrologueMatch pResult;
		if (matchPattern(address, pattern, pResult))
		{
			EpilogueMatch result;
			result.address = pResult.address;
			result.isThumb = pResult.isThumb;
			result.confidence = pResult.confidence;
			result.patternName = pResult.patternName;
			result.restoresLR = false;
			result.restoresPC = (pResult.savedRegisters & ArmRegs::PC_BIT) != 0;
			result.isConditional = false;
			result.restoredRegisters = pResult.savedRegisters;
			result.stackAdjustment = -pResult.stackAdjustment;  // Opposite of prologue
			result.patternLength = pResult.patternLength;
			result.byteLength = pResult.byteLength;

			matches.push_back(result);
		}
	}

	// Sort by confidence
	std::sort(matches.begin(), matches.end(),
		[](const EpilogueMatch& a, const EpilogueMatch& b) {
			return a.confidence > b.confidence;
		});

	return matches;
}

PrologueMatch PrologueMatcher::getBestPrologueMatch(uint64_t address, bool isThumb)
{
	auto matches = matchPrologue(address, isThumb);
	if (matches.empty())
	{
		PrologueMatch empty;
		empty.address = address;
		empty.isThumb = isThumb;
		empty.confidence = 0.0;
		return empty;
	}
	return matches[0];
}

std::vector<PrologueMatch> PrologueMatcher::scanForPrologues(uint64_t start, uint64_t end,
	bool scanArm, bool scanThumb, double minConfidence)
{
	std::vector<PrologueMatch> results;

	if (scanArm)
	{
		for (uint64_t addr = start; addr + 4 <= end; addr += 4)
		{
			auto matches = matchPrologue(addr, false);
			for (const auto& match : matches)
			{
				if (match.confidence >= minConfidence)
				{
					results.push_back(match);
					break;  // Only take best match at each address
				}
			}
		}
	}

	if (scanThumb)
	{
		for (uint64_t addr = start; addr + 2 <= end; addr += 2)
		{
			auto matches = matchPrologue(addr, true);
			for (const auto& match : matches)
			{
				if (match.confidence >= minConfidence)
				{
					results.push_back(match);
					break;
				}
			}
		}
	}

	return results;
}

bool PrologueMatcher::isLikelyLeafFunction(uint64_t address, bool isThumb)
{
	// A leaf function typically:
	// - Has no prologue (or minimal one)
	// - Contains no BL/BLX instructions
	// - Ends with BX LR or simple return

	// Check for absence of typical prologue
	auto matches = matchPrologue(address, isThumb);

	// If there's a strong prologue match, it's probably not a simple leaf
	for (const auto& match : matches)
	{
		if (match.confidence > 0.7 && match.savesLR)
			return false;
	}

	// Simple heuristic: scan first few instructions for call
	size_t instrSize = isThumb ? 2 : 4;
	for (int i = 0; i < 10; i++)
	{
		uint64_t addr = address + i * instrSize;

		if (isThumb)
		{
			uint16_t insn = readThumb16(addr);
			// Check for BL (32-bit)
			if ((insn & 0xF800) == 0xF000)
			{
				uint16_t next = readThumb16(addr + 2);
				if ((next & 0xD000) == 0xD000)  // BL or BLX
					return false;
			}
		}
		else
		{
			uint32_t insn = readArm(addr);
			// BL: cond 1011 xxxx xxxx xxxx xxxx xxxx xxxx
			if ((insn & 0x0F000000) == 0x0B000000)
				return false;
			// BLX: 1111 101H xxxx xxxx xxxx xxxx xxxx xxxx
			if ((insn & 0xFE000000) == 0xFA000000)
				return false;
		}
	}

	return true;
}

bool PrologueMatcher::isInterruptHandlerEntry(uint64_t address, bool isThumb)
{
	auto matches = matchPrologue(address, isThumb);
	for (const auto& match : matches)
	{
		if (match.isInterruptHandler && match.confidence >= 0.7)
			return true;
	}
	return false;
}

}  // namespace Armv5Analysis
