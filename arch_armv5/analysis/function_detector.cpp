/*
 * Advanced Function Detector Implementation
 */

#include "function_detector.h"

#include <algorithm>
#include <cmath>
#include <numeric>

using namespace BinaryNinja;

namespace Armv5Analysis
{

const char* DetectionSourceToString(DetectionSource source)
{
	switch (source)
	{
	case DetectionSource::ProloguePush:         return "PUSH prologue";
	case DetectionSource::PrologueSubSp:        return "SUB SP prologue";
	case DetectionSource::PrologueMovFp:        return "MOV FP prologue";
	case DetectionSource::PrologueStmfd:        return "STMFD prologue";
	case DetectionSource::BlTarget:             return "BL target";
	case DetectionSource::BlxTarget:            return "BLX target";
	case DetectionSource::IndirectCallTarget:   return "Indirect call target";
	case DetectionSource::HighXrefDensity:      return "High xref density";
	case DetectionSource::PointerTableEntry:    return "Pointer table entry";
	case DetectionSource::AfterUnconditionalRet: return "After return";
	case DetectionSource::AfterTailCall:        return "After tail call";
	case DetectionSource::AlignmentBoundary:    return "Aligned boundary";
	case DetectionSource::AfterLiteralPool:     return "After literal pool";
	case DetectionSource::AfterPadding:         return "After padding";
	case DetectionSource::VectorTableTarget:    return "Vector table handler";
	case DetectionSource::InterruptPrologue:    return "Interrupt prologue";
	case DetectionSource::ThunkPattern:         return "Thunk pattern";
	case DetectionSource::TrampolinePattern:    return "Trampoline";
	case DetectionSource::SwitchCaseHandler:    return "Switch case target";
	case DetectionSource::GccPrologue:          return "GCC prologue";
	case DetectionSource::ArmccPrologue:        return "ARMCC prologue";
	case DetectionSource::IarPrologue:          return "IAR prologue";
	case DetectionSource::TaskEntryPattern:     return "Task entry";
	case DetectionSource::CallbackPattern:      return "Callback pattern";
	case DetectionSource::InstructionSequence:  return "Instruction sequence";
	case DetectionSource::EntropyTransition:    return "Entropy transition";
	case DetectionSource::MidInstruction:       return "Mid-instruction (penalty)";
	case DetectionSource::InsideFunction:       return "Inside function (penalty)";
	case DetectionSource::DataRegion:           return "Data region (penalty)";
	case DetectionSource::InvalidInstruction:   return "Invalid instruction (penalty)";
	case DetectionSource::UnlikelyPattern:      return "Unlikely pattern (penalty)";
	default:                                    return "Unknown";
	}
}

const char* CompilerToString(DetectedCompiler compiler)
{
	switch (compiler)
	{
	case DetectedCompiler::GCC:         return "GCC";
	case DetectedCompiler::ARMCC:       return "ARM Compiler";
	case DetectedCompiler::IAR:         return "IAR EWARM";
	case DetectedCompiler::Clang:       return "Clang/LLVM";
	case DetectedCompiler::Keil:        return "Keil MDK";
	case DetectedCompiler::GreenHills:  return "Green Hills";
	default:                            return "Unknown";
	}
}

FunctionDetector::FunctionDetector(Ref<BinaryView> view)
	: m_view(view)
	, m_settings(DefaultSettings())
	, m_stats{}
{
	m_logger = LogRegistry::CreateLogger("FunctionDetector");
}

FunctionDetectionSettings FunctionDetector::DefaultSettings()
{
	return FunctionDetectionSettings();
}

FunctionDetectionSettings FunctionDetector::AggressiveSettings()
{
	FunctionDetectionSettings s;
	s.minimumScore = 0.25;
	s.highConfidenceScore = 0.6;
	s.alignmentPreference = 2;
	
	// Lower thresholds
	s.prologuePush.threshold = 0.3;
	s.blTarget.threshold = 0.2;
	s.afterUnconditionalRet.threshold = 0.3;
	
	// Higher weights for weak signals
	s.alignmentBoundary.weight = 0.5;
	s.instructionSequence.weight = 1.2;
	s.entropyTransition.weight = 1.0;
	
	// Lower penalties
	s.midInstructionPenalty = 0.5;
	s.unlikelyPatternPenalty = 0.1;
	
	return s;
}

FunctionDetectionSettings FunctionDetector::ConservativeSettings()
{
	FunctionDetectionSettings s;
	s.minimumScore = 0.6;
	s.highConfidenceScore = 0.9;
	s.alignmentPreference = 4;
	
	// Higher thresholds
	s.prologuePush.threshold = 0.7;
	s.blTarget.threshold = 0.5;
	s.afterUnconditionalRet.threshold = 0.7;
	
	// Lower weights for weak signals
	s.alignmentBoundary.weight = 0.1;
	s.instructionSequence.weight = 0.4;
	s.entropyTransition.weight = 0.3;
	
	// Higher penalties
	s.midInstructionPenalty = 1.5;
	s.unlikelyPatternPenalty = 0.6;
	
	return s;
}

FunctionDetectionSettings FunctionDetector::PrologueOnlySettings()
{
	FunctionDetectionSettings s;
	
	// Disable non-prologue detectors
	s.blTarget.enabled = false;
	s.blxTarget.enabled = false;
	s.indirectCallTarget.enabled = false;
	s.highXrefDensity.enabled = false;
	s.pointerTableEntry.enabled = false;
	s.afterUnconditionalRet.enabled = false;
	s.afterTailCall.enabled = false;
	s.alignmentBoundary.enabled = false;
	s.entropyTransition.enabled = false;
	
	// Boost prologue weights
	s.prologuePush.weight = 2.0;
	s.prologueSubSp.weight = 1.5;
	s.prologueMovFp.weight = 1.5;
	s.prologueStmfd.weight = 2.0;
	
	return s;
}

FunctionDetectionSettings FunctionDetector::CallTargetOnlySettings()
{
	FunctionDetectionSettings s;
	
	// Disable most detectors
	s.prologuePush.enabled = false;
	s.prologueSubSp.enabled = false;
	s.prologueMovFp.enabled = false;
	s.prologueStmfd.enabled = false;
	s.alignmentBoundary.enabled = false;
	s.entropyTransition.enabled = false;
	s.instructionSequence.enabled = false;
	
	// Boost call target weights
	s.blTarget.weight = 3.0;
	s.blxTarget.weight = 3.0;
	s.vectorTableTarget.weight = 3.0;
	
	return s;
}

uint32_t FunctionDetector::ReadInstruction32(uint64_t address)
{
	DataBuffer buf = m_view->ReadBuffer(address, 4);
	if (buf.GetLength() < 4)
		return 0;
	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

uint16_t FunctionDetector::ReadInstruction16(uint64_t address)
{
	DataBuffer buf = m_view->ReadBuffer(address, 2);
	if (buf.GetLength() < 2)
		return 0;
	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	return data[0] | (data[1] << 8);
}

bool FunctionDetector::IsValidInstruction(uint64_t address, bool thumb)
{
	if (thumb)
	{
		if (address & 1)
			return false;  // Must be 2-byte aligned
		uint16_t instr = ReadInstruction16(address);
		// Basic validity check
		return instr != 0x0000 && instr != 0xFFFF;
	}
	else
	{
		if (address & 3)
			return false;  // Must be 4-byte aligned
		uint32_t instr = ReadInstruction32(address);
		// Check condition field
		uint32_t cond = (instr >> 28) & 0xF;
		return instr != 0x00000000 && instr != 0xFFFFFFFF && cond <= 0xE;
	}
}

bool FunctionDetector::IsInsideKnownFunction(uint64_t address)
{
	// Check if address falls within any existing function
	for (const auto& func : m_view->GetAnalysisFunctionsContainingAddress(address))
	{
		if (func->GetStart() != address)
			return true;
	}
	return false;
}

bool FunctionDetector::IsDataRegion(uint64_t address)
{
	// Check if in a non-executable segment
	auto seg = m_view->GetSegmentAt(address);
	if (seg && !(seg->GetFlags() & SegmentExecutable))
		return true;
	return false;
}

bool FunctionDetector::CheckArmPrologue(uint64_t address, uint32_t instr)
{
	uint32_t cond = (instr >> 28) & 0xF;
	
	// PUSH {regs, lr} = STMDB sp!, {regs}
	// Encoding: cond 100 1 0 0 1 0 1101 reglist
	if ((instr & 0x0FFF0000) == 0x092D0000)
	{
		uint32_t reglist = instr & 0xFFFF;
		// Must include LR (bit 14) for function prologue
		if (reglist & (1 << 14))
			return true;
	}
	
	// STMFD sp!, {regs} with LR
	// Encoding: cond 100 1 0 0 1 0 1101 reglist (same as PUSH)
	if ((instr & 0x0FFF0000) == 0x092D0000)
	{
		uint32_t reglist = instr & 0xFFFF;
		if (reglist & (1 << 14))
			return true;
	}
	
	// SUB sp, sp, #imm
	// Encoding: cond 001 0010 0 1101 1101 imm12
	if ((instr & 0x0FFF0000) == 0x024DD000)
		return true;
	
	// MOV r11, sp (frame pointer setup)
	// Encoding: cond 000 1101 0 0000 1011 00000000 1101
	if ((instr & 0x0FFFFFFF) == 0x01A0B00D)
		return true;
	
	// STR lr, [sp, #-4]!
	// Encoding: cond 0101 0010 1101 1110 0000 0000 0100
	if ((instr & 0x0FFFFFFF) == 0x052DE004)
		return true;
	
	return false;
}

bool FunctionDetector::CheckThumbPrologue(uint64_t address, uint16_t instr, uint16_t next)
{
	// PUSH {regs, lr}
	// Encoding: 1011 0 10 M reglist8
	if ((instr & 0xFE00) == 0xB400)
	{
		// Bit 8 = push LR
		if (instr & 0x0100)
			return true;
	}
	
	// SUB sp, #imm7
	// Encoding: 1011 0000 1 imm7
	if ((instr & 0xFF80) == 0xB080)
		return true;
	
	// 32-bit Thumb PUSH.W
	// First halfword: 1110 1001 0010 1101 = 0xE92D
	if (instr == 0xE92D)
	{
		// Next halfword has register list
		if (next & (1 << 14))  // LR in list
			return true;
	}
	
	// MOV r7, sp (Thumb frame pointer)
	// Encoding: 0100 0110 01101 111 = 0x466F
	if (instr == 0x466F)
		return true;
	
	return false;
}

size_t FunctionDetector::CountIncomingReferences(uint64_t address)
{
	if (m_xrefCounts.empty())
	{
		// Build xref cache from code references
		auto refs = m_view->GetCodeReferences(address);
		return refs.size();
	}
	
	auto it = m_xrefCounts.find(address);
	return it != m_xrefCounts.end() ? it->second : 0;
}

double FunctionDetector::CalculateLocalEntropy(uint64_t address, size_t windowSize)
{
	DataBuffer buf = m_view->ReadBuffer(address, windowSize);
	if (buf.GetLength() < windowSize)
		return 0.0;
	
	uint64_t counts[256] = {0};
	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	
	for (size_t i = 0; i < windowSize; i++)
		counts[data[i]]++;
	
	double entropy = 0.0;
	for (int i = 0; i < 256; i++)
	{
		if (counts[i] > 0)
		{
			double p = static_cast<double>(counts[i]) / windowSize;
			entropy -= p * log2(p);
		}
	}
	
	return entropy;
}

void FunctionDetector::AddCandidate(std::map<uint64_t, FunctionCandidate>& candidates,
	uint64_t address, bool isThumb, DetectionSource source,
	double score, const std::string& description)
{
	auto it = candidates.find(address);
	if (it != candidates.end())
	{
		// Update existing candidate
		it->second.sources |= static_cast<uint32_t>(source);
		it->second.sourceScores[source] = score;
		if (!description.empty())
			it->second.description += "; " + description;
	}
	else
	{
		// New candidate
		FunctionCandidate c;
		c.address = address;
		c.isThumb = isThumb;
		c.score = 0;  // Calculated later
		c.sources = static_cast<uint32_t>(source);
		c.sourceScores[source] = score;
		c.description = description;
		candidates[address] = c;
	}
}

void FunctionDetector::ScanProloguePatterns(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.prologuePush.enabled && !m_settings.prologueSubSp.enabled &&
		!m_settings.prologueMovFp.enabled && !m_settings.prologueStmfd.enabled)
		return;
	
	m_logger->LogDebug("FunctionDetector: Scanning prologue patterns...");
	
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();
	
	// Scan ARM mode
	if (m_settings.detectArmFunctions)
	{
		for (uint64_t addr = start; addr + 4 <= end; addr += 4)
		{
			if (m_settings.scanExecutableOnly && IsDataRegion(addr))
				continue;
			
			uint32_t instr = ReadInstruction32(addr);
			if (CheckArmPrologue(addr, instr))
			{
				DetectionSource source = DetectionSource::ProloguePush;
				double score = m_settings.prologuePush.weight;
				
				// Check for STMFD specifically
				if ((instr & 0x0FFF0000) == 0x092D0000)
				{
					uint32_t reglist = instr & 0xFFFF;
					// More registers pushed = higher confidence
					int regCount = __builtin_popcount(reglist);
					if (regCount >= 4)
						score *= 1.2;
				}
				
				AddCandidate(candidates, addr, false, source, score,
					"ARM prologue detected");
			}
		}
	}
	
	// Scan Thumb mode
	if (m_settings.detectThumbFunctions)
	{
		for (uint64_t addr = start; addr + 4 <= end; addr += 2)
		{
			if (m_settings.scanExecutableOnly && IsDataRegion(addr))
				continue;
			
			uint16_t instr = ReadInstruction16(addr);
			uint16_t next = ReadInstruction16(addr + 2);
			
			if (CheckThumbPrologue(addr, instr, next))
			{
				DetectionSource source = DetectionSource::ProloguePush;
				double score = m_settings.prologuePush.weight;
				
				AddCandidate(candidates, addr, true, source, score,
					"Thumb prologue detected");
			}
		}
	}
}

void FunctionDetector::ScanCallTargets(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.blTarget.enabled && !m_settings.blxTarget.enabled)
		return;
	
	m_logger->LogDebug("FunctionDetector: Scanning call targets...");
	
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();
	
	// Collect all call targets
	m_callTargets.clear();
	
	// Scan for BL/BLX instructions
	for (uint64_t addr = start; addr + 4 <= end; addr += 4)
	{
		uint32_t instr = ReadInstruction32(addr);
		uint32_t cond = (instr >> 28) & 0xF;
		
		// BL <label> - Encoding: cond 1011 imm24
		if ((instr & 0x0F000000) == 0x0B000000 && cond <= 0xE)
		{
			int32_t offset = instr & 0x00FFFFFF;
			if (offset & 0x00800000)
				offset |= 0xFF000000;  // Sign extend
			offset = (offset << 2) + 8;  // PC + 8 + offset*4
			
			uint64_t target = addr + offset;
			if (target >= start && target < end)
			{
				m_callTargets.insert(target);
				AddCandidate(candidates, target, false,
					DetectionSource::BlTarget, m_settings.blTarget.weight,
					"BL target");
			}
		}
		
		// BLX <label> - Encoding: 1111 101 H imm24
		if ((instr & 0xFE000000) == 0xFA000000)
		{
			int32_t offset = instr & 0x00FFFFFF;
			if (offset & 0x00800000)
				offset |= 0xFF000000;
			offset = (offset << 2) + ((instr >> 23) & 2) + 8;
			
			uint64_t target = (addr + offset) & ~1ULL;
			if (target >= start && target < end)
			{
				m_callTargets.insert(target);
				AddCandidate(candidates, target, true,  // BLX targets Thumb
					DetectionSource::BlxTarget, m_settings.blxTarget.weight,
					"BLX target (Thumb)");
			}
		}
	}
	
	// Also scan Thumb BL/BLX
	for (uint64_t addr = start; addr + 4 <= end; addr += 2)
	{
		uint16_t hw1 = ReadInstruction16(addr);
		uint16_t hw2 = ReadInstruction16(addr + 2);
		
		// 32-bit Thumb BL: 11110 S imm10 11 J1 1 J2 imm11
		if ((hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0xD000)
		{
			uint32_t S = (hw1 >> 10) & 1;
			uint32_t imm10 = hw1 & 0x3FF;
			uint32_t J1 = (hw2 >> 13) & 1;
			uint32_t J2 = (hw2 >> 11) & 1;
			uint32_t imm11 = hw2 & 0x7FF;
			
			uint32_t I1 = ~(J1 ^ S) & 1;
			uint32_t I2 = ~(J2 ^ S) & 1;
			
			int32_t offset = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1);
			if (S)
				offset |= 0xFE000000;  // Sign extend
			
			uint64_t target = addr + 4 + offset;
			if (target >= start && target < end)
			{
				bool toThumb = (hw2 & 0x1000) != 0;  // BL vs BLX
				m_callTargets.insert(target);
				AddCandidate(candidates, target, toThumb,
					DetectionSource::BlTarget, m_settings.blTarget.weight,
					"Thumb BL target");
			}
		}
	}
	
	m_logger->LogDebug("FunctionDetector: Found %zu call targets", m_callTargets.size());
}

void FunctionDetector::ScanCrossReferences(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.highXrefDensity.enabled && !m_settings.pointerTableEntry.enabled)
		return;
	
	m_logger->LogDebug("FunctionDetector: Scanning cross-references...");
	
	// Find addresses with many incoming references
	for (const auto& func : m_view->GetAnalysisFunctionList())
	{
		size_t xrefs = CountIncomingReferences(func->GetStart());
		if (xrefs >= 3)  // High xref threshold
		{
			// Already a function, but note for stats
		}
	}
	
	// Scan for pointer tables
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();
	
	for (uint64_t addr = start; addr + 16 <= end; addr += 4)
	{
		// Look for sequences of valid code pointers
		int validPointers = 0;
		for (int i = 0; i < 4; i++)
		{
			uint32_t ptr = ReadInstruction32(addr + i * 4);
			uint64_t target = ptr & ~1ULL;
			
			if (target >= start && target < end && IsValidInstruction(target, ptr & 1))
			{
				validPointers++;
			}
		}
		
		if (validPointers >= 3)
		{
			// This looks like a pointer table
			for (int i = 0; i < 4; i++)
			{
				uint32_t ptr = ReadInstruction32(addr + i * 4);
				uint64_t target = ptr & ~1ULL;
				
				if (target >= start && target < end)
				{
					AddCandidate(candidates, target, ptr & 1,
						DetectionSource::PointerTableEntry, m_settings.pointerTableEntry.weight,
						"Pointer table entry");
				}
			}
		}
	}
}

void FunctionDetector::ScanStructuralPatterns(std::map<uint64_t, FunctionCandidate>& candidates)
{
	m_logger->LogDebug("FunctionDetector: Scanning structural patterns...");
	
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();
	
	// Look for code after return instructions
	if (m_settings.afterUnconditionalRet.enabled)
	{
		for (uint64_t addr = start; addr + 8 <= end; addr += 4)
		{
			uint32_t instr = ReadInstruction32(addr);
			
			// BX LR - Return from function
			// Encoding: cond 0001 0010 1111 1111 1111 0001 1110
			if ((instr & 0x0FFFFFFF) == 0x012FFF1E)
			{
				// Next instruction might be a new function
				uint64_t nextAddr = addr + 4;
				if (IsValidInstruction(nextAddr, false))
				{
					AddCandidate(candidates, nextAddr, false,
						DetectionSource::AfterUnconditionalRet, m_settings.afterUnconditionalRet.weight,
						"After BX LR");
				}
			}
			
			// POP {pc} variants
			// LDMIA sp!, {..., pc}
			if ((instr & 0x0FFF0000) == 0x08BD0000 && (instr & (1 << 15)))
			{
				uint64_t nextAddr = addr + 4;
				if (IsValidInstruction(nextAddr, false))
				{
					AddCandidate(candidates, nextAddr, false,
						DetectionSource::AfterUnconditionalRet, m_settings.afterUnconditionalRet.weight,
						"After POP {pc}");
				}
			}
		}
	}
	
	// Look for code after padding
	if (m_settings.afterPadding.enabled)
	{
		DataBuffer buf = m_view->ReadBuffer(start, std::min((uint64_t)65536, end - start));
		const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
		size_t len = buf.GetLength();
		
		size_t padCount = 0;
		for (size_t i = 0; i < len - 4; i++)
		{
			if (data[i] == 0x00 || data[i] == 0xFF)
			{
				padCount++;
			}
			else
			{
				if (padCount >= 8)
				{
					// End of padding - might be function start
					uint64_t addr = start + i;
					if ((addr % m_settings.alignmentPreference) == 0)
					{
						AddCandidate(candidates, addr, false,
							DetectionSource::AfterPadding, m_settings.afterPadding.weight,
							"After padding");
					}
				}
				padCount = 0;
			}
		}
	}
	
	// Alignment-based detection
	if (m_settings.alignmentBoundary.enabled)
	{
		for (uint64_t addr = start; addr < end; addr += m_settings.alignmentPreference)
		{
			if (!IsInsideKnownFunction(addr) && IsValidInstruction(addr, false))
			{
				// Only add if we haven't seen this address from other sources
				if (candidates.find(addr) == candidates.end())
				{
					// Very weak signal - only add if it looks like code
					uint32_t instr = ReadInstruction32(addr);
					if ((instr & 0x0E000000) != 0x06000000)  // Not undefined
					{
						AddCandidate(candidates, addr, false,
							DetectionSource::AlignmentBoundary, m_settings.alignmentBoundary.weight * 0.5,
							"Aligned boundary");
					}
				}
			}
		}
	}
}

void FunctionDetector::ScanExceptionHandlers(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.vectorTableTarget.enabled)
		return;
	
	m_logger->LogDebug("FunctionDetector: Scanning exception handlers...");
	
	// Look for vector table handlers by symbol name
	const char* handlerNames[] = {
		"reset_handler", "undefined_handler", "swi_handler", "svc_handler",
		"prefetch_abort_handler", "data_abort_handler", "irq_handler", "fiq_handler"
	};
	
	for (const auto& name : handlerNames)
	{
		auto syms = m_view->GetSymbolsByName(name);
		for (const auto& sym : syms)
		{
			AddCandidate(candidates, sym->GetAddress(), false,
				DetectionSource::VectorTableTarget, m_settings.vectorTableTarget.weight,
				std::string("Vector handler: ") + name);
		}
	}
}

void FunctionDetector::ScanAdvancedPatterns(std::map<uint64_t, FunctionCandidate>& candidates)
{
	m_logger->LogDebug("FunctionDetector: Scanning advanced patterns...");
	
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();
	
	// Thunk detection: LDR pc, [pc, #offset]
	if (m_settings.thunkPattern.enabled)
	{
		for (uint64_t addr = start; addr + 4 <= end; addr += 4)
		{
			uint32_t instr = ReadInstruction32(addr);
			
			// LDR pc, [pc, #imm]
			// Encoding: cond 0101 U001 1111 1111 imm12
			if ((instr & 0x0F7F0000) == 0x051F0000)
			{
				// This is a thunk - the target is also a function
				uint32_t offset = instr & 0xFFF;
				bool add = (instr >> 23) & 1;
				uint64_t target = addr + 8 + (add ? offset : -offset);
				
				if (target >= start && target < end)
				{
					uint32_t ptr = ReadInstruction32(target);
					if (ptr >= start && ptr < end)
					{
						AddCandidate(candidates, addr, false,
							DetectionSource::ThunkPattern, m_settings.thunkPattern.weight,
							"Thunk entry");
					}
				}
			}
		}
	}
}

void FunctionDetector::ScanCompilerPatterns(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.detectCompilerStyle)
		return;
	
	m_logger->LogDebug("FunctionDetector: Scanning compiler-specific patterns...");
	
	// Detect compiler from existing code
	DetectedCompiler compiler = DetectCompilerStyle();
	m_stats.detectedCompiler = compiler;
	
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();
	
	// GCC-specific patterns
	if (compiler == DetectedCompiler::GCC || compiler == DetectedCompiler::Unknown)
	{
		for (uint64_t addr = start; addr + 8 <= end; addr += 4)
		{
			uint32_t instr1 = ReadInstruction32(addr);
			uint32_t instr2 = ReadInstruction32(addr + 4);
			
			// GCC often uses: PUSH {r4-r11, lr} followed by SUB sp, sp, #imm
			if ((instr1 & 0x0FFF0000) == 0x092D0000 &&  // PUSH
				(instr2 & 0x0FFF0000) == 0x024DD000)    // SUB sp
			{
				AddCandidate(candidates, addr, false,
					DetectionSource::GccPrologue, m_settings.gccPrologue.weight,
					"GCC prologue pattern");
			}
		}
	}
	
	// ARMCC-specific patterns
	if (compiler == DetectedCompiler::ARMCC || compiler == DetectedCompiler::Unknown)
	{
		for (uint64_t addr = start; addr + 4 <= end; addr += 4)
		{
			uint32_t instr = ReadInstruction32(addr);
			
			// ARMCC often uses STMFD with r12
			if ((instr & 0x0FFF0000) == 0x092D0000)
			{
				uint32_t reglist = instr & 0xFFFF;
				if ((reglist & (1 << 12)) && (reglist & (1 << 14)))  // r12 and lr
				{
					AddCandidate(candidates, addr, false,
						DetectionSource::ArmccPrologue, m_settings.armccPrologue.weight,
						"ARMCC prologue pattern");
				}
			}
		}
	}
}

void FunctionDetector::ScanRtosPatterns(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.taskEntryPattern.enabled)
		return;
	
	m_logger->LogDebug("FunctionDetector: Scanning RTOS patterns...");
	
	// Look for task entry points by calling convention
	for (const auto& func : m_view->GetAnalysisFunctionList())
	{
		auto cc = func->GetCallingConvention();
		if (cc.GetValue() && cc.GetValue()->GetName() == "task-entry")
		{
			// This is already marked as a task entry
			continue;
		}
	}
}

void FunctionDetector::ScanStatisticalPatterns(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.instructionSequence.enabled && !m_settings.entropyTransition.enabled)
		return;
	
	m_logger->LogDebug("FunctionDetector: Scanning statistical patterns...");
	
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();
	
	// Entropy-based detection
	if (m_settings.entropyTransition.enabled)
	{
		double prevEntropy = 0;
		for (uint64_t addr = start; addr + 64 <= end; addr += 32)
		{
			double entropy = CalculateLocalEntropy(addr, 64);
			
			// Look for data->code transitions (high to medium entropy)
			if (prevEntropy < 3.0 && entropy > 4.5 && entropy < 7.0)
			{
				// Might be start of code after data
				AddCandidate(candidates, addr, false,
					DetectionSource::EntropyTransition, m_settings.entropyTransition.weight,
					"Entropy transition (data->code)");
			}
			
			prevEntropy = entropy;
		}
	}
}

void FunctionDetector::ApplyNegativePatterns(std::map<uint64_t, FunctionCandidate>& candidates)
{
	m_logger->LogDebug("FunctionDetector: Applying negative patterns...");
	
	for (auto& pair : candidates)
	{
		FunctionCandidate& c = pair.second;
		
		// Check if inside existing function
		if (m_settings.respectExistingFunctions && IsInsideKnownFunction(c.address))
		{
			c.sources |= static_cast<uint32_t>(DetectionSource::InsideFunction);
			c.sourceScores[DetectionSource::InsideFunction] = -m_settings.insideFunctionPenalty;
			c.warnings.push_back("Inside existing function");
		}
		
		// Check if in data region
		if (IsDataRegion(c.address))
		{
			c.sources |= static_cast<uint32_t>(DetectionSource::DataRegion);
			c.sourceScores[DetectionSource::DataRegion] = -m_settings.dataRegionPenalty;
			c.warnings.push_back("In data region");
		}
		
		// Check if mid-instruction (for ARM, must be 4-byte aligned)
		if (!c.isThumb && (c.address & 3))
		{
			c.sources |= static_cast<uint32_t>(DetectionSource::MidInstruction);
			c.sourceScores[DetectionSource::MidInstruction] = -m_settings.midInstructionPenalty;
			c.warnings.push_back("Misaligned for ARM");
		}
		
		// Check if invalid instruction
		if (!IsValidInstruction(c.address, c.isThumb))
		{
			c.sources |= static_cast<uint32_t>(DetectionSource::InvalidInstruction);
			c.sourceScores[DetectionSource::InvalidInstruction] = -m_settings.invalidInstructionPenalty;
			c.warnings.push_back("Invalid instruction");
		}
	}
}

double FunctionDetector::CalculateFinalScore(const FunctionCandidate& candidate)
{
	double positiveScore = 0;
	double negativeScore = 0;
	double maxPositive = 0;
	
	for (const auto& pair : candidate.sourceScores)
	{
		if (pair.second > 0)
		{
			positiveScore += pair.second;
			maxPositive += 3.0;  // Assume max weight of 3.0
		}
		else
		{
			negativeScore += std::abs(pair.second);
		}
	}
	
	// Normalize to 0-1 range
	double score = (positiveScore - negativeScore) / std::max(maxPositive, 1.0);
	return std::max(0.0, std::min(1.0, score));
}

DetectedCompiler FunctionDetector::DetectCompilerStyle()
{
	// Count patterns to determine compiler
	size_t gccPatterns = 0;
	size_t armccPatterns = 0;
	
	for (const auto& func : m_view->GetAnalysisFunctionList())
	{
		uint64_t addr = func->GetStart();
		uint32_t instr = ReadInstruction32(addr);
		
		// GCC pattern: PUSH without r12
		if ((instr & 0x0FFF0000) == 0x092D0000)
		{
			uint32_t reglist = instr & 0xFFFF;
			if (!(reglist & (1 << 12)) && (reglist & (1 << 14)))
				gccPatterns++;
			if ((reglist & (1 << 12)) && (reglist & (1 << 14)))
				armccPatterns++;
		}
	}
	
	if (gccPatterns > armccPatterns * 2)
		return DetectedCompiler::GCC;
	if (armccPatterns > gccPatterns * 2)
		return DetectedCompiler::ARMCC;
	
	return DetectedCompiler::Unknown;
}

std::vector<FunctionCandidate> FunctionDetector::Detect()
{
	return Detect(m_settings);
}

std::vector<FunctionCandidate> FunctionDetector::Detect(const FunctionDetectionSettings& settings)
{
	m_settings = settings;
	
	// Reset stats (don't use memset on struct with std::map!)
	m_stats.totalCandidates = 0;
	m_stats.highConfidence = 0;
	m_stats.mediumConfidence = 0;
	m_stats.lowConfidence = 0;
	m_stats.armFunctions = 0;
	m_stats.thumbFunctions = 0;
	m_stats.existingFunctions = 0;
	m_stats.newFunctions = 0;
	m_stats.detectedCompiler = DetectedCompiler::Unknown;
	m_stats.averageScore = 0.0;
	m_stats.sourceContributions.clear();
	
	m_logger->LogInfo("FunctionDetector: Starting detection...");
	
	// Cache existing functions
	m_existingFunctions.clear();
	for (const auto& func : m_view->GetAnalysisFunctionList())
	{
		m_existingFunctions.insert(func->GetStart());
	}
	m_stats.existingFunctions = m_existingFunctions.size();
	
	// Collect candidates from all detectors
	std::map<uint64_t, FunctionCandidate> candidates;
	
	ScanProloguePatterns(candidates);
	ScanCallTargets(candidates);
	ScanCrossReferences(candidates);
	ScanStructuralPatterns(candidates);
	ScanExceptionHandlers(candidates);
	ScanAdvancedPatterns(candidates);
	ScanCompilerPatterns(candidates);
	ScanRtosPatterns(candidates);
	ScanStatisticalPatterns(candidates);
	ApplyNegativePatterns(candidates);
	
	// Calculate final scores
	std::vector<FunctionCandidate> result;
	for (auto& pair : candidates)
	{
		FunctionCandidate& c = pair.second;
		c.score = CalculateFinalScore(c);
		
		if (c.score >= settings.minimumScore)
		{
			result.push_back(c);
			
			// Update stats
			if (c.score >= settings.highConfidenceScore)
				m_stats.highConfidence++;
			else if (c.score >= settings.minimumScore + 0.2)
				m_stats.mediumConfidence++;
			else
				m_stats.lowConfidence++;
			
			if (c.isThumb)
				m_stats.thumbFunctions++;
			else
				m_stats.armFunctions++;
			
			if (m_existingFunctions.find(c.address) == m_existingFunctions.end())
				m_stats.newFunctions++;
			
			// Track source contributions
			for (const auto& ss : c.sourceScores)
			{
				if (ss.second > 0)
					m_stats.sourceContributions[ss.first]++;
			}
		}
	}
	
	// Sort by score
	std::sort(result.begin(), result.end());
	
	// Limit results
	if (result.size() > settings.maxCandidates)
		result.resize(settings.maxCandidates);
	
	m_stats.totalCandidates = result.size();
	
	// Calculate average score
	double totalScore = 0;
	for (const auto& c : result)
		totalScore += c.score;
	m_stats.averageScore = result.empty() ? 0 : totalScore / result.size();
	
	m_logger->LogInfo("FunctionDetector: Found %zu candidates (high=%zu, med=%zu, low=%zu)",
		result.size(), m_stats.highConfidence, m_stats.mediumConfidence, m_stats.lowConfidence);
	
	return result;
}

size_t FunctionDetector::ApplyCandidates(const std::vector<FunctionCandidate>& candidates, double minScore)
{
	size_t applied = 0;
	
	for (const auto& c : candidates)
	{
		if (c.score < minScore)
			continue;
		
		// Skip existing functions
		if (m_existingFunctions.find(c.address) != m_existingFunctions.end())
			continue;
		
		// Create the function
		Ref<Platform> platform = m_view->GetDefaultPlatform();
		m_view->CreateUserFunction(platform, c.address);
		applied++;
		
		m_logger->LogDebug("FunctionDetector: Created function at 0x%llx (score=%.2f, %s)",
			(unsigned long long)c.address, c.score, c.isThumb ? "Thumb" : "ARM");
	}
	
	m_logger->LogInfo("FunctionDetector: Applied %zu functions", applied);
	return applied;
}

}
