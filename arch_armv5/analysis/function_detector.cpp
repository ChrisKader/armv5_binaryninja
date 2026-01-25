/*
 * Advanced Function Detector Implementation
 */

#include "function_detector.h"
#include "code_data_classifier.h"
#include "cfg/control_flow_graph.h"
#include "cfg/dominator_tree.h"
#include "linear_sweep.h"
#include "prologue_patterns.h"
#include "switch_resolver.h"
#include "common/armv5_utils.h"

#include <algorithm>
#include <chrono>
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
	case DetectionSource::CfgValidated:         return "CFG validated";
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
	m_logger = LogRegistry::CreateLogger("ARMv5.FunctionDetector");
}

void FunctionDetector::SetProgressCallback(ProgressCallback callback)
{
	m_progressCallback = std::move(callback);
	m_cancellationRequested = false;
}

bool FunctionDetector::IsCancellationRequested() const
{
	return m_cancellationRequested;
}

bool FunctionDetector::ReportProgress(size_t phase, size_t totalPhases, const std::string& phaseName)
{
	if (m_progressCallback)
	{
		if (!m_progressCallback(phase, totalPhases, phaseName))
		{
			m_cancellationRequested = true;
			return false;
		}
	}
	return !m_cancellationRequested;
}

FunctionDetectionSettings FunctionDetector::DefaultSettings()
{
	return FunctionDetectionSettings();
}

FunctionDetectionSettings FunctionDetector::AggressiveSettings()
{
	FunctionDetectionSettings s;
	s.ApplyUnifiedConfig(UnifiedDetectionConfig::Aggressive());
	s.alignmentPreference = 4;  // Prefer 4-byte aligned for ARM

	// Weights for weak signals (not covered by unified config)
	s.unlikelyPatternPenalty = 0.3;

	// Enable new detection methods with balanced weights
	// Our linear sweep is disabled - BN's built-in is faster and incremental
	// Our notification handler filters bad functions in real-time
	s.useLinearSweep = false;
	s.linearSweepWeight = 2.5;  // Weight if manually enabled
	s.useSwitchResolution = true;
	s.switchTargetWeight = 1.5;
	s.useTailCallAnalysis = true;
	s.tailCallTargetWeight = 1.5;

	// Higher limits for scanning
	s.linearSweepMaxBlocks = 75000;

	return s;
}

FunctionDetectionSettings FunctionDetector::ConservativeSettings()
{
	FunctionDetectionSettings s;
	s.ApplyUnifiedConfig(UnifiedDetectionConfig::Conservative());
	s.alignmentPreference = 4;

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

void FunctionDetector::InitDataCache()
{
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();

	m_dataCacheStart = start;
	m_dataCacheLen = static_cast<size_t>(end - start);
	m_dataCache = m_view->ReadBuffer(start, m_dataCacheLen);
	m_dataCacheLen = m_dataCache.GetLength();  // Actual bytes read

	if (m_logger)
		m_logger->LogInfo("FunctionDetector: Data cache initialized: 0x%llx - 0x%llx (%zu bytes)",
			(unsigned long long)start, (unsigned long long)(start + m_dataCacheLen),
			m_dataCacheLen);
}

uint32_t FunctionDetector::ReadInstruction32(uint64_t address)
{
	// Fast path: read from bulk cache
	if (address >= m_dataCacheStart && address + 4 <= m_dataCacheStart + m_dataCacheLen)
	{
		const uint8_t* data = static_cast<const uint8_t*>(m_dataCache.GetData());
		size_t offset = static_cast<size_t>(address - m_dataCacheStart);
		return data[offset] | (data[offset + 1] << 8) |
		       (data[offset + 2] << 16) | (data[offset + 3] << 24);
	}
	// Slow fallback for addresses outside cache
	DataBuffer buf = m_view->ReadBuffer(address, 4);
	if (buf.GetLength() < 4)
		return 0;
	const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
	return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

uint16_t FunctionDetector::ReadInstruction16(uint64_t address)
{
	// Fast path: read from bulk cache
	if (address >= m_dataCacheStart && address + 2 <= m_dataCacheStart + m_dataCacheLen)
	{
		const uint8_t* data = static_cast<const uint8_t*>(m_dataCache.GetData());
		size_t offset = static_cast<size_t>(address - m_dataCacheStart);
		return data[offset] | (data[offset + 1] << 8);
	}
	// Slow fallback for addresses outside cache
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
	}
	else
	{
		if (address & 3)
			return false;  // Must be 4-byte aligned
	}

	// Reject if this address is in a data region
	if (IsDataRegion(address))
		return false;

	// Read bytes and reject obvious padding
	size_t instrLen = thumb ? 2 : 4;
	DataBuffer buf = m_view->ReadBuffer(address, instrLen);
	if (buf.GetLength() < instrLen)
		return false;

	const uint8_t* bytes = static_cast<const uint8_t*>(buf.GetData());

	if (!thumb)
	{
		// Reject null and all-FF padding
		uint32_t instr = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
		if (instr == 0x00000000 || instr == 0xFFFFFFFF)
			return false;
		// Basic condition field check
		uint32_t cond = (instr >> 28) & 0xF;
		if (cond > 0xE)
			return false;
	}
	else
	{
		uint16_t instr = bytes[0] | (bytes[1] << 8);
		if (instr == 0x0000 || instr == 0xFFFF)
			return false;
	}

	// Attempt actual instruction decode via the architecture
	Ref<Architecture> arch = m_view->GetDefaultArchitecture();
	if (arch)
	{
		if (thumb)
		{
			uint64_t tempAddr = address | 1;
			Ref<Architecture> thumbArch = arch->GetAssociatedArchitectureByAddress(tempAddr);
			if (thumbArch)
				arch = thumbArch;
		}
		InstructionInfo info;
		if (!arch->GetInstructionInfo(bytes, address, buf.GetLength(), info) || info.length == 0)
			return false;
	}

	return true;
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
	return CodeDataClassifier::IsDataRegion(m_view, address);
}

bool FunctionDetector::IsValidBranchSource(uint64_t sourceAddress, bool thumb)
{
	// Validate that a BL/BLX instruction's source address is in a legitimate
	// code region. Data bytes that happen to decode as BL produce false call
	// targets, so we verify the source is real code before trusting its target.

	// Must be properly aligned
	if (!thumb && (sourceAddress & 3))
		return false;
	if (thumb && (sourceAddress & 1))
		return false;

	// Must not be in a data region (covers segment flags, data variables,
	// strings, code semantics, and file-backed checks)
	if (IsDataRegion(sourceAddress))
		return false;

	// Must be a decodable instruction at the source
	Ref<Architecture> arch = m_view->GetDefaultArchitecture();
	if (arch)
	{
		if (thumb)
		{
			uint64_t tempAddr = sourceAddress | 1;
			Ref<Architecture> thumbArch = arch->GetAssociatedArchitectureByAddress(tempAddr);
			if (thumbArch)
				arch = thumbArch;
		}
		size_t readLen = thumb ? 4 : 4;  // BL is always 4 bytes (even Thumb BL is 32-bit)
		DataBuffer buf = m_view->ReadBuffer(sourceAddress, readLen);
		if (buf.GetLength() < readLen)
			return false;

		InstructionInfo info;
		if (!arch->GetInstructionInfo(
				static_cast<const uint8_t*>(buf.GetData()), sourceAddress, buf.GetLength(), info)
			|| info.length == 0)
			return false;
	}

	return true;
}

bool FunctionDetector::CheckArmPrologue(uint64_t address, uint32_t instr)
{
	uint32_t cond = (instr >> 28) & 0xF;

	// Reject unconditional space (0xF) except for specific valid instructions
	if (cond == 0xF)
		return false;

	// PUSH {regs, lr} = STMDB sp!, {regs}
	// Encoding: cond 1001 0010 1101 reglist
	// Mask 0x0FFF0000 checks bits [27:16] for STMDB SP!
	if ((instr & 0x0FFF0000) == 0x092D0000)
	{
		uint32_t reglist = instr & 0xFFFF;
		// Must include LR (bit 14) for function prologue
		if (reglist & (1 << 14))
			return true;
	}

	// SUB sp, sp, #imm (stack frame allocation)
	// Encoding: cond 0010 0100 1101 1101 imm12
	// Mask 0x0FFF0000 checks bits [27:16] for SUB Rd=SP, Rn=SP
	if ((instr & 0x0FFF0000) == 0x024DD000)
		return true;

	// MOV r11, sp (frame pointer setup)
	// Encoding: cond 0001 1010 0000 1011 0000 0000 1101
	// Full instruction (with cond=AL): E1A0B00D
	// Mask out condition field and check opcode
	if ((instr & 0x0FFFFFFF) == 0x01A0B00D)
		return true;

	// MOV ip, sp (ARMCC frame pointer setup)
	// Encoding: cond 0001 1010 0000 1100 0000 0000 1101
	// Full instruction (with cond=AL): E1A0C00D
	if ((instr & 0x0FFFFFFF) == 0x01A0C00D)
		return true;

	// STR lr, [sp, #-4]! (pre-indexed store of LR)
	// Encoding: cond 0101 0010 1101 1110 0000 0000 0100
	// Full instruction (with cond=AL): E52DE004
	if ((instr & 0x0FFFFFFF) == 0x052DE004)
		return true;

	// STMFD sp!, {fp, ip, lr, pc} - full APCS prologue
	// Encoding: cond 1001 0010 1101 reglist (with fp,ip,lr,pc set)
	if ((instr & 0x0FFF0000) == 0x092D0000)
	{
		uint32_t reglist = instr & 0xFFFF;
		// Check for classic APCS prologue registers (r11, r12, lr, pc)
		if ((reglist & 0xD800) == 0xD800)  // fp(r11), ip(r12), lr set
			return true;
	}

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
	// Limit to estimated code region to avoid scanning data
	if (m_estimatedCodeEnd > 0 && m_estimatedCodeEnd < end)
		end = m_estimatedCodeEnd;
	
	uint64_t rangeSize = (end > start) ? (end - start) : 1;

	// Scan ARM mode
	if (m_settings.detectArmFunctions)
	{
		for (uint64_t addr = start; addr + 4 <= end; addr += 4)
		{
			if ((addr - start) % 0x10000 == 0 && addr > start)
			{
				size_t pct = (size_t)(100 * (addr - start) / rangeSize);
				ReportProgress(m_currentPhase, kTotalPhases,
					"[" + std::to_string(m_currentPhase) + "/" + std::to_string(kTotalPhases)
					+ "] ARM prologues... " + std::to_string(pct) + "%"
					+ " (" + std::to_string(candidates.size()) + " found)");
			}

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
			if ((addr - start) % 0x10000 == 0 && addr > start)
			{
				size_t pct = (size_t)(100 * (addr - start) / rangeSize);
				ReportProgress(m_currentPhase, kTotalPhases,
					"[" + std::to_string(m_currentPhase) + "/" + std::to_string(kTotalPhases)
					+ "] Thumb prologues... " + std::to_string(pct) + "%"
					+ " (" + std::to_string(candidates.size()) + " found)");
			}

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

bool FunctionDetector::IsEpilogueInstruction(uint64_t address, bool isThumb)
{
	// Check if the instruction at this address is an epilogue (return) pattern
	// Functions don't start with return instructions
	if (!isThumb)
	{
		uint32_t instr = ReadInstruction32(address);
		uint32_t cond = (instr >> 28) & 0xF;

		// Only unconditional returns are definite epilogues
		if (cond != 0xE)
			return false;

		// BX LR
		if ((instr & 0x0FFFFFFF) == 0x012FFF1E)
			return true;
		// MOV pc, lr
		if ((instr & 0x0FFFFFFF) == 0x01A0F00E)
			return true;
		// POP/LDMIA sp!, {..., pc}
		if ((instr & 0x0FFF0000) == 0x08BD0000 && (instr & (1 << 15)))
			return true;
		// LDR pc, [sp], #imm (post-indexed return)
		if ((instr & 0x0FFF0000) == 0x049D0000 && ((instr >> 12) & 0xF) == 0xF)
			return true;
	}
	else
	{
		uint16_t instr = ReadInstruction16(address);

		// POP {pc} - Thumb return
		if ((instr & 0xFE00) == 0xBC00 && (instr & 0x0100))
			return true;
		// BX LR - Thumb return
		if (instr == 0x4770)
			return true;
	}

	return false;
}

void FunctionDetector::ValidatePrologueBody(FunctionCandidate& candidate)
{
	// Skip if body validation is disabled
	if (!m_settings.useBodyValidation)
		return;

	// Only validate candidates that have a prologue source
	bool hasPrologue = (candidate.sources & static_cast<uint32_t>(DetectionSource::ProloguePush)) ||
	                   (candidate.sources & static_cast<uint32_t>(DetectionSource::PrologueStmfd)) ||
	                   (candidate.sources & static_cast<uint32_t>(DetectionSource::PrologueSubSp));
	if (!hasPrologue)
		return;

	// Reset validation state
	candidate.bodyValidated = false;
	candidate.bodyInstrCount = 0;
	candidate.bodyBlCalls = 0;
	candidate.bodyHasReturn = false;
	candidate.bodyValidationBonus = 0;

	uint64_t addr = candidate.address;
	bool isThumb = candidate.isThumb;
	size_t instrSize = isThumb ? 2 : 4;
	size_t maxInstrs = m_settings.bodyValidationMaxInstrs;

	// Start scanning after the prologue instruction
	addr += instrSize;

	for (size_t i = 0; i < maxInstrs; i++)
	{
		// Check bounds
		if (addr < m_dataCacheStart || addr >= m_dataCacheStart + m_dataCacheLen)
			break;

		if (!isThumb)
		{
			// ARM mode
			uint32_t instr = ReadInstruction32(addr);
			uint32_t cond = (instr >> 28) & 0xF;

			// Check for undefined/unpredictable instruction patterns
			// 0xE7XXXXXX with specific sub-patterns are undefined
			if (cond == 0xE && ((instr >> 25) & 0x7) == 0x3 && (instr & (1 << 4)))
			{
				// Undefined instruction - stop scanning
				break;
			}

			// Check for return instructions
			// BX LR (unconditional)
			if ((instr & 0x0FFFFFFF) == 0x012FFF1E && cond == 0xE)
			{
				candidate.bodyHasReturn = true;
				candidate.bodyInstrCount++;
				break;
			}
			// MOV pc, lr (unconditional)
			if ((instr & 0x0FFFFFFF) == 0x01A0F00E && cond == 0xE)
			{
				candidate.bodyHasReturn = true;
				candidate.bodyInstrCount++;
				break;
			}
			// POP/LDMIA sp!, {..., pc} (unconditional)
			if ((instr & 0x0FFF0000) == 0x08BD0000 && (instr & (1 << 15)) && cond == 0xE)
			{
				candidate.bodyHasReturn = true;
				candidate.bodyInstrCount++;
				break;
			}
			// LDMFD sp!, {..., pc} alternate encoding
			if ((instr & 0x0FFF0000) == 0x08BD0000 && (instr & (1 << 15)))
			{
				candidate.bodyHasReturn = true;
				candidate.bodyInstrCount++;
				break;
			}

			// Check for BL/BLX instructions (internal calls)
			// BL: 1110 1011 xxxx xxxx xxxx xxxx xxxx xxxx
			if ((instr & 0x0F000000) == 0x0B000000)
			{
				candidate.bodyBlCalls++;
			}
			// BLX: 1111 101H xxxx xxxx xxxx xxxx xxxx xxxx
			if ((instr & 0xFE000000) == 0xFA000000)
			{
				candidate.bodyBlCalls++;
			}

			// Check for obviously invalid patterns (all zeros, all ones)
			if (instr == 0x00000000 || instr == 0xFFFFFFFF)
				break;

			// Check for another prologue (would indicate function boundary)
			if ((instr & 0x0FFF0000) == 0x092D0000 && (instr & (1 << 14)))
			{
				// Found another prologue - we've crossed a function boundary
				break;
			}

			candidate.bodyInstrCount++;
			addr += 4;
		}
		else
		{
			// Thumb mode
			uint16_t instr = ReadInstruction16(addr);

			// Check for return instructions
			// BX LR: 0x4770
			if (instr == 0x4770)
			{
				candidate.bodyHasReturn = true;
				candidate.bodyInstrCount++;
				break;
			}
			// POP {pc}: 1011 1 10 1 reglist8 (bit 8 = PC)
			if ((instr & 0xFF00) == 0xBD00)
			{
				candidate.bodyHasReturn = true;
				candidate.bodyInstrCount++;
				break;
			}

			// Check for 32-bit Thumb instructions
			if ((instr & 0xE000) == 0xE000 && (instr & 0x1800) != 0)
			{
				// 32-bit Thumb instruction
				uint16_t instr2 = ReadInstruction16(addr + 2);
				uint32_t instr32 = (static_cast<uint32_t>(instr) << 16) | instr2;

				// Check for BL (32-bit): 1111 0xxx xxxx xxxx 11x1 xxxx xxxx xxxx
				if ((instr32 & 0xF800D000) == 0xF000D000)
				{
					candidate.bodyBlCalls++;
				}

				// Check for 32-bit POP.W {pc}
				// Encoding: 1110 1000 1011 1101 PM0x reglist
				if ((instr32 & 0xFFFF0000) == 0xE8BD0000 && (instr32 & (1 << 15)))
				{
					candidate.bodyHasReturn = true;
					candidate.bodyInstrCount++;
					break;
				}

				candidate.bodyInstrCount++;
				addr += 4;
				i++;  // Count as 2 instruction slots
			}
			else
			{
				// 16-bit Thumb instruction

				// Check for obviously invalid patterns
				if (instr == 0x0000 || instr == 0xFFFF)
					break;

				// Check for another Thumb prologue (PUSH {lr})
				if ((instr & 0xFF00) == 0xB500)
				{
					// Found another prologue - function boundary
					break;
				}

				// Check for BL prefix (we handle BL in 32-bit section above)
				// Just count valid instructions
				candidate.bodyInstrCount++;
				addr += 2;
			}
		}
	}

	// Determine if body validation passed
	// Criteria: found return instruction AND sufficient valid instructions
	if (candidate.bodyHasReturn && candidate.bodyInstrCount >= m_settings.bodyValidationMinInstrs)
	{
		candidate.bodyValidated = true;

		// Calculate bonus based on evidence strength
		double bonus = m_settings.bodyValidationWeight;

		// Bonus for BL calls found (indicates real function behavior)
		if (candidate.bodyBlCalls >= 3)
			bonus *= 1.2;
		else if (candidate.bodyBlCalls >= 1)
			bonus *= 1.1;

		// Bonus for longer instruction sequences (more confidence)
		if (candidate.bodyInstrCount >= 32)
			bonus *= 1.1;
		else if (candidate.bodyInstrCount >= 16)
			bonus *= 1.05;

		// Cap at reasonable maximum
		candidate.bodyValidationBonus = std::min(bonus, 2.0);
	}
}

void FunctionDetector::EstimateCodeBoundary()
{
	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();

	// Find the highest PROLOGUE address by scanning backward from the end.
	// Prologues (PUSH/STMFD with LR) are reliable code indicators.
	// Backward scan finds it in O(data_tail) instead of O(entire_image).
	uint64_t highestPrologue = start;
	if (end > start + 4)
	{
		// Align to 4-byte boundary, scan backward
		uint64_t addr = (end - 4) & ~3ULL;
		for (; addr >= start; addr -= 4)
		{
			uint32_t instr = ReadInstruction32(addr);
			// PUSH/STMFD sp!, {...} with LR (bit 14 set)
			if ((instr & 0x0FFF0000) == 0x092D0000 && (instr & 0x4000))
			{
				highestPrologue = addr;
				break;
			}
			// Guard against underflow
			if (addr == start)
				break;
		}
	}

	// Use configured boundary if set, otherwise auto-detect
	uint64_t configuredBoundary = 0;
	// TODO: Get firmware settings to access codeDataBoundary
	// For now, use automatic detection

	uint64_t codeBoundary = highestPrologue;

	// Add margin for tail code (functions without prologues)
	m_estimatedCodeEnd = codeBoundary + 0x8000;  // 32KB margin
	if (m_estimatedCodeEnd > end)
		m_estimatedCodeEnd = end;

	m_logger->LogInfo("FunctionDetector: Code boundary estimated at 0x%llx (highest prologue at 0x%llx)",
		(unsigned long long)m_estimatedCodeEnd, (unsigned long long)highestPrologue);
}

void FunctionDetector::ScanCallTargets(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.blTarget.enabled && !m_settings.blxTarget.enabled)
		return;

	m_logger->LogDebug("FunctionDetector: Scanning call targets...");

	uint64_t start = m_settings.scanStart ? m_settings.scanStart : m_view->GetStart();
	uint64_t end = m_settings.scanEnd ? m_settings.scanEnd : m_view->GetEnd();

	// Scan the FULL range for BL/BLX source instructions (not limited to
	// m_estimatedCodeEnd). The code boundary estimate can be wrong — code
	// can exist beyond the highest prologue. IsValidBranchSource() already
	// filters out BLs that originate from data regions, so scanning the
	// full range is safe and avoids missing call targets in late-code.
	m_logger->LogDebug("FunctionDetector: Scanning call targets from 0x%llx to 0x%llx",
		(unsigned long long)start, (unsigned long long)end);

	// Collect all call targets
	m_callTargets.clear();

	uint64_t armRangeSize = (end > start) ? (end - start) : 1;
	uint64_t thumbRangeSize = armRangeSize;

	// Scan for BL/BLX instructions across the full range.
	// IsValidBranchSource() filters out data-decoded BLs.
	for (uint64_t addr = start; addr + 4 <= end; addr += 4)
	{
		if ((addr - start) % 0x10000 == 0 && addr > start)
		{
			size_t pct = (size_t)(100 * (addr - start) / armRangeSize);
			ReportProgress(m_currentPhase, kTotalPhases,
				"[" + std::to_string(m_currentPhase) + "/" + std::to_string(kTotalPhases)
				+ "] ARM call targets... " + std::to_string(pct) + "%"
				+ " (" + std::to_string(m_callTargets.size()) + " found)");
		}

		uint32_t instr = ReadInstruction32(addr);
		uint32_t cond = (instr >> 28) & 0xF;

		// BL <label> - Encoding: cond 1011 imm24
		if ((instr & 0x0F000000) == 0x0B000000 && cond <= 0xE)
		{
			// Validate that the source BL instruction is in real code
			if (!IsValidBranchSource(addr, false))
				continue;

			int32_t offset = instr & 0x00FFFFFF;
			if (offset & 0x00800000)
				offset |= 0xFF000000;  // Sign extend
			offset = (offset << 2) + 8;  // PC + 8 + offset*4

			uint64_t target = addr + offset;
			if (target >= start && target < end)
			{
				// Skip targets that are epilogue instructions (stub functions)
				if (IsEpilogueInstruction(target, false))
					continue;

				m_callTargets.insert(target);
				AddCandidate(candidates, target, false,
					DetectionSource::BlTarget, m_settings.blTarget.weight,
					"BL target");
			}
		}

		// BLX <label> - Encoding: 1111 101 H imm24
		if ((instr & 0xFE000000) == 0xFA000000)
		{
			// Validate that the source BLX instruction is in real code
			if (!IsValidBranchSource(addr, false))
				continue;

			int32_t offset = instr & 0x00FFFFFF;
			if (offset & 0x00800000)
				offset |= 0xFF000000;
			offset = (offset << 2) + ((instr >> 23) & 2) + 8;

			uint64_t target = (addr + offset) & ~1ULL;
			if (target >= start && target < end)
			{
				// Skip targets that are epilogue instructions
				if (IsEpilogueInstruction(target, true))
					continue;

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
		if ((addr - start) % 0x10000 == 0 && addr > start)
		{
			size_t pct = (size_t)(100 * (addr - start) / thumbRangeSize);
			ReportProgress(m_currentPhase, kTotalPhases,
				"[" + std::to_string(m_currentPhase) + "/" + std::to_string(kTotalPhases)
				+ "] Thumb call targets... " + std::to_string(pct) + "%"
				+ " (" + std::to_string(m_callTargets.size()) + " found)");
		}

		uint16_t hw1 = ReadInstruction16(addr);
		uint16_t hw2 = ReadInstruction16(addr + 2);

		// 32-bit Thumb BL: 11110 S imm10 11 J1 1 J2 imm11
		if ((hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0xD000)
		{
			// Validate that the source Thumb BL instruction is in real code
			if (!IsValidBranchSource(addr, true))
				continue;

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

				// Skip targets that are epilogue instructions
				if (IsEpilogueInstruction(target, toThumb))
					continue;

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
	for (const auto& func : m_cachedFunctionList)
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
	// Limit to estimated code region — scanning data for structural patterns is noise
	if (m_estimatedCodeEnd > 0 && m_estimatedCodeEnd < end)
		end = m_estimatedCodeEnd;
	uint64_t rangeSize = (end > start) ? (end - start) : 1;

	// Look for code after return instructions
	if (m_settings.afterUnconditionalRet.enabled)
	{
		for (uint64_t addr = start; addr + 8 <= end; addr += 4)
		{
			if ((addr - start) % 0x10000 == 0 && addr > start)
			{
				size_t pct = (size_t)(100 * (addr - start) / rangeSize);
				ReportProgress(m_currentPhase, kTotalPhases,
					"[" + std::to_string(m_currentPhase) + "/" + std::to_string(kTotalPhases)
					+ "] Structural patterns... " + std::to_string(pct) + "%"
					+ " (" + std::to_string(candidates.size()) + " found)");
			}

			uint32_t instr = ReadInstruction32(addr);
			uint32_t cond = (instr >> 28) & 0xF;

			// Skip if conditional (not a definite return)
			bool isReturn = false;
			const char* returnType = nullptr;

			// BX LR - Return from function
			// Encoding: cond 0001 0010 1111 1111 1111 0001 1110
			if ((instr & 0x0FFFFFFF) == 0x012FFF1E && cond == 0xE)
			{
				isReturn = true;
				returnType = "After BX LR";
			}

			// MOV pc, lr - Return from function (common in ARMv4/ARMv5 leaf functions)
			// Encoding: cond 0001 1010 0000 1111 0000 0000 1110 = MOV pc, lr
			// With cond=AL: E1A0F00E
			if ((instr & 0x0FFFFFFF) == 0x01A0F00E && cond == 0xE)
			{
				isReturn = true;
				returnType = "After MOV pc, lr";
			}

			// POP {pc} / LDMIA sp!, {..., pc}
			// Encoding: cond 1000 1011 1101 reglist (LDMIA sp!)
			if ((instr & 0x0FFF0000) == 0x08BD0000 && (instr & (1 << 15)) && cond == 0xE)
			{
				isReturn = true;
				returnType = "After POP {pc}";
			}

			// LDMFD sp!, {..., pc} - same encoding as LDMIA sp!
			// Already covered above

			// LDR pc, [sp], #imm - Post-indexed load to PC
			// Encoding: cond 0100 1001 1101 1111 imm12 (LDR pc, [sp], #imm)
			// Example: E49DF004 = LDR pc, [sp], #4
			if ((instr & 0x0FFF0000) == 0x049D0000 && ((instr >> 12) & 0xF) == 0xF && cond == 0xE)
			{
				isReturn = true;
				returnType = "After LDR pc, [sp]";
			}

			// LDMDB sp, {..., pc} - Decrement before variant (sometimes used)
			// Encoding: cond 1001 0001 1101 reglist
			if ((instr & 0x0FFF0000) == 0x091D0000 && (instr & (1 << 15)) && cond == 0xE)
			{
				isReturn = true;
				returnType = "After LDMDB {pc}";
			}

			if (isReturn)
			{
				// Next instruction might be a new function
				// We no longer require a prologue pattern - this catches leaf functions
				// and optimized code that doesn't use traditional prologues
				uint64_t nextAddr = addr + 4;
				if (IsValidInstruction(nextAddr, false) && !IsInsideKnownFunction(nextAddr))
				{
					uint32_t nextInstr = ReadInstruction32(nextAddr);

					// Skip if this looks like an epilogue (return instruction)
					// These are false positives - function boundaries, not starts
					bool looksLikeEpilogue = IsEpilogueInstruction(nextAddr, false);
					if (looksLikeEpilogue)
						continue;

					// Skip if this looks like data (common patterns)
					// All zeros or all 0xFF are likely padding/data
					if (nextInstr == 0x00000000 || nextInstr == 0xFFFFFFFF)
						continue;

					// Skip undefined instruction space (0x06xxxxxx, 0x07xxxxxx with bit 4 set)
					uint32_t opcode = (nextInstr >> 25) & 0x7;
					if (opcode == 0x3 && (nextInstr & (1 << 4)))
						continue;  // Undefined instruction

					// Check for prologue patterns - if present, use full weight
					// If not present but still valid code, use reduced weight
					bool hasPrologue = false;

					// PUSH/STMFD sp!, {...}
					if ((nextInstr & 0x0FFF0000) == 0x092D0000)
						hasPrologue = true;
					// SUB sp, sp, #imm
					if ((nextInstr & 0x0FFF0000) == 0x024DD000)
						hasPrologue = true;
					// MOV ip, sp (ARMCC frame setup)
					if ((nextInstr & 0x0FFFFFFF) == 0x01A0C00D)
						hasPrologue = true;
					// MOV r11, sp (frame pointer setup)
					if ((nextInstr & 0x0FFFFFFF) == 0x01A0B00D)
						hasPrologue = true;
					// STR lr, [sp, #-4]! (pre-indexed store of LR)
					if ((nextInstr & 0x0FFFFFFF) == 0x052DE004)
						hasPrologue = true;
					// STR lr, [sp, #-imm]! (any pre-indexed LR store)
					if ((nextInstr & 0x0FFF0000) == 0x052D0000 && ((nextInstr >> 12) & 0xF) == 14)
						hasPrologue = true;

					// Use full weight for prologue, reduced weight for non-prologue.
					// Non-prologue: 1.3 * 0.8 = 1.04 -> score 1.04/6.0 = 0.173
					// This clears the 0.15 minimum threshold, allowing leaf functions
					// (which often lack prologues) to be detected when they appear
					// immediately after a return instruction.
					double weight = hasPrologue ? m_settings.afterUnconditionalRet.weight
					                            : m_settings.afterUnconditionalRet.weight * 0.8;

					AddCandidate(candidates, nextAddr, false,
						DetectionSource::AfterUnconditionalRet, weight,
						hasPrologue ? returnType : std::string(returnType) + " (no prologue)");
				}
			}
		}
	}
	
	// Look for code after unconditional tail calls (B instruction)
	// Functions can end with a tail call (B to another function) instead of return
	if (m_settings.afterTailCall.enabled)
	{
		for (uint64_t addr = start; addr + 8 <= end; addr += 4)
		{
			uint32_t instr = ReadInstruction32(addr);
			uint32_t cond = (instr >> 28) & 0xF;

			// Only unconditional branches are potential tail calls
			if (cond != 0xE)
				continue;

			// B <label> - Unconditional branch
			// Encoding: cond 1010 imm24
			if ((instr & 0x0F000000) == 0x0A000000)
			{
				// This could be a tail call - the next address might be a new function
				// However, we need to be careful: it could also be in the middle of
				// a function with a conditional branch around this.
				// Check if the target is outside a small range (likely tail call vs loop)
				int32_t offset = instr & 0x00FFFFFF;
				if (offset & 0x00800000)
					offset |= 0xFF000000;  // Sign extend
				int64_t relOffset = (int64_t)offset << 2;

				// Skip backward branches (loops) and very short forward branches
				// Tail calls typically jump far (to another function)
				if (relOffset < 8 || std::abs(relOffset) > 0x1000)
				{
					uint64_t nextAddr = addr + 4;
					// Only consider if next address looks like valid code start
					if (IsValidInstruction(nextAddr, false) && !IsInsideKnownFunction(nextAddr))
					{
						uint32_t nextInstr = ReadInstruction32(nextAddr);

						// Skip if this looks like an epilogue
						if (IsEpilogueInstruction(nextAddr, false))
							continue;

						// Skip if this looks like data
						if (nextInstr == 0x00000000 || nextInstr == 0xFFFFFFFF)
							continue;

						// Skip undefined instruction space
						uint32_t opcode = (nextInstr >> 25) & 0x7;
						if (opcode == 0x3 && (nextInstr & (1 << 4)))
							continue;

						// Check for prologue patterns - higher weight if present
						bool hasPrologue = false;
						// PUSH/STMFD
						if ((nextInstr & 0x0FFF0000) == 0x092D0000)
							hasPrologue = true;
						// SUB sp, sp, #imm
						if ((nextInstr & 0x0FFF0000) == 0x024DD000)
							hasPrologue = true;
						// MOV ip, sp (ARMCC)
						if ((nextInstr & 0x0FFFFFFF) == 0x01A0C00D)
							hasPrologue = true;
						// STR lr, [sp, #-4]!
						if ((nextInstr & 0x0FFFFFFF) == 0x052DE004)
							hasPrologue = true;

						double weight = hasPrologue ? m_settings.afterTailCall.weight
						                            : m_settings.afterTailCall.weight * 0.8;

						AddCandidate(candidates, nextAddr, false,
							DetectionSource::AfterTailCall, weight,
							hasPrologue ? "After tail call (B instruction)"
							            : "After tail call (no prologue)");
					}
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
	// Limit to estimated code region
	if (m_estimatedCodeEnd > 0 && m_estimatedCodeEnd < end)
		end = m_estimatedCodeEnd;
	
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

	// Instead of re-scanning the entire range (which duplicates Phase 1 work and
	// takes 20+ seconds for the PrologueMatcher's per-instruction ReadBuffer calls),
	// annotate existing prologue candidates with compiler-specific attribution.
	PrologueMatcher matcher(m_view);

	size_t annotated = 0;
	for (auto& pair : candidates)
	{
		FunctionCandidate& c = pair.second;

		// Only annotate candidates that came from prologue-related sources
		uint32_t prologueBits =
			static_cast<uint32_t>(DetectionSource::ProloguePush) |
			static_cast<uint32_t>(DetectionSource::PrologueSubSp) |
			static_cast<uint32_t>(DetectionSource::PrologueMovFp) |
			static_cast<uint32_t>(DetectionSource::PrologueStmfd);
		if (!(c.sources & prologueBits))
			continue;

		// Use PrologueMatcher to get detailed compiler attribution for this address
		auto matches = matcher.matchPrologue(c.address, c.isThumb);
		if (matches.empty() || matches[0].confidence < 0.7)
			continue;

		const auto& match = matches[0];

		// Determine detection source based on compiler
		DetectionSource source = DetectionSource::GccPrologue;
		double weight = m_settings.gccPrologue.weight;

		if (match.compiler == "ARMCC")
		{
			source = DetectionSource::ArmccPrologue;
			weight = m_settings.armccPrologue.weight;
		}
		else if (match.compiler == "IAR")
		{
			source = DetectionSource::IarPrologue;
			weight = m_settings.iarPrologue.weight;
		}
		else if (match.isInterruptHandler)
		{
			source = DetectionSource::InterruptPrologue;
			weight = m_settings.interruptPrologue.weight;
		}

		double score = weight * match.confidence;

		std::string desc = match.patternName;
		if (match.savesLR)
			desc += " (saves LR)";
		if (match.savesFramePointer)
			desc += " (uses FP)";
		if (match.stackAdjustment != 0)
			desc += " (stack: " + std::to_string(match.stackAdjustment) + ")";

		// Add compiler source to existing candidate
		c.sources |= static_cast<uint32_t>(source);
		c.sourceScores[source] = score;
		c.description += "; " + desc;
		annotated++;
	}

	m_logger->LogDebug("FunctionDetector: Annotated %zu candidates with compiler patterns", annotated);
}

void FunctionDetector::ScanRtosPatterns(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.taskEntryPattern.enabled)
		return;
	
	m_logger->LogDebug("FunctionDetector: Scanning RTOS patterns...");
	
	// Look for task entry points by calling convention
	for (const auto& func : m_cachedFunctionList)
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

void FunctionDetector::ScanSwitchTargets(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.useSwitchResolution)
		return;

	m_logger->LogDebug("FunctionDetector: Resolving switch tables...");

	// Configure switch resolver — limit to code region
	SwitchResolverSettings swSettings;
	swSettings.scanStart = m_settings.scanStart;
	swSettings.scanEnd = m_settings.scanEnd;
	if (m_estimatedCodeEnd > 0)
	{
		if (swSettings.scanEnd == 0 || m_estimatedCodeEnd < swSettings.scanEnd)
			swSettings.scanEnd = m_estimatedCodeEnd;
	}
	swSettings.maxTotalTables = m_settings.switchMaxTables;
	swSettings.validateTargets = true;

	SwitchResolver resolver(m_view);
	auto switches = resolver.resolveAll(swSettings);

	m_logger->LogDebug("FunctionDetector: Found %zu switch tables", switches.size());

	// Collect all switch targets
	std::set<uint64_t> switchTargets;
	for (const auto& sw : switches)
	{
		for (uint64_t target : sw.targets)
		{
			switchTargets.insert(target & ~1ULL);
		}
	}

	m_logger->LogDebug("FunctionDetector: %zu unique switch targets", switchTargets.size());

	// Add switch targets as candidates
	// These are typically case handlers, not full functions, so use lower weight
	// unless they look like function starts
	for (uint64_t target : switchTargets)
	{
		if (m_existingFunctions.count(target))
			continue;

		// Skip if inside known function
		if (IsInsideKnownFunction(target))
			continue;

		// Check if this target has a prologue pattern
		bool isThumb = false;  // Determine from address bit or context
		for (const auto& sw : switches)
		{
			for (uint64_t t : sw.targets)
			{
				if ((t & ~1ULL) == target)
				{
					isThumb = t & 1;
					break;
				}
			}
		}

		bool hasPrologue = false;
		if (!isThumb)
		{
			uint32_t instr = ReadInstruction32(target);
			// Check for PUSH/STMFD
			if ((instr & 0x0FFF0000) == 0x092D0000)
				hasPrologue = true;
			// Check for SUB sp
			if ((instr & 0x0FFF0000) == 0x024DD000)
				hasPrologue = true;
		}
		else
		{
			uint16_t instr = ReadInstruction16(target);
			// Check for PUSH
			if ((instr & 0xFE00) == 0xB400)
				hasPrologue = true;
		}

		// Use higher weight for targets with prologues (likely real functions)
		// Use lower weight for targets without (likely case blocks within a function)
		double weight = hasPrologue ? m_settings.switchTargetWeight
		                            : m_settings.switchTargetWeight * 0.4;

		AddCandidate(candidates, target, isThumb,
			DetectionSource::SwitchCaseHandler, weight,
			hasPrologue ? "Switch target (with prologue)" : "Switch case target");
	}

	auto stats = resolver.getStats();
	m_logger->LogDebug("FunctionDetector: Switch resolver stats: %zu TBB, %zu TBH, %zu ARM tables",
		stats.tbbTables, stats.tbhTables, stats.armTables);
}

void FunctionDetector::ScanTailCallTargets(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.useTailCallAnalysis)
		return;

	m_logger->LogDebug("FunctionDetector: Analyzing tail calls with stack tracking...");

	// Analyze existing functions to find tail calls
	// A tail call is an unconditional branch (B) where the stack has been restored
	// to its entry state (SP == entry SP)

	std::set<uint64_t> tailCallTargets;

	for (const auto& func : m_cachedFunctionList)
	{
		uint64_t funcStart = func->GetStart();
		auto arch = func->GetArchitecture();
		if (!arch)
			continue;

		bool isThumb = false;
		std::string archName = arch->GetName();
		if (archName.find('t') != std::string::npos || archName.find("thumb") != std::string::npos)
			isThumb = true;

		// Get basic blocks and look for unconditional branches at the end
		auto blocks = func->GetBasicBlocks();
		for (auto& block : blocks)
		{
			// Skip if not an exit block
			auto outEdges = block->GetOutgoingEdges();
			bool hasUnconditionalBranch = false;
			uint64_t branchTarget = 0;

			for (const auto& edge : outEdges)
			{
				if (edge.type == UnconditionalBranch)
				{
					hasUnconditionalBranch = true;
					branchTarget = edge.target->GetStart();
					break;
				}
			}

			if (!hasUnconditionalBranch || branchTarget == 0)
				continue;

			// Check if the branch target is outside this function
			bool targetOutsideFunction = true;
			for (auto& b : blocks)
			{
				if (branchTarget >= b->GetStart() && branchTarget < b->GetEnd())
				{
					targetOutsideFunction = false;
					break;
				}
			}

			if (!targetOutsideFunction)
				continue;  // Internal branch, not a tail call

			// Check if the stack is balanced at the branch point
			// We do this by looking for matching PUSH/POP or SUB/ADD pairs
			// This is a simplified analysis - full dataflow would be more accurate

			uint64_t blockStart = block->GetStart();
			uint64_t blockEnd = block->GetEnd();

			// Simple heuristic: check if there's a stack restore before the branch
			bool hasStackRestore = false;
			size_t instrSize = isThumb ? 2 : 4;

			// Scan backwards from the branch looking for stack restore
			for (uint64_t addr = blockEnd - instrSize; addr >= blockStart && addr >= blockEnd - 32; addr -= instrSize)
			{
				if (!isThumb)
				{
					uint32_t instr = ReadInstruction32(addr);

					// ADD sp, sp, #imm (stack cleanup)
					if ((instr & 0x0FFF0000) == 0x028DD000)
					{
						hasStackRestore = true;
						break;
					}

					// POP without PC (partial restore, then tail call)
					if ((instr & 0x0FFF0000) == 0x08BD0000 && !(instr & (1 << 15)))
					{
						hasStackRestore = true;
						break;
					}

					// LDM sp!, {...} without PC
					if ((instr & 0x0FFF0000) == 0x08BD0000 && !(instr & (1 << 15)))
					{
						hasStackRestore = true;
						break;
					}
				}
				else
				{
					uint16_t instr = ReadInstruction16(addr);

					// ADD sp, #imm (Thumb)
					if ((instr & 0xFF80) == 0xB000 && (instr & 0x80) == 0)
					{
						hasStackRestore = true;
						break;
					}

					// POP without PC (Thumb)
					if ((instr & 0xFE00) == 0xBC00 && !(instr & 0x100))
					{
						hasStackRestore = true;
						break;
					}
				}
			}

			// Also consider functions that never pushed (leaf functions doing tail calls)
			// Check if the function has any stack allocation at entry
			bool hasStackAlloc = false;
			uint64_t checkEnd = std::min(funcStart + 16, blockStart);
			for (uint64_t addr = funcStart; addr < checkEnd; addr += instrSize)
			{
				if (!isThumb)
				{
					uint32_t instr = ReadInstruction32(addr);
					// PUSH or SUB sp
					if ((instr & 0x0FFF0000) == 0x092D0000 ||
					    (instr & 0x0FFF0000) == 0x024DD000)
					{
						hasStackAlloc = true;
						break;
					}
				}
				else
				{
					uint16_t instr = ReadInstruction16(addr);
					// PUSH or SUB sp
					if ((instr & 0xFE00) == 0xB400 ||
					    ((instr & 0xFF80) == 0xB080))
					{
						hasStackAlloc = true;
						break;
					}
				}
			}

			// If no stack allocation, or stack was restored, this is likely a tail call
			if (!hasStackAlloc || hasStackRestore)
			{
				tailCallTargets.insert(branchTarget);
			}
		}
	}

	m_logger->LogDebug("FunctionDetector: Found %zu tail call targets", tailCallTargets.size());

	// Add tail call targets as function candidates
	for (uint64_t target : tailCallTargets)
	{
		if (m_existingFunctions.count(target))
			continue;

		// Skip if inside known function
		if (IsInsideKnownFunction(target))
			continue;

		// Determine if Thumb based on address or existing knowledge
		bool isThumb = (target & 1) != 0;
		target &= ~1ULL;

		if (!IsValidInstruction(target, isThumb))
			continue;

		if (IsEpilogueInstruction(target, isThumb))
			continue;

		AddCandidate(candidates, target, isThumb,
			DetectionSource::BlTarget,  // Reuse BL target since tail calls are similar
			m_settings.tailCallTargetWeight,
			"Tail call target (stack balanced)");
	}
}

void FunctionDetector::ScanLinearSweep(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.useLinearSweep)
		return;

	m_logger->LogDebug("FunctionDetector: Running linear sweep analysis (Nucleus-style)...");

	// Configure the linear sweep analyzer
	// LIMIT scan range to estimated code region to avoid finding blocks in data
	LinearSweepSettings lsSettings;

	// Apply unified config first (sets minimumConfidence, mode-specific params)
	lsSettings.ApplyUnifiedConfig(m_settings.unifiedConfig);

	// Then apply FunctionDetector-specific overrides
	lsSettings.scanStart = m_settings.scanStart;
	lsSettings.scanEnd = m_estimatedCodeEnd > 0 ? m_estimatedCodeEnd : m_settings.scanEnd;
	lsSettings.maxTotalBlocks = m_settings.linearSweepMaxBlocks;
	lsSettings.skipKnownFunctions = m_settings.respectExistingFunctions;
	
	m_logger->LogDebug("FunctionDetector: Linear sweep range 0x%llx to 0x%llx",
		(unsigned long long)lsSettings.scanStart, (unsigned long long)lsSettings.scanEnd);

	LinearSweepAnalyzer analyzer(m_view);
	auto functions = analyzer.analyze(lsSettings);

	m_logger->LogDebug("FunctionDetector: Linear sweep found %zu function candidates", functions.size());

	// Add discovered functions as candidates
	for (const auto& func : functions)
	{
		// Skip if already exists or already a candidate
		if (m_existingFunctions.count(func.entryPoint))
			continue;

		// Weight based on linear sweep confidence
		double weight = m_settings.linearSweepWeight * func.confidence;

		// Build description
		std::string desc = "Linear sweep: " + std::to_string(func.blockCount) + " blocks";
		if (func.hasReturn)
			desc += ", has return";
		if (func.isReferencedByCall)
			desc += ", called";

		// Add as candidate - use CfgValidated source since linear sweep validates via CFG structure
		AddCandidate(candidates, func.entryPoint, func.isThumb,
			DetectionSource::CfgValidated, weight, desc);
	}

	auto stats = analyzer.getStats();
	m_logger->LogDebug("FunctionDetector: Linear sweep stats: %zu blocks, %zu groups, %.2fs",
		stats.blocksDiscovered, stats.groupsFormed, stats.scanTimeSeconds);
}

void FunctionDetector::ScanCfgValidation(std::map<uint64_t, FunctionCandidate>& candidates)
{
	if (!m_settings.useCfgValidation || !m_settings.cfgValidation.enabled)
		return;

	m_logger->LogDebug("FunctionDetector: Validating candidates with CFG analysis...");

	size_t validated = 0;
	size_t failed = 0;
	size_t processed = 0;
	size_t totalCandidates = candidates.size();

	for (auto& pair : candidates)
	{
		if (++processed % 100 == 0)
		{
			ReportProgress(m_currentPhase, kTotalPhases,
				"[" + std::to_string(m_currentPhase) + "/" + std::to_string(kTotalPhases)
				+ "] CFG validation... " + std::to_string(processed) + "/" + std::to_string(totalCandidates)
				+ " (" + std::to_string(validated) + " valid)");
		}

		FunctionCandidate& c = pair.second;

		// Only validate candidates with a minimum score threshold
		if (c.score < m_settings.cfgValidation.threshold)
			continue;

		// Try to build a CFG from this candidate
		try
		{
			ControlFlowGraph cfg(m_view, c.address, c.isThumb);
			if (cfg.build(m_settings.cfgMaxBlocks, m_settings.cfgMaxInstructions))
			{
				// CFG built successfully - this is a strong signal
				c.cfgValidated = true;
				c.cfgBlockCount = cfg.blockCount();
				c.cfgEdgeCount = cfg.edgeCount();
				c.cfgComplexity = cfg.cyclomaticComplexity();

				// Check for valid structure (at least 1 block, has exit)
				auto exits = cfg.getExitBlocks();
				if (cfg.blockCount() >= 1 && !exits.empty())
				{
					c.sources |= static_cast<uint32_t>(DetectionSource::CfgValidated);
					c.sourceScores[DetectionSource::CfgValidated] = m_settings.cfgValidation.weight;

					// Compute loop count using dominator tree
					DominatorTree domTree(cfg);
					domTree.compute();
					auto loops = domTree.findNaturalLoops();
					c.cfgLoopCount = loops.size();

					validated++;
				}
			}
			else
			{
				// CFG failed to build - not necessarily bad, could be partial code
				c.warnings.push_back("CFG validation failed: " + cfg.errorMessage());
				failed++;
			}
		}
		catch (const std::exception& e)
		{
			c.warnings.push_back("CFG exception: " + std::string(e.what()));
			failed++;
		}
	}

	m_logger->LogDebug("FunctionDetector: CFG validation complete - %zu validated, %zu failed",
		validated, failed);
}

void FunctionDetector::ApplyNegativePatterns(std::map<uint64_t, FunctionCandidate>& candidates)
{
	m_logger->LogDebug("FunctionDetector: Applying negative patterns...");

	size_t processed = 0;
	size_t totalCandidates = candidates.size();

	for (auto& pair : candidates)
	{
		if (++processed % 200 == 0)
		{
			ReportProgress(m_currentPhase, kTotalPhases,
				"[" + std::to_string(m_currentPhase) + "/" + std::to_string(kTotalPhases)
				+ "] Negative patterns... " + std::to_string(processed) + "/" + std::to_string(totalCandidates));
		}

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
		
		// Check if mid-instruction (for ARM, must be 4-byte aligned; Thumb must be 2-byte aligned)
		bool isMisaligned = false;
		if (!c.isThumb && (c.address & 3))
			isMisaligned = true;
		if (c.isThumb && (c.address & 1))
			isMisaligned = true;

		if (isMisaligned)
		{
			c.sources |= static_cast<uint32_t>(DetectionSource::MidInstruction);
			c.sourceScores[DetectionSource::MidInstruction] = -m_settings.midInstructionPenalty;
			c.warnings.push_back(c.isThumb ? "Misaligned for Thumb" : "Misaligned for ARM");
			// Set score to 0 for misaligned - this is a hard rejection
			c.score = 0;
		}
		
		// Check if invalid instruction
		if (!IsValidInstruction(c.address, c.isThumb))
		{
			c.sources |= static_cast<uint32_t>(DetectionSource::InvalidInstruction);
			c.sourceScores[DetectionSource::InvalidInstruction] = -m_settings.invalidInstructionPenalty;
			c.warnings.push_back("Invalid instruction");
		}

		// Check if candidate is at an epilogue instruction (return pattern)
		// Functions don't start with return instructions - this is a strong anti-pattern
		if (!c.isThumb)
		{
			uint32_t instr = ReadInstruction32(c.address);
			uint32_t cond = (instr >> 28) & 0xF;
			bool isEpilogue = false;

			// BX LR - unconditional return
			if ((instr & 0x0FFFFFFF) == 0x012FFF1E && cond == 0xE)
				isEpilogue = true;
			// MOV pc, lr - unconditional return
			if ((instr & 0x0FFFFFFF) == 0x01A0F00E && cond == 0xE)
				isEpilogue = true;
			// POP/LDMIA sp!, {..., pc} - unconditional return
			if ((instr & 0x0FFF0000) == 0x08BD0000 && (instr & (1 << 15)) && cond == 0xE)
				isEpilogue = true;
			// LDR pc, [sp], #imm - post-indexed return
			if ((instr & 0x0FFF0000) == 0x049D0000 && ((instr >> 12) & 0xF) == 0xF && cond == 0xE)
				isEpilogue = true;

			if (isEpilogue)
			{
				// Use strong epilogue penalty - this is a definite anti-pattern
				c.sources |= static_cast<uint32_t>(DetectionSource::UnlikelyPattern);
				c.sourceScores[DetectionSource::UnlikelyPattern] = -m_settings.epiloguePenalty;
				c.warnings.push_back("Epilogue instruction (return) - not a function start");
			}
		}
		else
		{
			// Thumb epilogue detection
			uint16_t instr = ReadInstruction16(c.address);
			bool isEpilogue = false;

			// POP {pc} - Thumb return
			// Encoding: 1011 1 10 P reglist8
			if ((instr & 0xFE00) == 0xBC00 && (instr & 0x0100))
				isEpilogue = true;
			// BX LR - Thumb return
			// Encoding: 0100 0111 0 1110 000 = 0x4770
			if (instr == 0x4770)
				isEpilogue = true;

			if (isEpilogue)
			{
				// Use strong epilogue penalty - this is a definite anti-pattern
				c.sources |= static_cast<uint32_t>(DetectionSource::UnlikelyPattern);
				c.sourceScores[DetectionSource::UnlikelyPattern] = -m_settings.epiloguePenalty;
				c.warnings.push_back("Epilogue instruction (return) - not a function start");
			}
		}
	}
}

double FunctionDetector::GetConfiguredWeight(DetectionSource source) const
{
	switch (source)
	{
	case DetectionSource::ProloguePush:        return m_settings.prologuePush.weight;
	case DetectionSource::PrologueSubSp:       return m_settings.prologueSubSp.weight;
	case DetectionSource::PrologueMovFp:       return m_settings.prologueMovFp.weight;
	case DetectionSource::PrologueStmfd:       return m_settings.prologueStmfd.weight;
	case DetectionSource::BlTarget:            return m_settings.blTarget.weight;
	case DetectionSource::BlxTarget:           return m_settings.blxTarget.weight;
	case DetectionSource::IndirectCallTarget:  return m_settings.indirectCallTarget.weight;
	case DetectionSource::HighXrefDensity:     return m_settings.highXrefDensity.weight;
	case DetectionSource::PointerTableEntry:   return m_settings.pointerTableEntry.weight;
	case DetectionSource::AfterUnconditionalRet: return m_settings.afterUnconditionalRet.weight;
	case DetectionSource::AfterTailCall:       return m_settings.afterTailCall.weight;
	case DetectionSource::AlignmentBoundary:   return m_settings.alignmentBoundary.weight;
	case DetectionSource::AfterLiteralPool:    return m_settings.afterLiteralPool.weight;
	case DetectionSource::AfterPadding:        return m_settings.afterPadding.weight;
	case DetectionSource::VectorTableTarget:   return m_settings.vectorTableTarget.weight;
	case DetectionSource::InterruptPrologue:   return m_settings.interruptPrologue.weight;
	case DetectionSource::ThunkPattern:        return m_settings.thunkPattern.weight;
	case DetectionSource::TrampolinePattern:   return m_settings.trampolinePattern.weight;
	case DetectionSource::SwitchCaseHandler:   return m_settings.switchCaseHandler.weight;
	case DetectionSource::GccPrologue:         return m_settings.gccPrologue.weight;
	case DetectionSource::ArmccPrologue:       return m_settings.armccPrologue.weight;
	case DetectionSource::IarPrologue:         return m_settings.iarPrologue.weight;
	case DetectionSource::TaskEntryPattern:    return m_settings.taskEntryPattern.weight;
	case DetectionSource::CallbackPattern:     return m_settings.callbackPattern.weight;
	case DetectionSource::InstructionSequence: return m_settings.instructionSequence.weight;
	case DetectionSource::EntropyTransition:   return m_settings.entropyTransition.weight;
	case DetectionSource::CfgValidated:        return m_settings.cfgValidation.weight;
	// Negative sources — return their penalty values
	case DetectionSource::MidInstruction:      return m_settings.midInstructionPenalty;
	case DetectionSource::InsideFunction:      return m_settings.insideFunctionPenalty;
	case DetectionSource::DataRegion:          return m_settings.dataRegionPenalty;
	case DetectionSource::InvalidInstruction:  return m_settings.invalidInstructionPenalty;
	case DetectionSource::UnlikelyPattern:     return m_settings.unlikelyPatternPenalty;
	default:                                   return 1.0;
	}
}

double FunctionDetector::CalculateFinalScore(const FunctionCandidate& candidate)
{
	double positiveScore = 0;
	double negativeScore = 0;
	size_t positiveSourceCount = 0;

	for (const auto& pair : candidate.sourceScores)
	{
		if (pair.second > 0)
		{
			positiveScore += pair.second;
			positiveSourceCount++;
		}
		else
		{
			negativeScore += std::abs(pair.second);
		}
	}

	// Add body validation bonus if prologue body was validated
	// This rescues prologue-only candidates that have valid function bodies
	// but no incoming BL calls to corroborate their detection
	if (candidate.bodyValidated && candidate.bodyValidationBonus > 0)
	{
		positiveScore += candidate.bodyValidationBonus;
		positiveSourceCount++;  // Count as an additional source for corroboration
	}

	// Normalize against a FIXED maximum rather than per-candidate maximum.
	// This ensures a single weak source (e.g., AfterUnconditionalRet weight 0.78)
	// doesn't score the same as a multi-source candidate (e.g., BL target + prologue).
	//
	// The fixed denominator represents "ideal strong evidence": a BL target (3.0)
	// plus a prologue (1.5) plus structural evidence (1.3) = ~5.8.
	// Using 6.0 as the ceiling means:
	//   - Single BL target (3.0): score = 3.0/6.0 = 0.50
	//   - BL target + prologue (4.5): score = 4.5/6.0 = 0.75
	//   - BL + prologue + structural (5.8): score = 5.8/6.0 = 0.97
	//   - Single weak "after return" (0.78): score = 0.78/6.0 = 0.13
	//   - Prologue (1.5) + body validated (1.5): score = 3.0/6.0 = 0.50 ✓
	static constexpr double kScoreCeiling = 6.0;

	double rawScore = (positiveScore - negativeScore) / kScoreCeiling;

	// Corroboration bonus: multiple independent sources increase confidence.
	// Single-source candidates get no bonus; 2+ sources get a small boost.
	if (positiveSourceCount >= 3)
		rawScore *= 1.15;
	else if (positiveSourceCount >= 2)
		rawScore *= 1.05;

	return std::max(0.0, std::min(1.0, rawScore));
}

DetectedCompiler FunctionDetector::DetectCompilerStyle()
{
	// Count patterns to determine compiler
	size_t gccPatterns = 0;
	size_t armccPatterns = 0;

	for (const auto& func : m_cachedFunctionList)
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
	m_stats.bodyValidatedFunctions = 0;
	m_stats.detectedCompiler = DetectedCompiler::Unknown;
	m_stats.averageScore = 0.0;
	m_stats.sourceContributions.clear();
	
	m_logger->LogInfo("FunctionDetector: Starting detection...");

	auto setupStart = std::chrono::steady_clock::now();

	// Cache the function list once - calling GetAnalysisFunctionList() is expensive
	m_cachedFunctionList = m_view->GetAnalysisFunctionList();

	// Cache existing function addresses for O(1) lookup
	m_existingFunctions.clear();
	for (const auto& func : m_cachedFunctionList)
	{
		m_existingFunctions.insert(func->GetStart());
	}

	// Bulk-read the entire scan range into memory for fast instruction reads.
	// This eliminates millions of individual ReadBuffer() heap allocations.
	InitDataCache();

	// Estimate code boundary FIRST - this limits where we scan for candidates
	EstimateCodeBoundary();
	m_stats.existingFunctions = m_existingFunctions.size();

	double setupSecs = std::chrono::duration<double>(std::chrono::steady_clock::now() - setupStart).count();
	if (m_logger)
		m_logger->LogInfo("FunctionDetector: Setup (func list + data cache + boundary) took %.3f s", setupSecs);

	// Collect candidates from all detectors (14 phases total)
	std::map<uint64_t, FunctionCandidate> candidates;
	m_currentPhase = 0;

	// Reset cancellation state
	m_cancellationRequested = false;

	// Helper to build phase prefix string: "[N/14] label"
	auto phaseMsg = [&](const std::string& label) -> std::string {
		return "[" + std::to_string(m_currentPhase) + "/" + std::to_string(kTotalPhases) + "] " + label;
	};
	auto phaseDone = [&](const std::string& label) -> std::string {
		return phaseMsg(label) + " — " + std::to_string(candidates.size()) + " candidates";
	};

	// Timed phase runner: logs per-phase duration to help identify bottlenecks.
	auto runPhase = [&](const char* label, auto&& scanFn) -> bool {
		++m_currentPhase;
		if (!ReportProgress(m_currentPhase, kTotalPhases, phaseMsg(std::string("Scanning ") + label)))
			return false;
		auto t0 = std::chrono::steady_clock::now();
		scanFn();
		double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
		if (m_logger)
			m_logger->LogInfo("Phase %zu/%zu [%s] took %.3f s (%zu candidates)",
				m_currentPhase, kTotalPhases, label, secs, candidates.size());
		if (!ReportProgress(m_currentPhase, kTotalPhases, phaseDone(label)))
			return false;
		return true;
	};

	if (!runPhase("Prologue patterns", [&]() { ScanProloguePatterns(candidates); }))
		return {};
	if (!runPhase("Call targets", [&]() { ScanCallTargets(candidates); }))
		return {};
	if (!runPhase("Cross-references", [&]() { ScanCrossReferences(candidates); }))
		return {};
	if (!runPhase("Structural patterns", [&]() { ScanStructuralPatterns(candidates); }))
		return {};
	if (!runPhase("Exception handlers", [&]() { ScanExceptionHandlers(candidates); }))
		return {};
	if (!runPhase("Advanced patterns", [&]() { ScanAdvancedPatterns(candidates); }))
		return {};
	if (!runPhase("Compiler patterns", [&]() { ScanCompilerPatterns(candidates); }))
		return {};
	if (!runPhase("RTOS patterns", [&]() { ScanRtosPatterns(candidates); }))
		return {};
	if (!runPhase("Statistical patterns", [&]() { ScanStatisticalPatterns(candidates); }))
		return {};
	if (!runPhase("Switch tables", [&]() { ScanSwitchTargets(candidates); }))
		return {};
	if (!runPhase("Tail calls", [&]() { ScanTailCallTargets(candidates); }))
		return {};
	if (!runPhase("Linear sweep", [&]() { ScanLinearSweep(candidates); }))
		return {};
	if (!runPhase("Negative patterns", [&]() { ApplyNegativePatterns(candidates); }))
		return {};

	++m_currentPhase;
	if (!ReportProgress(m_currentPhase, kTotalPhases, phaseMsg("Scoring candidates")))
		return {};
	auto scoringStart = std::chrono::steady_clock::now();

	// Estimate code boundary using multiple heuristics
	// The key insight: data decoded as BL gives false targets, so we need to validate
	
	// Strategy 1: Find the highest PROLOGUE address (prologues are reliable)
	uint64_t highestPrologue = 0;
	// Strategy 2: Find the highest BL target where the CALLER is already a known function
	uint64_t highestValidBlTarget = 0;
	
	for (const auto& pair : candidates)
	{
		const FunctionCandidate& c = pair.second;
		
		// Prologues are very reliable indicators of real code
		if ((c.sources & static_cast<uint32_t>(DetectionSource::ProloguePush)) ||
		    (c.sources & static_cast<uint32_t>(DetectionSource::PrologueStmfd)))
		{
			highestPrologue = std::max(highestPrologue, c.address);
		}
		
		// Only count BL targets if the caller is an existing (seeded) function
		if (c.sources & static_cast<uint32_t>(DetectionSource::BlTarget))
		{
			// Check if this target is called from an existing function
			// (existing functions are the entry point and seeded handlers)
			if (m_existingFunctions.count(c.address) || c.address < highestPrologue)
			{
				highestValidBlTarget = std::max(highestValidBlTarget, c.address);
			}
		}
	}
	
	// Use the more conservative estimate (lower of the two)
	// Add a small margin for tail code
	uint64_t estimatedCodeEnd = std::max(highestPrologue, highestValidBlTarget);
	if (estimatedCodeEnd > 0)
		estimatedCodeEnd += 0x2000;  // 8KB margin for tail code
	
	// If we couldn't estimate, use a fallback based on view start
	if (estimatedCodeEnd == 0)
		estimatedCodeEnd = m_view->GetEnd();  // No filtering in this case
	
	m_logger->LogDebug("FunctionDetector: Estimated code end at 0x%llx (prologue=0x%llx, bl=0x%llx)", 
		(unsigned long long)estimatedCodeEnd, 
		(unsigned long long)highestPrologue,
		(unsigned long long)highestValidBlTarget);
	
	// Calculate final scores
	std::vector<FunctionCandidate> result;
	size_t scored = 0;
	size_t totalToScore = candidates.size();
	for (auto& pair : candidates)
	{
		if (++scored % 200 == 0)
		{
			ReportProgress(m_currentPhase, kTotalPhases,
				"[" + std::to_string(m_currentPhase) + "/" + std::to_string(kTotalPhases)
				+ "] Scoring... " + std::to_string(scored) + "/" + std::to_string(totalToScore)
				+ " (" + std::to_string(result.size()) + " passed)");
		}

		FunctionCandidate& c = pair.second;

		// HARD FILTER: Reject misaligned addresses - ARM must be 4-byte aligned, Thumb must be 2-byte aligned
		if (!c.isThumb && (c.address & 3))
			continue;  // Misaligned ARM
		if (c.isThumb && (c.address & 1))
			continue;  // Misaligned Thumb
		
		// HARD FILTER: Reject candidates well past estimated code end
		// unless they have strong evidence (call target, prologue)
		if (estimatedCodeEnd > 0 && c.address > estimatedCodeEnd)
		{
			bool hasStrongEvidence = (c.sources & static_cast<uint32_t>(DetectionSource::BlTarget)) ||
			                         (c.sources & static_cast<uint32_t>(DetectionSource::ProloguePush)) ||
			                         (c.sources & static_cast<uint32_t>(DetectionSource::PrologueStmfd));
			if (!hasStrongEvidence)
			{
				m_logger->LogDebug("FunctionDetector: Rejecting 0x%llx - past code end without strong evidence",
					(unsigned long long)c.address);
				continue;
			}
		}

		// PROLOGUE BODY VALIDATION: For candidates with prologue but no BL target,
		// scan forward to validate the function body. This rescues functions that
		// have valid prologues but no incoming calls to corroborate.
		bool hasPrologue = (c.sources & static_cast<uint32_t>(DetectionSource::ProloguePush)) ||
		                   (c.sources & static_cast<uint32_t>(DetectionSource::PrologueStmfd));
		bool hasBlTarget = (c.sources & static_cast<uint32_t>(DetectionSource::BlTarget)) ||
		                   (c.sources & static_cast<uint32_t>(DetectionSource::BlxTarget));

		// Only run body validation if:
		// 1. Candidate has a prologue
		// 2. Candidate does NOT have BL target (would already score well)
		// 3. Body validation is enabled
		if (m_settings.useBodyValidation && hasPrologue && !hasBlTarget)
		{
			ValidatePrologueBody(c);
		}

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

			// Track body-validated functions (rescued by forward scan)
			if (c.bodyValidated)
				m_stats.bodyValidatedFunctions++;

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

	// Limit results (0 = no limit)
	if (settings.maxCandidates > 0 && result.size() > settings.maxCandidates)
		result.resize(settings.maxCandidates);
	
	m_stats.totalCandidates = result.size();
	
	// Calculate average score
	double totalScore = 0;
	for (const auto& c : result)
		totalScore += c.score;
	m_stats.averageScore = result.empty() ? 0 : totalScore / result.size();

	// Log score distribution for diagnostics
	if (m_logger && !result.empty())
	{
		size_t above90 = 0, above70 = 0, above50 = 0, above30 = 0, below30 = 0;
		for (const auto& c : result)
		{
			if (c.score >= 0.9) above90++;
			else if (c.score >= 0.7) above70++;
			else if (c.score >= 0.5) above50++;
			else if (c.score >= 0.3) above30++;
			else below30++;
		}
		m_logger->LogInfo("FunctionDetector: Score distribution: >=0.9:%zu >=0.7:%zu >=0.5:%zu >=0.3:%zu <0.3:%zu (avg=%.3f, min=%.3f)",
			above90, above70, above50, above30, below30,
			m_stats.averageScore, result.back().score);
	}

	double scoringSecs = std::chrono::duration<double>(std::chrono::steady_clock::now() - scoringStart).count();
	if (m_logger)
		m_logger->LogInfo("Phase %zu/%zu [Scoring candidates] took %.3f s (%zu results)",
			m_currentPhase, kTotalPhases, scoringSecs, result.size());

	m_logger->LogInfo("FunctionDetector: Found %zu candidates (high=%zu, med=%zu, low=%zu, body-validated=%zu)",
		result.size(), m_stats.highConfidence, m_stats.mediumConfidence, m_stats.lowConfidence,
		m_stats.bodyValidatedFunctions);

	return result;
}

// ============================================================================
// DetectionFeedback Implementation
// ============================================================================

void DetectionFeedback::RecordCorrectDetection(uint64_t addr, uint32_t sources, double score)
{
	m_entries.push_back({addr, FeedbackType::Correct, sources, score});
}

void DetectionFeedback::RecordFalsePositive(uint64_t addr, uint32_t sources, double score)
{
	m_entries.push_back({addr, FeedbackType::FalsePositive, sources, score});
}

void DetectionFeedback::RecordMissedFunction(uint64_t addr)
{
	m_entries.push_back({addr, FeedbackType::Missed, 0, 0.0});
}

FunctionDetectionSettings DetectionFeedback::ComputeAdjustedSettings(const FunctionDetectionSettings& base) const
{
	FunctionDetectionSettings adjusted = base;

	if (m_entries.empty())
		return adjusted;

	// Count per-source correct and false-positive rates.
	// For each DetectionSource bit, tally how often it appears in correct
	// versus false-positive entries. Then scale the corresponding weight.
	std::map<uint32_t, size_t> sourceCorrect;
	std::map<uint32_t, size_t> sourceFalsePos;
	size_t totalCorrect = 0;
	size_t totalFalsePositive = 0;
	size_t totalMissed = 0;

	for (const auto& entry : m_entries)
	{
		switch (entry.type)
		{
		case FeedbackType::Correct:
			totalCorrect++;
			for (uint32_t bit = 0; bit < 32; bit++)
			{
				if (entry.detectionSources & (1U << bit))
					sourceCorrect[1U << bit]++;
			}
			break;
		case FeedbackType::FalsePositive:
			totalFalsePositive++;
			for (uint32_t bit = 0; bit < 32; bit++)
			{
				if (entry.detectionSources & (1U << bit))
					sourceFalsePos[1U << bit]++;
			}
			break;
		case FeedbackType::Missed:
			totalMissed++;
			break;
		}
	}

	// Helper: adjust a DetectorConfig weight based on its source bit's
	// correct/false-positive ratio. Increase weight when mostly correct,
	// decrease when mostly false-positive. Clamp to [0.1, 5.0].
	auto adjustWeight = [&](DetectorConfig& dc, uint32_t sourceBit) {
		size_t correct = sourceCorrect.count(sourceBit) ? sourceCorrect[sourceBit] : 0;
		size_t falsePos = sourceFalsePos.count(sourceBit) ? sourceFalsePos[sourceBit] : 0;
		size_t total = correct + falsePos;
		if (total < 3)
			return;  // Not enough data for this source

		double correctRate = static_cast<double>(correct) / total;
		// Scale factor: 0.7 for 0% correct, 1.0 for 50%, 1.3 for 100%
		double factor = 0.7 + 0.6 * correctRate;
		dc.weight = std::max(0.1, std::min(5.0, dc.weight * factor));
	};

	// Adjust prologue detector weights
	adjustWeight(adjusted.prologuePush, static_cast<uint32_t>(DetectionSource::ProloguePush));
	adjustWeight(adjusted.prologueSubSp, static_cast<uint32_t>(DetectionSource::PrologueSubSp));
	adjustWeight(adjusted.prologueMovFp, static_cast<uint32_t>(DetectionSource::PrologueMovFp));
	adjustWeight(adjusted.prologueStmfd, static_cast<uint32_t>(DetectionSource::PrologueStmfd));

	// Call targets
	adjustWeight(adjusted.blTarget, static_cast<uint32_t>(DetectionSource::BlTarget));
	adjustWeight(adjusted.blxTarget, static_cast<uint32_t>(DetectionSource::BlxTarget));
	adjustWeight(adjusted.indirectCallTarget, static_cast<uint32_t>(DetectionSource::IndirectCallTarget));

	// Cross-reference
	adjustWeight(adjusted.highXrefDensity, static_cast<uint32_t>(DetectionSource::HighXrefDensity));
	adjustWeight(adjusted.pointerTableEntry, static_cast<uint32_t>(DetectionSource::PointerTableEntry));

	// Structural
	adjustWeight(adjusted.afterUnconditionalRet, static_cast<uint32_t>(DetectionSource::AfterUnconditionalRet));
	adjustWeight(adjusted.afterTailCall, static_cast<uint32_t>(DetectionSource::AfterTailCall));
	adjustWeight(adjusted.alignmentBoundary, static_cast<uint32_t>(DetectionSource::AlignmentBoundary));
	adjustWeight(adjusted.afterLiteralPool, static_cast<uint32_t>(DetectionSource::AfterLiteralPool));
	adjustWeight(adjusted.afterPadding, static_cast<uint32_t>(DetectionSource::AfterPadding));

	// Exception/interrupt
	adjustWeight(adjusted.vectorTableTarget, static_cast<uint32_t>(DetectionSource::VectorTableTarget));
	adjustWeight(adjusted.interruptPrologue, static_cast<uint32_t>(DetectionSource::InterruptPrologue));

	// Advanced
	adjustWeight(adjusted.thunkPattern, static_cast<uint32_t>(DetectionSource::ThunkPattern));
	adjustWeight(adjusted.trampolinePattern, static_cast<uint32_t>(DetectionSource::TrampolinePattern));
	adjustWeight(adjusted.switchCaseHandler, static_cast<uint32_t>(DetectionSource::SwitchCaseHandler));

	// Compiler-specific
	adjustWeight(adjusted.gccPrologue, static_cast<uint32_t>(DetectionSource::GccPrologue));
	adjustWeight(adjusted.armccPrologue, static_cast<uint32_t>(DetectionSource::ArmccPrologue));
	adjustWeight(adjusted.iarPrologue, static_cast<uint32_t>(DetectionSource::IarPrologue));

	// RTOS
	adjustWeight(adjusted.taskEntryPattern, static_cast<uint32_t>(DetectionSource::TaskEntryPattern));
	adjustWeight(adjusted.callbackPattern, static_cast<uint32_t>(DetectionSource::CallbackPattern));

	// Statistical
	adjustWeight(adjusted.instructionSequence, static_cast<uint32_t>(DetectionSource::InstructionSequence));
	adjustWeight(adjusted.entropyTransition, static_cast<uint32_t>(DetectionSource::EntropyTransition));

	// CFG
	adjustWeight(adjusted.cfgValidation, static_cast<uint32_t>(DetectionSource::CfgValidated));

	// Adjust minimumScore based on overall false-positive vs missed ratio.
	// Too many false positives → raise threshold.
	// Too many missed → lower threshold.
	size_t totalFeedback = totalCorrect + totalFalsePositive + totalMissed;
	if (totalFeedback >= 5)
	{
		double fpRate = static_cast<double>(totalFalsePositive) / totalFeedback;
		double missRate = static_cast<double>(totalMissed) / totalFeedback;

		// Shift threshold: positive when FP > missed (raise), negative otherwise (lower)
		double shift = (fpRate - missRate) * 0.1;
		adjusted.minimumScore = std::max(0.1, std::min(0.9, adjusted.minimumScore + shift));
	}

	return adjusted;
}

Ref<Metadata> DetectionFeedback::ToMetadata() const
{
	// Serialize as an array of entry maps
	std::vector<Ref<Metadata>> entries;
	entries.reserve(m_entries.size());

	for (const auto& e : m_entries)
	{
		std::map<std::string, Ref<Metadata>> em;
		em["address"] = new Metadata(e.address);
		em["type"] = new Metadata((uint64_t)e.type);
		em["sources"] = new Metadata((uint64_t)e.detectionSources);
		em["score"] = new Metadata(e.originalScore);
		entries.push_back(new Metadata(em));
	}

	return new Metadata(entries);
}

DetectionFeedback DetectionFeedback::FromMetadata(Ref<Metadata> md)
{
	DetectionFeedback feedback;
	if (!md)
		return feedback;

	auto arr = md->GetArray();
	for (const auto& item : arr)
	{
		auto m = item->GetKeyValueStore();
		FeedbackEntry entry{};

		if (m.count("address"))
			entry.address = m["address"]->GetUnsignedInteger();
		if (m.count("type"))
		{
			uint64_t typeVal = m["type"]->GetUnsignedInteger();
			if (typeVal <= static_cast<uint64_t>(FeedbackType::Missed))
				entry.type = static_cast<FeedbackType>(typeVal);
		}
		if (m.count("sources"))
			entry.detectionSources = static_cast<uint32_t>(m["sources"]->GetUnsignedInteger());
		if (m.count("score"))
			entry.originalScore = m["score"]->GetDouble();

		feedback.m_entries.push_back(entry);
	}

	return feedback;
}

size_t FunctionDetector::ApplyCandidates(const std::vector<FunctionCandidate>& candidates, double minScore)
{
	size_t applied = 0;
	size_t skippedMisaligned = 0;
	Ref<Platform> defaultPlat = m_view->GetDefaultPlatform();
	Ref<Architecture> defaultArch = m_view->GetDefaultArchitecture();
	
	for (const auto& c : candidates)
	{
		if (c.score < minScore)
			continue;
		
		// Skip existing functions
		if (m_existingFunctions.find(c.address) != m_existingFunctions.end())
			continue;
		
		// Validate alignment: ARM requires 4-byte, Thumb requires 2-byte
		uint64_t funcAddr = c.address & ~1ULL;  // Clear potential Thumb bit
		if (!c.isThumb && (funcAddr & 3))
		{
			// ARM function at non-4-byte-aligned address - skip
			skippedMisaligned++;
			continue;
		}
		if (c.isThumb && (funcAddr & 1))
		{
			// Thumb function at odd address after clearing Thumb bit - skip
			skippedMisaligned++;
			continue;
		}
		
		// Use the correct platform based on candidate's isThumb flag
		Ref<Platform> platform = defaultPlat;
		if (c.isThumb && defaultArch)
		{
			// Get Thumb architecture and related platform
			uint64_t thumbAddr = c.address | 1;
			Ref<Architecture> thumbArch = defaultArch->GetAssociatedArchitectureByAddress(thumbAddr);
			if (thumbArch && thumbArch != defaultArch)
			{
				Ref<Platform> thumbPlat = defaultPlat->GetRelatedPlatform(thumbArch);
				if (thumbPlat)
					platform = thumbPlat;
			}
		}

		// Validate the function start (checks for strings, padding, etc.)
		if (!armv5::IsValidFunctionStart(m_view, platform, funcAddr, m_logger.GetPtr(), "FunctionDetector"))
		{
			m_logger->LogDebug("FunctionDetector: Rejected 0x%llx - failed validation",
				(unsigned long long)funcAddr);
			continue;
		}
		
		m_view->CreateUserFunction(platform, funcAddr);
		applied++;
		
		m_logger->LogDebug("FunctionDetector: Created function at 0x%llx (score=%.2f, %s)",
			(unsigned long long)funcAddr, c.score, c.isThumb ? "Thumb" : "ARM");
	}
	
	if (skippedMisaligned > 0)
		m_logger->LogDebug("FunctionDetector: Skipped %zu misaligned candidates", skippedMisaligned);
	
	m_logger->LogInfo("FunctionDetector: Applied %zu functions", applied);
	return applied;
}

}
