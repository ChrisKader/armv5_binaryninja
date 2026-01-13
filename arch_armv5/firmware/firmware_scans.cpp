/*
 * ARMv5 Firmware Scans
 */

#include "firmware_internal.h"
#include "firmware_view.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <map>
#include <set>
#include <unordered_set>
#include <vector>
#include <cstring>

using namespace std;
using namespace BinaryNinja;
using namespace armv5;

static bool IsAddressWithinView(const BinaryView* view, uint64_t addr, uint64_t size = 4)
{
	if (!view)
		return false;
	uint64_t length = view->GetLength();
	if (length < size)
		return false;
	uint64_t start = view->GetStart();
	if (addr < start)
		return false;
	uint64_t offset = addr - start;
	return offset <= length - size;
}

static void LogFirmwareActionSkip(Logger* logger, const char* action, uint64_t addr, const char* reason)
{
	if (!logger)
		return;
	logger->LogWarn("Firmware workflow: skip %s at 0x%llx (%s)",
		action, (unsigned long long)addr, reason);
}

static bool EnsureAddressInsideView(const BinaryView* view, Logger* logger,
	const char* action, uint64_t addr, uint64_t size = 4)
{
	if (IsAddressWithinView(view, addr, size))
		return true;
	LogFirmwareActionSkip(logger, action, addr, "outside view bounds");
	return false;
}

static inline bool ScanShouldAbort(const BinaryView* view)
{
	if (BNIsShutdownRequested())
		return true;
	if (!view)
		return true;
	if (IsFirmwareViewClosing(view))
		return true;
	if (IsFirmwareViewScanCancelled(view))
		return true;
	// Note: AnalysisIsAborted() is checked at phase boundaries in ShouldCancel(),
	// not here. Checking it here causes all scans to abort when maxFunctionUpdateCount
	// is hit for a single function, which is too aggressive.
	return false;
}

struct FirmwareActionPolicy
{
	bool allowAddFunction = true;
	bool allowDefineData = true;
	bool allowClearData = true;
	bool allowDefineSymbol = true;
	bool allowRemoveFunction = true;
};

static inline void PlanAddFunction(FirmwareScanPlan* plan, uint64_t addr)
{
	if (plan)
		plan->addFunctions.push_back(addr);
}

static inline void PlanRemoveFunction(FirmwareScanPlan* plan, uint64_t addr)
{
	if (plan)
		plan->removeFunctions.push_back(addr);
}

static inline void PlanDefineData(FirmwareScanPlan* plan, uint64_t addr, const Ref<Type>& type)
{
	if (plan)
		plan->defineData.push_back({addr, type});
}

static inline void PlanUndefineData(FirmwareScanPlan* plan, uint64_t addr)
{
	if (plan)
		plan->undefineData.push_back(addr);
}

static inline void PlanDefineSymbol(FirmwareScanPlan* plan, const Ref<Symbol>& symbol)
{
	if (plan)
		plan->defineSymbols.push_back(symbol);
}

static FirmwareActionPolicy ParseFirmwareActionPolicy()
{
	FirmwareActionPolicy policy;
	const char* env = getenv("BN_ARMV5_FIRMWARE_DISABLE_ACTIONS");
	if (!env || env[0] == '\0')
		return policy;

	auto normalize = [](std::string token) {
		for (char& ch : token)
		{
			if (ch == '-')
				ch = '_';
			ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
		}
		return token;
	};

	std::string current;
	auto applyToken = [&](const std::string& raw) {
		if (raw.empty())
			return;
		auto token = normalize(raw);
		if (token == "all")
		{
			policy.allowAddFunction = false;
			policy.allowDefineData = false;
			policy.allowClearData = false;
			policy.allowDefineSymbol = false;
			policy.allowRemoveFunction = false;
			return;
		}
		if (token == "add_function" || token == "add_functions")
		{
			policy.allowAddFunction = false;
			return;
		}
		if (token == "define_data" || token == "define_data_variable" || token == "define_data_variables")
		{
			policy.allowDefineData = false;
			return;
		}
		if (token == "clear_data" || token == "undefine_data" || token == "undefine_data_variable"
			|| token == "undefine_data_variables")
		{
			policy.allowClearData = false;
			return;
		}
		if (token == "define_symbol" || token == "define_symbols")
		{
			policy.allowDefineSymbol = false;
			return;
		}
		if (token == "remove_function" || token == "remove_functions")
		{
			policy.allowRemoveFunction = false;
			return;
		}
	};

	for (const char* p = env; *p; ++p)
	{
		char c = *p;
		if (c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
		{
			applyToken(current);
			current.clear();
			continue;
		}
		current.push_back(c);
	}
	applyToken(current);
	return policy;
}

static const FirmwareActionPolicy& GetFirmwareActionPolicy()
{
	static FirmwareActionPolicy policy = ParseFirmwareActionPolicy();
	return policy;
}

static bool HasExplicitCodeSemantics(BinaryView* view)
{
	auto sections = view->GetSections();
	for (auto& section : sections)
	{
		if (section->GetSemantics() == ReadOnlyCodeSectionSemantics)
			return true;
	}
	return false;
}

static inline bool IsPaddingWord(uint32_t word)
{
	return (word == 0) || (word == 0xFFFFFFFF) || (word == 0xE1A00000);
}

// Detect PC-relative literal loads (LDR Rt, [PC, #imm]) using instruction bits.
static inline bool IsLdrLiteral(uint32_t instr)
{
	// bits[27:26]=01, bit25=0 (imm), bit20=1 (L), Rn=PC (0b1111)
	return (instr & 0x0E1F0000) == 0x041F0000;
}

static inline bool IsJumpTableDispatchInstruction(uint32_t instr)
{
	// LDR PC, [PC, #imm] (PC-relative indirect jump)
	if ((instr & 0x0F7FF000) == 0x051FF000)
		return true;

	// ADD PC, PC, Rn (computed jump used by switch tables)
	if ((instr & 0x0FFFF010) == 0x008FF000)
		return true;

	return false;
}

static bool IsPcWriteInstruction(const Instruction& instr)
{
	// Direct branches
	switch (instr.operation)
	{
	case ARMV5_B:
	case ARMV5_BL:
	case ARMV5_BLX:
	case ARMV5_BX:
		return true;
	default:
		break;
	}

	// LDR PC, [...]
	if (instr.operation == ARMV5_LDR &&
		instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
		return true;

	// POP/LDM with PC in reg list
	if (instr.operation == ARMV5_POP || instr.operation == ARMV5_LDM ||
		instr.operation == ARMV5_LDMIA || instr.operation == ARMV5_LDMIB ||
		instr.operation == ARMV5_LDMDA || instr.operation == ARMV5_LDMDB)
	{
		for (int i = 0; i < MAX_OPERANDS; i++)
		{
			if (instr.operands[i].cls == NONE)
				break;
			if (instr.operands[i].cls == REG_LIST)
			{
				if (instr.operands[i].imm & (1U << REG_PC))
					return true;
				break;
			}
		}
	}

	// Data-processing writing to PC
	switch (instr.operation)
	{
	case ARMV5_ADC:
	case ARMV5_ADCS:
	case ARMV5_ADD:
	case ARMV5_ADDS:
	case ARMV5_AND:
	case ARMV5_ANDS:
	case ARMV5_ASR:
	case ARMV5_ASRS:
	case ARMV5_BIC:
	case ARMV5_BICS:
	case ARMV5_EOR:
	case ARMV5_EORS:
	case ARMV5_LSL:
	case ARMV5_LSLS:
	case ARMV5_LSR:
	case ARMV5_LSRS:
	case ARMV5_MVN:
	case ARMV5_MVNS:
	case ARMV5_ORR:
	case ARMV5_ORRS:
	case ARMV5_ROR:
	case ARMV5_RORS:
	case ARMV5_RSB:
	case ARMV5_RSBS:
	case ARMV5_RSC:
	case ARMV5_SBC:
	case ARMV5_SBCS:
	case ARMV5_SUB:
	case ARMV5_SUBS:
	case ARMV5_MOV:
	case ARMV5_MOVS:
		if (instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
			return true;
		break;
	default:
		break;
	}

	return false;
}

static bool IsLikelyFunctionBoundary(const uint8_t* data, uint64_t dataLen, BNEndianness endian,
	uint64_t imageBase, uint64_t length, uint64_t addr)
{
	// Treat the start of the code region as a boundary.
	if (addr <= imageBase + 0x40)
		return true;
	if (addr < imageBase + 4)
		return true;

	uint64_t prevAddr = addr - 4;
	if (prevAddr < imageBase || prevAddr + 4 > imageBase + length)
		return false;

	uint64_t prevOff = prevAddr - imageBase;
	if (prevOff + 4 > dataLen)
		return false;

	uint32_t prevWord = 0;
	memcpy(&prevWord, data + prevOff, sizeof(prevWord));
	if (endian == BigEndian)
		prevWord = Swap32(prevWord);

	// Padding or erased data implies a boundary.
	if (IsPaddingWord(prevWord))
		return true;

	armv5::Instruction decoded;
	memset(&decoded, 0, sizeof(decoded));
	if (armv5::armv5_decompose(prevWord, &decoded, (uint32_t)prevAddr, (uint32_t)(endian == BigEndian)) != 0)
		return true;

	// Only treat unconditional PC writes as hard boundaries.
	if (UNCONDITIONAL(decoded.cond) && IsPcWriteInstruction(decoded))
		return true;

	return false;
}

static bool IsAllowedPcWriteStart(const Instruction& instr)
{
	// Allow unconditional/conditional branch thunks and BL/BLX/BX.
	switch (instr.operation)
	{
	case ARMV5_B:
	case ARMV5_BL:
	case ARMV5_BLX:
	case ARMV5_BX:
		return true;
	default:
		break;
	}

	// Allow literal veneer style: LDR PC, [PC, #imm] (no register index)
	if (instr.operation == ARMV5_LDR &&
		instr.operands[0].cls == REG && instr.operands[0].reg == REG_PC)
	{
		const InstructionOperand& mem = instr.operands[1];
		if ((mem.cls == MEM_IMM || mem.cls == MEM_PRE_IDX) &&
			(mem.reg == REG_PC) && !mem.flags.offsetRegUsed)
			return true;
	}

	return false;
}

static bool ValidateFirmwareFunctionCandidate(BinaryView* view, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t imageBase, uint64_t length, uint64_t addr,
	const FirmwareScanTuning& tuning, bool requireBodyInstr, bool allowPcWriteStart)
{
	if (ScanShouldAbort(view))
		return false;
	uint64_t imageEnd = imageBase + length;
	if (addr < imageBase || addr + 4 > imageEnd)
		return false;
	if (addr & 3)
		return false;

	// Avoid defining functions on typed data when available.
	DataVariable dataVar;
	if (view->GetDataVariableAtAddress(addr, dataVar) && (dataVar.address == addr))
		return false;

	// Align candidate validation with core analysis by using the architecture's
	// GetInstructionInfo callback. This applies the same IsLikelyData heuristics
	// and undefined/unpredictable filtering the core uses when accepting code.
	Ref<Architecture> arch = view->GetDefaultArchitecture();
	if (!arch)
		arch = Architecture::GetByName("armv5");
	if (!arch)
		return false;

	uint64_t offset = addr - imageBase;
	if (offset + 4 > dataLen)
		return false;

	uint32_t minValid = (tuning.minValidInstr > 0) ? tuning.minValidInstr : 1;
	uint32_t minBody = tuning.minBodyInstr;
	uint32_t window = minValid;
	if (requireBodyInstr)
	{
		uint32_t needed = 1 + minBody;
		if (needed > window)
			window = needed;
	}

	uint32_t validCount = 0;
	uint32_t bodyCount = 0;
	uint32_t literalRun = 0;
	uint32_t paddingRun = 0;

	for (uint32_t i = 0; i < window; i++)
	{
		if (ScanShouldAbort(view))
			return false;
		uint64_t curOff = offset + (uint64_t)i * 4;
		if (curOff + 4 > dataLen)
			return false;

		uint32_t instr = 0;
		memcpy(&instr, data + curOff, sizeof(instr));
		if (endian == BigEndian)
			instr = Swap32(instr);

		if (i == 0 && IsPaddingWord(instr))
			return false;

		// Treat consecutive padding words as data, not code.
		if (IsPaddingWord(instr))
		{
			paddingRun++;
			if (paddingRun >= 2)
				return false;
			continue;
		}
		else
		{
			paddingRun = 0;
		}

		InstructionInfo info;
		size_t maxLen = 4;
		if (!arch->GetInstructionInfo(data + curOff, addr + i * 4, maxLen, info))
			return false;
		if (info.length != 4)
			return false;

		armv5::Instruction decoded;
		memset(&decoded, 0, sizeof(decoded));
		if (armv5::armv5_decompose(instr, &decoded, (uint32_t)(addr + i * 4), (uint32_t)(endian == BigEndian)) != 0)
			return false;

		if (i == 0 && IsPcWriteInstruction(decoded))
		{
			if (!allowPcWriteStart || !IsAllowedPcWriteStart(decoded))
				return false;
		}

		validCount++;
		if (i > 0)
			bodyCount++;

		if (IsLdrLiteral(instr))
			literalRun++;
		else
			literalRun = 0;

		if (literalRun > tuning.maxLiteralRun)
			return false;

		// Reject candidates that immediately branch/jump outside the binary image.
		// This prevents core analysis from chasing invalid targets and reading past EOF.
		if ((instr & 0x0E000000) == 0x0A000000)
		{
			int32_t imm24 = (int32_t)(instr & 0x00FFFFFF);
			if (imm24 & 0x00800000)
				imm24 |= 0xFF000000;
			int64_t target = (int64_t)(addr + (i * 4) + 8) + ((int64_t)imm24 << 2);
			if (target < (int64_t)imageBase || target >= (int64_t)(imageBase + length))
				return false;
		}

		// LDR PC, [PC, #imm] should reference a literal inside the image.
		if ((instr & 0x0F7FF000) == 0x051FF000)
		{
			uint32_t imm12 = instr & 0xFFF;
			bool add = (instr & 0x00800000) != 0;
			uint64_t litAddr = add ? (addr + (i * 4) + 8 + imm12) : (addr + (i * 4) + 8 - imm12);
			if (litAddr < imageBase || (litAddr + 4) > (imageBase + length))
				return false;
		}
	}

	if (validCount < minValid)
		return false;
	if (requireBodyInstr && (bodyCount < minBody))
		return false;

	return true;
}


static bool LooksLikeReturnThunk(const uint8_t* data, uint64_t dataLen, BNEndianness endian,
	uint64_t imageBase, uint64_t length, uint64_t addr)
{
	if (addr < imageBase || addr + 4 > imageBase + length)
		return false;
	uint64_t offset = addr - imageBase;
	const uint32_t maxInstrs = 6;

	for (uint32_t i = 0; i < maxInstrs; i++)
	{
		uint64_t cur = offset + (uint64_t)i * 4;
		if (cur + 4 > dataLen)
			return false;
		uint32_t word = 0;
		memcpy(&word, data + cur, sizeof(word));
		if (endian == BigEndian)
			word = Swap32(word);

		if (word == 0xE1A00000 || word == 0x00000000 || word == 0xFFFFFFFF)
			continue;

		armv5::Instruction instr;
		memset(&instr, 0, sizeof(instr));
		if (armv5::armv5_decompose(word, &instr, (uint32_t)cur, 0) != 0)
			return false;

		if ((instr.cond != armv5::COND_AL) && (instr.cond != armv5::COND_NV))
			return false;

		if (instr.operation == armv5::ARMV5_BX &&
			instr.operands[0].cls == armv5::REG && instr.operands[0].reg == armv5::REG_LR)
			return true;

		if (instr.operation == armv5::ARMV5_MOV &&
			instr.operands[0].cls == armv5::REG && instr.operands[0].reg == armv5::REG_PC &&
			instr.operands[1].cls == armv5::REG && instr.operands[1].reg == armv5::REG_LR)
			return true;

		if (instr.operation == armv5::ARMV5_POP || instr.operation == armv5::ARMV5_LDM ||
			instr.operation == armv5::ARMV5_LDMIA || instr.operation == armv5::ARMV5_LDMIB ||
			instr.operation == armv5::ARMV5_LDMDA || instr.operation == armv5::ARMV5_LDMDB)
		{
			for (int op = 0; op < MAX_OPERANDS; op++)
			{
				if (instr.operands[op].cls == armv5::NONE)
					break;
				if (instr.operands[op].cls == armv5::REG_LIST &&
					(instr.operands[op].imm & (1U << armv5::REG_PC)))
					return true;
			}
		}

		return false;
	}

	return false;
}


/*
 * Scan for ARM function prologues and add them as entry points.
 *
 * This provides more accurate function detection than Binary Ninja's generic
 * linear sweep, which over-detects due to ARM's dense instruction encoding.
 *
 * Detected ARM function prologues:
 *
 * Pattern 1: STMFD/PUSH sp!, {..., lr} with 2+ registers including lr
 *   Encoding: 0xE92D4xxx where reglist includes lr
 *   Example: push {r4, lr} = 0xE92D4010
 *
 * Pattern 1b: STMFD/PUSH sp!, {r0-r3, ip, lr} with 3+ scratch registers only
 *   Encoding: 0xE92D4xxx where reglist has 3+ regs but no r4-r11
 *   Example: push {r0, r1, r2, lr} = 0xE92D4007
 *   Common for wrapper/thunk functions that save args before a call
 *
 * Pattern 2: STMFD/PUSH sp!, {rX, lr} with 2 registers
 *   Encoding: 0xE92D40xx where popcount(reglist) == 2
 *   Common for small leaf functions that only need one callee-saved register
 *
 * Pattern 3: MOV ip, sp followed by STMFD with fp and lr
 *   Encoding: 0xE1A0C00D followed by 0xE92Dxxxx with bits 11 and 14 set
 *   Classic APCS frame pointer setup prologue
 *
 * Pattern 4: STR lr, [sp, #-4]! followed by SUB sp, sp, #imm
 *   Encoding: 0xE52DE004 followed by 0xE24DD0xx
 *   Common for small leaf functions and for stack frame allocation
 *
 * Pattern 5: MRS Rx, CPSR (when preceded by a boundary instruction)
 *   Encoding: 0xE10Fx000 (MRS Rd, CPSR)
 *   Interrupt enable/disable utility functions
 *   Only detected when immediately following a return or unconditional branch
 *
 * Pattern 6: MOV/MVN Rd, #imm followed by BX LR (short return-value function)
 *   Encoding: 0xE3A0xxxx or 0xE3E0xxxx followed by 0xE12FFF1E
 *   Example: mov r0, #0 + bx lr (return 0 function)
 *   Only detected when preceded by a boundary instruction
 *
 * Pattern 7: MCR/MRC (coprocessor access) when preceded by a boundary instruction
 *   Encoding: 0xEE....10 (MCR) or 0xEE....10 (MRC)
 *   System register accessor functions (CP15, etc.)
 *   Only detected when immediately following a boundary instruction
 *
 * NOT detected (high false positive rate):
 *   - Single-instruction stack adjustments or literal loads
 *   - Thumb prologues (0xB5xx appears frequently in ARM literals)
 *
 * Returns the number of function prologues found.
 */
size_t ScanForFunctionPrologues(BinaryView* view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	Ref<Architecture> armArch, Ref<Architecture> thumbArch, Ref<Platform> plat, Ref<Logger> logger,
	bool verboseLog, const FirmwareScanTuning& tuning, std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan)
{
	size_t prologuesFound = 0;
	size_t totalWords = 0;
	size_t codeWords = 0;
	size_t prologueHits = 0;
	size_t addedCount = 0;
	size_t skippedExisting = 0;
	size_t skippedNonCode = 0;
	size_t skippedInvalidCandidate = 0;

	const auto& actionPolicy = GetFirmwareActionPolicy();
	Logger* log = logger ? logger.GetPtr() : nullptr;
	bool enforceCodeSemantics = HasExplicitCodeSemantics(view);

	// Minimum offset to start scanning (skip vector table area)
	uint64_t startOffset = 0x40;
	uint64_t scanLen = (dataLen < length) ? dataLen : length;
	if (scanLen <= startOffset)
		return 0;

	// Track addresses we've already added to avoid duplicates
	std::set<uint64_t> addedAddrs;
	std::vector<uint64_t> pendingAdds;
	pendingAdds.reserve(256);
	const size_t addBatchSize = 256;

	auto flushAdds = [&]()
	{
		if (pendingAdds.empty())
			return;
		for (uint64_t addr : pendingAdds)
		{
			if (ScanShouldAbort(view))
				break;
			if (!EnsureAddressInsideView(view, log, "AddFunction", addr))
				continue;
			if (!actionPolicy.allowAddFunction)
				continue;
			if (plan)
			{
				PlanAddFunction(plan, addr);
				if (seededFunctions)
					seededFunctions->insert(addr);
				addedCount++;
				continue;
			}
			if (view->AddFunctionForAnalysis(plat, addr, true))
			{
				if (seededFunctions)
					seededFunctions->insert(addr);
				addedCount++;
			}
		}
		pendingAdds.clear();
	};

	// Helper to add a function if not already added
	auto addFunction = [&](uint64_t funcAddr, bool requireBodyInstr) {
		if (ScanShouldAbort(view))
			return;
		if (addedAddrs.find(funcAddr) == addedAddrs.end())
		{
			if (!view->GetAnalysisFunctionsContainingAddress(funcAddr).empty())
			{
				skippedExisting++;
				return;
			}
			if (!ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
				funcAddr, tuning, requireBodyInstr, false))
			{
				skippedInvalidCandidate++;
				return;
			}
			addedAddrs.insert(funcAddr);
			pendingAdds.push_back(funcAddr);
			if (pendingAdds.size() >= addBatchSize)
				flushAdds();
			prologuesFound++;
		}
	};

	if (logger)
		logger->LogInfo("Prologue scan: Scanning for function prologues in %llu bytes",
			(unsigned long long)(length - startOffset));

	// Track the previous instruction for boundary-based patterns
	uint32_t prevInstr = 0;
	uint32_t prevPrevInstr = 0;

	// Scan for ARM prologues (4-byte aligned)
	for (uint64_t offset = startOffset; offset + 4 <= scanLen; offset += 4)
	{
		if (ScanShouldAbort(view))
			break;
		totalWords++;
		uint64_t instrAddr = imageBase + offset;
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(instrAddr))
		{
			skippedNonCode++;
			prevPrevInstr = 0;
			prevInstr = 0;
			continue;
		}
		codeWords++;

		uint32_t instr = 0;
		if (offset + 4 <= dataLen)
		{
			memcpy(&instr, data + offset, sizeof(instr));
			if (endian == BigEndian)
				instr = Swap32(instr);
		}

		bool isPrologue = false;
		bool requireBodyInstr = true;

		auto isReturnInstr = [](uint32_t ins) -> bool {
			// BX Rn = 0xE12FFF1x (BX LR = 0xE12FFF1E)
			if ((ins & 0x0FFFFFF0) == 0x012FFF10)
				return true;
			// MOV PC, LR = 0xE1A0F00E
			if (ins == 0xE1A0F00E)
				return true;
			// LDMFD sp!, {..., pc} = 0xE8BD8xxx (POP with pc)
			if ((ins & 0xFFFF0000) == 0xE8BD0000 && (ins & 0x8000))
				return true;
			// LDMFD Rn!, {..., pc} = 0xE8B.8xxx (more general POP with pc)
			if ((ins & 0x0FFF0000) == 0x08B00000 && (ins & 0x8000))
				return true;
			return false;
		};

		auto isBoundaryInstr = [&](uint32_t ins) -> bool {
			if (isReturnInstr(ins))
				return true;
			// Unconditional B = 0xEAxxxxxx
			if ((ins & 0xFF000000) == 0xEA000000)
				return true;
			return false;
		};

		auto isValidArmInstruction = [&](uint32_t ins, uint64_t addr) -> bool {
			armv5::Instruction decoded;
			memset(&decoded, 0, sizeof(decoded));
			return armv5::armv5_decompose(ins, &decoded, (uint32_t)addr, 0) == 0;
		};

		auto readWordAt = [&](uint64_t wordOffset, uint32_t& outWord) -> bool {
			if (wordOffset + 4 > dataLen)
				return false;
			memcpy(&outWord, data + wordOffset, sizeof(outWord));
			if (endian == BigEndian)
				outWord = Swap32(outWord);
			return true;
		};

		auto boundaryBefore = [&](uint64_t currOffset) -> bool {
			if (currOffset == startOffset)
				return true;
			int checked = 0;
			uint64_t off = currOffset;
			while (off >= 4 && checked < 8)
			{
				uint32_t w = 0;
				if (!readWordAt(off - 4, w))
					return false;
				if (IsPaddingWord(w))
				{
					off -= 4;
					checked++;
					continue;
				}
				return isBoundaryInstr(w);
			}
			return false;
		};

		auto hasReturnSoon = [&](uint64_t currOffset) -> bool {
			for (int i = 1; i <= 4; i++)
			{
				uint64_t off = currOffset + (uint64_t)i * 4;
				uint32_t w = 0;
				if (!readWordAt(off, w))
					return false;
				if (!isValidArmInstruction(w, off))
					return false;
				if (isReturnInstr(w))
					return true;
			}
			return false;
		};

		bool prevIsBoundary = boundaryBefore(offset);

		// Pattern 1: STMFD/STMDB/PUSH sp!, {..., lr} with 2+ registers
		// Encoding: cond 100 P U S W L Rn reglist
		// STMFD sp! = 1001 0010 1101 xxxx = 0xE92Dxxxx
		// Must have LR (bit 14) in register list
		if ((instr & 0xFFFF0000) == 0xE92D0000 && (instr & 0x4000) != 0)
		{
			uint32_t reglist = instr & 0xFFFF;
			int regCount = __builtin_popcount(reglist);
			if (regCount >= 2 && prevIsBoundary)
				isPrologue = true;
		}

		// Pattern 3: MOV ip, sp followed by STMFD with fp and lr
		// This is the classic APCS prologue
		// Very reliable as the two-instruction sequence is unlikely to appear in data
		if (instr == 0xE1A0C00D && prevIsBoundary)
		{
			if (offset + 8 <= dataLen)
			{
				uint32_t nextInstr = 0;
				memcpy(&nextInstr, data + offset + 4, sizeof(nextInstr));
				if (endian == BigEndian)
					nextInstr = Swap32(nextInstr);

				// STMDB sp!, {..., fp, ..., lr} = 0xE92D0800 | 0x4000
				if ((nextInstr & 0xFFFF0000) == 0xE92D0000 &&
					(nextInstr & 0x4800) == 0x4800)  // both fp (bit 11) and lr (bit 14)
					isPrologue = true;
			}
		}

		// Pattern 4: STR lr, [sp, #-4]! followed by SUB sp, sp, #imm
		// Encoding: 0xE52DE004 followed by 0xE24DD0xx
		if (instr == 0xE52DE004 && prevIsBoundary)
		{
			if (offset + 8 <= dataLen)
			{
				uint32_t nextInstr = 0;
				memcpy(&nextInstr, data + offset + 4, sizeof(nextInstr));
				if (endian == BigEndian)
					nextInstr = Swap32(nextInstr);

				if ((nextInstr & 0xFFFFF000) == 0xE24DD000)
					isPrologue = true;
			}
		}

		// Pattern 5: MRS Rx, CPSR when preceded by a return instruction
		// These are small interrupt enable/disable utility functions
		// Encoding: cond 0001 0 R 00 1111 Rd 0000 0000 0000
		// MRS Rd, CPSR = 0xE10F0000 | (Rd << 12)
		// Mask: 0x0FBF0FFF (ignore condition and Rd)
		if ((instr & 0x0FBF0FFF) == 0x010F0000)
		{
			if (prevIsBoundary && hasReturnSoon(offset))
			{
				isPrologue = true;
				requireBodyInstr = false;
			}
		}

		// Pattern 6: MOV/MVN Rd, #imm followed by BX LR (short return-value function)
		// These are small functions that just return a constant value
		// Very reliable as we verify both the MOV/MVN and the following BX LR
		// Only detected when preceded by a return (function boundary)
		if ((instr & 0x0FE00000) == 0x03A00000 || (instr & 0x0FE00000) == 0x03E00000)
		{
			if (prevIsBoundary && offset + 8 <= dataLen)
			{
				// Check if followed by BX LR
				uint32_t nextInstr = 0;
				memcpy(&nextInstr, data + offset + 4, sizeof(nextInstr));
				if (endian == BigEndian)
					nextInstr = Swap32(nextInstr);

				// BX LR = 0xE12FFF1E (or conditional)
				if ((nextInstr & 0x0FFFFFFF) == 0x012FFF1E)
				{
					isPrologue = true;
					requireBodyInstr = false;
				}
			}
		}

		// Pattern 7: MCR/MRC (coprocessor access) when preceded by a return
		// These are small system register accessor functions
		// MCR: cond 1110 opc1 0 CRn Rt coproc opc2 1 CRm
		// MRC: cond 1110 opc1 1 CRn Rt coproc opc2 1 CRm
		// Mask: check for 0xEE......1. pattern
		if ((instr & 0x0F000010) == 0x0E000010)
		{
			if (prevIsBoundary && hasReturnSoon(offset))
			{
				isPrologue = true;
				requireBodyInstr = false;
			}
		}

		if (isPrologue)
		{
			prologueHits++;
			addFunction(imageBase + offset, requireBodyInstr);
		}

		// Remember this instruction for next iteration
		prevPrevInstr = prevInstr;
		prevInstr = instr;
	}

	// NOTE: Thumb prologue scanning is disabled for now.
	// The TI-Nspire firmware is primarily ARM code, and scanning for Thumb
	// prologues creates many false positives because:
	// 1. 0xB5xx patterns appear frequently in ARM data/literals
	// 2. Without proper mode switching analysis, we can't reliably identify
	//    which regions are actually Thumb code
	//
	// Thumb functions will still be discovered via BX/BLX calls from ARM code
	// that set the Thumb bit in the target address.
	if (!ScanShouldAbort(view))
		flushAdds();

	if (logger)
		logger->LogInfo("Prologue scan: Found %zu function prologues", prologuesFound);
	if (verboseLog)
	{
		if (logger)
			logger->LogInfo(
				"Prologue scan detail: scanned=%zu code=%zu prologue_hits=%zu added=%zu skipped_existing=%zu "
				"skipped_noncode=%zu skipped_invalid_candidate=%zu",
				totalWords, codeWords, prologueHits, addedCount, skippedExisting, skippedNonCode,
				skippedInvalidCandidate);
	}
	return prologuesFound;
}


/*
 * Scan for BL, BLX, and LDR PC call targets to discover additional functions.
 *
 * This complements prologue scanning by finding functions that are called
 * but might not have recognizable prologues (e.g., hand-written assembly,
 * optimized leaf functions, Thumb code).
 * To reduce false positives, only callsites within discovered functions
 * are considered.
 *
 * Detected patterns:
 *
 * Pattern 1: BL imm (ARM branch-and-link)
 *   Encoding: cond 1011 imm24
 *   Example: BL 0x1000 = 0xEBxxxxxx
 *   The 24-bit signed offset is shifted left 2 and added to PC+8
 *
 * Pattern 2: BLX imm (ARM to Thumb call)
 *   Encoding: 1111 101 H imm24
 *   Example: BLX 0x1001 = 0xFAxxxxxx or 0xFBxxxxxx
 *   Target has Thumb bit set (bit 0 = 1)
 *
 * Pattern 3: LDR PC, [PC, #imm] (indirect jump via literal pool)
 *   Encoding: cond 0101 1001 1111 Rd imm12
 *   Example: LDR PC, [PC, #0x10] = 0xE59FFxxx
 *   Loads a function address from a nearby literal pool entry
 *
 * Returns the number of call targets found.
 */
size_t ScanForCallTargets(BinaryView* view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	Ref<Platform> plat, Ref<Logger> logger, bool verboseLog, const FirmwareScanTuning& tuning,
	std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan)
{
	size_t targetsFound = 0;
	uint64_t scanLen = (dataLen < length) ? dataLen : length;
	size_t totalInstrs = 0;
	size_t codeInstrs = 0;
	size_t inFunctionInstrs = 0;
	size_t nonFunctionInstrs = 0;
	size_t skippedNonCode = 0;
	size_t skippedNotInFunction = 0;
	size_t skippedPrevNotCode = 0;
	size_t blMatches = 0;
	size_t ldrMatches = 0;
	size_t addedCount = 0;
	size_t skipLdrPcInFunction = 0;
	size_t skipBlIntraFunction = 0;
	size_t skipBlNonFuncBoundary = 0;
	size_t skipMisaligned = 0;
	size_t skipOutOfBounds = 0;
	size_t skipNonCodeTarget = 0;
	size_t skipNonBoundary = 0;
	size_t skipExistingTarget = 0;
	size_t skipReturnThunk = 0;
	size_t skipInvalidTarget = 0;
	size_t skipDuplicate = 0;
	size_t skipInvalidCandidate = 0;

	const auto& actionPolicy = GetFirmwareActionPolicy();
	// Track addresses we've already added to avoid duplicates
	std::set<uint64_t> addedAddrs;
	bool enforceCodeSemantics = HasExplicitCodeSemantics(view);
	Logger* log = logger ? logger.GetPtr() : nullptr;
	std::vector<uint64_t> pendingAdds;
	pendingAdds.reserve(256);
	const size_t addBatchSize = 256;

	auto flushAdds = [&]()
	{
		if (pendingAdds.empty())
			return;
		for (uint64_t addr : pendingAdds)
		{
			if (ScanShouldAbort(view))
				break;
			if (!EnsureAddressInsideView(view, log, "AddFunction", addr))
				continue;
			if (!actionPolicy.allowAddFunction)
				continue;
			if (plan)
			{
				PlanAddFunction(plan, addr);
				if (seededFunctions)
					seededFunctions->insert(addr);
				addedCount++;
				continue;
			}
			if (view->AddFunctionForAnalysis(plat, addr, true))
			{
				if (seededFunctions)
					seededFunctions->insert(addr);
				addedCount++;
			}
		}
		pendingAdds.clear();
	};

	// Helper to add a function if not already added and target is valid
	auto addFunction = [&](uint64_t funcAddr, const char* source, bool requireBoundary) {
		if (ScanShouldAbort(view))
			return;
		// For ARM mode, addresses must be 4-byte aligned.
		// Strip any Thumb bit and reject misaligned addresses.
		uint64_t alignedAddr = funcAddr & ~3ULL;
		if (funcAddr & 3)
		{
			skipMisaligned++;
			return;
		}

		// Must be within image bounds
		if (alignedAddr < imageBase || alignedAddr >= imageBase + length)
		{
			skipOutOfBounds++;
			return;
		}

		// Only add functions in code semantics (standard BN behavior)
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(alignedAddr))
		{
			skipNonCodeTarget++;
			return;
		}

		// Reject targets that are not at a likely function boundary.
		if (requireBoundary && !IsLikelyFunctionBoundary(data, dataLen, endian, imageBase, length, alignedAddr))
		{
			skipNonBoundary++;
			return;
		}

		if (!view->GetAnalysisFunctionsContainingAddress(alignedAddr).empty())
		{
			skipExistingTarget++;
			return;
		}

		if (LooksLikeReturnThunk(data, dataLen, endian, imageBase, length, alignedAddr))
		{
			skipReturnThunk++;
			return;
		}

		// Validate target looks like valid ARM code
		uint64_t offset = alignedAddr - imageBase;
		if (offset + 4 <= dataLen)
		{
			uint32_t targetInstr = 0;
			memcpy(&targetInstr, data + offset, sizeof(targetInstr));
			if (endian == BigEndian)
				targetInstr = Swap32(targetInstr);

			// Skip if target is all zeros (BSS/uninitialized data)
			if (targetInstr == 0)
			{
				skipInvalidTarget++;
				return;
			}

			// Skip if target is all 0xFF (erased flash)
			if (targetInstr == 0xFFFFFFFF)
			{
				skipInvalidTarget++;
				return;
			}

			// In ARMv5, condition code 0b1111 (0xFxxxxxxx) is mostly undefined
			// except for a few specific encodings. Most valid ARM code uses
			// condition codes 0x0-0xE. Skip obvious non-code.
			uint32_t cond = (targetInstr >> 28) & 0xF;
			if (cond == 0xF)
			{
				// Only a few 0xF instructions are valid in ARMv5:
				// - BLX imm (0xFAxxxxxx, 0xFBxxxxxx)
				// - PLD (0xF55FF000 pattern)
				// Most other 0xFxxxxxxx patterns are undefined
				uint32_t op = (targetInstr >> 24) & 0xFF;
				if (op != 0xFA && op != 0xFB)
				{
					skipInvalidTarget++;
					return;  // Likely data, not code
				}
			}

			// Additional heuristic: very unlikely instruction patterns
			// ANDEQ r0, r0, r0 with random high bits often indicates data
			if ((targetInstr & 0x0FFFFFFF) == 0x00000000 && cond != 0xE)
			{
				skipInvalidTarget++;
				return;
			}
		}

		// Call-targets should start with real code, not a PC-write stub. Requiring
		// a body instruction and disallowing PC-write starts avoids seeding functions
		// that the core later merges or deletes as mid-function labels.
		if (!ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
			alignedAddr, tuning, true, false))
		{
			skipInvalidCandidate++;
			return;
		}

		if (addedAddrs.find(alignedAddr) == addedAddrs.end())
		{
			addedAddrs.insert(alignedAddr);
			pendingAdds.push_back(alignedAddr);
			if (pendingAdds.size() >= addBatchSize)
				flushAdds();
			targetsFound++;
		}
		else
		{
			skipDuplicate++;
		}
	};

	// Helper to check if an instruction looks like valid ARM code
	// Returns true if the instruction has a valid condition code and
	// doesn't match common literal pool patterns
	auto isLikelyCode = [&](uint32_t instr) -> bool {
		uint32_t cond = (instr >> 28) & 0xF;

		// Condition 0xF is mostly undefined in ARMv5
		if (cond == 0xF)
		{
			uint32_t op = (instr >> 24) & 0xFF;
			if (op != 0xFA && op != 0xFB)  // Only BLX is valid
				return false;
		}

		// All zeros or all ones is data
		if (instr == 0 || instr == 0xFFFFFFFF)
			return false;

		// Check for address-like patterns (literal pool entries)
		uint32_t highByte = (instr >> 24) & 0xFF;
		if ((highByte == 0x10 || highByte == 0x11 || highByte == 0x12 ||
		     highByte == 0x13 || highByte == 0xA4) && (instr & 0x3) == 0)
			return false;  // Likely an aligned address

		return true;
	};

	// Track previous instruction for context checking
	uint32_t prevInstr = 0;

	// Skip vector table and pointer table regions
	uint64_t startOffset = 0x40;

	// Scan for ARM call instructions (4-byte aligned)
	for (uint64_t offset = startOffset; offset + 4 <= scanLen; offset += 4)
	{
		if (ScanShouldAbort(view))
			break;
		totalInstrs++;
		uint32_t instr = 0;
		if (offset + 4 <= dataLen)
		{
			memcpy(&instr, data + offset, sizeof(instr));
			if (endian == BigEndian)
				instr = Swap32(instr);
		}

		uint64_t instrAddr = imageBase + offset;
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(instrAddr))
		{
			skippedNonCode++;
			prevInstr = 0;
			continue;
		}
		codeInstrs++;
		auto callsiteFuncs = view->GetAnalysisFunctionsContainingAddress(instrAddr);
		bool inFunction = !callsiteFuncs.empty();
		if (!inFunction)
		{
			nonFunctionInstrs++;
			if (tuning.requireCallInFunction)
			{
				skippedNotInFunction++;
				prevInstr = 0;
				continue;
			}
		}
		else
		{
			inFunctionInstrs++;
		}

		// Pattern 1: BL imm (ARM branch-and-link)
		// Encoding: cond 1011 imm24 where cond != 1111
		// Mask: 0x0F000000, value: 0x0B000000
		if ((instr & 0x0F000000) == 0x0B000000 && (instr & 0xF0000000) != 0xF0000000)
		{
			// Only trust BL if the previous instruction also looks like code
			// This filters out BL-like patterns in literal pools
			if (offset >= 4 && isLikelyCode(prevInstr))
			{
				blMatches++;
				// Extract 24-bit signed offset, shift left 2, add to PC+8
				int32_t imm24 = instr & 0x00FFFFFF;
				// Sign-extend from 24 bits
				if (imm24 & 0x00800000)
					imm24 |= 0xFF000000;
				int32_t offset_bytes = imm24 << 2;
				uint64_t target = instrAddr + 8 + offset_bytes;
				uint64_t alignedTarget = target & ~3ULL;

				// If the BL is inside a function and the target is also inside that
				// same function, it's almost certainly an internal label (PIC, thunk).
				if (inFunction)
				{
					auto targetFuncs = view->GetAnalysisFunctionsContainingAddress(alignedTarget);
					bool intraFunction = false;
					for (const auto& cf : callsiteFuncs)
					{
						if (!cf)
							continue;
						for (const auto& tf : targetFuncs)
						{
							if (tf && (tf->GetStart() == cf->GetStart()))
							{
								intraFunction = true;
								break;
							}
						}
						if (intraFunction)
							break;
					}
					if (intraFunction)
					{
						skipBlIntraFunction++;
						prevInstr = instr;
						continue;
					}
				}
				// BL targets are likely real function starts.
				addFunction(target, "BL", false);
			}
			else
			{
				skippedPrevNotCode++;
			}
		}

		// Pattern 2: BLX imm (ARM to Thumb call)
		// Encoding: 1111 101 H imm24
		// H bit (bit 24) adds 2 to the offset for Thumb alignment
		// NOTE: For ARMv5 firmware with no Thumb code, we skip BLX entirely
		// since it shouldn't exist in pure ARM binaries
		// if ((instr & 0xFE000000) == 0xFA000000) { ... }

		// Pattern 3: LDR PC, [PC, #imm] (indirect jump via literal pool)
		// Encoding: cond 0101 U001 1111 1111 imm12
		// U bit (bit 23) indicates add/subtract
		// Example: LDR PC, [PC, #0x10] = 0xE59FF010
		if ((instr & 0x0F7FF000) == 0x051FF000)
		{
			// LDR PC is commonly used for jump tables inside functions; those
			// targets are *not* function entry points. Only treat LDR PC as a
			// potential function target when the dispatch itself is outside any
			// existing function (e.g., a veneer in standalone code).
			if (!view->GetAnalysisFunctionsContainingAddress(instrAddr).empty())
			{
				skipLdrPcInFunction++;
				prevInstr = instr;
				continue;
			}

			// Only trust LDR PC if preceded by valid code
			if (offset >= 4 && isLikelyCode(prevInstr))
			{
				ldrMatches++;
				uint32_t imm12 = instr & 0xFFF;
				bool add = (instr & 0x00800000) != 0;
				// PC reads as instrAddr + 8 in ARM mode
				uint64_t litPoolAddr = add ? (instrAddr + 8 + imm12) : (instrAddr + 8 - imm12);

				// Read the literal pool entry
				if (litPoolAddr >= imageBase && litPoolAddr + 4 <= imageBase + length)
				{
					uint64_t litPoolOffset = litPoolAddr - imageBase;
					if (litPoolOffset + 4 <= dataLen)
					{
						uint32_t target = 0;
						memcpy(&target, data + litPoolOffset, sizeof(target));
						if (endian == BigEndian)
							target = Swap32(target);

						// Add as function (preserving Thumb bit if present)
						// Indirect branches are common for jump tables; require a boundary.
						addFunction(target, "LDR PC", true);
					}
				}
			}
			else
			{
				skippedPrevNotCode++;
			}
		}

	// Remember this instruction for next iteration
	prevInstr = instr;
}

	if (!ScanShouldAbort(view))
		flushAdds();

	if (logger)
		logger->LogInfo("Call target scan: Found %zu call targets", targetsFound);
	if (verboseLog)
	{
		if (logger)
			logger->LogInfo(
				"Call target scan detail: scanned=%zu code=%zu in_func=%zu non_func=%zu bl=%zu ldr_pc=%zu added=%zu "
				"skip_noncode=%zu skip_not_in_func=%zu skip_prev_not_code=%zu skip_misaligned=%zu "
				"skip_oob=%zu skip_noncode_target=%zu skip_non_boundary=%zu skip_existing=%zu skip_return_thunk=%zu skip_ldr_pc_in_func=%zu "
				"skip_bl_intra_func=%zu skip_bl_nonfunc_boundary=%zu "
				"skip_invalid_target=%zu skip_duplicate=%zu skip_invalid_candidate=%zu",
				totalInstrs, codeInstrs, inFunctionInstrs, nonFunctionInstrs, blMatches, ldrMatches, addedCount,
				skippedNonCode, skippedNotInFunction, skippedPrevNotCode, skipMisaligned,
				skipOutOfBounds, skipNonCodeTarget, skipNonBoundary, skipExistingTarget, skipReturnThunk, skipLdrPcInFunction,
				skipBlIntraFunction, skipBlNonFuncBoundary,
				skipInvalidTarget, skipDuplicate, skipInvalidCandidate);
	}
	return targetsFound;
}

/*
 * Scan for 32-bit pointers that reference executable code and add them as functions.
 *
 * This discovers entry points referenced via data tables. To reduce false
 * positives, only data variables that are referenced from code are considered.
 *
 * Returns the number of pointer targets found.
 */
size_t ScanForPointerTargets(BinaryView* view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	Ref<Platform> plat, Ref<Logger> logger, bool verboseLog, const FirmwareScanTuning& tuning,
	std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan)
{
	size_t targetsFound = 0;
	std::set<uint64_t> addedAddrs;
	size_t dataVarCount = 0;
	size_t withCodeRefs = 0;
	size_t pointerTyped = 0;
	size_t addedCount = 0;
	size_t skipNonCodeTarget = 0;
	size_t skipOutOfBounds = 0;
	size_t skipMisaligned = 0;
	size_t skipExistingTarget = 0;
	size_t skipReturnThunk = 0;
	size_t skipInvalidTarget = 0;
	size_t skipNotPointerType = 0;
	size_t skipInvalidCandidate = 0;
	size_t skipJumpTableRefs = 0;
	size_t skipNonBoundary = 0;
	size_t rawWordScanned = 0;
	size_t rawRunsFound = 0;
	size_t rawRunsWithRefs = 0;
	size_t rawRunsNoRefs = 0;
	size_t rawRunsAllowedNoRefs = 0;
	size_t rawAddedCount = 0;
	size_t rawSkipInFunction = 0;
	size_t rawSkipInvalidTarget = 0;
	size_t rawSkipJumpTableRefs = 0;

	const auto& actionPolicy = GetFirmwareActionPolicy();
	uint64_t imageEnd = imageBase + length;
	uint8_t minHigh = (uint8_t)(imageBase >> 24);
	uint8_t maxHigh = (uint8_t)((imageEnd - 1) >> 24);
	bool enforceCodeSemantics = HasExplicitCodeSemantics(view);
	Logger* log = logger ? logger.GetPtr() : nullptr;
	std::vector<uint64_t> pendingAdds;
	pendingAdds.reserve(256);
	const size_t addBatchSize = 256;

	auto flushAdds = [&]()
	{
		if (pendingAdds.empty())
			return;
		for (uint64_t addr : pendingAdds)
		{
			if (ScanShouldAbort(view))
				break;
			if (!EnsureAddressInsideView(view, log, "AddFunction", addr))
				continue;
			if (!actionPolicy.allowAddFunction)
				continue;
			if (plan)
			{
				PlanAddFunction(plan, addr);
				if (seededFunctions)
					seededFunctions->insert(addr);
				addedCount++;
				continue;
			}
			if (view->AddFunctionForAnalysis(plat, addr, true))
			{
				if (seededFunctions)
					seededFunctions->insert(addr);
				addedCount++;
			}
		}
		pendingAdds.clear();
	};

	if (ScanShouldAbort(view))
		return 0;

	auto addFunction = [&](uint64_t funcAddr) {
		if (ScanShouldAbort(view))
			return;
		uint64_t alignedAddr = funcAddr & ~3ULL;
		if (funcAddr & 3)
		{
			skipMisaligned++;
			return;
		}
		if (alignedAddr < imageBase || alignedAddr >= imageEnd)
		{
			skipOutOfBounds++;
			return;
		}
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(alignedAddr))
		{
			skipNonCodeTarget++;
			return;
		}
		if (!IsLikelyFunctionBoundary(data, dataLen, endian, imageBase, length, alignedAddr))
		{
			skipNonBoundary++;
			return;
		}
		if (!view->GetAnalysisFunctionsContainingAddress(alignedAddr).empty())
		{
			skipExistingTarget++;
			return;
		}
		if (LooksLikeReturnThunk(data, dataLen, endian, imageBase, length, alignedAddr))
		{
			skipReturnThunk++;
			return;
		}
		// Pointer targets should also look like real function entries; avoid
		// PC-write stubs and require a body instruction to reduce false starts.
		if (!ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
			alignedAddr, tuning, true, false))
		{
			skipInvalidCandidate++;
			return;
		}
		if (addedAddrs.find(alignedAddr) != addedAddrs.end())
			return;
		addedAddrs.insert(alignedAddr);
		pendingAdds.push_back(alignedAddr);
		if (pendingAdds.size() >= addBatchSize)
			flushAdds();
		targetsFound++;
	};

	auto isValidTarget = [&](uint64_t targetAddr, bool countInvalid) -> bool {
		if (ScanShouldAbort(view))
			return false;
		if (targetAddr < imageBase || targetAddr + 4 > imageEnd)
			return false;
		uint64_t targetOffset = targetAddr - imageBase;
		if (targetOffset + 4 > dataLen)
			return false;
		uint32_t targetInstr = 0;
		memcpy(&targetInstr, data + targetOffset, sizeof(targetInstr));
		if (endian == BigEndian)
			targetInstr = Swap32(targetInstr);
		if (targetInstr == 0 || targetInstr == 0xFFFFFFFF)
		{
			if (countInvalid)
				skipInvalidTarget++;
			return false;
		}
		uint32_t cond = (targetInstr >> 28) & 0xF;
		if (cond == 0xF)
		{
			uint32_t op = (targetInstr >> 24) & 0xFF;
			if (op != 0xFA && op != 0xFB)
			{
				if (countInvalid)
					skipInvalidTarget++;
				return false;
			}
		}
		armv5::Instruction decoded;
		memset(&decoded, 0, sizeof(decoded));
		if (armv5::armv5_decompose(targetInstr, &decoded, (uint32_t)targetOffset, 0) != 0)
		{
			if (countInvalid)
				skipInvalidTarget++;
			return false;
		}
		return true;
	};

	auto readInstrAt = [&](uint64_t addr, uint32_t& outInstr) -> bool {
		if (addr < imageBase || addr + 4 > imageEnd)
			return false;
		uint64_t off = addr - imageBase;
		if (off + 4 > dataLen)
			return false;
		memcpy(&outInstr, data + off, sizeof(outInstr));
		if (endian == BigEndian)
			outInstr = Swap32(outInstr);
		return true;
	};

	auto hasOnlyJumpTableRefs = [&](uint64_t addr) -> bool {
		auto refs = view->GetCodeReferences(addr);
		if (refs.empty())
			return false;
		for (const auto& ref : refs)
		{
			uint32_t instr = 0;
			if (!readInstrAt(ref.addr, instr))
				return false;
			if (!IsJumpTableDispatchInstruction(instr))
				return false;
		}
		return true;
	};

	// Only consider data variables that are referenced from code.
	auto dataVars = view->GetDataVariables();
	for (const auto& entry : dataVars)
	{
		if (ScanShouldAbort(view))
			break;
		dataVarCount++;
		uint64_t locationAddr = entry.first;
		const DataVariable& dataVar = entry.second;
		if (locationAddr < imageBase + 0x40)
			continue;
		if (locationAddr + 4 > imageEnd)
			continue;
		if (enforceCodeSemantics && view->IsOffsetCodeSemantics(locationAddr))
			continue;

		if (view->GetCodeReferences(locationAddr).empty())
			continue;

		// If all code refs are jump-table dispatches, these pointers are case labels,
		// not function entry points. Skip to avoid adding mid-function functions.
		if (hasOnlyJumpTableRefs(locationAddr))
		{
			skipJumpTableRefs++;
			continue;
		}
		withCodeRefs++;
		if (dataVar.type.GetValue())
		{
			Ref<Type> varType = dataVar.type.GetValue();
			if (varType && varType->GetClass() != PointerTypeClass)
			{
				if (varType->GetClass() != ArrayTypeClass)
				{
					skipNotPointerType++;
					continue;
				}
				Ref<Type> elemType = varType->GetChildType().GetValue();
				if (!elemType || elemType->GetClass() != PointerTypeClass)
				{
					skipNotPointerType++;
					continue;
				}
			}
		}
		pointerTyped++;

		uint64_t offset = locationAddr - imageBase;
		if (offset + 4 > dataLen)
			continue;

		uint32_t value = 0;
		memcpy(&value, data + offset, sizeof(value));
		if (endian == BigEndian)
			value = Swap32(value);
		if (value == 0 || value == 0xFFFFFFFF)
			continue;
		if ((value & 3) != 0)
			continue;
		if (value < imageBase || value >= imageEnd)
			continue;
		uint8_t high = (uint8_t)(value >> 24);
		if (high < minHigh || high > maxHigh)
			continue;

		if (isValidTarget(value, true))
			addFunction(value);
	}

	// Scan raw words for pointer tables to fill gaps when core pointer sweep is disabled.
	// Heuristics: require a consecutive run of valid pointers *and* at least one code reference into
	// the table so we don't treat random code bytes as pointer arrays.
	if (tuning.scanRawPointerTables && tuning.minPointerRun > 0)
	{
		const uint64_t scanStart = 0x40;
		uint32_t runLen = 0;
		uint64_t runStartOffset = 0;

		auto finalizeRun = [&](uint64_t startOffset, uint32_t count)
		{
			if (ScanShouldAbort(view))
				return;
			if (count < tuning.minPointerRun)
				return;
			rawRunsFound++;

			uint64_t tableAddr = imageBase + startOffset;
			bool hasCodeRefs = false;
			bool hasNonJumpRef = false;
			for (uint32_t i = 0; i < count; i++)
			{
				uint64_t addr = imageBase + startOffset + (uint64_t)i * 4;
				if (!view->GetCodeReferences(addr).empty())
				{
					hasCodeRefs = true;
					if (!hasOnlyJumpTableRefs(addr))
						hasNonJumpRef = true;
					if (hasNonJumpRef)
						break;
				}
			}

		if (!hasCodeRefs)
		{
			rawRunsNoRefs++;
			if (tuning.requirePointerTableCodeRefs)
				return;
			if (view->IsOffsetCodeSemantics(tableAddr) && !tuning.allowPointerTablesInCode)
				return;
			rawRunsAllowedNoRefs++;
		}
		else
		{
			if (!hasNonJumpRef)
			{
				rawSkipJumpTableRefs++;
				return;
			}
			rawRunsWithRefs++;
		}

			// Define the pointer table as data if it doesn't already exist.
			DataVariable existing;
			if (!view->GetDataVariableAtAddress(tableAddr, existing))
			{
				Ref<Type> ptrType = Type::PointerType(view->GetDefaultArchitecture(), Type::VoidType());
				Ref<Type> tableType = Type::ArrayType(ptrType, count);
				if (actionPolicy.allowDefineData &&
					EnsureAddressInsideView(view, log, "DefineDataVariable", tableAddr))
				{
					if (plan)
					{
						PlanDefineData(plan, tableAddr, tableType);
					}
					else
					{
						view->DefineDataVariable(tableAddr, tableType);
					}
				}
			}

			for (uint32_t i = 0; i < count; i++)
			{
				uint64_t addr = imageBase + startOffset + (uint64_t)i * 4;
				uint64_t offset = startOffset + (uint64_t)i * 4;
				if (offset + 4 > dataLen)
					break;

				uint32_t value = 0;
				memcpy(&value, data + offset, sizeof(value));
				if (endian == BigEndian)
					value = Swap32(value);

				if (value == 0 || value == 0xFFFFFFFF)
					continue;
				if ((value & 3) != 0)
					continue;
				if (!isValidTarget(value, false))
				{
					rawSkipInvalidTarget++;
					continue;
				}

				size_t prevAdded = addedCount;
				addFunction(value);
				if (addedCount > prevAdded)
					rawAddedCount++;
			}
		};

		for (uint64_t offset = scanStart; offset + 4 <= dataLen; offset += 4)
		{
			if (ScanShouldAbort(view))
				break;
			rawWordScanned++;
			uint64_t addr = imageBase + offset;
			if (!view->GetAnalysisFunctionsContainingAddress(addr).empty())
			{
				rawSkipInFunction++;
				if (runLen > 0)
				{
					finalizeRun(runStartOffset, runLen);
					runLen = 0;
				}
				continue;
			}

			uint32_t value = 0;
			memcpy(&value, data + offset, sizeof(value));
			if (endian == BigEndian)
				value = Swap32(value);

			if (value == 0 || value == 0xFFFFFFFF || (value & 3) != 0 ||
				value < imageBase || value >= imageEnd)
			{
				if (runLen > 0)
				{
					finalizeRun(runStartOffset, runLen);
					runLen = 0;
				}
				continue;
			}

			uint8_t high = (uint8_t)(value >> 24);
			if (high < minHigh || high > maxHigh)
			{
				if (runLen > 0)
				{
					finalizeRun(runStartOffset, runLen);
					runLen = 0;
				}
				continue;
			}

			if (!isValidTarget(value, false))
			{
				if (runLen > 0)
				{
					finalizeRun(runStartOffset, runLen);
					runLen = 0;
				}
				continue;
			}

			if (runLen == 0)
				runStartOffset = offset;
			runLen++;
		}

	if (runLen > 0)
		finalizeRun(runStartOffset, runLen);
	}

	if (!ScanShouldAbort(view))
		flushAdds();

	if (logger)
		logger->LogInfo("Pointer target scan: Found %zu pointer targets", targetsFound);
	if (verboseLog)
	{
		if (logger)
			logger->LogInfo(
				"Pointer target scan detail: data_vars=%zu code_ref_vars=%zu pointer_typed=%zu added=%zu "
				"skip_not_pointer_type=%zu skip_misaligned=%zu skip_oob=%zu skip_noncode_target=%zu "
				"skip_non_boundary=%zu skip_existing=%zu skip_return_thunk=%zu skip_invalid_target=%zu skip_invalid_candidate=%zu "
				"skip_jump_table_refs=%zu raw_words=%zu raw_runs=%zu raw_runs_with_refs=%zu raw_runs_no_refs=%zu "
				"raw_runs_allowed_no_refs=%zu raw_added=%zu raw_skip_in_func=%zu raw_skip_invalid_target=%zu "
				"raw_skip_jump_table_refs=%zu",
				dataVarCount, withCodeRefs, pointerTyped, addedCount,
				skipNotPointerType, skipMisaligned, skipOutOfBounds, skipNonCodeTarget,
				skipNonBoundary, skipExistingTarget, skipReturnThunk, skipInvalidTarget, skipInvalidCandidate, skipJumpTableRefs,
				rawWordScanned, rawRunsFound, rawRunsWithRefs, rawRunsNoRefs, rawRunsAllowedNoRefs, rawAddedCount,
				rawSkipInFunction, rawSkipInvalidTarget, rawSkipJumpTableRefs);
	}
	return targetsFound;
}

/*
 * Scan for orphaned code blocks post-analysis.
 *
 * After core analysis completes, find basic blocks that are not yet part of
 * any function. These represent undiscovered functions that weren't captured by
 * explicit calls or prologue patterns. This is a post-analysis sweep that fills
 * gaps left by the CFG-based discovery process.
 *
 * Returns the number of orphan functions found and added.
 */
size_t ScanForOrphanCodeBlocks(BinaryView* view, const uint8_t* data,
	uint64_t dataLen, BNEndianness endian, uint64_t imageBase, uint64_t length,
	Ref<Platform> plat, Ref<Logger> logger, bool verboseLog, const FirmwareScanTuning& tuning,
	uint32_t minValidInstr, uint32_t minBodyInstr, uint32_t minSpacingBytes, uint32_t maxPerPage,
	bool requirePrologue,
	std::set<uint64_t>* seededFunctions, FirmwareScanPlan* plan)
{
	size_t orphansFound = 0;
	size_t blocksScanned = 0;
	size_t orphanCandidates = 0;
	size_t addedCount = 0;
	size_t skipExisting = 0;
	size_t skipInvalidCandidate = 0;
	size_t skipProtected = 0;
	size_t skipNonBoundaryOrPrologue = 0;
	size_t skipSpacing = 0;
	size_t skipPageCap = 0;
	size_t skipPaddingRun = 0;
	size_t skipNoPrologue = 0;

	const auto& actionPolicy = GetFirmwareActionPolicy();
	std::set<uint64_t> addedAddrs;
	bool enforceCodeSemantics = HasExplicitCodeSemantics(view);
	uint64_t lastAddedAddr = 0;
	std::unordered_map<uint64_t, uint32_t> pageCounts;
	Logger* log = logger ? logger.GetPtr() : nullptr;
	std::vector<uint64_t> pendingAdds;
	pendingAdds.reserve(256);
	const size_t addBatchSize = 256;

	auto flushAdds = [&]()
	{
		if (pendingAdds.empty())
			return;
		for (uint64_t addr : pendingAdds)
		{
			if (ScanShouldAbort(view))
				break;
			if (!EnsureAddressInsideView(view, log, "AddFunction", addr))
				continue;
			if (!actionPolicy.allowAddFunction)
				continue;
			if (plan)
			{
				PlanAddFunction(plan, addr);
				if (seededFunctions)
					seededFunctions->insert(addr);
				addedCount++;
				continue;
			}
			if (view->AddFunctionForAnalysis(plat, addr, true))
			{
				if (seededFunctions)
					seededFunctions->insert(addr);
				addedCount++;
			}
		}
		pendingAdds.clear();
	};

	if (ScanShouldAbort(view))
		return 0;

	auto isStrongPrologue = [&](uint32_t instr) -> bool {
		uint32_t cond = (instr >> 28) & 0xF;
		if (cond != 0xE)
			return false;
		if ((instr & 0xFFFF0000) != 0xE92D0000)
			return false;
		uint32_t reglist = instr & 0xFFFF;
		if (!(reglist & (1U << REG_LR)))
			return false;
		return __builtin_popcount(reglist) >= 3;
	};
	auto isWeakPrologue = [&](uint32_t instr) -> bool {
		uint32_t cond = (instr >> 28) & 0xF;
		if (cond != 0xE)
			return false;
		// STMDB/STMFD sp!, {..., lr}
		if ((instr & 0xFFFF0000) == 0xE92D0000)
		{
			uint32_t reglist = instr & 0xFFFF;
			return (reglist & (1U << REG_LR)) != 0;
		}
		// SUB sp, sp, #imm (stack allocation)
		if ((instr & 0xFFFFF000) == 0xE24DD000)
			return true;
		return false;
	};

	auto addFunction = [&](uint64_t funcAddr) {
		if (ScanShouldAbort(view))
			return;
		uint64_t alignedAddr = funcAddr & ~3ULL;
		if (alignedAddr < imageBase || alignedAddr >= imageBase + length)
			return;
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(alignedAddr))
			return;
		if (!view->GetAnalysisFunctionsContainingAddress(alignedAddr).empty())
		{
			skipExisting++;
			return;
		}
		// Protect seeded functions from being removed later
		if (seededFunctions && seededFunctions->find(alignedAddr) != seededFunctions->end())
		{
			skipProtected++;
			return;
		}
		FirmwareScanTuning orphanTuning = tuning;
		orphanTuning.minValidInstr = minValidInstr;
		orphanTuning.minBodyInstr = minBodyInstr;
		// Validate that the orphan block looks like real code
		if (!ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
			alignedAddr, orphanTuning, true, false))
		{
			skipInvalidCandidate++;
			return;
		}
		if (addedAddrs.find(alignedAddr) != addedAddrs.end())
			return;
		addedAddrs.insert(alignedAddr);
		pendingAdds.push_back(alignedAddr);
		lastAddedAddr = alignedAddr;
		pageCounts[alignedAddr & ~0xFFFULL]++;
		if (pendingAdds.size() >= addBatchSize)
			flushAdds();
		orphansFound++;
	};

	// Collect all basic blocks from the view
	auto allFuncs = view->GetAnalysisFunctionList();
	struct AddressRange
	{
		uint64_t start;
		uint64_t end;
	};
	std::vector<AddressRange> coveredRanges;
	coveredRanges.reserve(allFuncs.size());

	// Build a set of all addresses covered by existing functions
	for (const auto& func : allFuncs)
	{
		if (ScanShouldAbort(view))
			break;
		if (!func)
			continue;
		uint64_t funcStart = func->GetStart();
		uint64_t funcEnd = func->GetHighestAddress();
		if (funcEnd < funcStart)
			continue;
		coveredRanges.push_back({funcStart, funcEnd});
	}

	std::sort(coveredRanges.begin(), coveredRanges.end(),
		[](const AddressRange& a, const AddressRange& b) {
			return a.start < b.start;
		});
	size_t mergedCount = 0;
	for (const auto& range : coveredRanges)
	{
		if (mergedCount == 0)
		{
			coveredRanges[mergedCount++] = range;
			continue;
		}
		AddressRange& last = coveredRanges[mergedCount - 1];
		if (range.start <= last.end + 4)
		{
			if (range.end > last.end)
				last.end = range.end;
		}
		else
		{
			coveredRanges[mergedCount++] = range;
		}
	}
	coveredRanges.resize(mergedCount);

	// Scan for orphaned 4-byte aligned code in code semantics regions
	if (logger)
		logger->LogInfo("Orphan code scan: Scanning for unreachable functions in %llu bytes",
			(unsigned long long)(length));
	size_t rangeIndex = 0;

	for (uint64_t offset = 0; offset + 4 <= length; offset += 4)
	{
		if (ScanShouldAbort(view))
			break;
		uint64_t instrAddr = imageBase + offset;

		// Skip if already covered by a function
		while (rangeIndex < coveredRanges.size() && instrAddr > coveredRanges[rangeIndex].end)
			rangeIndex++;
		if (rangeIndex < coveredRanges.size() && instrAddr >= coveredRanges[rangeIndex].start)
			continue;

		// Skip if not in code semantics
		if (enforceCodeSemantics && !view->IsOffsetCodeSemantics(instrAddr))
			continue;

		blocksScanned++;

		// Enforce spacing between added functions to avoid runaway growth.
		if (lastAddedAddr && (instrAddr - lastAddedAddr) < minSpacingBytes)
		{
			skipSpacing++;
			continue;
		}

		// Per-page cap to avoid flooding a single 4KB region with functions.
		uint64_t page = instrAddr & ~0xFFFULL;
		if (maxPerPage > 0)
		{
			auto it = pageCounts.find(page);
			if (it != pageCounts.end() && it->second >= maxPerPage)
			{
				skipPageCap++;
				continue;
			}
		}

		// Candidate if it looks like a boundary or a prologue.
		bool isBoundary = IsLikelyFunctionBoundary(data, dataLen, endian, imageBase, length, instrAddr);
		bool isPrologue = false;

		// Quick filter: reject regions dominated by padding/erased words.
		// This avoids ballooning candidate counts on zero-filled data.
		uint32_t paddingCount = 0;
		const uint32_t padWindow = 3;
		if (offset + (uint64_t)padWindow * 4 <= dataLen)
		{
			for (uint32_t i = 0; i < padWindow; i++)
			{
				uint32_t word = 0;
				memcpy(&word, data + offset + (uint64_t)i * 4, sizeof(word));
				if (endian == BigEndian)
					word = Swap32(word);
				if (IsPaddingWord(word))
					paddingCount++;
			}
		}
		if (paddingCount >= 2)
		{
			skipPaddingRun++;
			continue;
		}

		// Strong prologue pattern (STMFD/PUSH sp!, {..., lr} with 3+ regs)
		if (offset + 4 <= dataLen)
		{
			uint32_t instr = 0;
			memcpy(&instr, data + offset, sizeof(instr));
			if (endian == BigEndian)
				instr = Swap32(instr);
			isPrologue = isWeakPrologue(instr) || isStrongPrologue(instr);
		}

		if (requirePrologue && !isPrologue)
		{
			skipNoPrologue++;
			continue;
		}

		if (!requirePrologue && !isBoundary && !isPrologue)
		{
			skipNonBoundaryOrPrologue++;
			continue;
		}
		orphanCandidates++;
		addFunction(instrAddr);
	}

	if (!ScanShouldAbort(view))
		flushAdds();

	if (logger)
		logger->LogInfo("Orphan code scan: Found %zu orphaned functions", orphansFound);
	if (verboseLog)
	{
		if (logger)
			logger->LogInfo(
				"Orphan code scan detail: scanned=%zu candidates=%zu added=%zu "
				"skip_existing=%zu skip_invalid_candidate=%zu skip_protected=%zu "
				"skip_non_boundary_or_prologue=%zu skip_spacing=%zu skip_page_cap=%zu "
				"skip_padding_run=%zu skip_no_prologue=%zu",
				blocksScanned, orphanCandidates, addedCount,
				skipExisting, skipInvalidCandidate, skipProtected,
				skipNonBoundaryOrPrologue, skipSpacing, skipPageCap,
				skipPaddingRun, skipNoPrologue);
	}
	return orphansFound;
}

size_t CleanupInvalidFunctions(BinaryView* view, const uint8_t* data, uint64_t dataLen,
	BNEndianness endian, uint64_t imageBase, uint64_t length, Ref<Logger> logger, bool verboseLog,
	const FirmwareScanTuning& tuning, uint32_t maxSizeBytes, bool requireZeroRefs,
	bool requirePcWriteStart, uint64_t entryPoint, const std::set<uint64_t>& protectedStarts,
	FirmwareScanPlan* plan)
{
	if (ScanShouldAbort(view))
		return 0;

	size_t scanned = 0;
	size_t candidates = 0;
	size_t removed = 0;
	size_t skipUser = 0;
	size_t skipTooLarge = 0;
	size_t skipHasRefs = 0;
	size_t skipProtected = 0;
	size_t skipNonPcWrite = 0;
	size_t skipValid = 0;
	size_t skipNoData = 0;

	const auto& actionPolicy = GetFirmwareActionPolicy();
	Ref<Platform> defaultPlat = view->GetDefaultPlatform();
	FirmwareScanTuning cleanupTuning = tuning;
	cleanupTuning.minValidInstr = 1;
	cleanupTuning.minBodyInstr = 0;

	std::vector<uint64_t> toRemove;
	auto funcs = view->GetAnalysisFunctionList();
	for (const auto& func : funcs)
	{
		if (ScanShouldAbort(view))
			break;
		scanned++;
		if (!func || !func->WasAutomaticallyDiscovered())
		{
			skipUser++;
			continue;
		}

		Ref<Symbol> sym = func->GetSymbol();
		if (sym && !sym->IsAutoDefined())
		{
			skipUser++;
			continue;
		}

		uint64_t start = func->GetStart();
		if (start < imageBase || start >= imageBase + length)
			continue;
		if (start == entryPoint || protectedStarts.find(start) != protectedStarts.end())
		{
			skipProtected++;
			continue;
		}

		uint64_t sizeBytes = 0;
		Ref<Architecture> arch = func->GetArchitecture();
		if (arch)
			sizeBytes = func->GetHighestAddress() - start + arch->GetDefaultIntegerSize();
		if (maxSizeBytes > 0 && sizeBytes > maxSizeBytes)
		{
			skipTooLarge++;
			continue;
		}

		if (requireZeroRefs && !view->GetCodeReferences(start).empty())
		{
			skipHasRefs++;
			continue;
		}

		uint64_t offset = start - imageBase;
		if (offset + 4 > dataLen)
		{
			skipNoData++;
			continue;
		}

		uint32_t firstWord = 0;
		memcpy(&firstWord, data + offset, sizeof(firstWord));
		if (endian == BigEndian)
			firstWord = Swap32(firstWord);

		armv5::Instruction decoded;
		memset(&decoded, 0, sizeof(decoded));
		bool decodeOk = (armv5::armv5_decompose(firstWord, &decoded, (uint32_t)start,
			(uint32_t)(endian == BigEndian)) == 0);

		bool pcWrite = decodeOk ? IsPcWriteInstruction(decoded) : false;
		if (requirePcWriteStart && !pcWrite && decodeOk)
		{
			skipNonPcWrite++;
			continue;
		}

		candidates++;
		if (ValidateFirmwareFunctionCandidate(view, data, dataLen, endian, imageBase, length,
			start, cleanupTuning, false, true))
		{
			skipValid++;
			continue;
		}

		toRemove.push_back(start);
	}

	for (uint64_t start : toRemove)
	{
		if (ScanShouldAbort(view))
			break;
		if (!actionPolicy.allowRemoveFunction)
			continue;
		if (plan)
		{
			PlanRemoveFunction(plan, start);
			removed++;
			continue;
		}
		Ref<Function> func = view->GetAnalysisFunction(defaultPlat.GetPtr(), start);
		if (!func)
		{
			auto funcs = view->GetAnalysisFunctionsContainingAddress(start);
			if (!funcs.empty())
				func = funcs.front();
		}
		if (func)
		{
			view->RemoveAnalysisFunction(func, true);
			removed++;
		}
	}

	if (logger)
		logger->LogInfo("Cleanup invalid functions: removed=%zu candidates=%zu scanned=%zu",
			removed, candidates, scanned);
	if (verboseLog)
	{
		if (logger)
			logger->LogInfo(
				"Cleanup invalid detail: skip_user=%zu skip_protected=%zu skip_too_large=%zu "
				"skip_has_refs=%zu skip_non_pc_write=%zu skip_valid=%zu skip_no_data=%zu",
				skipUser, skipProtected, skipTooLarge, skipHasRefs,
				skipNonPcWrite, skipValid, skipNoData);
	}

	return removed;
}


// Structure to hold discovered config array info

static bool IsLikelyMMIOPointer(uint32_t value, uint64_t imageBase, uint64_t imageEnd)
{
	// Must be aligned
	if ((value & 3) != 0)
		return false;

	// Inside the image - it's a code/data pointer, not MMIO
	if (value >= imageBase && value < imageEnd)
		return false;

	// Common MMIO ranges for embedded ARM systems:
	// 0x40000000+ (STM32, many ARM MCUs)
	// 0x80000000+ (SDRAM, peripherals on many SoCs)
	// 0x90000000+ (peripherals)
	// 0xA0000000+ (external memory/peripherals)
	// 0xC0000000+ (peripherals)
	// 0xD0000000+ (peripherals)
	// 0xE0000000+ (ARM Cortex-M system peripherals)
	// 0xF0000000+ (vendor peripherals)
	uint32_t highNibble = (value >> 28) & 0xF;
	return highNibble >= 4;  // 0x40000000 and above
}

// Scan for PC-relative loads and type their literal pool entries as data
// This keeps literal pools from being interpreted as code and improves display
void TypeLiteralPoolEntries(const FirmwareScanContext& ctx)
{
	if (ctx.logger)
		ctx.logger->LogDebug("Typing literal pool entries...");

	Logger* log = ctx.logger ? ctx.logger.GetPtr() : nullptr;
	if (ScanShouldAbort(ctx.view))
		return;

	const auto& actionPolicy = GetFirmwareActionPolicy();
	Ref<Type> ptrType = Type::PointerType(ctx.arch, Type::VoidType());
	Ref<Type> u32Type = Type::IntegerType(4, false);
	uint32_t entriesTyped = 0;
	uint32_t ldrPcCount = 0;
	uint32_t skippedNonCode = 0;
	uint32_t skippedInFunction = 0;
	uint32_t skippedDecodedCode = 0;
	uint32_t skippedExisting = 0;

	for (uint64_t offset = 0; offset + 4 <= ctx.length; offset += 4)
	{
		if (ScanShouldAbort(ctx.view))
			break;
		uint32_t instr = 0;
		ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, instr, ctx.length);
		uint64_t instrAddr = ctx.imageBase + offset;
		// Only type literal pools referenced from code.
		if (!ctx.view->IsOffsetCodeSemantics(instrAddr))
		{
			skippedNonCode++;
			continue;
		}

		// LDR Rd, [PC, #imm] - pattern: cond 01 0 P U 0 W 1 1111 Rd imm12
		// We want P=1, W=0 (offset addressing, no writeback), Rn=PC (1111)
		// Mask: 0x0F7F0000, expect: 0x051F0000
		if ((instr & 0x0F7F0000) == 0x051F0000)
		{
			ldrPcCount++;
			uint32_t imm12 = instr & 0xFFF;
			bool add = (instr & 0x00800000) != 0;
			uint64_t pc = offset + 8;  // PC is 8 bytes ahead
			uint64_t literalOffset = add ? (pc + imm12) : (pc - imm12);

			if (literalOffset + 4 <= ctx.length)
			{
				uint32_t value = 0;
				ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, literalOffset, value, ctx.length);

				uint64_t literalAddr = ctx.imageBase + literalOffset;
				// Avoid typing data inside discovered functions to reduce accidental code suppression.
				if (!ctx.view->GetAnalysisFunctionsContainingAddress(literalAddr).empty())
				{
					skippedInFunction++;
					continue;
				}
				if (ctx.view->IsOffsetCodeSemantics(literalAddr))
				{
					armv5::Instruction decoded;
					memset(&decoded, 0, sizeof(decoded));
					if (armv5::armv5_decompose(value, &decoded, (uint32_t)literalOffset, 0) == 0)
					{
						skippedDecodedCode++;
						continue;
					}
				}
				DataVariable existing;
				if (ctx.view->GetDataVariableAtAddress(literalAddr, existing) &&
					existing.address == literalAddr)
				{
					skippedExisting++;
					continue;
				}

				Ref<Type> entryType = u32Type;
				if (IsLikelyMMIOPointer(value, ctx.imageBase, ctx.ImageEnd()) ||
					((value & 3) == 0 && value >= ctx.imageBase && value < ctx.ImageEnd()))
					entryType = ptrType;

				if (actionPolicy.allowDefineData &&
					EnsureAddressInsideView(ctx.view, log, "DefineDataVariable", literalAddr))
				{
					if (ctx.plan)
					{
						PlanDefineData(ctx.plan, literalAddr, entryType);
						entriesTyped++;
					}
					else
					{
						ctx.view->DefineDataVariable(literalAddr, entryType);
						entriesTyped++;
					}
				}
			}
		}
	}

	if (ctx.logger)
		ctx.logger->LogInfo("Typed %u literal pool entries as data", entriesTyped);
	if (ctx.verboseLog)
	{
		if (ctx.logger)
			ctx.logger->LogInfo(
				"Literal pool typing detail: ldr_pc=%u typed=%u skipped_noncode=%u skipped_in_function=%u "
				"skipped_decoded_code=%u skipped_existing=%u",
				ldrPcCount, entriesTyped, skippedNonCode, skippedInFunction, skippedDecodedCode, skippedExisting);
	}
}

void ClearAutoDataOnCodeReferences(const FirmwareScanContext& ctx)
{
	uint32_t cleared = 0;
	uint32_t dataVarCount = 0;
	uint32_t autoVarCount = 0;
	uint32_t withCodeRefs = 0;
	uint32_t decodeFailed = 0;
	if (ctx.logger)
		ctx.logger->LogDebug("Clearing auto data at code-referenced addresses...");

	const auto& actionPolicy = GetFirmwareActionPolicy();
	Logger* log = ctx.logger ? ctx.logger.GetPtr() : nullptr;
	if (ScanShouldAbort(ctx.view))
		return;
	auto dataVars = ctx.view->GetDataVariables();
	for (const auto& entry : dataVars)
	{
		if (ScanShouldAbort(ctx.view))
			break;
		dataVarCount++;
		uint64_t addr = entry.first;
		const DataVariable& dataVar = entry.second;
		if (!dataVar.autoDiscovered || dataVar.address != addr)
			continue;
		autoVarCount++;
		if (addr < ctx.imageBase || addr + 8 > ctx.ImageEnd())
			continue;
		if (!ctx.view->IsOffsetCodeSemantics(addr))
			continue;
		if (ctx.view->GetCodeReferences(addr).empty())
			continue;
		withCodeRefs++;

		uint64_t offset = addr - ctx.imageBase;
		uint32_t word0 = 0;
		uint32_t word1 = 0;
		if (!ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, word0, ctx.length))
		{
			decodeFailed++;
			continue;
		}
		if (!ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset + 4, word1, ctx.length))
		{
			decodeFailed++;
			continue;
		}

		armv5::Instruction instr0;
		armv5::Instruction instr1;
		memset(&instr0, 0, sizeof(instr0));
		memset(&instr1, 0, sizeof(instr1));
		if (armv5::armv5_decompose(word0, &instr0, (uint32_t)offset, 0) != 0)
		{
			decodeFailed++;
			continue;
		}
		if (armv5::armv5_decompose(word1, &instr1, (uint32_t)(offset + 4), 0) != 0)
		{
			decodeFailed++;
			continue;
		}

		if (actionPolicy.allowClearData &&
			EnsureAddressInsideView(ctx.view, log, "UndefineDataVariable", addr))
		{
			if (ctx.plan)
			{
				PlanUndefineData(ctx.plan, addr);
				cleared++;
			}
			else
			{
				ctx.view->UndefineDataVariable(addr, false);
				cleared++;
			}
		}
	}

	if (ctx.logger)
		ctx.logger->LogInfo("Cleared %u auto data variables at code-referenced addresses", cleared);
	if (ctx.verboseLog)
	{
		if (ctx.logger)
			ctx.logger->LogInfo(
				"Clear auto data detail: data_vars=%u auto=%u code_ref=%u cleared=%u decode_fail=%u",
				dataVarCount, autoVarCount, withCodeRefs, cleared, decodeFailed);
	}
}

void ClearAutoDataInFunctionEntryBlocks(const FirmwareScanContext& ctx,
	const std::set<uint64_t>* seededFunctions)
{
	uint32_t cleared = 0;
	uint32_t targetsCount = 0;
	uint32_t decodeFailed = 0;
	const size_t maxInstrs = 16;

	const auto& actionPolicy = GetFirmwareActionPolicy();
	Logger* log = ctx.logger ? ctx.logger.GetPtr() : nullptr;
	if (ScanShouldAbort(ctx.view))
		return;
	std::vector<uint64_t> targets;
	if (seededFunctions && !seededFunctions->empty())
	{
		targets.reserve(seededFunctions->size());
		for (auto addr : *seededFunctions)
			targets.push_back(addr);
	}
	else
	{
		auto functions = ctx.view->GetAnalysisFunctionList();
		targets.reserve(functions.size());
		for (const auto& func : functions)
		{
			if (func)
				targets.push_back(func->GetStart());
		}
	}

	for (auto startAddr : targets)
	{
		if (ScanShouldAbort(ctx.view))
			break;
		targetsCount++;
		uint64_t addr = startAddr;
		for (size_t i = 0; i < maxInstrs; i++)
		{
			if (ScanShouldAbort(ctx.view))
				break;
			if (addr + 8 > ctx.ImageEnd())
				break;
			uint64_t offset = addr - ctx.imageBase;
			uint32_t word0 = 0;
			uint32_t word1 = 0;
			if (!ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, word0, ctx.length))
			{
				decodeFailed++;
				break;
			}
			if (!ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset + 4, word1, ctx.length))
			{
				decodeFailed++;
				break;
			}

			armv5::Instruction instr0;
			armv5::Instruction instr1;
			memset(&instr0, 0, sizeof(instr0));
			memset(&instr1, 0, sizeof(instr1));
			if (armv5::armv5_decompose(word0, &instr0, (uint32_t)offset, 0) != 0)
			{
				decodeFailed++;
				break;
			}
			if (armv5::armv5_decompose(word1, &instr1, (uint32_t)(offset + 4), 0) != 0)
			{
				decodeFailed++;
				break;
			}

			DataVariable dataVar;
			if (ctx.view->GetDataVariableAtAddress(addr, dataVar) &&
				dataVar.address == addr && dataVar.autoDiscovered)
			{
				if (actionPolicy.allowClearData &&
					EnsureAddressInsideView(ctx.view, log, "UndefineDataVariable", addr))
				{
					if (ctx.plan)
					{
						PlanUndefineData(ctx.plan, addr);
						cleared++;
					}
					else
					{
						ctx.view->UndefineDataVariable(addr, false);
						cleared++;
					}
				}
			}

			if ((instr0.operation == armv5::ARMV5_B) &&
				(instr0.cond == armv5::COND_AL || instr0.cond == armv5::COND_NV))
				break;
			if (instr0.operation == armv5::ARMV5_BX)
				break;

			addr += 4;
		}
	}

	if (cleared && ctx.logger)
		ctx.logger->LogInfo("Cleared %u auto data variables inside function entry blocks", cleared);
	if (ctx.verboseLog)
	{
		if (ctx.logger)
			ctx.logger->LogInfo(
				"Entry block clear detail: targets=%u cleared=%u decode_fail=%u",
				targetsCount, cleared, decodeFailed);
	}
}

// Scan for jump tables (ADD PC, PC, Rn pattern) and mark them as uint32 arrays
// NOTE: Currently unused, kept for future IL-based jump table resolution
static void ScanForJumpTables(const FirmwareScanContext& ctx)
{
	if (ctx.logger)
		ctx.logger->LogDebug("Scanning for jump tables...");

	const auto& actionPolicy = GetFirmwareActionPolicy();
	Ref<Type> uint32Type = Type::IntegerType(4, false);
	Logger* log = ctx.logger ? ctx.logger.GetPtr() : nullptr;
	if (ScanShouldAbort(ctx.view))
		return;

	for (uint64_t offset = 0; offset + 4 <= ctx.length; offset += 4)
	{
		if (ScanShouldAbort(ctx.view))
			break;
		uint32_t instr = 0;
		ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset, instr, ctx.length);

		// ADD PC, PC, Rn (computed jump for switch tables)
		if ((instr & 0x0FFFF010) == 0x008FF000)
		{
			uint64_t tableBase = 0;
			uint32_t maxCases = 0;

			for (int i = 1; i <= 16 && offset >= (uint64_t)(i * 4); i++)
			{
				uint32_t scanInstr = 0;
				ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, offset - (i * 4), scanInstr, ctx.length);

				// ADD Rx, PC, #imm (table base calculation)
				if ((scanInstr & 0x0FFF0000) == 0x028F0000)
				{
					uint32_t imm12 = scanInstr & 0xFFF;
					uint32_t rotate = (scanInstr >> 8) & 0xF;
					uint32_t immediate = (imm12 >> (rotate * 2)) | (imm12 << (32 - rotate * 2));
					tableBase = ctx.imageBase + (offset - (i * 4)) + 8 + immediate;
				}

				// CMP Rx, #imm (bounds check)
				if ((scanInstr & 0x0FF00000) == 0x03500000 && maxCases == 0)
				{
					uint32_t imm8 = scanInstr & 0xFF;
					uint32_t rotate = (scanInstr >> 8) & 0xF;
					maxCases = ((imm8 >> (rotate * 2)) | (imm8 << (32 - rotate * 2))) + 1;
				}

				if (tableBase != 0 && maxCases > 0)
					break;
			}

			if (tableBase != 0)
			{
				if (maxCases == 0 || maxCases > 64)
					maxCases = 32;

				uint32_t validEntries = 0;
				for (uint32_t i = 0; i < maxCases; i++)
				{
					uint64_t entryFileOffset = (tableBase - ctx.imageBase) + (i * 4);
					if (entryFileOffset + 4 > ctx.length)
						break;
					uint32_t entryValue = 0;
					ReadU32At(ctx.reader, ctx.data, ctx.dataLen, ctx.endian, entryFileOffset, entryValue, ctx.length);
					if (entryValue > 0x100000)
						break;
					validEntries++;
				}

				if (validEntries > 0)
				{
					Ref<Type> arrayType = Type::ArrayType(uint32Type, validEntries);
					if (actionPolicy.allowDefineData &&
						EnsureAddressInsideView(ctx.view, log, "DefineDataVariable", tableBase))
					{
						if (ctx.plan)
						{
							PlanDefineData(ctx.plan, tableBase, arrayType);
						}
						else
						{
							ctx.view->DefineDataVariable(tableBase, arrayType);
						}
					}

					char symName[32];
					snprintf(symName, sizeof(symName), "switch_table_%llx",
						(unsigned long long)tableBase);
					if (actionPolicy.allowDefineSymbol &&
						EnsureAddressInsideView(ctx.view, log, "DefineAutoSymbol", tableBase))
					{
						if (ctx.plan)
						{
							PlanDefineSymbol(ctx.plan,
								new Symbol(DataSymbol, symName, tableBase, LocalBinding));
						}
						else
						{
							ctx.view->DefineAutoSymbol(new Symbol(DataSymbol, symName, tableBase, LocalBinding));
						}
					}

					if (ctx.logger)
						ctx.logger->LogDebug("Defined switch table at 0x%llx with %u entries",
							(unsigned long long)tableBase, validEntries);
				}
			}
		}
	}
}
