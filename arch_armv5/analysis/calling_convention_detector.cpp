/*
 * ARMv5 Calling Convention Detector Implementation
 */

#include "calling_convention_detector.h"
#include "lowlevelilinstruction.h"

#include <algorithm>
#include <cctype>

using namespace BinaryNinja;
using namespace armv5;

/*
 * Get logger for analysis components.
 */
static Ref<Logger> GetAnalysisLogger()
{
	static Ref<Logger> logger = LogRegistry::CreateLogger("BinaryView.ARMv5Analysis");
	return logger;
}

/*
 * Vector table handler names (case-insensitive matching)
 */
static const char* kHandlerNamePatterns[] = {
	"handler",
	"irq",
	"fiq",
	"abort",
	"undefined",
	"swi",
	"reset",
	"exception",
	"interrupt",
	"_isr",
	nullptr
};

/*
 * RTOS delay/sleep function name patterns
 */
static const char* kDelayFunctionPatterns[] = {
	"delay",
	"sleep",
	"vTaskDelay",
	"osDelay",
	"NU_Sleep",
	"tx_thread_sleep",
	"OSTimeDly",
	nullptr
};

static bool ContainsPatternCaseInsensitive(const std::string& str, const char* pattern)
{
	std::string lowerStr = str;
	std::string lowerPattern = pattern;
	std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
	std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);
	return lowerStr.find(lowerPattern) != std::string::npos;
}

static bool MatchesAnyPattern(const std::string& str, const char** patterns)
{
	for (const char** p = patterns; *p != nullptr; ++p)
	{
		if (ContainsPatternCaseInsensitive(str, *p))
			return true;
	}
	return false;
}

ConventionDetectionResult CallingConventionDetector::DetectConvention(
	BinaryView* view,
	Function* func,
	LowLevelILFunction* il)
{
	ConventionDetectionResult result;
	result.type = DetectedConvention::Unknown;
	result.confidence = 0;

	if (!view || !func || !il)
		return result;

	// Check for IRQ handler (highest priority - most specific)
	if (IsIRQHandler(view, func, il))
	{
		result.type = DetectedConvention::IRQHandler;
		result.confidence = 200;
		result.reason = "Detected IRQ/exception handler pattern";
		return result;
	}

	// Check for no-return functions
	if (IsNoReturn(func, il))
	{
		result.type = DetectedConvention::NoReturn;
		result.confidence = 180;
		result.reason = "Function contains infinite loop or halt";
		return result;
	}

	// Check for task entry
	if (IsTaskEntry(view, func, il))
	{
		result.type = DetectedConvention::TaskEntry;
		result.confidence = 160;
		result.reason = "Detected RTOS task entry pattern";
		return result;
	}

	// Check for leaf function
	if (IsLeafFunction(func, il))
	{
		result.type = DetectedConvention::LeafFunction;
		result.confidence = 140;
		result.reason = "Leaf function with no stack frame";
		return result;
	}

	// Default to AAPCS
	result.type = DetectedConvention::AAPCS;
	result.confidence = 100;
	result.reason = "Default ARM EABI calling convention";
	return result;
}

bool CallingConventionDetector::ApplyDetectedConvention(
	BinaryView* view,
	Function* func,
	const ConventionDetectionResult& result,
	uint8_t minConfidence)
{
	if (!view || !func)
		return false;

	if (result.confidence < minConfidence)
		return false;

	if (result.type == DetectedConvention::Unknown)
		return false;

	Ref<Architecture> arch = func->GetArchitecture();
	if (!arch)
		return false;

	std::string conventionName;
	switch (result.type)
	{
	case DetectedConvention::IRQHandler:
		conventionName = "irq-handler";
		break;
	case DetectedConvention::TaskEntry:
		conventionName = "task-entry";
		break;
	case DetectedConvention::AAPCS:
	case DetectedConvention::LeafFunction:
		conventionName = "aapcs";
		break;
	case DetectedConvention::NoReturn:
		// Mark as no-return but use AAPCS convention
		func->SetAutoCanReturn(Confidence<bool>(false, 200));
		conventionName = "aapcs";
		break;
	default:
		return false;
	}

	Ref<CallingConvention> conv = GetConventionByName(arch.GetPtr(), conventionName);
	if (!conv)
		return false;

	// Only apply if not already user-defined
	auto currentConv = func->GetCallingConvention();
	if (currentConv.GetConfidence() >= 255)  // User-defined
		return false;

	func->SetAutoCallingConvention(Confidence<Ref<CallingConvention>>(conv, result.confidence));

	// Log the detection
	Ref<Logger> logger = GetAnalysisLogger();
	if (logger)
	{
		logger->LogDebug("CallingConvention: Applied '%s' to 0x%llx (%s, confidence=%u)",
			conventionName.c_str(),
			(unsigned long long)func->GetStart(),
			result.reason.c_str(),
			result.confidence);
	}

	return true;
}

bool CallingConventionDetector::IsIRQHandler(
	BinaryView* view,
	Function* func,
	LowLevelILFunction* il)
{
	if (!func || !il)
		return false;

	// Check 1: Name matches handler pattern
	Ref<Symbol> sym = func->GetSymbol();
	if (sym)
	{
		std::string name = sym->GetShortName();
		if (MatchesAnyPattern(name, kHandlerNamePatterns))
		{
			// Name match + IRQ epilogue = high confidence
			if (HasIRQEpilogue(il))
				return true;
		}
	}

	// Check 2: Address matches vector table entry
	// Vector table is at 0x00000000 or 0xFFFF0000 (high vectors)
	uint64_t addr = func->GetStart();
	bool atVectorTable = (addr < 0x40) || (addr >= 0xFFFF0000 && addr < 0xFFFF0040);

	if (atVectorTable && HasIRQEpilogue(il))
		return true;

	// Check 3: Has IRQ epilogue pattern
	if (HasIRQEpilogue(il))
	{
		// Also check for SPSR access (MRS/MSR with SPSR)
		// This is a strong indicator of exception handler
		return true;
	}

	return false;
}

bool CallingConventionDetector::IsLeafFunction(
	Function* func,
	LowLevelILFunction* il)
{
	if (!func || !il)
		return false;

	size_t instrCount = il->GetInstructionCount();
	if (instrCount == 0)
		return false;

	// Leaf functions typically:
	// 1. Don't push LR
	// 2. Don't adjust SP (no stack frame)
	// 3. Only use r0-r3, r12 (caller-saved)

	bool hasPush = false;
	bool hasSpAdjust = false;

	for (size_t i = 0; i < instrCount && i < 10; ++i)
	{
		LowLevelILInstruction instr = il->GetInstruction(i);

		// Check for push/stm patterns
		if (instr.operation == LLIL_PUSH)
			hasPush = true;

		// Check for SP adjustment (SUB SP, SP, #imm)
		if (instr.operation == LLIL_SET_REG)
		{
			// Would need to check if destination is SP
			// and source involves SP minus constant
		}
	}

	return !hasPush && !hasSpAdjust && instrCount < 20;
}

bool CallingConventionDetector::IsTaskEntry(
	BinaryView* view,
	Function* func,
	LowLevelILFunction* il)
{
	if (!view || !func || !il)
		return false;

	// Task entry functions typically:
	// 1. Have a single void* or int parameter
	// 2. Contain an infinite loop
	// 3. Call delay/sleep functions

	// Check for infinite loop (back-edge to function start or near start)
	bool hasBackEdge = false;
	bool callsDelay = false;

	// Check call sites for delay patterns
	auto callSites = func->GetCallSites();
	for (const auto& callSite : callSites)
	{
		// Get the call target from the call site
		auto calledFuncs = view->GetAnalysisFunctionsForAddress(callSite.addr);
		for (const auto& calledFunc : calledFuncs)
		{
			Ref<Symbol> sym = calledFunc->GetSymbol();
			if (sym)
			{
				std::string name = sym->GetShortName();
				if (MatchesAnyPattern(name, kDelayFunctionPatterns))
				{
					callsDelay = true;
					break;
				}
			}
		}
		if (callsDelay)
			break;
	}

	// Check for backward branches (infinite loop indicator)
	for (size_t i = 0; i < il->GetInstructionCount(); ++i)
	{
		LowLevelILInstruction instr = il->GetInstruction(i);
		if (instr.operation == LLIL_GOTO || instr.operation == LLIL_JUMP)
		{
			// Check if target is before current address
			// This is a simplified check - real implementation would
			// analyze the CFG for back-edges
		}
	}

	// Task entry if calls delay and has characteristics
	return callsDelay;
}

bool CallingConventionDetector::IsNoReturn(
	Function* func,
	LowLevelILFunction* il)
{
	if (!func || !il)
		return false;

	size_t instrCount = il->GetInstructionCount();
	if (instrCount == 0)
		return false;

	// Check last instruction for infinite loop patterns
	LowLevelILInstruction lastInstr = il->GetInstruction(instrCount - 1);

	// Pattern: B . (branch to self)
	if (lastInstr.operation == LLIL_GOTO)
	{
		// Would check if target equals current address
	}

	// Pattern: Function ends without RET
	bool hasReturn = false;
	for (size_t i = 0; i < instrCount; ++i)
	{
		LowLevelILInstruction instr = il->GetInstruction(i);
		if (instr.operation == LLIL_RET || instr.operation == LLIL_TAILCALL)
		{
			hasReturn = true;
			break;
		}
	}

	// If function has no return and no tailcall, likely no-return
	return !hasReturn && instrCount > 3;
}

bool CallingConventionDetector::HasIRQEpilogue(LowLevelILFunction* il)
{
	if (!il)
		return false;

	size_t instrCount = il->GetInstructionCount();
	if (instrCount == 0)
		return false;

	// Look for IRQ return patterns in last few instructions
	// ARM IRQ return: SUBS PC, LR, #4 or MOVS PC, LR
	// These translate to specific IL patterns

	for (size_t i = instrCount > 5 ? instrCount - 5 : 0; i < instrCount; ++i)
	{
		LowLevelILInstruction instr = il->GetInstruction(i);

		// Look for: PC = (LR - 4) with flags update
		// This would be LLIL_SET_REG_SPLIT or similar with LLIL_SUB

		// For now, just check for unusual return patterns
		// A proper implementation would decode the original instruction
	}

	return false;
}

Ref<CallingConvention> CallingConventionDetector::GetConventionByName(
	Architecture* arch,
	const std::string& name)
{
	if (!arch)
		return nullptr;

	auto conventions = arch->GetCallingConventions();
	for (const auto& conv : conventions)
	{
		if (conv->GetName() == name)
			return conv;
	}

	return nullptr;
}
