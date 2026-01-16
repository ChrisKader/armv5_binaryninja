/*
 * ARMv5 Function Signature Recovery Implementation
 */

#include "signature_recovery.h"
#include "lowlevelilinstruction.h"

#include <algorithm>

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
 * ARM register indices for argument registers
 */
constexpr uint32_t REG_R0 = 0;
constexpr uint32_t REG_R1 = 1;
constexpr uint32_t REG_R2 = 2;
constexpr uint32_t REG_R3 = 3;

/*
 * Format string function name patterns (for variadic detection)
 */
static const char* kFormatFunctionPatterns[] = {
	"printf",
	"sprintf",
	"snprintf",
	"fprintf",
	"scanf",
	"sscanf",
	"log",
	nullptr
};

static bool ContainsPattern(const std::string& str, const char* pattern)
{
	return str.find(pattern) != std::string::npos;
}

RecoveredSignature SignatureRecovery::RecoverSignature(
	BinaryView* view,
	Function* func,
	LowLevelILFunction* il)
{
	RecoveredSignature sig;
	sig.returnKind = InferredTypeKind::Unknown;
	sig.returnConfidence = 0;
	sig.isVoid = true;
	sig.is64BitReturn = false;
	sig.isVariadic = false;
	sig.overallConfidence = 0;

	if (!view || !func || !il)
		return sig;

	// Detect parameter count
	size_t paramCount = DetectParameterCount(il);

	// Infer parameter types
	sig.parameters = InferParameterTypes(view, il, paramCount);

	// Detect return type
	auto [returnKind, is64Bit] = DetectReturnType(il);
	sig.returnKind = returnKind;
	sig.is64BitReturn = is64Bit;
	sig.isVoid = (returnKind == InferredTypeKind::Unknown);
	sig.returnConfidence = sig.isVoid ? 100 : 150;

	// Check for variadic
	sig.isVariadic = DetectVariadic(view, func);

	// Calculate overall confidence
	uint32_t totalConfidence = sig.returnConfidence;
	for (const auto& param : sig.parameters)
		totalConfidence += param.confidence;

	if (sig.parameters.size() > 0)
	{
		uint32_t avgConfidence = totalConfidence / static_cast<uint32_t>(sig.parameters.size() + 1);
		sig.overallConfidence = static_cast<uint8_t>(avgConfidence > 255 ? 255 : avgConfidence);
	}
	else
		sig.overallConfidence = static_cast<uint8_t>(sig.returnConfidence);

	return sig;
}

bool SignatureRecovery::ApplyRecoveredSignature(
	BinaryView* view,
	Function* func,
	const RecoveredSignature& sig,
	uint8_t minConfidence)
{
	if (!view || !func)
		return false;

	if (sig.overallConfidence < minConfidence)
		return false;

	// Build parameter types
	std::vector<FunctionParameter> params;
	for (const auto& param : sig.parameters)
	{
		FunctionParameter fp;
		fp.name = param.suggestedName;
		fp.type = KindToType(view, param.kind);
		if (!fp.type)
			fp.type = Type::IntegerType(4, true);  // Default to int32
		fp.defaultLocation = false;
		params.push_back(fp);
	}

	// Build return type
	Ref<Type> returnType;
	if (sig.isVoid)
	{
		returnType = Type::VoidType();
	}
	else if (sig.is64BitReturn)
	{
		returnType = Type::IntegerType(8, true);  // int64_t
	}
	else
	{
		returnType = KindToType(view, sig.returnKind);
		if (!returnType)
			returnType = Type::IntegerType(4, true);
	}

	// Create function type
	Ref<Type> funcType = Type::FunctionType(
		returnType,
		func->GetCallingConvention().GetValue(),
		params,
		sig.isVariadic);

	// Apply to function
	func->SetAutoType(funcType);

	// Log the detection
	Ref<Logger> logger = GetAnalysisLogger();
	if (logger)
	{
		logger->LogDebug("SignatureRecovery: Applied signature to 0x%llx (%zu params, %s return, confidence=%u)",
			(unsigned long long)func->GetStart(),
			sig.parameters.size(),
			sig.isVoid ? "void" : (sig.is64BitReturn ? "64-bit" : "32-bit"),
			sig.overallConfidence);
	}

	return true;
}

size_t SignatureRecovery::DetectParameterCount(LowLevelILFunction* il)
{
	if (!il)
		return 0;

	// Track which argument registers are read before written
	bool regRead[4] = {false, false, false, false};
	bool regWritten[4] = {false, false, false, false};

	size_t instrCount = il->GetInstructionCount();

	// Analyze first N instructions (prologue + early body)
	size_t limit = std::min(instrCount, size_t(50));

	for (size_t i = 0; i < limit; ++i)
	{
		LowLevelILInstruction instr = il->GetInstruction(i);

		// Recursively scan for register reads and writes
		// This is a simplified version - full implementation would
		// properly walk the IL expression tree

		if (instr.operation == LLIL_SET_REG)
		{
			// Check if destination is r0-r3
			uint32_t dest = instr.GetDestRegister();
			if (dest <= REG_R3)
				regWritten[dest] = true;

			// Check source for reads
			// Would need to recursively check source expression
		}

		if (instr.operation == LLIL_REG)
		{
			uint32_t src = instr.GetSourceRegister();
			if (src <= REG_R3 && !regWritten[src])
				regRead[src] = true;
		}
	}

	// Count consecutive parameters (gaps mean unused args)
	size_t count = 0;
	for (size_t i = 0; i < 4; ++i)
	{
		if (regRead[i])
			count = i + 1;
	}

	return count;
}

std::vector<RecoveredParameter> SignatureRecovery::InferParameterTypes(
	BinaryView* view,
	LowLevelILFunction* il,
	size_t count)
{
	std::vector<RecoveredParameter> params;

	if (!view || !il)
		return params;

	for (size_t i = 0; i < count; ++i)
	{
		RecoveredParameter param;
		param.regIndex = static_cast<uint32_t>(i);
		param.kind = InferTypeFromUsage(il, param.regIndex);
		param.confidence = 128;  // Moderate confidence

		// Generate parameter name
		switch (param.kind)
		{
		case InferredTypeKind::Pointer:
			param.suggestedName = "ptr" + std::to_string(i);
			break;
		case InferredTypeKind::FunctionPtr:
			param.suggestedName = "callback" + std::to_string(i);
			break;
		case InferredTypeKind::Char:
			param.suggestedName = "ch" + std::to_string(i);
			break;
		case InferredTypeKind::Boolean:
			param.suggestedName = "flag" + std::to_string(i);
			break;
		default:
			param.suggestedName = "arg" + std::to_string(i);
			break;
		}

		params.push_back(param);
	}

	return params;
}

std::pair<InferredTypeKind, bool> SignatureRecovery::DetectReturnType(
	LowLevelILFunction* il)
{
	if (!il)
		return {InferredTypeKind::Unknown, false};

	bool r0Written = false;
	bool r1Written = false;
	bool hasReturn = false;

	size_t instrCount = il->GetInstructionCount();

	// Look for writes to r0/r1 before return instructions
	for (size_t i = 0; i < instrCount; ++i)
	{
		LowLevelILInstruction instr = il->GetInstruction(i);

		if (instr.operation == LLIL_SET_REG)
		{
			uint32_t dest = instr.GetDestRegister();
			if (dest == REG_R0)
				r0Written = true;
			else if (dest == REG_R1)
				r1Written = true;
		}

		if (instr.operation == LLIL_RET)
		{
			hasReturn = true;
		}
	}

	if (!hasReturn)
		return {InferredTypeKind::Unknown, false};

	if (!r0Written)
		return {InferredTypeKind::Unknown, false};  // void

	if (r1Written)
		return {InferredTypeKind::LongLong, true};  // 64-bit return

	return {InferredTypeKind::Integer, false};  // 32-bit return
}

bool SignatureRecovery::DetectVariadic(
	BinaryView* view,
	Function* func)
{
	if (!view || !func)
		return false;

	// Check function name for format function patterns
	Ref<Symbol> sym = func->GetSymbol();
	if (sym)
	{
		std::string name = sym->GetShortName();
		for (const char** p = kFormatFunctionPatterns; *p != nullptr; ++p)
		{
			if (ContainsPattern(name, *p))
				return true;
		}
	}

	// Could also check for va_start/va_arg patterns in IL
	return false;
}

InferredTypeKind SignatureRecovery::InferTypeFromUsage(
	LowLevelILFunction* il,
	uint32_t regIndex)
{
	if (!il)
		return InferredTypeKind::Unknown;

	// Check if register is dereferenced
	if (IsDereferenced(il, regIndex))
		return InferredTypeKind::Pointer;

	// Default to integer
	return InferredTypeKind::Integer;
}

bool SignatureRecovery::IsDereferenced(
	LowLevelILFunction* il,
	uint32_t regIndex)
{
	if (!il)
		return false;

	size_t instrCount = il->GetInstructionCount();

	for (size_t i = 0; i < instrCount; ++i)
	{
		LowLevelILInstruction instr = il->GetInstruction(i);

		// Check for LOAD using register as address
		if (instr.operation == LLIL_LOAD)
		{
			// Would need to check if source expression contains
			// reference to regIndex
		}

		// Check for STORE using register as address
		if (instr.operation == LLIL_STORE)
		{
			// Similar check for destination
		}
	}

	return false;
}

Ref<Type> SignatureRecovery::KindToType(
	BinaryView* view,
	InferredTypeKind kind)
{
	if (!view)
		return nullptr;

	switch (kind)
	{
	case InferredTypeKind::Integer:
		return Type::IntegerType(4, true);  // int32_t
	case InferredTypeKind::Pointer:
		return Type::PointerType(view->GetDefaultArchitecture(), Type::VoidType());
	case InferredTypeKind::FunctionPtr:
		return Type::PointerType(
			view->GetDefaultArchitecture(),
			Type::FunctionType(Type::VoidType(), nullptr, {}));
	case InferredTypeKind::Boolean:
		return Type::BoolType();
	case InferredTypeKind::Char:
		return Type::IntegerType(1, true);  // char
	case InferredTypeKind::Short:
		return Type::IntegerType(2, true);  // int16_t
	case InferredTypeKind::LongLong:
		return Type::IntegerType(8, true);  // int64_t
	case InferredTypeKind::Float:
		return Type::FloatType(4);
	case InferredTypeKind::Double:
		return Type::FloatType(8);
	default:
		return Type::IntegerType(4, true);  // Default to int32
	}
}
