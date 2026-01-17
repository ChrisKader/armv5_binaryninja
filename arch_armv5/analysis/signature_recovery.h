/*
 * ARMv5 Function Signature Recovery
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * Recovers function signatures (parameter count, types, return type) by
 * analyzing register usage patterns in the function's IL.
 *
 * ANALYSIS STRATEGY:
 * ------------------
 *
 * 1. Parameter Detection:
 *    - Count reads of r0-r3 before any writes at function entry
 *    - Each read indicates a parameter
 *    - Stop counting when a register is written before read
 *
 * 2. Parameter Type Inference:
 *    - Pointer: Register is dereferenced (LLIL_LOAD with reg as address)
 *    - Integer: Used in arithmetic, comparisons
 *    - Size hint: Used with specific load/store sizes (byte, halfword, word)
 *
 * 3. Return Value Detection:
 *    - Check if r0 is written before any return/tailcall
 *    - r0+r1 pair written = 64-bit return
 *    - No r0 write = void return
 *
 * 4. Variadic Detection:
 *    - Look for format string patterns
 *    - Check for variable argument list access patterns
 *
 * ============================================================================
 * ARM REGISTER USAGE (AAPCS)
 * ============================================================================
 *
 * | Register | Purpose           | Notes                    |
 * |----------|-------------------|--------------------------|
 * | r0-r3    | Arguments/Return  | First 4 args, r0 return  |
 * | r4-r11   | Callee-saved      | Must be preserved        |
 * | r12 (IP) | Scratch           | Intra-procedure scratch  |
 * | r13 (SP) | Stack Pointer     | Must be 8-byte aligned   |
 * | r14 (LR) | Link Register     | Return address           |
 * | r15 (PC) | Program Counter   | Instruction pointer      |
 *
 * ============================================================================
 */

#pragma once

#include "binaryninjaapi.h"

#include <optional>
#include <vector>

namespace armv5 {

/**
 * Inferred type category for a register.
 */
enum class InferredTypeKind {
	Unknown,
	Integer,      // General integer (int, uint32_t, etc.)
	Pointer,      // Pointer to data
	FunctionPtr,  // Pointer to function
	Boolean,      // Used in boolean context
	Char,         // Byte-sized value
	Short,        // Halfword value
	LongLong,     // 64-bit value (r0+r1)
	Float,        // VFP single
	Double        // VFP double
};

/**
 * Recovered parameter information.
 */
struct RecoveredParameter {
	uint32_t regIndex;        // Register index (0-3)
	InferredTypeKind kind;    // Inferred type category
	uint8_t confidence;       // 0-255
	std::string suggestedName;
};

/**
 * Recovered function signature.
 */
struct RecoveredSignature {
	std::vector<RecoveredParameter> parameters;
	InferredTypeKind returnKind;
	uint8_t returnConfidence;
	bool isVoid;              // True if no return value
	bool is64BitReturn;       // True if r0+r1 used for return
	bool isVariadic;          // True if varargs detected
	uint8_t overallConfidence;
};

/**
 * Function Signature Recovery
 *
 * Analyzes function IL to recover parameter and return type information.
 */
class SignatureRecovery {
public:
	/**
	 * Recover the signature for a function.
	 *
	 * @param view The binary view.
	 * @param func The function to analyze.
	 * @param il   The function's low-level IL.
	 * @return Recovered signature information.
	 */
	static RecoveredSignature RecoverSignature(
		BinaryNinja::BinaryView* view,
		BinaryNinja::Function* func,
		BinaryNinja::LowLevelILFunction* il);

	/**
	 * Apply recovered signature to function.
	 *
	 * Creates a function type and applies it to the function.
	 *
	 * @param view   The binary view.
	 * @param func   The function to modify.
	 * @param sig    The recovered signature.
	 * @param minConfidence Minimum confidence to apply (default: 128).
	 * @return true if signature was applied.
	 */
	static bool ApplyRecoveredSignature(
		BinaryNinja::BinaryView* view,
		BinaryNinja::Function* func,
		const RecoveredSignature& sig,
		uint8_t minConfidence = 128);

private:
	/**
	 * Detect parameter count by analyzing r0-r3 reads at entry.
	 */
	static size_t DetectParameterCount(BinaryNinja::LowLevelILFunction* il);

	/**
	 * Infer types for each detected parameter.
	 */
	static std::vector<RecoveredParameter> InferParameterTypes(
		BinaryNinja::BinaryView* view,
		BinaryNinja::LowLevelILFunction* il,
		size_t count);

	/**
	 * Detect return value by analyzing r0 writes before returns.
	 */
	static std::pair<InferredTypeKind, bool> DetectReturnType(
		BinaryNinja::LowLevelILFunction* il);

	/**
	 * Check if function appears to be variadic.
	 */
	static bool DetectVariadic(
		BinaryNinja::BinaryView* view,
		BinaryNinja::Function* func);

	/**
	 * Analyze how a register is used to infer its type.
	 */
	static InferredTypeKind InferTypeFromUsage(
		BinaryNinja::LowLevelILFunction* il,
		uint32_t regIndex);

	/**
	 * Check if a register is dereferenced (used as pointer).
	 */
	static bool IsDereferenced(
		BinaryNinja::LowLevelILFunction* il,
		uint32_t regIndex);

	/**
	 * Convert inferred type to Binary Ninja type.
	 */
	static BinaryNinja::Ref<BinaryNinja::Type> KindToType(
		BinaryNinja::BinaryView* view,
		InferredTypeKind kind);
};

} // namespace armv5
