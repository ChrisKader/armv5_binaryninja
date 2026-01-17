/*
 * ARMv5 Calling Convention Detector
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * Automatically detects and applies calling conventions based on function
 * prologue/epilogue patterns and context (e.g., vector table location).
 *
 * DETECTION STRATEGY:
 * -------------------
 *
 * 1. IRQ/Exception Handlers:
 *    - Located at vector table addresses
 *    - Epilogue: SUBS PC, LR, #4 or MOVS PC, LR
 *    - Saves/restores SPSR
 *    - Apply: irq-handler convention
 *
 * 2. Standard AAPCS Functions:
 *    - Prologue: PUSH {r4-r11, lr} or STMFD sp!, {regs, lr}
 *    - Uses r0-r3 for arguments
 *    - Preserves r4-r11
 *    - Apply: aapcs convention (default)
 *
 * 3. Leaf Functions:
 *    - No stack frame setup
 *    - No callee-saved register preservation
 *    - May use only r0-r3, r12
 *    - Apply: aapcs (but mark as leaf for optimization)
 *
 * 4. RTOS Task Entry:
 *    - Called from scheduler with task parameter
 *    - Infinite loop pattern (while(1) with delay)
 *    - Apply: task-entry convention
 *
 * ============================================================================
 */

#pragma once

#include "binaryninjaapi.h"

namespace armv5 {

/**
 * Detected calling convention type.
 */
enum class DetectedConvention {
	Unknown,      // Could not determine
	AAPCS,        // Standard ARM EABI
	IRQHandler,   // Interrupt/exception handler
	LeafFunction, // No stack frame, uses only scratch regs
	TaskEntry,    // RTOS task entry point
	NoReturn      // Function never returns (infinite loop)
};

/**
 * Result of calling convention detection.
 */
struct ConventionDetectionResult {
	DetectedConvention type = DetectedConvention::Unknown;
	uint8_t confidence = 0;  // 0-255, higher = more confident
	std::string reason;      // Human-readable explanation
};

/**
 * Calling Convention Detector
 *
 * Analyzes function IL and context to determine the appropriate
 * calling convention to apply.
 */
class CallingConventionDetector {
public:
	/**
	 * Detect the calling convention for a function.
	 *
	 * @param view The binary view.
	 * @param func The function to analyze.
	 * @param il   The function's low-level IL.
	 * @return Detection result with convention type and confidence.
	 */
	static ConventionDetectionResult DetectConvention(
		BinaryNinja::BinaryView* view,
		BinaryNinja::Function* func,
		BinaryNinja::LowLevelILFunction* il);

	/**
	 * Apply the detected convention to a function.
	 *
	 * Only applies if confidence exceeds threshold and the function
	 * doesn't already have a user-defined convention.
	 *
	 * @param view   The binary view.
	 * @param func   The function to modify.
	 * @param result The detection result.
	 * @param minConfidence Minimum confidence to apply (default: 128).
	 * @return true if convention was applied.
	 */
	static bool ApplyDetectedConvention(
		BinaryNinja::BinaryView* view,
		BinaryNinja::Function* func,
		const ConventionDetectionResult& result,
		uint8_t minConfidence = 128);

private:
	/**
	 * Check if function is an IRQ/exception handler.
	 *
	 * Criteria:
	 * - Address matches vector table entry
	 * - Name contains "handler", "irq", "fiq", "abort", etc.
	 * - Epilogue uses SUBS PC, LR pattern
	 */
	static bool IsIRQHandler(
		BinaryNinja::BinaryView* view,
		BinaryNinja::Function* func,
		BinaryNinja::LowLevelILFunction* il);

	/**
	 * Check if function is a leaf function (no stack frame).
	 */
	static bool IsLeafFunction(
		BinaryNinja::Function* func,
		BinaryNinja::LowLevelILFunction* il);

	/**
	 * Check if function is an RTOS task entry point.
	 *
	 * Criteria:
	 * - Contains infinite loop pattern
	 * - Calls delay/sleep functions
	 * - Called from scheduler/task creation
	 */
	static bool IsTaskEntry(
		BinaryNinja::BinaryView* view,
		BinaryNinja::Function* func,
		BinaryNinja::LowLevelILFunction* il);

	/**
	 * Check if function never returns (infinite loop, halt).
	 */
	static bool IsNoReturn(
		BinaryNinja::Function* func,
		BinaryNinja::LowLevelILFunction* il);

	/**
	 * Check for IRQ epilogue patterns.
	 *
	 * ARM IRQ return patterns:
	 * - SUBS PC, LR, #4  (IRQ)
	 * - SUBS PC, LR, #8  (Data Abort)
	 * - MOVS PC, LR      (SWI, Undefined)
	 */
	static bool HasIRQEpilogue(BinaryNinja::LowLevelILFunction* il);

	/**
	 * Get calling convention by name from architecture.
	 */
	static BinaryNinja::Ref<BinaryNinja::CallingConvention> GetConventionByName(
		BinaryNinja::Architecture* arch,
		const std::string& name);
};

} // namespace armv5
