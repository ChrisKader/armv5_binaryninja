/*
 * ARMv5 RTOS Detector
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * Detects common Real-Time Operating Systems used in ARM embedded firmware
 * and applies appropriate type definitions, calling conventions, and
 * structure annotations.
 *
 * SUPPORTED RTOS:
 * ---------------
 *
 * 1. FreeRTOS
 *    - Detection: xTaskCreate, vTaskDelay, pxCurrentTCB
 *    - Structures: tskTCB, ListItem_t, List_t
 *    - Task pattern: Infinite loop with vTaskDelay
 *
 * 2. ThreadX
 *    - Detection: tx_thread_create, _tx_timer_thread
 *    - Structures: TX_THREAD, TX_TIMER, TX_QUEUE
 *    - Task pattern: Entry with tx_thread_sleep
 *
 * 3. Nucleus PLUS
 *    - Detection: NU_Create_Task, NU_Resume_Task, NU_Sleep
 *    - Structures: NU_TASK with linked list pointers
 *    - Features: Dynamic task creation, signals, preemption
 *
 * 4. Nucleus SE
 *    - Detection: NUSE_Task_Start_Address, NUSE_Scheduler
 *    - Structures: Static arrays (no heap allocation)
 *    - Features: Table-driven, index-based task IDs
 *
 * 5. uC/OS-II
 *    - Detection: OSTaskCreate, OSTimeDly, OS_TCB
 *    - Structures: OS_TCB, OS_EVENT
 *    - Task pattern: Priority-based scheduling
 *
 * 6. Zephyr
 *    - Detection: k_thread_create, k_sleep
 *    - Structures: struct k_thread
 *
 * ============================================================================
 * DETECTION STRATEGY
 * ============================================================================
 *
 * 1. Symbol Search: Look for RTOS-specific function names
 * 2. String Search: Find RTOS-specific string constants
 * 3. Pattern Match: Identify characteristic code patterns
 * 4. Structure Heuristics: Find data structures by layout
 *
 * ============================================================================
 */

#pragma once

#include "binaryninjaapi.h"

#include <optional>
#include <string>
#include <vector>

namespace armv5 {

/**
 * Detected RTOS type.
 */
enum class RTOSType {
	Unknown,
	FreeRTOS,
	ThreadX,
	NucleusPLUS,    // Full commercial Nucleus RTOS
	NucleusSE,      // Simplified embedded Nucleus
	UCOSII,         // uC/OS-II
	UCOSIII,        // uC/OS-III
	Zephyr,
	NuttX,
	ChibiOS,
	RTXCMSIS        // Keil RTX / CMSIS-RTOS
};

/**
 * Convert RTOS type to human-readable string.
 */
const char* RTOSTypeToString(RTOSType type);

/**
 * Detected task/thread information.
 */
struct RTOSTask {
	uint64_t tcbAddress;       // Address of task control block
	uint64_t entryPoint;       // Task entry function address
	std::string taskName;      // Task name (if available)
	uint32_t priority;         // Task priority
	uint64_t stackStart;       // Stack start address
	uint64_t stackSize;        // Stack size in bytes
	uint32_t taskId;           // Task ID or index
	bool isIdleTask;           // True if this is the idle task
	bool isTimerTask;          // True if this is a timer service task
};

/**
 * RTOS detection result.
 */
struct RTOSDetectionResult {
	RTOSType type = RTOSType::Unknown;
	uint8_t confidence = 0;              // 0-255
	std::string version;                 // Version string if detected
	std::vector<RTOSTask> tasks;         // Detected tasks
	std::vector<uint64_t> apiAddresses;  // RTOS API function addresses
	std::string reason;                  // Detection reason
};

/**
 * RTOS Detector
 *
 * Detects the RTOS type and extracts task information from firmware binaries.
 */
class RTOSDetector {
public:
	/**
	 * Detect which RTOS (if any) is present in the binary.
	 *
	 * @param view The binary view to analyze.
	 * @return Detection result with RTOS type and confidence.
	 */
	static RTOSDetectionResult DetectRTOS(BinaryNinja::BinaryView* view);

	/**
	 * Find all tasks/threads in the binary.
	 *
	 * @param view The binary view.
	 * @param type The detected RTOS type.
	 * @return Vector of detected tasks.
	 */
	static std::vector<RTOSTask> FindTasks(
		BinaryNinja::BinaryView* view,
		RTOSType type);

	/**
	 * Apply task-entry calling convention to detected task functions.
	 *
	 * @param view  The binary view.
	 * @param tasks The detected tasks.
	 */
	static void ApplyTaskConventions(
		BinaryNinja::BinaryView* view,
		const std::vector<RTOSTask>& tasks);

	/**
	 * Define RTOS-specific types in the binary view.
	 *
	 * @param view The binary view.
	 * @param type The RTOS type.
	 */
	static void DefineRTOSTypes(
		BinaryNinja::BinaryView* view,
		RTOSType type);

	/**
	 * Apply detected type to task control block addresses.
	 *
	 * @param view  The binary view.
	 * @param tasks The detected tasks.
	 * @param type  The RTOS type.
	 */
	static void AnnotateTCBs(
		BinaryNinja::BinaryView* view,
		const std::vector<RTOSTask>& tasks,
		RTOSType type);

private:
	// ========================================================================
	// FreeRTOS Detection
	// ========================================================================

	static bool DetectFreeRTOS(BinaryNinja::BinaryView* view);
	static std::vector<RTOSTask> FindFreeRTOSTasks(BinaryNinja::BinaryView* view);
	static void DefineFreeRTOSTypes(BinaryNinja::BinaryView* view);

	// ========================================================================
	// ThreadX Detection
	// ========================================================================

	static bool DetectThreadX(BinaryNinja::BinaryView* view);
	static std::vector<RTOSTask> FindThreadXTasks(BinaryNinja::BinaryView* view);
	static void DefineThreadXTypes(BinaryNinja::BinaryView* view);

	// ========================================================================
	// Nucleus PLUS Detection
	// ========================================================================

	static bool DetectNucleusPLUS(BinaryNinja::BinaryView* view);
	static std::vector<RTOSTask> FindNucleusPLUSTasks(BinaryNinja::BinaryView* view);
	static void DefineNucleusPLUSTypes(BinaryNinja::BinaryView* view);

	// ========================================================================
	// Nucleus SE Detection
	// ========================================================================

	static bool DetectNucleusSE(BinaryNinja::BinaryView* view);
	static std::vector<RTOSTask> FindNucleusSETasks(BinaryNinja::BinaryView* view);
	static void DefineNucleusSETypes(BinaryNinja::BinaryView* view);

	// ========================================================================
	// uC/OS-II Detection
	// ========================================================================

	static bool DetectUCOSII(BinaryNinja::BinaryView* view);
	static std::vector<RTOSTask> FindUCOSIITasks(BinaryNinja::BinaryView* view);
	static void DefineUCOSIITypes(BinaryNinja::BinaryView* view);

	// ========================================================================
	// Zephyr Detection
	// ========================================================================

	static bool DetectZephyr(BinaryNinja::BinaryView* view);
	static std::vector<RTOSTask> FindZephyrTasks(BinaryNinja::BinaryView* view);
	static void DefineZephyrTypes(BinaryNinja::BinaryView* view);

	// ========================================================================
	// Helper Methods
	// ========================================================================

	/**
	 * Search for symbols matching a pattern.
	 */
	static std::vector<BinaryNinja::Ref<BinaryNinja::Symbol>> FindSymbolsMatching(
		BinaryNinja::BinaryView* view,
		const std::vector<std::string>& patterns);

	/**
	 * Search for strings matching a pattern.
	 */
	static std::vector<uint64_t> FindStringsMatching(
		BinaryNinja::BinaryView* view,
		const std::vector<std::string>& patterns);

	/**
	 * Check if an address appears to be a task entry function.
	 *
	 * Criteria: Contains infinite loop, calls delay function
	 */
	static bool IsTaskEntryFunction(
		BinaryNinja::BinaryView* view,
		uint64_t address);
};

} // namespace armv5
