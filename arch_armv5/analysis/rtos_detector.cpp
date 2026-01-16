/*
 * ARMv5 RTOS Detector Implementation
 *
 * Detects common embedded RTOS and extracts task/thread information.
 */

#include "rtos_detector.h"

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

// ============================================================================
// RTOS Signature Strings
// ============================================================================

/*
 * FreeRTOS detection patterns
 */
static const std::vector<std::string> kFreeRTOSSymbols = {
	"xTaskCreate",
	"xTaskCreateStatic",
	"vTaskDelay",
	"vTaskDelayUntil",
	"vTaskStartScheduler",
	"pxCurrentTCB",
	"xQueueCreate",
	"xSemaphoreCreateMutex"
};

static const std::vector<std::string> kFreeRTOSStrings = {
	"IDLE",
	"Tmr Svc",
	"FreeRTOS"
};

/*
 * ThreadX detection patterns
 */
static const std::vector<std::string> kThreadXSymbols = {
	"tx_thread_create",
	"tx_thread_sleep",
	"tx_thread_suspend",
	"_tx_timer_thread",
	"_tx_thread_execute_ptr",
	"tx_queue_create",
	"tx_semaphore_create"
};

static const std::vector<std::string> kThreadXStrings = {
	"TX_THREAD",
	"ThreadX"
};

/*
 * Nucleus PLUS detection patterns
 */
static const std::vector<std::string> kNucleusPLUSSymbols = {
	"NU_Create_Task",
	"NU_Delete_Task",
	"NU_Resume_Task",
	"NU_Suspend_Task",
	"NU_Sleep",
	"NU_Change_Priority",
	"NU_Task_Information",
	"NU_Create_Queue",
	"NU_Create_Semaphore"
};

static const std::vector<std::string> kNucleusPLUSStrings = {
	"Nucleus",
	"NU_TASK"
};

/*
 * Nucleus SE detection patterns
 */
static const std::vector<std::string> kNucleusSESymbols = {
	"NUSE_Task_Start_Address",
	"NUSE_Task_Stack_Base",
	"NUSE_Task_Stack_Size",
	"NUSE_Task_Context",
	"NUSE_Task_Status",
	"NUSE_Scheduler",
	"NUSE_Init_Task"
};

static const std::vector<std::string> kNucleusSEStrings = {
	"NUSE_"
};

/*
 * uC/OS-II detection patterns
 */
static const std::vector<std::string> kUCOSIISymbols = {
	"OSTaskCreate",
	"OSTaskCreateExt",
	"OSTimeDly",
	"OSTimeDlyHMSM",
	"OSTCBCur",
	"OSTCBHighRdy",
	"OSStart",
	"OSQCreate",
	"OSSemCreate"
};

static const std::vector<std::string> kUCOSIIStrings = {
	"OS_TCB",
	"uC/OS"
};

/*
 * Zephyr detection patterns
 */
static const std::vector<std::string> kZephyrSymbols = {
	"k_thread_create",
	"k_sleep",
	"k_msleep",
	"k_thread_start",
	"_kernel",
	"k_queue_init",
	"k_sem_init"
};

static const std::vector<std::string> kZephyrStrings = {
	"Zephyr",
	"k_thread"
};

// ============================================================================
// Utility Functions
// ============================================================================

const char* armv5::RTOSTypeToString(RTOSType type)
{
	switch (type)
	{
	case RTOSType::FreeRTOS:     return "FreeRTOS";
	case RTOSType::ThreadX:     return "ThreadX";
	case RTOSType::NucleusPLUS: return "Nucleus PLUS";
	case RTOSType::NucleusSE:   return "Nucleus SE";
	case RTOSType::UCOSII:      return "uC/OS-II";
	case RTOSType::UCOSIII:     return "uC/OS-III";
	case RTOSType::Zephyr:      return "Zephyr";
	case RTOSType::NuttX:       return "NuttX";
	case RTOSType::ChibiOS:     return "ChibiOS";
	case RTOSType::RTXCMSIS:    return "RTX/CMSIS-RTOS";
	default:                    return "Unknown";
	}
}

static bool ContainsPatternCaseInsensitive(const std::string& str, const std::string& pattern)
{
	std::string lowerStr = str;
	std::string lowerPattern = pattern;
	std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
	std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);
	return lowerStr.find(lowerPattern) != std::string::npos;
}

// ============================================================================
// Main Detection Entry Point
// ============================================================================

RTOSDetectionResult RTOSDetector::DetectRTOS(BinaryView* view)
{
	RTOSDetectionResult result;
	result.type = RTOSType::Unknown;
	result.confidence = 0;

	if (!view)
		return result;

	// Try each RTOS detector in order of specificity
	// Nucleus SE before PLUS (SE is more specific)

	Ref<Logger> logger = GetAnalysisLogger();

	if (DetectNucleusSE(view))
	{
		result.type = RTOSType::NucleusSE;
		result.confidence = 200;
		result.reason = "Detected Nucleus SE symbols (NUSE_Task_*)";
		result.tasks = FindNucleusSETasks(view);
		if (logger)
			logger->LogInfo("RTOSDetector: Detected %s (%zu tasks)", RTOSTypeToString(result.type), result.tasks.size());
		return result;
	}

	if (DetectNucleusPLUS(view))
	{
		result.type = RTOSType::NucleusPLUS;
		result.confidence = 200;
		result.reason = "Detected Nucleus PLUS symbols (NU_Create_Task, etc.)";
		result.tasks = FindNucleusPLUSTasks(view);
		if (logger)
			logger->LogInfo("RTOSDetector: Detected %s (%zu tasks)", RTOSTypeToString(result.type), result.tasks.size());
		return result;
	}

	if (DetectFreeRTOS(view))
	{
		result.type = RTOSType::FreeRTOS;
		result.confidence = 200;
		result.reason = "Detected FreeRTOS symbols (xTaskCreate, vTaskDelay)";
		result.tasks = FindFreeRTOSTasks(view);
		if (logger)
			logger->LogInfo("RTOSDetector: Detected %s (%zu tasks)", RTOSTypeToString(result.type), result.tasks.size());
		return result;
	}

	if (DetectThreadX(view))
	{
		result.type = RTOSType::ThreadX;
		result.confidence = 200;
		result.reason = "Detected ThreadX symbols (tx_thread_create)";
		result.tasks = FindThreadXTasks(view);
		if (logger)
			logger->LogInfo("RTOSDetector: Detected %s (%zu tasks)", RTOSTypeToString(result.type), result.tasks.size());
		return result;
	}

	if (DetectUCOSII(view))
	{
		result.type = RTOSType::UCOSII;
		result.confidence = 200;
		result.reason = "Detected uC/OS-II symbols (OSTaskCreate)";
		result.tasks = FindUCOSIITasks(view);
		if (logger)
			logger->LogInfo("RTOSDetector: Detected %s (%zu tasks)", RTOSTypeToString(result.type), result.tasks.size());
		return result;
	}

	if (DetectZephyr(view))
	{
		result.type = RTOSType::Zephyr;
		result.confidence = 200;
		result.reason = "Detected Zephyr symbols (k_thread_create)";
		result.tasks = FindZephyrTasks(view);
		if (logger)
			logger->LogInfo("RTOSDetector: Detected %s (%zu tasks)", RTOSTypeToString(result.type), result.tasks.size());
		return result;
	}

	if (logger)
		logger->LogDebug("RTOSDetector: No RTOS detected");

	return result;
}

// ============================================================================
// Task Finding
// ============================================================================

std::vector<RTOSTask> RTOSDetector::FindTasks(BinaryView* view, RTOSType type)
{
	if (!view)
		return {};

	switch (type)
	{
	case RTOSType::FreeRTOS:     return FindFreeRTOSTasks(view);
	case RTOSType::ThreadX:     return FindThreadXTasks(view);
	case RTOSType::NucleusPLUS: return FindNucleusPLUSTasks(view);
	case RTOSType::NucleusSE:   return FindNucleusSETasks(view);
	case RTOSType::UCOSII:      return FindUCOSIITasks(view);
	case RTOSType::Zephyr:      return FindZephyrTasks(view);
	default:                    return {};
	}
}

void RTOSDetector::ApplyTaskConventions(
	BinaryView* view,
	const std::vector<RTOSTask>& tasks)
{
	if (!view)
		return;

	Ref<Architecture> arch = view->GetDefaultArchitecture();
	if (!arch)
		return;

	// Get task-entry calling convention
	Ref<CallingConvention> taskConv;
	for (const auto& conv : arch->GetCallingConventions())
	{
		if (conv->GetName() == "task-entry")
		{
			taskConv = conv;
			break;
		}
	}

	if (!taskConv)
		return;

	for (const auto& task : tasks)
	{
		if (task.entryPoint == 0)
			continue;

		Ref<Function> func = view->GetAnalysisFunction(
			view->GetDefaultPlatform(), task.entryPoint);

		if (!func)
			continue;

		// Apply task-entry calling convention
		func->SetAutoCallingConvention(
			Confidence<Ref<CallingConvention>>(taskConv, 200));

		// Set function name if we have a task name
		if (!task.taskName.empty())
		{
			std::string name = "task_" + task.taskName;
			view->DefineAutoSymbol(new Symbol(FunctionSymbol, name, task.entryPoint));
		}
	}
}

void RTOSDetector::DefineRTOSTypes(BinaryView* view, RTOSType type)
{
	if (!view)
		return;

	switch (type)
	{
	case RTOSType::FreeRTOS:     DefineFreeRTOSTypes(view); break;
	case RTOSType::ThreadX:     DefineThreadXTypes(view); break;
	case RTOSType::NucleusPLUS: DefineNucleusPLUSTypes(view); break;
	case RTOSType::NucleusSE:   DefineNucleusSETypes(view); break;
	case RTOSType::UCOSII:      DefineUCOSIITypes(view); break;
	case RTOSType::Zephyr:      DefineZephyrTypes(view); break;
	default: break;
	}
}

void RTOSDetector::AnnotateTCBs(
	BinaryView* view,
	const std::vector<RTOSTask>& tasks,
	RTOSType type)
{
	if (!view)
		return;

	std::string tcbTypeName;
	switch (type)
	{
	case RTOSType::FreeRTOS:     tcbTypeName = "tskTCB"; break;
	case RTOSType::ThreadX:     tcbTypeName = "TX_THREAD"; break;
	case RTOSType::NucleusPLUS: tcbTypeName = "NU_TASK"; break;
	case RTOSType::UCOSII:      tcbTypeName = "OS_TCB"; break;
	case RTOSType::Zephyr:      tcbTypeName = "k_thread"; break;
	default: return;
	}

	// Get the TCB type
	auto types = view->GetTypeByName(tcbTypeName);
	if (!types)
		return;

	for (const auto& task : tasks)
	{
		if (task.tcbAddress == 0)
			continue;

		// Apply TCB type at the address
		view->DefineDataVariable(task.tcbAddress, Confidence<Ref<Type>>(types, 200));

		// Create symbol for the TCB
		std::string symName = "tcb_" + (task.taskName.empty() ?
			std::to_string(task.taskId) : task.taskName);
		view->DefineAutoSymbol(new Symbol(DataSymbol, symName, task.tcbAddress));
	}
}

// ============================================================================
// FreeRTOS Detection and Type Definitions
// ============================================================================

bool RTOSDetector::DetectFreeRTOS(BinaryView* view)
{
	auto symbols = FindSymbolsMatching(view, kFreeRTOSSymbols);
	if (symbols.size() >= 2)
		return true;

	auto strings = FindStringsMatching(view, kFreeRTOSStrings);
	return strings.size() >= 1 && symbols.size() >= 1;
}

std::vector<RTOSTask> RTOSDetector::FindFreeRTOSTasks(BinaryView* view)
{
	std::vector<RTOSTask> tasks;

	// Find xTaskCreate calls and extract task entry points
	auto symbols = view->GetSymbolsByName("xTaskCreate");
	for (const auto& sym : symbols)
	{
		// Find callers and extract first argument (task entry)
		auto refs = view->GetCodeReferences(sym->GetAddress());
		for (const auto& ref : refs)
		{
			// Would need to analyze call site to extract arguments
			// For now, just note that we found a task creation call
		}
	}

	// Look for pxCurrentTCB to find the current task
	auto currentTCB = view->GetSymbolsByName("pxCurrentTCB");
	if (!currentTCB.empty())
	{
		// pxCurrentTCB points to current task's TCB
	}

	return tasks;
}

/*
 * Helper function to parse type definitions and add them to the view.
 */
static void ParseAndDefineTypes(BinaryView* view, const std::string& source, const std::string& fileName)
{
	if (!view)
		return;

	Ref<Platform> platform = view->GetDefaultPlatform();
	if (!platform)
		return;

	std::map<QualifiedName, Ref<Type>> types;
	std::map<QualifiedName, Ref<Type>> variables;
	std::map<QualifiedName, Ref<Type>> functions;
	std::string errors;

	bool success = platform->ParseTypesFromSource(
		source,
		fileName,
		types,
		variables,
		functions,
		errors);

	if (!success)
	{
		LogError("Failed to parse %s: %s", fileName.c_str(), errors.c_str());
		return;
	}

	for (const auto& [name, type] : types)
	{
		view->DefineUserType(name, type);
	}
}

void RTOSDetector::DefineFreeRTOSTypes(BinaryView* view)
{
	// Define ListItem_t
	std::string listItemDef = R"(
struct ListItem_t {
    uint32_t xItemValue;
    struct ListItem_t* pxNext;
    struct ListItem_t* pxPrevious;
    void* pvOwner;
    void* pvContainer;
};
)";

	// Define List_t
	std::string listDef = R"(
struct List_t {
    uint32_t uxNumberOfItems;
    struct ListItem_t* pxIndex;
    struct ListItem_t xListEnd;
};
)";

	// Define tskTCB (Task Control Block)
	std::string tcbDef = R"(
struct tskTCB {
    uint32_t* pxTopOfStack;
    struct ListItem_t xGenericListItem;
    struct ListItem_t xEventListItem;
    uint32_t uxPriority;
    uint32_t* pxStack;
    char pcTaskName[16];
    uint32_t uxBasePriority;
    uint32_t uxMutexesHeld;
};
)";

	ParseAndDefineTypes(view, listItemDef + listDef + tcbDef, "freertos_types.h");
}

// ============================================================================
// ThreadX Detection and Type Definitions
// ============================================================================

bool RTOSDetector::DetectThreadX(BinaryView* view)
{
	auto symbols = FindSymbolsMatching(view, kThreadXSymbols);
	return symbols.size() >= 2;
}

std::vector<RTOSTask> RTOSDetector::FindThreadXTasks(BinaryView* view)
{
	std::vector<RTOSTask> tasks;
	// Implementation similar to FreeRTOS
	return tasks;
}

void RTOSDetector::DefineThreadXTypes(BinaryView* view)
{
	std::string txThreadDef = R"(
struct TX_THREAD {
    uint32_t tx_thread_id;
    uint32_t tx_thread_run_count;
    void* tx_thread_stack_ptr;
    void* tx_thread_stack_start;
    void* tx_thread_stack_end;
    uint32_t tx_thread_stack_size;
    uint32_t tx_thread_priority;
    uint32_t tx_thread_state;
    uint32_t tx_thread_delayed_suspend;
    uint32_t tx_thread_suspending;
    uint32_t tx_thread_preempt_threshold;
    uint32_t tx_thread_schedule_count;
    uint32_t tx_thread_time_slice;
    uint32_t tx_thread_new_time_slice;
    struct TX_THREAD* tx_thread_created_next;
    struct TX_THREAD* tx_thread_created_previous;
    struct TX_THREAD* tx_thread_ready_next;
    struct TX_THREAD* tx_thread_ready_previous;
    char tx_thread_name[32];
    void (*tx_thread_entry)(uint32_t);
    uint32_t tx_thread_entry_parameter;
};
)";

	ParseAndDefineTypes(view, txThreadDef, "threadx_types.h");
}

// ============================================================================
// Nucleus PLUS Detection and Type Definitions
// ============================================================================

bool RTOSDetector::DetectNucleusPLUS(BinaryView* view)
{
	auto symbols = FindSymbolsMatching(view, kNucleusPLUSSymbols);
	return symbols.size() >= 2;
}

std::vector<RTOSTask> RTOSDetector::FindNucleusPLUSTasks(BinaryView* view)
{
	std::vector<RTOSTask> tasks;

	// Find NU_Create_Task calls
	auto symbols = view->GetSymbolsByName("NU_Create_Task");
	for (const auto& sym : symbols)
	{
		auto refs = view->GetCodeReferences(sym->GetAddress());
		for (const auto& ref : refs)
		{
			// Extract task parameters from call site
			// NU_Create_Task(task, name, entry, argc, argv, stack, stack_size, ...)
		}
	}

	return tasks;
}

void RTOSDetector::DefineNucleusPLUSTypes(BinaryView* view)
{
	// NU_TASK structure based on Nucleus PLUS documentation
	std::string nuTaskDef = R"(
struct NU_TASK {
    // Linked list pointers for kernel queues
    struct NU_TASK* tq_ready_prev;
    struct NU_TASK* tq_ready_next;
    struct NU_TASK* tq_suspended_prev;
    struct NU_TASK* tq_suspended_next;
    struct NU_TASK* tq_created_prev;
    struct NU_TASK* tq_created_next;

    // CPU context (saved registers)
    void* cpu_context;

    // Task identification
    char task_name[8];  // 7 chars + null (NU_MAX_NAME)

    // Entry point and arguments
    void (*task_entry)(uint32_t argc, void* argv);
    uint32_t argc;
    void* argv;

    // Stack management
    void* stack_base;
    uint32_t stack_size;
    uint32_t min_stack_remaining;

    // Scheduling parameters
    uint8_t priority;      // 0-255 (0 = highest)
    uint8_t preempt;       // NU_PREEMPT or NU_NO_PREEMPT
    uint32_t time_slice;   // Ticks (0 = no time slice)

    // Runtime state
    uint8_t task_status;   // READY, SUSPENDED, EXECUTING, etc.
    uint32_t scheduled_count;

    // Signal handling
    uint32_t signal_mask;
    void (*signal_handler)(uint32_t signals);
    uint32_t pending_signals;

    // Timing and blocking
    uint32_t sleep_ticks;
    void* wait_object;

    // Debug ID
    uint32_t task_id;
};
)";

	ParseAndDefineTypes(view, nuTaskDef, "nucleus_plus_types.h");
}

// ============================================================================
// Nucleus SE Detection and Type Definitions
// ============================================================================

bool RTOSDetector::DetectNucleusSE(BinaryView* view)
{
	auto symbols = FindSymbolsMatching(view, kNucleusSESymbols);
	return symbols.size() >= 2;
}

std::vector<RTOSTask> RTOSDetector::FindNucleusSETasks(BinaryView* view)
{
	std::vector<RTOSTask> tasks;

	// Nucleus SE uses static arrays, so we look for the configuration arrays
	auto startAddrs = view->GetSymbolsByName("NUSE_Task_Start_Address");
	auto stackBases = view->GetSymbolsByName("NUSE_Task_Stack_Base");

	if (startAddrs.empty())
		return tasks;

	// Read the start address array to find task entry points
	uint64_t startArrayAddr = startAddrs[0]->GetAddress();

	// Would need to determine array size from NUSE_TASK_NUMBER
	// For now, scan for valid code pointers
	for (size_t i = 0; i < 16; ++i)  // Assume max 16 tasks
	{
		DataBuffer buf = view->ReadBuffer(startArrayAddr + i * 4, 4);
		if (buf.GetLength() < 4)
			break;

		uint32_t entryPoint = *(uint32_t*)buf.GetData();
		if (entryPoint == 0 || entryPoint == 0xFFFFFFFF)
			continue;

		// Check if this looks like a valid code address
		// Look for an existing function or valid segment
		Ref<Segment> seg = view->GetSegmentAt(entryPoint);
		if (!seg)
			continue;
		
		// Check if the segment is executable
		if (!(seg->GetFlags() & SegmentExecutable))
			continue;

		RTOSTask task;
		task.taskId = static_cast<uint32_t>(i);
		task.entryPoint = entryPoint;
		task.taskName = "task_" + std::to_string(i);
		task.tcbAddress = 0;  // No TCB in Nucleus SE (table-based)
		task.priority = 0;
		task.stackStart = 0;
		task.stackSize = 0;
		task.isIdleTask = false;
		task.isTimerTask = false;

		tasks.push_back(task);
	}

	return tasks;
}

void RTOSDetector::DefineNucleusSETypes(BinaryView* view)
{
	// Nucleus SE uses arrays rather than structs
	// Define typedefs for the array element types
	std::string nuclSETypes = R"(
typedef uint32_t NUSE_TaskAddress;
typedef uint32_t NUSE_StackBase;
typedef uint16_t NUSE_StackSize;
typedef uint8_t NUSE_TaskState;
typedef uint8_t NUSE_TaskStatus;
typedef uint8_t NUSE_SignalFlags;
)";

	ParseAndDefineTypes(view, nuclSETypes, "nucleus_se_types.h");
}

// ============================================================================
// uC/OS-II Detection and Type Definitions
// ============================================================================

bool RTOSDetector::DetectUCOSII(BinaryView* view)
{
	auto symbols = FindSymbolsMatching(view, kUCOSIISymbols);
	return symbols.size() >= 2;
}

std::vector<RTOSTask> RTOSDetector::FindUCOSIITasks(BinaryView* view)
{
	std::vector<RTOSTask> tasks;
	// Find OSTaskCreate/OSTaskCreateExt calls
	return tasks;
}

void RTOSDetector::DefineUCOSIITypes(BinaryView* view)
{
	std::string osTcbDef = R"(
struct OS_TCB {
    uint32_t* OSTCBStkPtr;
    void* OSTCBExtPtr;
    uint32_t* OSTCBStkBottom;
    uint32_t OSTCBStkSize;
    uint16_t OSTCBOpt;
    uint16_t OSTCBId;
    struct OS_TCB* OSTCBNext;
    struct OS_TCB* OSTCBPrev;
    void* OSTCBEventPtr;
    void* OSTCBMsg;
    uint16_t OSTCBDly;
    uint8_t OSTCBStat;
    uint8_t OSTCBStatPend;
    uint8_t OSTCBPrio;
    uint8_t OSTCBX;
    uint8_t OSTCBY;
    uint8_t OSTCBBitX;
    uint8_t OSTCBBitY;
    uint8_t OSTCBDelReq;
    uint32_t OSTCBCtxSwCtr;
    uint32_t OSTCBCyclesTot;
    uint32_t OSTCBCyclesStart;
    uint32_t* OSTCBStkBase;
    uint32_t OSTCBStkUsed;
    char OSTCBTaskName[16];
    uint32_t OSTCBRegTbl[8];
};
)";

	ParseAndDefineTypes(view, osTcbDef, "ucos_ii_types.h");
}

// ============================================================================
// Zephyr Detection and Type Definitions
// ============================================================================

bool RTOSDetector::DetectZephyr(BinaryView* view)
{
	auto symbols = FindSymbolsMatching(view, kZephyrSymbols);
	return symbols.size() >= 2;
}

std::vector<RTOSTask> RTOSDetector::FindZephyrTasks(BinaryView* view)
{
	std::vector<RTOSTask> tasks;
	// Find k_thread_create calls
	return tasks;
}

void RTOSDetector::DefineZephyrTypes(BinaryView* view)
{
	std::string kThreadDef = R"(
struct k_thread {
    void* callee_saved;
    void* init_data;
    void* fn_abort;
    void* stack_info_start;
    uint32_t stack_info_size;
    int prio;
    uint32_t sched_locked;
    void* swap_data;
    uint32_t base_order_key;
    void* pended_on;
    struct k_thread* next_thread;
    void* resource_pool;
    char name[32];
};
)";

	ParseAndDefineTypes(view, kThreadDef, "zephyr_types.h");
}

// ============================================================================
// Helper Methods
// ============================================================================

std::vector<Ref<Symbol>> RTOSDetector::FindSymbolsMatching(
	BinaryView* view,
	const std::vector<std::string>& patterns)
{
	std::vector<Ref<Symbol>> result;

	if (!view)
		return result;

	for (const auto& pattern : patterns)
	{
		auto symbols = view->GetSymbolsByName(pattern);
		for (const auto& sym : symbols)
		{
			result.push_back(sym);
		}

		// Also try partial matching via all symbols
		// This is expensive, so only do it if exact match failed
		if (symbols.empty())
		{
			auto allSymbols = view->GetSymbols();
			for (const auto& sym : allSymbols)
			{
				if (ContainsPatternCaseInsensitive(sym->GetShortName(), pattern))
				{
					result.push_back(sym);
				}
			}
		}
	}

	return result;
}

std::vector<uint64_t> RTOSDetector::FindStringsMatching(
	BinaryView* view,
	const std::vector<std::string>& patterns)
{
	std::vector<uint64_t> result;

	if (!view)
		return result;

	auto strings = view->GetStrings();
	for (const auto& strRef : strings)
	{
		// Read the string content from the binary
		DataBuffer buf = view->ReadBuffer(strRef.start, strRef.length);
		if (buf.GetLength() == 0)
			continue;

		// Convert to string (assuming ASCII/UTF-8 for now)
		std::string str(reinterpret_cast<const char*>(buf.GetData()), buf.GetLength());

		for (const auto& pattern : patterns)
		{
			if (ContainsPatternCaseInsensitive(str, pattern))
			{
				result.push_back(strRef.start);
				break;
			}
		}
	}

	return result;
}

bool RTOSDetector::IsTaskEntryFunction(BinaryView* view, uint64_t address)
{
	if (!view)
		return false;

	Ref<Function> func = view->GetAnalysisFunction(
		view->GetDefaultPlatform(), address);

	if (!func)
		return false;

	// Check for infinite loop pattern
	// Check for calls to delay functions

	auto callSites = func->GetCallSites();
	for (const auto& callSite : callSites)
	{
		// Get the call target from the call site
		auto calledFuncs = view->GetAnalysisFunctionsForAddress(callSite.addr);
		for (const auto& calledFunc : calledFuncs)
		{
			Ref<Symbol> sym = calledFunc->GetSymbol();
			if (!sym)
				continue;

			std::string name = sym->GetShortName();
			if (ContainsPatternCaseInsensitive(name, "delay") ||
				ContainsPatternCaseInsensitive(name, "sleep"))
			{
				return true;
			}
		}
	}

	return false;
}
