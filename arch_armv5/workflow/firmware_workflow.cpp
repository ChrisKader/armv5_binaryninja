/*
 * ARMv5 Firmware Workflow Registration
 *
 * ============================================================================
 * WHY USE A WORKFLOW?
 * ============================================================================
 *
 * Binary Ninja workflows provide a structured way to run analysis passes.
 * For firmware analysis, we need to run our custom scans (prologue detection,
 * call target discovery, etc.) at the right point in the analysis pipeline.
 *
 * ALTERNATIVES CONSIDERED:
 * ------------------------
 * 1. BinaryViewType callbacks (Init/PerformLoad):
 *    - Runs too early, before initial analysis completes
 *    - Can't leverage existing function discovery
 *
 * 2. Notification callbacks (OnAnalysisComplete):
 *    - Runs after ALL analysis, may be too late
 *    - No control over ordering with other passes
 *
 * 3. Workflow activities (CHOSEN):
 *    - Runs at a specific point in the pipeline
 *    - Can depend on and trigger other activities
 *    - Proper integration with Binary Ninja's analysis system
 *
 * ============================================================================
 * WORKFLOW STRUCTURE
 * ============================================================================
 *
 * We clone the "core.module.metaAnalysis" workflow and add our activity:
 *
 *   core.module.extendedAnalysis   (built-in)
 *           |
 *           v
 *   analysis.armv5.firmwareScan    <-- OUR ACTIVITY
 *           |
 *           v
 *   core.module.update             (built-in, our downstream dependency)
 *
 * This ensures our scans run after extended analysis (which may have found
 * some functions) but before the final update pass (which finalizes state).
 *
 * ============================================================================
 * LIFETIME SAFETY - CRITICAL
 * ============================================================================
 *
 * Workflow callbacks receive an AnalysisContext. We MUST follow these rules:
 *
 * 1. NEVER store Ref<BinaryView> across callback invocations
 *    - The callback may be invoked multiple times
 *    - Storing extends the view's lifetime beyond user expectations
 *
 * 2. ALWAYS re-acquire the view from AnalysisContext each time
 *    - auto view = analysisContext->GetBinaryView();
 *    - This gets the current, valid reference
 *
 * 3. CHECK for closing before doing work
 *    - IsFirmwareViewClosing(view.GetPtr()) checks if user closed the view
 *    - Without this check, we might operate on a dying view
 *
 * 4. HANDLE exceptions gracefully
 *    - Uncaught exceptions in workflow callbacks can crash Binary Ninja
 *    - Wrap activity code in try/catch
 *
 * REFERENCE: binaryninja-api/workflow.cpp, arch/armv7/arch_armv7.cpp
 */

#include "firmware_workflow.h"
#include "firmware/firmware_view.h"
#include <exception>

using namespace BinaryNinja;

/**
 * Workflow activity callback for ARMv5 firmware analysis.
 *
 * This function is called by Binary Ninja's workflow system when our
 * activity is eligible to run. It performs the firmware scan passes.
 *
 * SAFETY NOTES:
 * - Re-acquires view from context (never cached)
 * - Checks for view closing before work
 * - Catches exceptions to prevent crashes
 *
 * @param analysisContext The analysis context from Binary Ninja.
 */
static void RunArmv5FirmwareWorkflow(const Ref<AnalysisContext>& analysisContext)
{
	/*
	 * Guard 1: Validate analysis context
	 * This should never be null, but defensive programming is good.
	 */
	if (!analysisContext)
		return;

	/*
	 * Guard 2: Re-acquire the BinaryView from context
	 *
	 * IMPORTANT: We get a fresh Ref<BinaryView> each callback invocation.
	 * This is the correct pattern - never store the view across callbacks.
	 */
	auto view = analysisContext->GetBinaryView();
	if (!view)
		return;
	if (!view->GetObject())
		return;

	/*
	 * Guard 3: Check if the view is closing
	 *
	 * The user may have closed the view while waiting for this activity.
	 * IsFirmwareViewClosing() checks our instance tracking system.
	 */
	if (IsFirmwareViewClosing(view.GetPtr()))
		return;

	/*
	 * Run the firmware scans with exception handling.
	 *
	 * Uncaught exceptions in workflow callbacks can crash Binary Ninja.
	 * We catch and log them to prevent data loss.
	 */
	try
	{
		RunArmv5FirmwareWorkflowScans(view);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "Armv5 Firmware Workflow failed with uncaught exception: %s", e.what());
	}
}

/**
 * Register the ARMv5 firmware workflow.
 *
 * Called once at plugin initialization. Creates and registers our
 * custom workflow by cloning and extending the metaAnalysis workflow.
 *
 * WORKFLOW REGISTRATION PROCESS:
 * 1. Get the base metaAnalysis workflow
 * 2. Clone it (so we don't modify the original)
 * 3. Register our activity with eligibility predicates
 * 4. Insert our activity at the right point in the pipeline
 * 5. Register the modified workflow
 */
void BinaryNinja::RegisterArmv5FirmwareWorkflow()
{
	/*
	 * Get the base workflow to extend.
	 * "core.module.metaAnalysis" is the standard module analysis workflow.
	 */
	Ref<Workflow> metaWorkflow = Workflow::Get("core.module.metaAnalysis");
	if (!metaWorkflow)
		return;

	/*
	 * Clone the workflow so we don't modify the shared original.
	 * Our clone will have our activity added.
	 */
	Ref<Workflow> firmwareWorkflow = metaWorkflow->Clone();
	if (!firmwareWorkflow)
		return;

	/*
	 * Register our activity with JSON configuration.
	 *
	 * CONFIGURATION FIELDS:
	 * - title: Human-readable name shown in UI
	 * - name: Unique identifier for the activity
	 * - role: "action" means it performs analysis work
	 * - description: Tooltip/documentation text
	 * - eligibility:
	 *   - runOnce: Only run once per analysis (not on incremental updates)
	 *   - predicates: Conditions for running (only on ARMv5 Firmware views)
	 * - dependencies:
	 *   - downstream: Activities that should run after us
	 */
	Ref<Activity> activity = firmwareWorkflow->RegisterActivity(R"~({
		"title": "ARMv5 Firmware Scan",
		"name": "analysis.armv5.firmwareScan",
		"role": "action",
		"description": "Run ARMv5 firmware discovery passes (prologue/call/pointer/orphan scans and cleanup).",
		"eligibility": {
			"runOnce": false,
			"auto": {},
			"predicates": [
				{
					"type": "viewType",
					"value": ["ARMv5 Firmware"],
					"operator": "in"
				}
			]
		},
		"dependencies": {
			"downstream": ["core.module.loadDebugInfo"]
		}
	})~", &RunArmv5FirmwareWorkflow);
	if (!activity)
		return;

	/*
	 * Insert our activity after extendedAnalysis.
	 *
	 * This means:
	 * 1. Initial analysis and extended analysis run first
	 * 2. Then our firmware scans run
	 * 3. Then the update pass finalizes everything
	 */
	std::vector<std::string> inserted = { "analysis.armv5.firmwareScan" };
	firmwareWorkflow->Insert("core.module.loadDebugInfo", inserted);

	/*
	 * Register the workflow.
	 *
	 * Binary Ninja will use this workflow for views that match our
	 * eligibility predicates (ARMv5 Firmware type).
	 */
	Workflow::RegisterWorkflow(firmwareWorkflow);
}
