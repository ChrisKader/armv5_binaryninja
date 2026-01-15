/*
 * ARMv5 Firmware Workflow Registration
 */

#include "firmware_workflow.h"
#include "firmware/firmware_view.h"
#include <exception>

using namespace BinaryNinja;
using namespace std;

static void RunArmv5FirmwareWorkflow(const Ref<AnalysisContext>& analysisContext)
{
	if (!analysisContext)
		return;
	auto view = analysisContext->GetBinaryView();
	if (!view)
		return;
	if (!view->GetObject())
		return;
	if (IsFirmwareViewClosing(view.GetPtr()))
		return;
	try
	{
		RunArmv5FirmwareWorkflowScans(view);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "Armv5 Firmware Workflow failed with uncaught exception: %s", e.what());
	}
}

void BinaryNinja::RegisterArmv5FirmwareWorkflow()
{
	Ref<Workflow> metaWorkflow = Workflow::Get("core.module.metaAnalysis");
	if (!metaWorkflow)
		return;
	Ref<Workflow> firmwareWorkflow = metaWorkflow->Clone();
	if (!firmwareWorkflow)
		return;
	Ref<Activity> activity = firmwareWorkflow->RegisterActivity(R"~({
		"title": "ARMv5 Firmware Scan",
		"name": "analysis.armv5.firmwareScan",
		"role": "action",
		"description": "Run ARMv5 firmware discovery passes (prologue/call/pointer/orphan scans and cleanup).",
		"eligibility": {
			"runOnce": true,
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
			"downstream": ["core.module.update"]
		}
	})~", &RunArmv5FirmwareWorkflow);
	if (!activity)
		return;
	firmwareWorkflow->InsertAfter("core.module.extendedAnalysis", "analysis.armv5.firmwareScan");
	Workflow::RegisterWorkflow(firmwareWorkflow);
}
