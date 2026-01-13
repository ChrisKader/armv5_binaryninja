/*
 * ARMv5 Firmware Workflow Registration
 */

#include "firmware_workflow.h"
#include "firmware/firmware_view.h"

#include <cctype>
#include <cstdlib>
#include <exception>
#include <string>

using namespace BinaryNinja;
using namespace std;

static bool FirmwareWorkflowDisabledByEnv()
{
	const char* disableScans = getenv("BN_ARMV5_FIRMWARE_DISABLE_SCANS");
	if (!disableScans || disableScans[0] == '\0')
		return false;
	string token;
	auto checkToken = [&](const string& raw) -> bool {
		if (raw.empty())
			return false;
		string normalized;
		normalized.reserve(raw.size());
		for (char ch : raw)
		{
			if (ch == '-')
				ch = '_';
			normalized.push_back(static_cast<char>(tolower(static_cast<unsigned char>(ch))));
		}
		return (normalized == "all" || normalized == "skip" || normalized == "skip_scans"
			|| normalized == "skip_firmware_scans");
	};
	for (const char* p = disableScans; *p; ++p)
	{
		char c = *p;
		if (c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
		{
			if (checkToken(token))
				return true;
			token.clear();
			continue;
		}
		token.push_back(c);
	}
	return checkToken(token);
}

static void RunArmv5FirmwareWorkflow(const Ref<AnalysisContext>& analysisContext)
{
	LogInfo("RunArmv5FirmwareWorkflow: called");
	if (BNIsShutdownRequested())
	{
		LogInfo("RunArmv5FirmwareWorkflow: shutdown requested, returning");
		return;
	}
	if (!analysisContext)
	{
		LogInfo("RunArmv5FirmwareWorkflow: no analysis context, returning");
		return;
	}
	auto view = analysisContext->GetBinaryView();
	if (!view)
	{
		LogInfo("RunArmv5FirmwareWorkflow: no view, returning");
		return;
	}
	if (!view->GetObject())
	{
		LogInfo("RunArmv5FirmwareWorkflow: view has no object, returning");
		return;
	}
	LogInfo("RunArmv5FirmwareWorkflow: view type = %s", view->GetTypeName().c_str());
	if (view->GetTypeName() != "ARMv5 Firmware")
		return;
	if (IsFirmwareViewClosing(view.GetPtr()))
	{
		LogInfo("RunArmv5FirmwareWorkflow: view closing, returning");
		return;
	}
	if (FirmwareWorkflowDisabledByEnv())
	{
		LogInfo("RunArmv5FirmwareWorkflow: disabled by env, returning");
		return;
	}

	LogInfo("RunArmv5FirmwareWorkflow: calling RunArmv5FirmwareWorkflowScans");
	try
	{
		RunArmv5FirmwareWorkflowScans(view);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "Armv5 Firmware Workflow failed with uncaught exception: %s", e.what());
	}
	LogInfo("RunArmv5FirmwareWorkflow: done");
}

static bool Armv5FirmwareWorkflowEligible(Ref<Activity>, Ref<AnalysisContext> analysisContext)
{
	if (BNIsShutdownRequested())
		return false;
	if (!analysisContext)
		return false;
	auto view = analysisContext->GetBinaryView();
	if (!view || !view->GetObject())
		return false;
	if (view->GetTypeName() != "ARMv5 Firmware")
		return false;
	if (IsFirmwareViewClosing(view.GetPtr()))
		return false;
	if (FirmwareWorkflowDisabledByEnv())
		return false;
	return true;
}

void BinaryNinja::RegisterArmv5FirmwareWorkflow()
{
	const char* disableWorkflow = getenv("BN_ARMV5_DISABLE_WORKFLOW");
	if (disableWorkflow && disableWorkflow[0] != '\0')
	{
		LogInfo("ARMv5 firmware workflow disabled via BN_ARMV5_DISABLE_WORKFLOW");
		return;
	}

	// Register a module workflow activity that runs ARMv5 firmware scans alongside core analysis.
	// Clone the metaAnalysis workflow WITHOUT a name (like RTTI plugin does).
	// This creates a new workflow that gets registered alongside the default.
	// The activity will run for all binaries but we filter by view type in the callback.
	Ref<Workflow> metaWorkflow = Workflow::Get("core.module.metaAnalysis");
	if (!metaWorkflow)
	{
		LogError("RegisterArmv5FirmwareWorkflow: failed to get core.module.metaAnalysis");
		return;
	}
	LogInfo("RegisterArmv5FirmwareWorkflow: got metaAnalysis workflow");

	Ref<Workflow> firmwareWorkflow = metaWorkflow->Clone();
	if (!firmwareWorkflow)
	{
		LogError("RegisterArmv5FirmwareWorkflow: failed to clone workflow");
		return;
	}
	LogInfo("RegisterArmv5FirmwareWorkflow: cloned workflow, name = %s", firmwareWorkflow->GetName().c_str());

	Ref<Activity> activity = firmwareWorkflow->RegisterActivity(new Activity(R"~({
		"title": "ARMv5 Firmware Scan",
		"name": "analysis.armv5.firmwareScan",
		"role": "action",
		"description": "Run ARMv5 firmware discovery passes (prologue/call/pointer/orphan scans and cleanup).",
		"eligibility": {
			"runOnce": true,
			"auto": {}
		},
		"dependencies": {
				"downstream": ["core.module.update"]
			}
	})~",
																																					 &RunArmv5FirmwareWorkflow, &Armv5FirmwareWorkflowEligible));
	if (!activity)
	{
		LogError("RegisterArmv5FirmwareWorkflow: failed to register activity");
		return;
	}
	LogInfo("RegisterArmv5FirmwareWorkflow: registered activity");

	// Insert before loadDebugInfo (like RTTI does with rttiAnalysis)
	bool inserted = firmwareWorkflow->InsertAfter("core.module.extendedAnalysis", "analysis.armv5.firmwareScan");
	LogInfo("RegisterArmv5FirmwareWorkflow: Insert returned %s", inserted ? "true" : "false");

	bool registered = Workflow::RegisterWorkflow(firmwareWorkflow);
	LogInfo("RegisterArmv5FirmwareWorkflow: RegisterWorkflow returned %s", registered ? "true" : "false");
}
