/*
 * ARMv5 Firmware Workflow Registration
 */

#include "firmware_workflow.h"
#include "firmware/firmware_view.h"
#include "settings/plugin_settings.h"
#include "settings/env_config.h"

#include <exception>
#include <string>

using namespace BinaryNinja;
using namespace std;

static Ref<Logger> GetFirmwareWorkflowLogger()
{
	return LogRegistry::CreateLogger("BinaryView.ARMv5FirmwareView");
}

static bool FirmwareWorkflowDisabledByEnv()
{
	// Check for skip tokens in the disable scans env var
	const char* disableScans = Armv5EnvConfig::GetEnv(Armv5EnvConfig::kDisableScans);
	if (!disableScans || disableScans[0] == '\0')
		return false;

	auto tokens = Armv5EnvConfig::ParseTokenList(disableScans);
	for (const auto& raw : tokens)
	{
		auto token = Armv5EnvConfig::NormalizeToken(raw);
		if (token == "all" || token == "skip" || token == "skip_scans" || token == "skip_firmware_scans")
			return true;
	}
	return false;
}

static void RunArmv5FirmwareWorkflow(const Ref<AnalysisContext>& analysisContext)
{
	if (BNIsShutdownRequested())
		return;

	if (Armv5Settings::PluginConfig::Get().AreAllScansDisabled())
		return;

	auto logger = GetFirmwareWorkflowLogger();
	if (logger)
		logger->LogInfo("RunArmv5FirmwareWorkflow: called");

	if (!analysisContext)
	{
		if (logger)
			logger->LogInfo("RunArmv5FirmwareWorkflow: no analysis context, returning");
		return;
	}
	auto view = analysisContext->GetBinaryView();
	if (!view)
	{
		if (logger)
			logger->LogInfo("RunArmv5FirmwareWorkflow: no view, returning");
		return;
	}
	if (!view->GetObject())
	{
		if (logger)
			logger->LogInfo("RunArmv5FirmwareWorkflow: view has no object, returning");
		return;
	}
	if (logger)
		logger->LogInfo("RunArmv5FirmwareWorkflow: view type = %s", view->GetTypeName().c_str());
	if (view->GetTypeName() != "ARMv5 Firmware")
		return;
	
	if (IsFirmwareViewClosing(view.GetPtr()))
	{
		if (logger)
			logger->LogInfo("RunArmv5FirmwareWorkflow: view closing, returning");
		return;
	}
	Armv5FirmwareView* firmwareView = dynamic_cast<Armv5FirmwareView*>(view.GetPtr());
	if (firmwareView && firmwareView->IsParseOnly())
	{
		if (logger)
			logger->LogInfo("RunArmv5FirmwareWorkflow: parse-only view, returning");
		return;
	}
	if (FirmwareWorkflowDisabledByEnv())
	{
		if (logger)
			logger->LogInfo("RunArmv5FirmwareWorkflow: disabled by env, returning");
		return;
	}
	if (logger)
		logger->LogInfo("RunArmv5FirmwareWorkflow: calling RunArmv5FirmwareWorkflowScans");
	try
	{
		RunArmv5FirmwareWorkflowScans(view);
	}
	catch (std::exception& e)
	{
		LogErrorForException(e, "Armv5 Firmware Workflow failed with uncaught exception: %s", e.what());
	}
	if (logger)
		logger->LogInfo("RunArmv5FirmwareWorkflow: done");
}

void BinaryNinja::RegisterArmv5FirmwareWorkflow()
{
	auto logger = GetFirmwareWorkflowLogger();

	// Check workflow disable via singleton (which caches the env var at startup)
	if (Armv5Settings::PluginConfig::Get().IsWorkflowDisabled())
	{
		if (logger)
			logger->LogInfo("ARMv5 firmware workflow disabled via BN_ARMV5_DISABLE_WORKFLOW");
		return;
	}

	// Register a module workflow activity that runs ARMv5 firmware scans alongside core analysis.
	// Clone the metaAnalysis workflow WITHOUT a name (like RTTI plugin does).
	// This creates a new workflow that gets registered alongside the default.
	// The activity will run for all binaries but we filter by view type in the callback.
	Ref<Workflow> metaWorkflow = Workflow::Get("core.module.metaAnalysis");
	if (!metaWorkflow)
	{
		if (logger)
			logger->LogError("RegisterArmv5FirmwareWorkflow: failed to get core.module.metaAnalysis");
		return;
	}
	if (logger)
		logger->LogInfo("RegisterArmv5FirmwareWorkflow: got metaAnalysis workflow");

	Ref<Workflow> firmwareWorkflow = metaWorkflow->Clone();
	if (!firmwareWorkflow)
	{
		if (logger)
			logger->LogError("RegisterArmv5FirmwareWorkflow: failed to clone workflow");
		return;
	}
	if (logger)
		logger->LogInfo("RegisterArmv5FirmwareWorkflow: cloned workflow, name = %s", firmwareWorkflow->GetName().c_str());

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
	{
		if (logger)
			logger->LogError("RegisterArmv5FirmwareWorkflow: failed to register activity");
		return;
	}
	if (logger)
		logger->LogInfo("RegisterArmv5FirmwareWorkflow: registered activity");

	// Insert before loadDebugInfo (like RTTI does with rttiAnalysis)
	bool inserted = firmwareWorkflow->InsertAfter("core.module.extendedAnalysis", "analysis.armv5.firmwareScan");
	if (!inserted)
	{
		// Fallback for older API versions or different workflow structures
		if (logger)
			logger->LogInfo("RegisterArmv5FirmwareWorkflow: failed to insert after core.module.extendedAnalysis, trying core.module.analysis");
		inserted = firmwareWorkflow->InsertAfter("core.module.analysis", "analysis.armv5.firmwareScan");
	}
	
	if (logger)
		logger->LogInfo("RegisterArmv5FirmwareWorkflow: Insert returned %s", inserted ? "true" : "false");

	bool registered = Workflow::RegisterWorkflow(firmwareWorkflow);
	if (logger)
		logger->LogInfo("RegisterArmv5FirmwareWorkflow: RegisterWorkflow returned %s", registered ? "true" : "false");
}
