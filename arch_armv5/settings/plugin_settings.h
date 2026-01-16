/*
 * ARMv5 Plugin Settings
 *
 * Centralized settings infrastructure with component registration.
 * Components register under the plugin prefix and define their own settings.
 */

#pragma once

#include "binaryninjaapi.h"

#include <memory>
#include <string>

namespace Armv5Settings
{

// Base plugin key prefix - all component settings are under this
constexpr const char* kPluginPrefix = "loader.armv5.";

// Standard loader keys (not under our prefix)
constexpr const char* kImageBase = "loader.imageBase";
constexpr const char* kPlatform = "loader.platform";

/*
 * SettingsComponent - represents a registered component under the plugin prefix.
 *
 * Usage:
 *   auto firmware = Armv5Settings::RegisterComponent("firmware");
 *   firmware->RegisterBool(settings, "scanPrologues", true, "Title", "Description");
 *   // Registers key: "loader.armv5.firmware.scanPrologues"
 */
class SettingsComponent
{
public:
	explicit SettingsComponent(const std::string& name);

	// Get the component name (e.g., "firmware")
	const std::string& GetName() const { return m_name; }

	// Get the full prefix for this component (e.g., "loader.armv5.firmware.")
	const std::string& GetPrefix() const { return m_prefix; }

	// Build a full key for a setting under this component
	std::string GetKey(const char* setting) const;

	// Register a boolean setting
	void RegisterBool(const BinaryNinja::Ref<BinaryNinja::Settings>& settings,
		const char* name, bool defaultValue, const char* title, const char* description);

	// Register a number setting with min/max
	void RegisterNumber(const BinaryNinja::Ref<BinaryNinja::Settings>& settings,
		const char* name, uint64_t defaultValue, uint64_t min, uint64_t max,
		const char* title, const char* description);

private:
	std::string m_name;
	std::string m_prefix;
};

// Register a new component under the plugin prefix.
// Returns existing component if already registered.
std::shared_ptr<SettingsComponent> RegisterComponent(const std::string& name);

// Get an existing component by name (returns nullptr if not found)
std::shared_ptr<SettingsComponent> GetComponent(const std::string& name);

// Initialize the plugin settings system (called from CorePluginInit)
void InitPluginSettings();

// Register analysis-specific settings (calling conventions, signatures, RTOS)
void RegisterAnalysisSettings();

// Register global firmware settings in the Settings panel
void RegisterGlobalFirmwareSettings();

/*
 * PluginConfig - singleton for cached environment variable state.
 *
 * Environment variables are parsed once at initialization and cached.
 */
class PluginConfig
{
public:
	static PluginConfig& Get();

	// Check if the firmware workflow is disabled via BN_ARMV5_DISABLE_WORKFLOW
	bool IsWorkflowDisabled() const { return m_workflowDisabled; }

	// Check if all firmware scans are disabled
	bool AreAllScansDisabled() const { return m_allScansDisabled; }

	// Get the raw disable scans env value (for token parsing by components)
	const char* GetDisableScansEnv() const { return m_disableScansEnv; }

private:
	PluginConfig();

	bool m_workflowDisabled;
	bool m_allScansDisabled;
	const char* m_disableScansEnv;
};

}
