/*
 * ARMv5 Plugin Settings
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This file implements the plugin settings infrastructure. Settings allow
 * users and developers to configure plugin behavior without recompiling.
 *
 * TWO CONFIGURATION SYSTEMS:
 * --------------------------
 *
 * 1. Binary Ninja Settings (UI-configurable):
 *    - Registered via Settings API
 *    - Appear in Binary Ninja's Settings dialog
 *    - Persisted per-project or globally
 *    - Accessed via Settings::Get() at runtime
 *
 * 2. Environment Variables (developer override):
 *    - Parsed at plugin initialization
 *    - Override UI settings when set
 *    - Useful for debugging and CI/testing
 *    - See env_config.h for variable names
 *
 * ============================================================================
 * SETTINGS HIERARCHY
 * ============================================================================
 *
 * Settings are organized by component:
 *
 *   armv5.firmware.* - Firmware analysis settings
 *   armv5.scan.*     - Scan pass configuration
 *   armv5.debug.*    - Debugging/logging options
 *
 * Each setting key follows the pattern:
 *   armv5.<component>.<setting>
 *
 * ============================================================================
 * ENVIRONMENT VARIABLE REFERENCE
 * ============================================================================
 *
 * BN_ARMV5_DISABLE_WORKFLOW
 *   - Disables the firmware workflow entirely
 *   - Set to any non-empty value to enable
 *
 * BN_ARMV5_FIRMWARE_DISABLE_SCANS
 *   - Disables specific scan passes
 *   - Values: "all", "prologue", "calltarget", "pointer", "orphan", "cleanup"
 *   - Comma-separated list supported
 *
 * BN_ARMV5_FIRMWARE_DISABLE_ACTIONS
 *   - Disables specific plan actions (for debugging)
 *   - Values: "all", "add_function", "define_data", "define_symbol", etc.
 *
 * ============================================================================
 * USAGE
 * ============================================================================
 *
 * To disable all firmware scans:
 *   export BN_ARMV5_FIRMWARE_DISABLE_SCANS=all
 *
 * To disable only prologue scanning:
 *   export BN_ARMV5_FIRMWARE_DISABLE_SCANS=prologue
 *
 * To disable workflow but allow manual scans:
 *   export BN_ARMV5_DISABLE_WORKFLOW=1
 *
 * ============================================================================
 */

#include "plugin_settings.h"
#include "env_config.h"

#include <mutex>
#include <unordered_map>

using namespace BinaryNinja;

namespace Armv5Settings
{

// Component registry
static std::mutex s_registryMutex;
static std::unordered_map<std::string, std::shared_ptr<SettingsComponent>> s_components;

SettingsComponent::SettingsComponent(const std::string& name)
	: m_name(name)
	, m_prefix(std::string(kPluginPrefix) + name + ".")
{
}

std::string SettingsComponent::GetKey(const char* setting) const
{
	return m_prefix + setting;
}

void SettingsComponent::RegisterBool(const Ref<Settings>& settings,
	const char* name, bool defaultValue, const char* title, const char* description)
{
	if (!settings)
		return;

	std::string key = GetKey(name);
	std::string json = R"({
		"title" : ")" + std::string(title) + R"(",
		"type" : "boolean",
		"default" : )" + (defaultValue ? "true" : "false") + R"(,
		"description" : ")" + std::string(description) + R"("
	})";
	settings->RegisterSetting(key, json);
}

void SettingsComponent::RegisterNumber(const Ref<Settings>& settings,
	const char* name, uint64_t defaultValue, uint64_t min, uint64_t max,
	const char* title, const char* description)
{
	if (!settings)
		return;

	std::string key = GetKey(name);
	std::string json = R"({
		"title" : ")" + std::string(title) + R"(",
		"type" : "number",
		"default" : )" + std::to_string(defaultValue) + R"(,
		"min" : )" + std::to_string(min) + R"(,
		"max" : )" + std::to_string(max) + R"(,
		"description" : ")" + std::string(description) + R"("
	})";
	settings->RegisterSetting(key, json);
}

std::shared_ptr<SettingsComponent> RegisterComponent(const std::string& name)
{
	std::lock_guard<std::mutex> lock(s_registryMutex);

	auto it = s_components.find(name);
	if (it != s_components.end())
		return it->second;

	auto component = std::make_shared<SettingsComponent>(name);
	s_components[name] = component;
	return component;
}

std::shared_ptr<SettingsComponent> GetComponent(const std::string& name)
{
	std::lock_guard<std::mutex> lock(s_registryMutex);

	auto it = s_components.find(name);
	if (it != s_components.end())
		return it->second;
	return nullptr;
}

void InitPluginSettings()
{
	// Force singleton initialization to parse env vars early
	(void)PluginConfig::Get();

	// Register Binary Ninja settings for the plugin
	RegisterAnalysisSettings();
	RegisterGlobalFirmwareSettings();
}

/*
 * Register analysis feature settings in Binary Ninja's settings UI.
 *
 * These settings control the automatic analysis features:
 * - Calling convention detection
 * - Function signature recovery
 * - RTOS detection
 *
 * Settings are registered under the "analysis" group (a standard Binary Ninja group)
 * with an "armv5" subgroup prefix.
 */
void RegisterAnalysisSettings()
{
	Ref<Settings> settings = Settings::Instance();
	if (!settings)
		return;

	// Use the standard "analysis" group which already exists in Binary Ninja
	// Settings are prefixed with "analysis.armv5." for our plugin

	// Calling convention detection
	settings->RegisterSetting("analysis.armv5.autoDetectCallingConvention",
		R"({
			"title": "ARMv5: Auto-Detect Calling Conventions",
			"type": "boolean",
			"default": true,
			"description": "Automatically detect and apply calling conventions based on function patterns. Detects IRQ handlers, task entry functions, and leaf functions."
		})");

	// Signature recovery
	settings->RegisterSetting("analysis.armv5.recoverSignatures",
		R"({
			"title": "ARMv5: Recover Function Signatures",
			"type": "boolean",
			"default": true,
			"description": "Automatically recover function signatures by analyzing register usage patterns. Infers parameter count and types from r0-r3 reads."
		})");

	// RTOS detection
	settings->RegisterSetting("analysis.armv5.detectRTOS",
		R"({
			"title": "ARMv5: Detect RTOS",
			"type": "boolean",
			"default": true,
			"description": "Detect common RTOS (FreeRTOS, ThreadX, Nucleus PLUS, Nucleus SE, uC/OS-II) and apply appropriate type definitions."
		})");

	// Minimum confidence threshold
	settings->RegisterSetting("analysis.armv5.minConfidence",
		R"({
			"title": "ARMv5: Minimum Analysis Confidence",
			"type": "number",
			"default": 128,
			"minValue": 0,
			"maxValue": 255,
			"description": "Minimum confidence level (0-255) required to apply detected calling conventions or signatures. Higher values are more conservative."
		})");
}

/*
 * Register global firmware settings in Binary Ninja's settings UI.
 *
 * These settings are accessible in the global Settings panel (Edit > Preferences > Settings)
 * and provide defaults for firmware analysis. Per-file overrides can be set in the
 * Open with Options dialog.
 *
 * Settings are registered under the "armv5.firmware" group.
 */
void RegisterGlobalFirmwareSettings()
{
	Ref<Settings> settings = Settings::Instance();
	if (!settings)
		return;

	// Register the armv5 group (Binary Ninja groups are simple identifiers without dots)
	// The settings use "armv5.firmware.*" keys but the group is just "armv5"
	settings->RegisterGroup("armv5", "ARMv5 Firmware Analysis");

	// --- Scan Toggles ---

	settings->RegisterSetting("armv5.firmware.scanPrologues",
		"{\"title\": \"Scan for Function Prologues\", "
		"\"type\": \"boolean\", "
		"\"default\": true, "
		"\"description\": \"Discover additional function entry points by scanning for common prologue patterns (PUSH, STMFD, etc.).\"}");

	settings->RegisterSetting("armv5.firmware.scanCallTargets",
		"{\"title\": \"Scan for Call Targets\", "
		"\"type\": \"boolean\", "
		"\"default\": true, "
		"\"description\": \"Discover additional function entry points from direct call and indirect branch targets.\"}");

	settings->RegisterSetting("armv5.firmware.scanPointerTargets",
		"{\"title\": \"Scan for Pointer Targets\", "
		"\"type\": \"boolean\", "
		"\"default\": true, "
		"\"description\": \"Discover function entry points referenced by data pointers.\"}");

	settings->RegisterSetting("armv5.firmware.scanOrphanCode",
		"{\"title\": \"Scan for Orphan Code Blocks\", "
		"\"type\": \"boolean\", "
		"\"default\": true, "
		"\"description\": \"Discover unreachable functions post-analysis by finding orphaned code blocks.\"}");

	// --- Orphan Scan Tuning ---

	settings->RegisterSetting("armv5.firmware.orphanMinValidInstr",
		"{\"title\": \"Orphan Scan: Min Valid Instructions\", "
		"\"type\": \"number\", "
		"\"default\": 6, "
		"\"minValue\": 1, "
		"\"maxValue\": 16, "
		"\"description\": \"Minimum consecutive valid ARM instructions required for an orphan code candidate.\"}");

	settings->RegisterSetting("armv5.firmware.orphanMinBodyInstr",
		"{\"title\": \"Orphan Scan: Min Body Instructions\", "
		"\"type\": \"number\", "
		"\"default\": 2, "
		"\"minValue\": 0, "
		"\"maxValue\": 16, "
		"\"description\": \"Minimum valid instructions after the candidate prologue when validating orphan code.\"}");

	settings->RegisterSetting("armv5.firmware.orphanMinSpacingBytes",
		"{\"title\": \"Orphan Scan: Min Spacing (bytes)\", "
		"\"type\": \"number\", "
		"\"default\": 128, "
		"\"minValue\": 0, "
		"\"maxValue\": 4096, "
		"\"description\": \"Minimum spacing between orphan functions added during the post-analysis scan.\"}");

	settings->RegisterSetting("armv5.firmware.orphanMaxPerPage",
		"{\"title\": \"Orphan Scan: Max Per 4KB Page\", "
		"\"type\": \"number\", "
		"\"default\": 6, "
		"\"minValue\": 0, "
		"\"maxValue\": 64, "
		"\"description\": \"Maximum orphan functions to add per 4KB page (0 disables the cap).\"}");

	settings->RegisterSetting("armv5.firmware.orphanRequirePrologue",
		"{\"title\": \"Orphan Scan: Require Prologue\", "
		"\"type\": \"boolean\", "
		"\"default\": true, "
		"\"description\": \"Require a prologue-like instruction at the candidate start to reduce false positives.\"}");

	// --- Limits ---

	settings->RegisterSetting("armv5.firmware.maxFunctionAdds",
		"{\"title\": \"Max Function Additions Per Scan\", "
		"\"type\": \"number\", "
		"\"default\": 2000, "
		"\"minValue\": 0, "
		"\"maxValue\": 100000, "
		"\"description\": \"Cap the number of functions added per firmware scan run (0 disables the cap).\"}");

	// --- Cleanup ---

	settings->RegisterSetting("armv5.firmware.cleanupInvalidFunctions",
		"{\"title\": \"Cleanup Invalid Functions\", "
		"\"type\": \"boolean\", "
		"\"default\": true, "
		"\"description\": \"Remove tiny auto-discovered functions that fail ARMv5 validation checks after analysis.\"}");

	settings->RegisterSetting("armv5.firmware.cleanupMaxSize",
		"{\"title\": \"Cleanup: Max Function Size (bytes)\", "
		"\"type\": \"number\", "
		"\"default\": 8, "
		"\"minValue\": 4, "
		"\"maxValue\": 32, "
		"\"description\": \"Maximum size (bytes) for functions eligible for invalid cleanup.\"}");

	// --- Advanced ---

	settings->RegisterSetting("armv5.firmware.typeLiteralPools",
		"{\"title\": \"Type Literal Pool Entries\", "
		"\"type\": \"boolean\", "
		"\"default\": true, "
		"\"description\": \"Define literal pool entries as data to avoid disassembling them as code.\"}");

	settings->RegisterSetting("armv5.firmware.clearAutoDataOnCodeRefs",
		"{\"title\": \"Clear Auto Data on Code References\", "
		"\"type\": \"boolean\", "
		"\"default\": true, "
		"\"description\": \"Undefine auto-discovered data at code-referenced addresses when nearby bytes decode as valid instructions.\"}");

	settings->RegisterSetting("armv5.firmware.disablePointerSweep",
		"{\"title\": \"Disable Core Pointer Sweep\", "
		"\"type\": \"boolean\", "
		"\"default\": false, "
		"\"description\": \"Disable Binary Ninja's core pointer sweep to reduce false positives in raw firmware blobs.\"}");

	settings->RegisterSetting("armv5.firmware.disableLinearSweep",
		"{\"title\": \"Disable Core Linear Sweep\", "
		"\"type\": \"boolean\", "
		"\"default\": false, "
		"\"description\": \"Disable Binary Ninja's core linear sweep so firmware scans drive function discovery.\"}");

	settings->RegisterSetting("armv5.firmware.verboseLogging",
		"{\"title\": \"Verbose Firmware Analysis Logging\", "
		"\"type\": \"boolean\", "
		"\"default\": true, "
		"\"description\": \"Emit per-pass summary logs for firmware analysis heuristics without enabling global debug logging.\"}");

	settings->RegisterSetting("armv5.firmware.skipFirmwareScans",
		"{\"title\": \"Skip Firmware Scans\", "
		"\"type\": \"boolean\", "
		"\"default\": false, "
		"\"description\": \"Disable the firmware-specific pointer/orphan/call scans so only the core sweep runs.\"}");
}

PluginConfig& PluginConfig::Get()
{
	static PluginConfig instance;
	return instance;
}

PluginConfig::PluginConfig()
	: m_workflowDisabled(false)
	, m_allScansDisabled(false)
	, m_disableScansEnv(nullptr)
{
	// Parse workflow disable
	m_workflowDisabled = Armv5EnvConfig::IsEnvSet(Armv5EnvConfig::kDisableWorkflow);

	// Parse scan disable - check for "all" token
	m_disableScansEnv = Armv5EnvConfig::GetEnv(Armv5EnvConfig::kDisableScans);
	if (m_disableScansEnv && m_disableScansEnv[0] != '\0')
	{
		auto tokens = Armv5EnvConfig::ParseTokenList(m_disableScansEnv);
		for (const auto& token : tokens)
		{
			auto normalized = Armv5EnvConfig::NormalizeToken(token);
			if (normalized == "all")
			{
				m_allScansDisabled = true;
				break;
			}
		}
	}
}

}
