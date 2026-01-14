/*
 * ARMv5 Plugin Settings
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
