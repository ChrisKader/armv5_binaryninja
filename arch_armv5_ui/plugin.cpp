/*
 * ARMv5 UI Plugin
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This plugin provides a sidebar widget for ARMv5 firmware analysis. It requires
 * the core arch_armv5 plugin to be loaded first.
 *
 * Features:
 * - Sidebar panel with tabs for Functions, RTOS Tasks, and Scans
 * - Table views for discovered functions and their calling conventions
 * - Action buttons for running analysis scans
 * - Real-time update as analysis progresses
 * - Theme selection: Default (BN native) or Cockpit (Boeing 737 style)
 *
 * ============================================================================
 */

#include "binaryninjaapi.h"
#include "sidebar/armv5_sidebar_type.h"
#include "widgets/common/armv5_theme.h"

using namespace BinaryNinja;

// Theme setting key
static const char* kThemeSettingKey = "ui.armv5.theme";

static void RegisterUISettings()
{
	Ref<Settings> settings = Settings::Instance();
	if (!settings)
		return;

	// Register theme selection setting
	settings->RegisterSetting(kThemeSettingKey,
		R"({
			"title": "ARMv5: UI Theme",
			"type": "string",
			"default": "default",
			"enum": ["default", "cockpit"],
			"enumDescriptions": [
				"Binary Ninja native styling - blends with BN theme",
				"Boeing 737 cockpit style - dark panels with amber accents"
			],
			"description": "Choose the visual theme for ARMv5 plugin widgets. The Cockpit theme provides a distinctive aerospace-inspired look with amber indicators."
		})");
}

static void InitThemeFromSettings()
{
	Ref<Settings> settings = Settings::Instance();
	if (!settings)
		return;

	std::string themeName = settings->Get<std::string>(kThemeSettingKey);
	if (themeName == "cockpit")
		Armv5UI::theme().setTheme(Armv5UI::ThemeType::Cockpit);
	else
		Armv5UI::theme().setTheme(Armv5UI::ThemeType::Default);
}

extern "C"
{
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		// Depend on the core ARMv5 plugin
		AddRequiredPluginDependency("arch_armv5");
	}

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		// Register UI settings
		RegisterUISettings();

		// Initialize theme from settings
		InitThemeFromSettings();

		// Register the sidebar widget
		Armv5UI::RegisterArmv5Sidebar();

		return true;
	}
}
