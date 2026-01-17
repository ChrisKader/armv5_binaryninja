/*
 * ARMv5 Theme System
 *
 * Provides theme switching between:
 * - Cockpit: Boeing 737-style dark panels, amber accents, industrial look
 * - Default: Binary Ninja native styling, blends with BN theme
 */

#pragma once

#include <QtCore/QString>
#include <QtCore/QMap>
#include <QtGui/QColor>

namespace Armv5UI
{

enum class ThemeType
{
	Default,    // Binary Ninja native styling
	Cockpit     // Boeing 737 cockpit-style
};

// Theme color identifiers
enum class ThemeColor
{
	// Backgrounds
	PanelBackground,
	PanelBackgroundAlt,
	ToolbarBackground,
	InputBackground,
	HeaderBackground,

	// Borders
	PanelBorder,
	SectionBorder,
	InputBorder,
	AccentBorder,

	// Text
	TextPrimary,
	TextSecondary,
	TextDisabled,
	TextAccent,
	TextHighlight,

	// Accent colors
	AccentPrimary,       // Main accent (amber for cockpit, blue for default)
	AccentSecondary,
	AccentSuccess,
	AccentWarning,
	AccentError,

	// Interactive
	ButtonBackground,
	ButtonBackgroundHover,
	ButtonBackgroundPressed,
	ButtonText,

	// Status indicators
	StatusActive,
	StatusInactive,
	StatusRunning,

	// Specific UI elements
	TreeRowAlt,
	SelectionBackground,
	SelectionBorder
};

class Theme
{
public:
	static Theme& instance();

	ThemeType currentTheme() const { return m_currentTheme; }
	void setTheme(ThemeType theme);

	// Get color for current theme
	QColor color(ThemeColor id) const;

	// Get complete stylesheet for a widget type
	QString controlBarStyle() const;
	QString statusBarStyle() const;
	QString filterBarStyle() const;
	QString treeViewStyle() const;
	QString tabWidgetStyle() const;
	QString settingsWidgetStyle() const;
	QString panelStyle() const;
	QString buttonStyle() const;
	QString inputStyle() const;

	// Quick access to common styles
	QString applyButtonStyle() const;
	QString warningButtonStyle() const;
	QString dangerButtonStyle() const;

private:
	Theme();
	~Theme() = default;
	Theme(const Theme&) = delete;
	Theme& operator=(const Theme&) = delete;

	void loadCockpitColors();
	void loadDefaultColors();

	ThemeType m_currentTheme = ThemeType::Default;
	QMap<ThemeColor, QColor> m_colors;
};

// Convenience function
inline Theme& theme() { return Theme::instance(); }

}  // namespace Armv5UI
