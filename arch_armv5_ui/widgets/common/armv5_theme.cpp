/*
 * ARMv5 Theme System - Implementation
 */

#include "armv5_theme.h"
#include "theme.h"

namespace Armv5UI
{

Theme& Theme::instance()
{
	static Theme inst;
	return inst;
}

Theme::Theme()
{
	loadDefaultColors();
}

void Theme::setTheme(ThemeType newTheme)
{
	if (m_currentTheme == newTheme)
		return;

	m_currentTheme = newTheme;

	switch (newTheme)
	{
	case ThemeType::Cockpit:
		loadCockpitColors();
		break;
	case ThemeType::Default:
	default:
		loadDefaultColors();
		break;
	}
}

void Theme::loadCockpitColors()
{
	// Boeing 737 Cockpit-inspired theme
	// Dark panels, amber/yellow accents, industrial feel

	// Backgrounds - dark metal panel feel
	m_colors[ThemeColor::PanelBackground] = QColor("#252525");
	m_colors[ThemeColor::PanelBackgroundAlt] = QColor("#2a2a2a");
	m_colors[ThemeColor::ToolbarBackground] = QColor("#2d2d2d");
	m_colors[ThemeColor::InputBackground] = QColor("#1a1a1a");
	m_colors[ThemeColor::HeaderBackground] = QColor("#333333");

	// Borders - subtle definition
	m_colors[ThemeColor::PanelBorder] = QColor("#3a3a3a");
	m_colors[ThemeColor::SectionBorder] = QColor("#4a4a4a");
	m_colors[ThemeColor::InputBorder] = QColor("#5a5a5a");
	m_colors[ThemeColor::AccentBorder] = QColor("#ffcc00");

	// Text
	m_colors[ThemeColor::TextPrimary] = QColor("#ffffff");
	m_colors[ThemeColor::TextSecondary] = QColor("#999999");
	m_colors[ThemeColor::TextDisabled] = QColor("#666666");
	m_colors[ThemeColor::TextAccent] = QColor("#ffcc00");
	m_colors[ThemeColor::TextHighlight] = QColor("#ffd700");

	// Accent - amber/yellow cockpit indicators
	m_colors[ThemeColor::AccentPrimary] = QColor("#ffcc00");
	m_colors[ThemeColor::AccentSecondary] = QColor("#ff9900");
	m_colors[ThemeColor::AccentSuccess] = QColor("#00cc44");
	m_colors[ThemeColor::AccentWarning] = QColor("#ff9900");
	m_colors[ThemeColor::AccentError] = QColor("#ff4444");

	// Buttons
	m_colors[ThemeColor::ButtonBackground] = QColor("#3a3a3a");
	m_colors[ThemeColor::ButtonBackgroundHover] = QColor("#4a4a4a");
	m_colors[ThemeColor::ButtonBackgroundPressed] = QColor("#2a2a2a");
	m_colors[ThemeColor::ButtonText] = QColor("#cccccc");

	// Status indicators
	m_colors[ThemeColor::StatusActive] = QColor("#00ff00");
	m_colors[ThemeColor::StatusInactive] = QColor("#666666");
	m_colors[ThemeColor::StatusRunning] = QColor("#ffcc00");

	// Tree/list
	m_colors[ThemeColor::TreeRowAlt] = QColor("#2a2a2a");
	m_colors[ThemeColor::SelectionBackground] = QColor("#3a4a3a");
	m_colors[ThemeColor::SelectionBorder] = QColor("#4a6a4a");
}

void Theme::loadDefaultColors()
{
	// Binary Ninja native styling - uses BN theme colors where possible
	// Use sidebar colors as a good proxy for general UI backgrounds
	auto bg = getThemeColor(SidebarBackgroundColor);
	auto bgAlt = getThemeColor(BackgroundHighlightDarkColor);
	auto border = getThemeColor(OutlineColor);
	auto text = getThemeColor(InstructionColor);  // General text color
	auto textSecondary = getThemeColor(CommentColor);
	auto accent = getThemeColor(BlueStandardHighlightColor);

	// Backgrounds - follow BN theme
	m_colors[ThemeColor::PanelBackground] = bg;
	m_colors[ThemeColor::PanelBackgroundAlt] = bgAlt;
	m_colors[ThemeColor::ToolbarBackground] = bg.lighter(110);
	m_colors[ThemeColor::InputBackground] = bg.darker(110);
	m_colors[ThemeColor::HeaderBackground] = bg.lighter(115);

	// Borders
	m_colors[ThemeColor::PanelBorder] = border;
	m_colors[ThemeColor::SectionBorder] = border.lighter(120);
	m_colors[ThemeColor::InputBorder] = border.lighter(130);
	m_colors[ThemeColor::AccentBorder] = accent;

	// Text
	m_colors[ThemeColor::TextPrimary] = text;
	m_colors[ThemeColor::TextSecondary] = textSecondary;
	m_colors[ThemeColor::TextDisabled] = textSecondary.darker(130);
	m_colors[ThemeColor::TextAccent] = accent;
	m_colors[ThemeColor::TextHighlight] = getThemeColor(GreenStandardHighlightColor);

	// Accent - blue for default (matches BN)
	m_colors[ThemeColor::AccentPrimary] = accent;
	m_colors[ThemeColor::AccentSecondary] = getThemeColor(CyanStandardHighlightColor);
	m_colors[ThemeColor::AccentSuccess] = getThemeColor(GreenStandardHighlightColor);
	m_colors[ThemeColor::AccentWarning] = getThemeColor(OrangeStandardHighlightColor);
	m_colors[ThemeColor::AccentError] = getThemeColor(RedStandardHighlightColor);

	// Buttons
	m_colors[ThemeColor::ButtonBackground] = bg.lighter(120);
	m_colors[ThemeColor::ButtonBackgroundHover] = bg.lighter(140);
	m_colors[ThemeColor::ButtonBackgroundPressed] = bg;
	m_colors[ThemeColor::ButtonText] = text;

	// Status indicators
	m_colors[ThemeColor::StatusActive] = getThemeColor(GreenStandardHighlightColor);
	m_colors[ThemeColor::StatusInactive] = textSecondary;
	m_colors[ThemeColor::StatusRunning] = accent;

	// Tree/list
	m_colors[ThemeColor::TreeRowAlt] = bgAlt;
	m_colors[ThemeColor::SelectionBackground] = getThemeColor(SelectionColor);
	m_colors[ThemeColor::SelectionBorder] = accent;
}

QColor Theme::color(ThemeColor id) const
{
	return m_colors.value(id, QColor("#ff00ff"));  // Magenta for missing colors (debug)
}

QString Theme::controlBarStyle() const
{
	auto bg = color(ThemeColor::ToolbarBackground);
	auto border = color(ThemeColor::PanelBorder);
	auto text = color(ThemeColor::ButtonText);
	auto hover = color(ThemeColor::ButtonBackgroundHover);
	auto pressed = color(ThemeColor::ButtonBackgroundPressed);
	auto disabled = color(ThemeColor::TextDisabled);

	if (m_currentTheme == ThemeType::Cockpit)
	{
		return QString(
			"AnalysisControlBar {"
			"  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3a3c3e, stop:1 #2a2c2e);"
			"  border-bottom: 1px solid #1a1a1a;"
			"}"
			"QToolButton {"
			"  color: %1;"
			"  border: none;"
			"  border-radius: 3px;"
			"  padding: 4px 6px;"
			"}"
			"QToolButton:hover { background-color: %2; }"
			"QToolButton:pressed { background-color: %3; }"
			"QToolButton:disabled { color: %4; }"
		).arg(text.name(), hover.name(), pressed.name(), disabled.name());
	}
	else
	{
		return QString(
			"AnalysisControlBar {"
			"  background-color: %1;"
			"  border-bottom: 1px solid %2;"
			"}"
			"QToolButton {"
			"  color: %3;"
			"  border: none;"
			"  border-radius: 2px;"
			"  padding: 4px 6px;"
			"}"
			"QToolButton:hover { background-color: %4; }"
			"QToolButton:pressed { background-color: %5; }"
			"QToolButton:disabled { color: %6; }"
		).arg(bg.name(), border.name(), text.name(), hover.name(), pressed.name(), disabled.name());
	}
}

QString Theme::statusBarStyle() const
{
	auto bg = color(ThemeColor::PanelBackground);
	auto border = color(ThemeColor::PanelBorder);
	auto text = color(ThemeColor::TextSecondary);
	auto accent = color(ThemeColor::AccentPrimary);

	if (m_currentTheme == ThemeType::Cockpit)
	{
		return QString(
			"AnalysisStatusBar {"
			"  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2a2c2e, stop:1 #252527);"
			"  border-top: 1px solid #1a1a1a;"
			"  font-size: 11px;"
			"}"
			"QLabel { color: %1; }"
			"QLabel#status { color: %2; font-weight: bold; }"
		).arg(text.name(), accent.name());
	}
	else
	{
		return QString(
			"AnalysisStatusBar {"
			"  background-color: %1;"
			"  border-top: 1px solid %2;"
			"}"
			"QLabel { color: %3; }"
		).arg(bg.name(), border.name(), text.name());
	}
}

QString Theme::filterBarStyle() const
{
	auto bg = color(ThemeColor::PanelBackgroundAlt);
	auto border = color(ThemeColor::PanelBorder);
	auto inputBg = color(ThemeColor::InputBackground);
	auto inputBorder = color(ThemeColor::InputBorder);
	auto text = color(ThemeColor::TextPrimary);
	auto textSecondary = color(ThemeColor::TextSecondary);
	auto accent = color(ThemeColor::AccentPrimary);

	if (m_currentTheme == ThemeType::Cockpit)
	{
		return QString(
			"FilterBar {"
			"  background-color: #2d2d2d;"
			"  border-bottom: 1px solid #3a3a3a;"
			"}"
			"QLineEdit {"
			"  background-color: #1a1a1a;"
			"  border: 1px solid #4a4a4a;"
			"  border-radius: 3px;"
			"  padding: 3px 6px;"
			"  color: %1;"
			"}"
			"QLineEdit:focus { border-color: %2; }"
			"QComboBox {"
			"  background-color: #2a2a2a;"
			"  border: 1px solid #4a4a4a;"
			"  border-radius: 3px;"
			"  padding: 2px 6px;"
			"  color: %3;"
			"  min-width: 60px;"
			"}"
		).arg(text.name(), accent.name(), textSecondary.name());
	}
	else
	{
		return QString(
			"FilterBar {"
			"  background-color: %1;"
			"  border-bottom: 1px solid %2;"
			"}"
			"QLineEdit {"
			"  background-color: %3;"
			"  border: 1px solid %4;"
			"  border-radius: 2px;"
			"  padding: 3px 6px;"
			"  color: %5;"
			"}"
			"QLineEdit:focus { border-color: %6; }"
			"QComboBox {"
			"  background-color: %3;"
			"  border: 1px solid %4;"
			"  padding: 2px 6px;"
			"  color: %5;"
			"}"
		).arg(bg.name(), border.name(), inputBg.name(), inputBorder.name(), text.name(), accent.name());
	}
}

QString Theme::treeViewStyle() const
{
	auto bg = color(ThemeColor::PanelBackground);
	auto altRow = color(ThemeColor::TreeRowAlt);
	auto selection = color(ThemeColor::SelectionBackground);
	auto text = color(ThemeColor::TextPrimary);
	auto border = color(ThemeColor::PanelBorder);
	auto header = color(ThemeColor::HeaderBackground);

	if (m_currentTheme == ThemeType::Cockpit)
	{
		return QString(
			"QTreeView {"
			"  background-color: #252525;"
			"  alternate-background-color: #2a2a2a;"
			"  border: none;"
			"  gridline-color: #3a3a3a;"
			"  color: %1;"
			"}"
			"QTreeView::item:selected {"
			"  background-color: #3a4a3a;"
			"  color: #ffffff;"
			"}"
			"QTreeView::item:hover {"
			"  background-color: #303030;"
			"}"
			"QHeaderView::section {"
			"  background-color: #2d2d2d;"
			"  color: #999999;"
			"  padding: 4px 6px;"
			"  border: none;"
			"  border-right: 1px solid #3a3a3a;"
			"  border-bottom: 1px solid #3a3a3a;"
			"  font-size: 11px;"
			"}"
		).arg(text.name());
	}
	else
	{
		return QString(
			"QTreeView {"
			"  background-color: %1;"
			"  alternate-background-color: %2;"
			"  border: none;"
			"  color: %3;"
			"}"
			"QTreeView::item:selected {"
			"  background-color: %4;"
			"}"
			"QHeaderView::section {"
			"  background-color: %5;"
			"  color: %3;"
			"  padding: 4px 6px;"
			"  border: none;"
			"  border-right: 1px solid %6;"
			"  border-bottom: 1px solid %6;"
			"}"
		).arg(bg.name(), altRow.name(), text.name(), selection.name(), header.name(), border.name());
	}
}

QString Theme::tabWidgetStyle() const
{
	auto bg = color(ThemeColor::PanelBackground);
	auto tabBg = color(ThemeColor::PanelBackgroundAlt);
	auto text = color(ThemeColor::TextSecondary);
	auto textSelected = color(ThemeColor::TextPrimary);
	auto accent = color(ThemeColor::AccentPrimary);

	if (m_currentTheme == ThemeType::Cockpit)
	{
		return QString(
			"QTabWidget::pane {"
			"  border: none;"
			"  background-color: #252525;"
			"}"
			"QTabBar::tab {"
			"  background: #2a2a2a;"
			"  color: #999999;"
			"  padding: 6px 12px;"
			"  border: none;"
			"  border-bottom: 2px solid transparent;"
			"  font-size: 11px;"
			"}"
			"QTabBar::tab:selected {"
			"  color: #ffffff;"
			"  background: #303030;"
			"  border-bottom: 2px solid #ffcc00;"
			"}"
			"QTabBar::tab:hover:!selected {"
			"  color: #cccccc;"
			"  background: #333333;"
			"}"
		);
	}
	else
	{
		return QString(
			"QTabWidget::pane {"
			"  border: none;"
			"  background-color: %1;"
			"}"
			"QTabBar::tab {"
			"  background: %2;"
			"  color: %3;"
			"  padding: 6px 12px;"
			"  border: none;"
			"  border-bottom: 2px solid transparent;"
			"}"
			"QTabBar::tab:selected {"
			"  color: %4;"
			"  border-bottom-color: %5;"
			"}"
			"QTabBar::tab:hover:!selected {"
			"  background: %1;"
			"}"
		).arg(bg.name(), tabBg.name(), text.name(), textSelected.name(), accent.name());
	}
}

QString Theme::settingsWidgetStyle() const
{
	auto bg = color(ThemeColor::PanelBackgroundAlt);
	auto border = color(ThemeColor::SectionBorder);
	auto text = color(ThemeColor::TextPrimary);
	auto textSecondary = color(ThemeColor::TextSecondary);

	if (m_currentTheme == ThemeType::Cockpit)
	{
		return QString(
			"QWidget#settings {"
			"  background-color: #2a2a2a;"
			"}"
			"QGroupBox {"
			"  background-color: #252525;"
			"  border: 1px solid #3a3a3a;"
			"  border-radius: 4px;"
			"  margin-top: 12px;"
			"  padding-top: 8px;"
			"}"
			"QGroupBox::title {"
			"  color: #ffcc00;"
			"  subcontrol-origin: margin;"
			"  left: 8px;"
			"  padding: 0 4px;"
			"}"
			"QLabel { color: %1; }"
			"QCheckBox { color: %2; }"
			"QCheckBox::indicator { width: 14px; height: 14px; }"
		).arg(textSecondary.name(), text.name());
	}
	else
	{
		return QString(
			"QGroupBox {"
			"  background-color: %1;"
			"  border: 1px solid %2;"
			"  border-radius: 3px;"
			"  margin-top: 12px;"
			"}"
			"QGroupBox::title {"
			"  subcontrol-origin: margin;"
			"  left: 8px;"
			"}"
			"QLabel { color: %3; }"
			"QCheckBox { color: %4; }"
		).arg(bg.name(), border.name(), textSecondary.name(), text.name());
	}
}

QString Theme::panelStyle() const
{
	auto bg = color(ThemeColor::PanelBackground);
	auto border = color(ThemeColor::PanelBorder);

	if (m_currentTheme == ThemeType::Cockpit)
	{
		return QString(
			"background-color: #252525;"
			"border: 1px solid #3a3a3a;"
		);
	}
	else
	{
		return QString(
			"background-color: %1;"
			"border: 1px solid %2;"
		).arg(bg.name(), border.name());
	}
}

QString Theme::buttonStyle() const
{
	auto bg = color(ThemeColor::ButtonBackground);
	auto hover = color(ThemeColor::ButtonBackgroundHover);
	auto pressed = color(ThemeColor::ButtonBackgroundPressed);
	auto text = color(ThemeColor::ButtonText);
	auto border = color(ThemeColor::InputBorder);

	return QString(
		"QPushButton {"
		"  background-color: %1;"
		"  color: %2;"
		"  border: 1px solid %3;"
		"  border-radius: 3px;"
		"  padding: 4px 12px;"
		"}"
		"QPushButton:hover { background-color: %4; }"
		"QPushButton:pressed { background-color: %5; }"
	).arg(bg.name(), text.name(), border.name(), hover.name(), pressed.name());
}

QString Theme::inputStyle() const
{
	auto bg = color(ThemeColor::InputBackground);
	auto border = color(ThemeColor::InputBorder);
	auto text = color(ThemeColor::TextPrimary);
	auto accent = color(ThemeColor::AccentPrimary);

	return QString(
		"QLineEdit, QSpinBox, QDoubleSpinBox {"
		"  background-color: %1;"
		"  border: 1px solid %2;"
		"  border-radius: 2px;"
		"  padding: 2px 4px;"
		"  color: %3;"
		"}"
		"QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {"
		"  border-color: %4;"
		"}"
	).arg(bg.name(), border.name(), text.name(), accent.name());
}

QString Theme::applyButtonStyle() const
{
	auto success = color(ThemeColor::AccentSuccess);
	auto successDark = success.darker(120);
	auto successLight = success.lighter(110);

	return QString(
		"QToolButton, QPushButton {"
		"  background-color: %1;"
		"  color: #ffffff;"
		"  border: 1px solid %2;"
		"  border-radius: 3px;"
		"  padding: 4px 10px;"
		"}"
		"QToolButton:hover, QPushButton:hover { background-color: %3; }"
		"QToolButton:pressed, QPushButton:pressed { background-color: %1; }"
		"QToolButton:disabled, QPushButton:disabled {"
		"  background-color: #2a2c2e;"
		"  color: #666666;"
		"  border-color: #3a3c3e;"
		"}"
	).arg(successDark.name(), success.name(), successLight.name());
}

QString Theme::warningButtonStyle() const
{
	auto warning = color(ThemeColor::AccentWarning);
	auto warningDark = warning.darker(120);

	return QString(
		"QToolButton, QPushButton {"
		"  background-color: %1;"
		"  color: #ffffff;"
		"  border: 1px solid %2;"
		"  border-radius: 3px;"
		"  padding: 4px 10px;"
		"}"
		"QToolButton:hover, QPushButton:hover { background-color: %2; }"
	).arg(warningDark.name(), warning.name());
}

QString Theme::dangerButtonStyle() const
{
	auto error = color(ThemeColor::AccentError);
	auto errorDark = error.darker(120);

	return QString(
		"QToolButton, QPushButton {"
		"  background-color: %1;"
		"  color: #ffffff;"
		"  border: 1px solid %2;"
		"  border-radius: 3px;"
		"  padding: 4px 10px;"
		"}"
		"QToolButton:hover, QPushButton:hover { background-color: %2; }"
	).arg(errorDark.name(), error.name());
}

}  // namespace Armv5UI
