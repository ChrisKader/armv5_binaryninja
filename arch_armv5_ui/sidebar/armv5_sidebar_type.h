/*
 * ARMv5 Sidebar Widget Type
 *
 * Registers the sidebar widget with Binary Ninja's sidebar system.
 */

#pragma once

#include "sidebarwidget.h"

namespace Armv5UI
{

/**
 * Register the ARMv5 sidebar widget type.
 * Called during UI plugin initialization.
 */
void RegisterArmv5Sidebar();

/**
 * Sidebar widget type for ARMv5 analysis.
 *
 * This class defines how the sidebar appears (icon, name, location)
 * and creates widget instances for each view.
 */
class Armv5SidebarWidgetType : public SidebarWidgetType
{
public:
	Armv5SidebarWidgetType();

	/**
	 * Create a new sidebar widget for the given view.
	 * Called when the user opens the sidebar for an ARMv5 view.
	 */
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;

	/**
	 * Default location in the sidebar (left or right, top/middle/bottom).
	 */
	SidebarWidgetLocation defaultLocation() const override;

	/**
	 * Context sensitivity - how widgets are shared across views.
	 * PerViewTypeSidebarContext: One widget per view type (e.g., ARMv5 Firmware).
	 */
	SidebarContextSensitivity contextSensitivity() const override;
};

}
