/*
 * ARMv5 Sidebar Widget Type Implementation
 */

#include "armv5_sidebar_type.h"
#include "armv5_sidebar.h"
#include "sidebar.h"

#include <QtCore/QRectF>
#include <QtGui/QImage>
#include <QtGui/QPainter>
#include <QtGui/QFont>
#include <QtGui/QColor>

namespace Armv5UI
{

/*
 * Create a sidebar icon.
 *
 * Sidebar icons are 28x28 points, but should be 56x56 pixels for HiDPI.
 * The icon should be grayscale - Binary Ninja will apply theme colors.
 */
static QImage CreateSidebarIcon()
{
	QImage icon(56, 56, QImage::Format_ARGB32);
	icon.fill(Qt::transparent);

	QPainter painter(&icon);
	painter.setRenderHint(QPainter::Antialiasing);
	painter.setRenderHint(QPainter::TextAntialiasing);

	// Draw "A5" text as the icon (ARMv5)
	QFont font("Helvetica", 24, QFont::Bold);
	painter.setFont(font);
	painter.setPen(QColor(255, 255, 255, 255));
	painter.drawText(QRectF(0, 0, 56, 56), Qt::AlignCenter, "A5");

	painter.end();
	return icon;
}

Armv5SidebarWidgetType::Armv5SidebarWidgetType()
	: SidebarWidgetType(CreateSidebarIcon(), "ARMv5")
{
}

SidebarWidget* Armv5SidebarWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	// Only create for ARMv5 views
	if (!data)
		return nullptr;

	std::string archName;
	auto arch = data->GetDefaultArchitecture();
	if (arch)
		archName = arch->GetName();

	std::string typeName = data->GetTypeName();

	// Accept ARMv5 Firmware or any ARMv5 architecture
	bool isArmv5 = (typeName == "ARMv5 Firmware") ||
	               (archName == "armv5") ||
	               (archName == "armv5t");

	if (!isArmv5)
		return nullptr;

	return new Armv5SidebarWidget(frame, data);
}

SidebarWidgetLocation Armv5SidebarWidgetType::defaultLocation() const
{
	// Appear on the right side, in the content area (middle section)
	return SidebarWidgetLocation::RightContent;
}

SidebarContextSensitivity Armv5SidebarWidgetType::contextSensitivity() const
{
	// One widget per view type - ARMv5 Firmware views share one widget
	return PerViewTypeSidebarContext;
}

void RegisterArmv5Sidebar()
{
	Sidebar::addSidebarWidgetType(new Armv5SidebarWidgetType());
}

}
