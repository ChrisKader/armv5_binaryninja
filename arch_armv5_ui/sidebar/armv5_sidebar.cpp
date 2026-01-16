/*
 * ARMv5 Sidebar Widget Implementation
 */

#include "armv5_sidebar.h"
#include "widgets/function_table.h"
#include "widgets/rtos_table.h"
#include "widgets/scan_controls.h"
#include "binaryninjaapi.h"

#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>

namespace Armv5UI
{

Armv5SidebarWidget::Armv5SidebarWidget(ViewFrame* frame, BinaryViewRef data)
	: SidebarWidget("ARMv5 Analysis")
	, m_frame(frame)
	, m_data(data)
	, m_tabs(nullptr)
	, m_functionTable(nullptr)
	, m_rtosTable(nullptr)
	, m_scanControls(nullptr)
	, m_actionBar(nullptr)
	, m_runAllButton(nullptr)
	, m_detectRTOSButton(nullptr)
	, m_refreshButton(nullptr)
{
	setupUI();
	connectSignals();
	refreshData();
}

Armv5SidebarWidget::~Armv5SidebarWidget()
{
}

void Armv5SidebarWidget::setupUI()
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Create tab widget
	m_tabs = new QTabWidget(this);
	m_tabs->setDocumentMode(true);

	// Create tab contents
	m_functionTable = new FunctionTableWidget(this);
	m_rtosTable = new RTOSTableWidget(this);
	m_scanControls = new ScanControlsWidget(this);

	// Add tabs
	m_tabs->addTab(m_functionTable, "Functions");
	m_tabs->addTab(m_rtosTable, "RTOS");
	m_tabs->addTab(m_scanControls, "Scans");

	layout->addWidget(m_tabs, 1);

	// Create action bar
	m_actionBar = new QWidget(this);
	QHBoxLayout* actionLayout = new QHBoxLayout(m_actionBar);
	actionLayout->setContentsMargins(4, 4, 4, 4);
	actionLayout->setSpacing(4);

	m_runAllButton = new QPushButton("Run Scans", m_actionBar);
	m_runAllButton->setToolTip("Run all firmware analysis scans");

	m_detectRTOSButton = new QPushButton("Detect RTOS", m_actionBar);
	m_detectRTOSButton->setToolTip("Detect RTOS and apply type definitions");

	m_refreshButton = new QPushButton("Refresh", m_actionBar);
	m_refreshButton->setToolTip("Refresh analysis data");

	actionLayout->addWidget(m_runAllButton);
	actionLayout->addWidget(m_detectRTOSButton);
	actionLayout->addWidget(m_refreshButton);
	actionLayout->addStretch();

	layout->addWidget(m_actionBar);

	setLayout(layout);
}

void Armv5SidebarWidget::connectSignals()
{
	connect(m_runAllButton, &QPushButton::clicked, this, &Armv5SidebarWidget::onRunAllScansClicked);
	connect(m_detectRTOSButton, &QPushButton::clicked, this, &Armv5SidebarWidget::onDetectRTOSClicked);
	connect(m_refreshButton, &QPushButton::clicked, this, &Armv5SidebarWidget::onRefreshClicked);
}

void Armv5SidebarWidget::notifyViewChanged(ViewFrame* frame)
{
	m_frame = frame;
	if (frame)
	{
		// Get the new view's data
		// Note: This may need adjustment based on how ViewFrame provides the view
		refreshData();
	}
}

void Armv5SidebarWidget::notifyOffsetChanged(uint64_t offset)
{
	// Could highlight the function at the current offset
	if (m_functionTable)
		m_functionTable->highlightAddress(offset);
}

void Armv5SidebarWidget::refreshData()
{
	if (!m_data)
		return;

	if (m_functionTable)
		m_functionTable->refresh(m_data);

	if (m_rtosTable)
		m_rtosTable->refresh(m_data);

	if (m_scanControls)
		m_scanControls->refresh(m_data);
}

void Armv5SidebarWidget::onRunAllScansClicked()
{
	if (!m_data)
		return;

	// Find and execute the plugin command
	auto commands = BinaryNinja::PluginCommand::GetList();
	for (const auto& cmd : commands)
	{
		if (cmd.GetName() == "ARMv5\\Run All Firmware Scans")
		{
			BinaryNinja::PluginCommandContext ctx;
			ctx.binaryView = m_data;
			ctx.address = 0;
			ctx.length = 0;
			ctx.function = nullptr;
			if (cmd.IsValid(ctx))
				cmd.Execute(ctx);
			break;
		}
	}
}

void Armv5SidebarWidget::onDetectRTOSClicked()
{
	if (!m_data)
		return;

	// Find and execute the RTOS detection command
	auto commands = BinaryNinja::PluginCommand::GetList();
	for (const auto& cmd : commands)
	{
		if (cmd.GetName() == "ARMv5\\Detect RTOS")
		{
			BinaryNinja::PluginCommandContext ctx;
			ctx.binaryView = m_data;
			ctx.address = 0;
			ctx.length = 0;
			ctx.function = nullptr;
			if (cmd.IsValid(ctx))
				cmd.Execute(ctx);
			break;
		}
	}
	
	// Refresh RTOS table after detection
	if (m_rtosTable)
		m_rtosTable->refresh(m_data);
}

void Armv5SidebarWidget::onRefreshClicked()
{
	refreshData();
}

}
