/*
 * ARMv5 Sidebar Widget Implementation
 */

#include "armv5_sidebar.h"
#include "widgets/function_table.h"
#include "widgets/discover/discover_widget.h"
#include "widgets/security/security_scanner_widget.h"
#include "widgets/health/health_dashboard.h"
#include "widgets/diff/diff_widget.h"
#include "widgets/rtos_table.h"
#include "widgets/vector_table.h"
#include "widgets/region_detector_widget.h"
#include "widgets/scan_controls.h"
#include "binaryninjaapi.h"
#include "viewframe.h"

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
	, m_discoverWidget(nullptr)
	, m_securityScanner(nullptr)
	, m_healthDashboard(nullptr)
	, m_diffWidget(nullptr)
	, m_rtosTable(nullptr)
	, m_vectorTable(nullptr)
	, m_regionDetector(nullptr)
	, m_scanControls(nullptr)
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

	// Create tab widget - use native BN styling
	m_tabs = new QTabWidget(this);
	m_tabs->setDocumentMode(true);

	// Create tab contents
	m_functionTable = new FunctionTableWidget(this);
	m_discoverWidget = new DiscoverWidget(this);
	m_securityScanner = new SecurityScannerWidget(this);
	m_healthDashboard = new HealthDashboard(this);
	m_diffWidget = new FirmwareDiffWidget(this);
	m_rtosTable = new RTOSTableWidget(this);
	m_vectorTable = new VectorTableWidget(this);
	m_regionDetector = new RegionDetectorWidget(this);
	m_scanControls = new ScanControlsWidget(this);

	// Add tabs - organized by workflow
	m_tabs->addTab(m_functionTable, "Functions");
	m_tabs->addTab(m_discoverWidget, "Discover");
	m_tabs->addTab(m_vectorTable, "Vectors");
	m_tabs->addTab(m_regionDetector, "Regions");
	m_tabs->addTab(m_securityScanner, "Security");
	m_tabs->addTab(m_healthDashboard, "Health");
	m_tabs->addTab(m_diffWidget, "Diff");
	m_tabs->addTab(m_rtosTable, "RTOS");
	m_tabs->addTab(m_scanControls, "Scans");

	layout->addWidget(m_tabs, 1);

	setLayout(layout);
}

void Armv5SidebarWidget::connectSignals()
{
	// Connect function table selection to navigate in view
	connect(m_functionTable, &FunctionTableWidget::functionSelected,
		this, &Armv5SidebarWidget::onFunctionSelected);
	
	// Connect RTOS table selection to navigate (uses entry point address)
	connect(m_rtosTable, &RTOSTableWidget::taskSelected,
		this, [this](uint64_t entryPoint, uint64_t /*tcbAddress*/) {
			onFunctionSelected(entryPoint);
		});
	
	// Connect vector table selection to navigate
	connect(m_vectorTable, &VectorTableWidget::handlerSelected,
		this, &Armv5SidebarWidget::onFunctionSelected);
	
	// Connect region detector selection to navigate
	connect(m_regionDetector, &RegionDetectorWidget::regionSelected,
		this, &Armv5SidebarWidget::onFunctionSelected);
	
	// Connect region detector apply to refresh
	connect(m_regionDetector, &RegionDetectorWidget::regionsApplied,
		this, &Armv5SidebarWidget::onRefreshClicked);
	
	// Connect discover widget selection to navigate
	connect(m_discoverWidget, &DiscoverWidget::addressSelected,
		this, &Armv5SidebarWidget::onFunctionSelected);
	
	// Connect discover widget apply to refresh
	connect(m_discoverWidget, &DiscoverWidget::analysisApplied,
		this, [this](size_t /*count*/) { onRefreshClicked(); });
	
	// Connect security scanner selection to navigate
	connect(m_securityScanner, &SecurityScannerWidget::addressSelected,
		this, &Armv5SidebarWidget::onFunctionSelected);
	
	// Connect health dashboard selection to navigate
	connect(m_healthDashboard, &HealthDashboard::addressSelected,
		this, &Armv5SidebarWidget::onFunctionSelected);
	
	// Connect diff widget selection to navigate
	connect(m_diffWidget, &FirmwareDiffWidget::addressSelected,
		this, &Armv5SidebarWidget::onFunctionSelected);
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

	if (m_discoverWidget)
		m_discoverWidget->setBinaryView(m_data);

	if (m_securityScanner)
		m_securityScanner->setBinaryView(m_data);

	if (m_healthDashboard)
		m_healthDashboard->setBinaryView(m_data);

	if (m_diffWidget)
		m_diffWidget->setBinaryView(m_data);

	if (m_vectorTable)
		m_vectorTable->refresh(m_data);

	if (m_regionDetector)
	{
		m_regionDetector->setBinaryView(m_data);
		m_regionDetector->refresh();
	}

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

void Armv5SidebarWidget::onFunctionSelected(uint64_t address)
{
	// Navigate to the selected function in the view
	if (m_frame)
	{
		m_frame->navigate(m_data, address, true, true);
	}
}

}
