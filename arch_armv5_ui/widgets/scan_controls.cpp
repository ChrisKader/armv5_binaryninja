/*
 * Scan Controls Widget Implementation
 */

#include "scan_controls.h"
#include "binaryninjaapi.h"

#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QFrame>

using namespace BinaryNinja;

namespace
{

// Helper to execute a plugin command by name
void ExecutePluginCommandByName(const std::string& name, BinaryViewRef data)
{
	if (!data)
		return;

	auto commands = BinaryNinja::PluginCommand::GetList();
	for (const auto& cmd : commands)
	{
		if (cmd.GetName() == name)
		{
			BinaryNinja::PluginCommandContext ctx;
			ctx.binaryView = data;
			ctx.address = 0;
			ctx.length = 0;
			ctx.function = nullptr;
			if (cmd.IsValid(ctx))
				cmd.Execute(ctx);
			break;
		}
	}
}

}

namespace Armv5UI
{

ScanControlsWidget::ScanControlsWidget(QWidget* parent)
	: QWidget(parent)
	, m_data(nullptr)
	, m_prologueButton(nullptr)
	, m_callTargetButton(nullptr)
	, m_pointerButton(nullptr)
	, m_orphanButton(nullptr)
	, m_cleanupButton(nullptr)
	, m_functionCountLabel(nullptr)
	, m_architectureLabel(nullptr)
	, m_viewTypeLabel(nullptr)
{
	setupUI();
}

void ScanControlsWidget::setupUI()
{
	// Global stylesheet for this widget
	setStyleSheet(
		"QGroupBox {"
		"  font-weight: bold;"
		"  font-size: 11px;"
		"  color: #ffffff;"
		"  border: 1px solid #3a3a3a;"
		"  border-radius: 4px;"
		"  margin-top: 8px;"
		"  padding-top: 8px;"
		"}"
		"QGroupBox::title {"
		"  subcontrol-origin: margin;"
		"  subcontrol-position: top left;"
		"  left: 8px;"
		"  padding: 0 4px;"
		"  background-color: #252525;"
		"}"
		"QLabel {"
		"  color: #cccccc;"
		"  font-size: 11px;"
		"}"
		"QPushButton {"
		"  background-color: #3a3c3e;"
		"  color: #cccccc;"
		"  border: 1px solid #4a4a4a;"
		"  border-radius: 3px;"
		"  padding: 6px 12px;"
		"  font-size: 11px;"
		"}"
		"QPushButton:hover {"
		"  background-color: #4a4c4e;"
		"  color: #ffffff;"
		"}"
		"QPushButton:pressed {"
		"  background-color: #2a2c2e;"
		"}"
	);

	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(8, 8, 8, 8);
	layout->setSpacing(12);

	// --- Stats Group ---
	QGroupBox* statsGroup = new QGroupBox("Analysis Stats", this);
	QVBoxLayout* statsLayout = new QVBoxLayout(statsGroup);
	statsLayout->setSpacing(4);

	m_viewTypeLabel = new QLabel("View Type: -", statsGroup);
	m_architectureLabel = new QLabel("Architecture: -", statsGroup);
	m_functionCountLabel = new QLabel("Functions: 0", statsGroup);

	statsLayout->addWidget(m_viewTypeLabel);
	statsLayout->addWidget(m_architectureLabel);
	statsLayout->addWidget(m_functionCountLabel);
	statsGroup->setLayout(statsLayout);
	layout->addWidget(statsGroup);

	// --- Scan Buttons Group ---
	QGroupBox* scanGroup = new QGroupBox("Individual Scans", this);
	QVBoxLayout* scanLayout = new QVBoxLayout(scanGroup);
	scanLayout->setSpacing(6);

	m_prologueButton = new QPushButton("Run Prologue Scan", scanGroup);
	m_prologueButton->setToolTip("Scan for function prologues (PUSH, STMFD patterns)");
	scanLayout->addWidget(m_prologueButton);

	m_callTargetButton = new QPushButton("Run Call Target Scan", scanGroup);
	m_callTargetButton->setToolTip("Scan for BL/BLX call targets");
	scanLayout->addWidget(m_callTargetButton);

	m_pointerButton = new QPushButton("Run Pointer Target Scan", scanGroup);
	m_pointerButton->setToolTip("Scan for code pointers in data tables");
	scanLayout->addWidget(m_pointerButton);

	m_orphanButton = new QPushButton("Run Orphan Code Scan", scanGroup);
	m_orphanButton->setToolTip("Scan for orphaned code blocks");
	scanLayout->addWidget(m_orphanButton);

	// Separator
	QFrame* separator = new QFrame(scanGroup);
	separator->setFrameShape(QFrame::HLine);
	separator->setStyleSheet("QFrame { background-color: #3a3a3a; max-height: 1px; }");
	scanLayout->addWidget(separator);

	m_cleanupButton = new QPushButton("Run Cleanup Pass", scanGroup);
	m_cleanupButton->setToolTip("Remove invalid auto-discovered functions");
	m_cleanupButton->setStyleSheet(
		"QPushButton {"
		"  background-color: #5a3a3a;"
		"  border-color: #6a4a4a;"
		"}"
		"QPushButton:hover { background-color: #6a4a4a; }"
		"QPushButton:pressed { background-color: #4a2a2a; }"
	);
	scanLayout->addWidget(m_cleanupButton);

	scanGroup->setLayout(scanLayout);
	layout->addWidget(scanGroup);

	// Stretch at bottom
	layout->addStretch();

	setLayout(layout);

	// Connect signals
	connect(m_prologueButton, &QPushButton::clicked, this, &ScanControlsWidget::onPrologueScanClicked);
	connect(m_callTargetButton, &QPushButton::clicked, this, &ScanControlsWidget::onCallTargetScanClicked);
	connect(m_pointerButton, &QPushButton::clicked, this, &ScanControlsWidget::onPointerScanClicked);
	connect(m_orphanButton, &QPushButton::clicked, this, &ScanControlsWidget::onOrphanScanClicked);
	connect(m_cleanupButton, &QPushButton::clicked, this, &ScanControlsWidget::onCleanupClicked);
}

void ScanControlsWidget::refresh(BinaryViewRef data)
{
	m_data = data;
	updateStats();
}

void ScanControlsWidget::updateStats()
{
	if (!m_data)
	{
		m_viewTypeLabel->setText("View Type: -");
		m_architectureLabel->setText("Architecture: -");
		m_functionCountLabel->setText("Functions: 0");
		return;
	}

	// View type
	std::string typeName = m_data->GetTypeName();
	m_viewTypeLabel->setText(QString("View Type: %1").arg(QString::fromStdString(typeName)));

	// Architecture
	Ref<Architecture> arch = m_data->GetDefaultArchitecture();
	std::string archName = arch ? arch->GetName() : "unknown";
	m_architectureLabel->setText(QString("Architecture: %1").arg(QString::fromStdString(archName)));

	// Function count
	size_t funcCount = m_data->GetAnalysisFunctionList().size();
	m_functionCountLabel->setText(QString("Functions: %1").arg(funcCount));
}

void ScanControlsWidget::onPrologueScanClicked()
{
	ExecutePluginCommandByName("ARMv5\\Scans\\Run Prologue Scan", m_data);
}

void ScanControlsWidget::onCallTargetScanClicked()
{
	ExecutePluginCommandByName("ARMv5\\Scans\\Run Call Target Scan", m_data);
}

void ScanControlsWidget::onPointerScanClicked()
{
	ExecutePluginCommandByName("ARMv5\\Scans\\Run Pointer Target Scan", m_data);
}

void ScanControlsWidget::onOrphanScanClicked()
{
	ExecutePluginCommandByName("ARMv5\\Scans\\Run Orphan Code Scan", m_data);
}

void ScanControlsWidget::onCleanupClicked()
{
	ExecutePluginCommandByName("ARMv5\\Scans\\Run Cleanup Pass", m_data);
}

}
