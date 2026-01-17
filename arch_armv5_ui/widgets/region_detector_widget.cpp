/*
 * Region Detector Widget Implementation
 */

#include "region_detector_widget.h"
#include "binaryninjaapi.h"
#include "analysis/region_detector.h"
#include "theme.h"

#include <QtWidgets/QHeaderView>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QApplication>
#include <QtWidgets/QScrollArea>
#include <QtGui/QColor>

using namespace BinaryNinja;

namespace Armv5UI
{

// ============================================================================
// RegionResultsModel
// ============================================================================

RegionResultsModel::RegionResultsModel(QObject* parent)
	: TreeResultsModel(parent)
{
	setColumns({"", "Start", "End", "Size", "Type", "Name", "Entropy", "Code%", "Conf"},
		{24, 85, 85, 65, 70, 100, 55, 50, 55});
}

void RegionResultsModel::setRegions(const std::vector<DetectedRegionUI>& regions)
{
	beginResetModel();
	m_regions = regions;
	endResetModel();
}

std::vector<DetectedRegionUI> RegionResultsModel::getSelectedRegions() const
{
	std::vector<DetectedRegionUI> selected;
	for (const auto& r : m_regions)
	{
		if (r.selected)
			selected.push_back(r);
	}
	return selected;
}

const DetectedRegionUI* RegionResultsModel::getRegionAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_regions.size()))
		return nullptr;
	return &m_regions[row];
}

void RegionResultsModel::sort(int column, Qt::SortOrder order)
{
	beginResetModel();
	std::sort(m_regions.begin(), m_regions.end(),
		[column, order](const DetectedRegionUI& a, const DetectedRegionUI& b) {
			bool less = false;
			switch (column)
			{
			case ColStart:
				less = a.start < b.start;
				break;
			case ColEnd:
				less = a.end < b.end;
				break;
			case ColSize:
				less = (a.end - a.start) < (b.end - b.start);
				break;
			case ColType:
				less = a.type < b.type;
				break;
			case ColEntropy:
				less = a.entropy < b.entropy;
				break;
			case ColCodeDens:
				less = a.codeDensity < b.codeDensity;
				break;
			default:
				less = a.start < b.start;
				break;
			}
			return order == Qt::AscendingOrder ? less : !less;
		});
	endResetModel();
}

int RegionResultsModel::itemCount() const
{
	return static_cast<int>(m_regions.size());
}

bool RegionResultsModel::isItemSelected(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_regions.size()))
		return false;
	return m_regions[row].selected;
}

void RegionResultsModel::setItemSelected(int row, bool selected)
{
	if (row >= 0 && row < static_cast<int>(m_regions.size()))
		m_regions[row].selected = selected;
}

void RegionResultsModel::setSelected(int row, bool selected)
{
	setItemSelected(row, selected);
}

void RegionResultsModel::selectByType(const QString& type)
{
	for (size_t i = 0; i < m_regions.size(); i++)
	{
		if (type == "Code" && m_regions[i].type == "Code")
			m_regions[i].selected = true;
		else if (type == "Data" && (m_regions[i].type == "Data" || m_regions[i].type == "RWData"))
			m_regions[i].selected = true;
	}
}

uint64_t RegionResultsModel::itemAddress(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_regions.size()))
		return 0;
	return m_regions[row].start;
}

QVariant RegionResultsModel::itemData(int row, int column, int role) const
{
	if (row < 0 || row >= static_cast<int>(m_regions.size()))
		return QVariant();

	const DetectedRegionUI& region = m_regions[row];

	if (role == Qt::DisplayRole)
	{
		switch (column)
		{
		case ColStart:
			return QString("0x%1").arg(region.start, 8, 16, QChar('0'));
		case ColEnd:
			return QString("0x%1").arg(region.end, 8, 16, QChar('0'));
		case ColSize:
		{
			uint64_t size = region.end - region.start;
			if (size >= 1024 * 1024)
				return QString("%1 MB").arg(size / (1024 * 1024));
			else if (size >= 1024)
				return QString("%1 KB").arg(size / 1024);
			return QString("%1 B").arg(size);
		}
		case ColType:
			return region.type;
		case ColName:
			return region.name;
		case ColEntropy:
			return QString::number(region.entropy, 'f', 2);
		case ColCodeDens:
			return QString("%1%").arg(static_cast<int>(region.codeDensity * 100));
		case ColConfidence:
			return region.confidence;
		default:
			return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		// Color by type
		if (region.type == "Code")
			return getThemeColor(BlueStandardHighlightColor);
		else if (region.type == "Data" || region.type == "RWData")
			return getThemeColor(GreenStandardHighlightColor);
		else if (region.type == "MMIO")
			return getThemeColor(OrangeStandardHighlightColor);
		else if (region.type == "Padding" || region.type == "BSS")
			return getThemeColor(CommentColor);
		else if (region.type == "Compressed")
			return getThemeColor(RedStandardHighlightColor);
		else if (region.type == "Strings")
			return getThemeColor(YellowStandardHighlightColor);
		return QVariant();
	}
	else if (role == Qt::BackgroundRole)
	{
		if (region.selected)
			return getThemeColor(SelectionColor);
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(region.start);
	}
	else if (role == Qt::ToolTipRole)
	{
		return region.description;
	}
	else if (role == Qt::TextAlignmentRole)
	{
		if (column == ColSize || column == ColEntropy || column == ColCodeDens)
			return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
	}

	return QVariant();
}

QVariant RegionResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_regions.size()))
		return QVariant();

	const DetectedRegionUI& region = m_regions[parentRow];

	// Detail rows:
	// 0: Description
	// 1: Permissions
	// 2: String density

	if (role == Qt::DisplayRole)
	{
		if (detailRow == 0 && column == ColName)
		{
			return region.description.isEmpty() ? "No description" : region.description;
		}
		else if (detailRow == 1 && column == ColName)
		{
			QString perms;
			perms += region.readable ? "R" : "-";
			perms += region.writable ? "W" : "-";
			perms += region.executable ? "X" : "-";
			return QString("Permissions: %1 | Alignment: %2").arg(perms).arg(region.alignment);
		}
		else if (detailRow == 2 && column == ColName)
		{
			return QString("String density: %1%").arg(static_cast<int>(region.stringDensity * 100));
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		return getThemeColor(CommentColor);
	}

	return QVariant();
}

int RegionResultsModel::detailRowCount(int parentRow) const
{
	Q_UNUSED(parentRow);
	return 3;  // Description, permissions, string density
}

// ============================================================================
// RegionDetectorWidget
// ============================================================================

RegionDetectorWidget::RegionDetectorWidget(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void RegionDetectorWidget::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void RegionDetectorWidget::refresh()
{
	if (m_data)
		m_statusBar->setStatus("Ready to scan");
}

QWidget* RegionDetectorWidget::createSettingsWidget()
{
	m_settingsPanel = new QWidget(this);
	QVBoxLayout* layout = new QVBoxLayout(m_settingsPanel);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(4);

	// Preset selector row
	QHBoxLayout* presetRow = new QHBoxLayout();
	presetRow->addWidget(new QLabel("Preset:", m_settingsPanel));
	
	m_presetCombo = new QComboBox(m_settingsPanel);
	m_presetCombo->addItem("Default");
	m_presetCombo->addItem("Aggressive (More Regions)");
	m_presetCombo->addItem("Conservative (Fewer False Positives)");
	m_presetCombo->addItem("Custom");
	m_presetCombo->setMaximumWidth(200);
	presetRow->addWidget(m_presetCombo);
	presetRow->addStretch();
	layout->addLayout(presetRow);

	// Compact settings row using horizontal layout
	QHBoxLayout* settingsRow = new QHBoxLayout();
	settingsRow->setSpacing(12);

	// Entropy group
	settingsRow->addWidget(new QLabel("Entropy:", m_settingsPanel));
	m_codeEntropyMin = new QDoubleSpinBox(m_settingsPanel);
	m_codeEntropyMin->setRange(0.0, 8.0);
	m_codeEntropyMin->setValue(4.5);
	m_codeEntropyMin->setMaximumWidth(55);
	m_codeEntropyMin->setToolTip("Minimum entropy for code regions (typical ARM code: 4.5-7.0)");
	settingsRow->addWidget(m_codeEntropyMin);
	settingsRow->addWidget(new QLabel("-", m_settingsPanel));
	m_codeEntropyMax = new QDoubleSpinBox(m_settingsPanel);
	m_codeEntropyMax->setRange(0.0, 8.0);
	m_codeEntropyMax->setValue(7.0);
	m_codeEntropyMax->setMaximumWidth(55);
	m_codeEntropyMax->setToolTip("Maximum entropy for code regions (>7.5 usually indicates compressed/encrypted data)");
	settingsRow->addWidget(m_codeEntropyMax);

	// Code density
	settingsRow->addWidget(new QLabel("Code%:", m_settingsPanel));
	m_minCodeDensity = new QDoubleSpinBox(m_settingsPanel);
	m_minCodeDensity->setRange(0.0, 1.0);
	m_minCodeDensity->setSingleStep(0.05);
	m_minCodeDensity->setValue(0.7);
	m_minCodeDensity->setMaximumWidth(55);
	m_minCodeDensity->setToolTip("Minimum percentage of valid instructions to classify as code");
	settingsRow->addWidget(m_minCodeDensity);

	// Min size
	settingsRow->addWidget(new QLabel("Min:", m_settingsPanel));
	m_minRegionSize = new QSpinBox(m_settingsPanel);
	m_minRegionSize->setRange(16, 65536);
	m_minRegionSize->setValue(64);
	m_minRegionSize->setSuffix(" B");
	m_minRegionSize->setMaximumWidth(75);
	m_minRegionSize->setToolTip("Minimum region size to report");
	settingsRow->addWidget(m_minRegionSize);

	// Options
	m_mergeRegions = new QCheckBox("Merge", m_settingsPanel);
	m_mergeRegions->setChecked(true);
	m_mergeRegions->setToolTip("Merge adjacent regions of the same type");
	settingsRow->addWidget(m_mergeRegions);

	m_detectMMIO = new QCheckBox("MMIO", m_settingsPanel);
	m_detectMMIO->setChecked(true);
	m_detectMMIO->setToolTip("Detect memory-mapped I/O regions based on address patterns");
	settingsRow->addWidget(m_detectMMIO);

	settingsRow->addStretch();
	layout->addLayout(settingsRow);

	// Initialize other settings (hidden but used)
	m_compressedEntropyMin = new QDoubleSpinBox(m_settingsPanel);
	m_compressedEntropyMin->setValue(7.5);
	m_compressedEntropyMin->hide();

	m_minCodeRegion = new QSpinBox(m_settingsPanel);
	m_minCodeRegion->setValue(256);
	m_minCodeRegion->hide();

	m_paddingThreshold = new QSpinBox(m_settingsPanel);
	m_paddingThreshold->setValue(16);
	m_paddingThreshold->hide();

	m_windowSize = new QSpinBox(m_settingsPanel);
	m_windowSize->setValue(256);
	m_windowSize->hide();

	m_windowStep = new QSpinBox(m_settingsPanel);
	m_windowStep->setValue(64);
	m_windowStep->hide();

	m_preferredAlignment = new QComboBox(m_settingsPanel);
	m_preferredAlignment->addItem("4 KB", 4096);
	m_preferredAlignment->hide();

	m_useAlignmentHints = new QCheckBox(m_settingsPanel);
	m_useAlignmentHints->setChecked(true);
	m_useAlignmentHints->hide();

	m_detectLiteralPools = new QCheckBox(m_settingsPanel);
	m_detectLiteralPools->setChecked(true);
	m_detectLiteralPools->hide();

	return m_settingsPanel;
}

QWidget* RegionDetectorWidget::createFilterBar()
{
	m_filterBar = new FilterBar(this);
	m_filterBar->addCustomCombo("Type", {"All", "Code", "Data", "MMIO", "Padding", "Compressed", "Strings"});
	m_filterBar->addSearchBox("Filter regions...");
	m_filterBar->addPresetButton("Select Code", "Select all code regions");
	m_filterBar->addPresetButton("Select Data", "Select all data regions");
	return m_filterBar;
}

QWidget* RegionDetectorWidget::createResultsView()
{
	m_model = new RegionResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);
	m_treeView->setAlternatingRowColors(true);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_treeView->setSortingEnabled(true);
	m_treeView->setRootIsDecorated(true);
	m_treeView->setUniformRowHeights(true);
	m_treeView->setExpandsOnDoubleClick(false);
	m_treeView->setStyleSheet(
		"QTreeView {"
		"  background-color: #1e1e1e;"
		"  alternate-background-color: #252525;"
		"  color: #cccccc;"
		"  border: none;"
		"  font-size: 11px;"
		"}"
		"QTreeView::item:selected {"
		"  background-color: #3a4a5a;"
		"  color: #ffffff;"
		"}"
		"QTreeView::branch { background-color: #1e1e1e; }"
		"QHeaderView::section {"
		"  background-color: #2a2a2a;"
		"  color: #aaaaaa;"
		"  border: none;"
		"  border-bottom: 1px solid #3a3a3a;"
		"  padding: 4px 8px;"
		"  font-size: 11px;"
		"  font-weight: bold;"
		"}"
	);

	// Set column widths
	m_treeView->setColumnWidth(RegionResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(RegionResultsModel::ColStart, 85);
	m_treeView->setColumnWidth(RegionResultsModel::ColEnd, 85);
	m_treeView->setColumnWidth(RegionResultsModel::ColSize, 65);
	m_treeView->setColumnWidth(RegionResultsModel::ColType, 70);
	m_treeView->setColumnWidth(RegionResultsModel::ColEntropy, 55);
	m_treeView->setColumnWidth(RegionResultsModel::ColCodeDens, 50);
	m_treeView->header()->setStretchLastSection(true);

	// Default sort by start address
	m_treeView->sortByColumn(RegionResultsModel::ColStart, Qt::AscendingOrder);

	return m_treeView;
}

void RegionDetectorWidget::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &RegionDetectorWidget::onRunClicked);
		connect(m_controlBar, &AnalysisControlBar::resetClicked, this, &RegionDetectorWidget::onResetClicked);
		connect(m_controlBar, &AnalysisControlBar::applyClicked, this, &RegionDetectorWidget::onApplyClicked);
	}

	if (m_filterBar)
	{
		connect(m_filterBar, &FilterBar::filtersChanged, this, &RegionDetectorWidget::onFiltersChanged);
		connect(m_filterBar, &FilterBar::presetClicked, [this](const QString& preset) {
			m_model->selectNone();
			if (preset == "Select Code")
				m_model->selectByType("Code");
			else if (preset == "Select Data")
				m_model->selectByType("Data");
			updateStatusBar();
		});
	}

	if (m_presetCombo)
	{
		connect(m_presetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
			this, &RegionDetectorWidget::onPresetChanged);
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &RegionDetectorWidget::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &RegionDetectorWidget::onItemDoubleClicked);
	}

	if (m_model)
	{
		connect(m_model, &QAbstractItemModel::dataChanged, this, &RegionDetectorWidget::onSelectionChanged);
	}
}

void RegionDetectorWidget::onRunClicked()
{
	scanRegions();
}

void RegionDetectorWidget::onResetClicked()
{
	m_model->setRegions({});
	if (m_preview)
		m_preview->clear();
	m_statusBar->setStatus("Ready to scan");
	m_statusBar->setSummary("");
	m_controlBar->setSelectionCount(0);
}

void RegionDetectorWidget::onApplyClicked()
{
	if (!m_data)
		return;

	auto selected = m_model->getSelectedRegions();
	if (selected.empty())
	{
		QMessageBox::information(this, "Apply Regions", "No regions selected.");
		return;
	}

	// Convert back to engine format
	std::vector<Armv5Analysis::DetectedRegion> regions;
	for (const auto& uiR : selected)
	{
		Armv5Analysis::DetectedRegion r;
		r.start = uiR.start;
		r.end = uiR.end;
		r.name = uiR.name.toStdString();
		r.description = uiR.description.toStdString();
		r.entropy = uiR.entropy;
		r.codeDensity = uiR.codeDensity;
		r.readable = uiR.readable;
		r.writable = uiR.writable;
		r.executable = uiR.executable;
		
		// Map type string back to enum
		if (uiR.type == "Code") r.type = Armv5Analysis::RegionType::Code;
		else if (uiR.type == "Data") r.type = Armv5Analysis::RegionType::Data;
		else if (uiR.type == "RWData") r.type = Armv5Analysis::RegionType::RWData;
		else if (uiR.type == "BSS") r.type = Armv5Analysis::RegionType::BSS;
		else if (uiR.type == "LiteralPool") r.type = Armv5Analysis::RegionType::LiteralPool;
		else if (uiR.type == "Strings") r.type = Armv5Analysis::RegionType::StringTable;
		else if (uiR.type == "Vectors") r.type = Armv5Analysis::RegionType::VectorTable;
		else if (uiR.type == "JumpTable") r.type = Armv5Analysis::RegionType::JumpTable;
		else if (uiR.type == "MMIO") r.type = Armv5Analysis::RegionType::MMIO;
		else if (uiR.type == "Padding") r.type = Armv5Analysis::RegionType::Padding;
		else if (uiR.type == "Compressed") r.type = Armv5Analysis::RegionType::Compressed;
		else r.type = Armv5Analysis::RegionType::Unknown;
		
		regions.push_back(r);
	}

	// Apply to binary view
	Armv5Analysis::RegionDetector detector(m_data);
	detector.ApplyRegions(regions);

	QMessageBox::information(this, "Apply Regions",
		QString("Applied %1 region(s) as segments/sections.").arg(selected.size()));
	
	emit regionsApplied();
	emit analysisApplied(selected.size());
}

void RegionDetectorWidget::onFiltersChanged()
{
	// TODO: Implement filtering
	updateStatusBar();
}

void RegionDetectorWidget::onPresetChanged(int index)
{
	if (index < 3)  // Not custom
		applyPreset(index);
}

void RegionDetectorWidget::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	// Toggle expansion
	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);

	// Show preview
	if (auto* region = m_model->getRegionAt(index.row()))
	{
		if (m_preview)
			m_preview->showHex(region->start, std::min<uint64_t>(region->end - region->start, 128));
	}
}

void RegionDetectorWidget::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (auto* region = m_model->getRegionAt(index.row()))
	{
		emit regionSelected(region->start);
		navigateToAddress(region->start);
	}
}

void RegionDetectorWidget::onSelectionChanged()
{
	updateStatusBar();
}

void RegionDetectorWidget::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int selected = m_model->selectedCount();

	m_statusBar->setSummary("Regions", total, "Selected", selected);
	m_controlBar->setSelectionCount(selected);
}

void RegionDetectorWidget::applyPreset(int index)
{
	switch (index)
	{
	case 0:  // Default
		m_codeEntropyMin->setValue(4.5);
		m_codeEntropyMax->setValue(7.0);
		m_compressedEntropyMin->setValue(7.5);
		m_minCodeDensity->setValue(0.7);
		m_minRegionSize->setValue(64);
		m_minCodeRegion->setValue(256);
		m_paddingThreshold->setValue(16);
		m_windowSize->setValue(256);
		m_windowStep->setValue(64);
		break;
	case 1:  // Aggressive
		m_codeEntropyMin->setValue(4.0);
		m_codeEntropyMax->setValue(7.5);
		m_compressedEntropyMin->setValue(7.8);
		m_minCodeDensity->setValue(0.5);
		m_minRegionSize->setValue(32);
		m_minCodeRegion->setValue(64);
		m_paddingThreshold->setValue(8);
		m_windowSize->setValue(128);
		m_windowStep->setValue(32);
		break;
	case 2:  // Conservative
		m_codeEntropyMin->setValue(5.0);
		m_codeEntropyMax->setValue(6.5);
		m_compressedEntropyMin->setValue(7.5);
		m_minCodeDensity->setValue(0.85);
		m_minRegionSize->setValue(256);
		m_minCodeRegion->setValue(512);
		m_paddingThreshold->setValue(32);
		m_windowSize->setValue(512);
		m_windowStep->setValue(128);
		break;
	default:  // Custom - don't change
		break;
	}
}

void RegionDetectorWidget::scanRegions()
{
	if (!m_data)
		return;

	m_statusBar->setStatus("Scanning...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	// Build settings from UI
	Armv5Analysis::RegionDetectionSettings settings;
	settings.codeEntropyMin = m_codeEntropyMin->value();
	settings.codeEntropyMax = m_codeEntropyMax->value();
	settings.compressedEntropyMin = m_compressedEntropyMin->value();
	settings.minCodeDensity = m_minCodeDensity->value();
	settings.minRegionSize = m_minRegionSize->value();
	settings.minCodeRegion = m_minCodeRegion->value();
	settings.paddingThreshold = m_paddingThreshold->value();
	settings.windowSize = m_windowSize->value();
	settings.windowStep = m_windowStep->value();
	settings.preferredAlignment = m_preferredAlignment->currentData().toUInt();
	settings.useAlignmentHints = m_useAlignmentHints->isChecked();
	settings.detectLiteralPools = m_detectLiteralPools->isChecked();
	settings.detectMMIOPatterns = m_detectMMIO->isChecked();
	settings.mergeAdjacentRegions = m_mergeRegions->isChecked();

	// Run detection
	Armv5Analysis::RegionDetector detector(m_data);
	auto results = detector.Detect(settings);

	// Convert to UI format
	std::vector<DetectedRegionUI> uiRegions;
	for (const auto& r : results)
	{
		DetectedRegionUI uiR;
		uiR.start = r.start;
		uiR.end = r.end;
		uiR.type = QString::fromUtf8(Armv5Analysis::RegionTypeToString(r.type));
		uiR.confidence = QString::fromUtf8(Armv5Analysis::ConfidenceToString(r.confidence));
		uiR.name = QString::fromStdString(r.name);
		uiR.description = QString::fromStdString(r.description);
		uiR.entropy = r.entropy;
		uiR.codeDensity = r.codeDensity;
		uiR.stringDensity = r.stringDensity;
		uiR.alignment = r.alignment;
		uiR.readable = r.readable;
		uiR.writable = r.writable;
		uiR.executable = r.executable;
		uiR.selected = true;  // Select all by default
		uiRegions.push_back(uiR);
	}

	m_model->setRegions(uiRegions);
	
	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

}  // namespace Armv5UI

