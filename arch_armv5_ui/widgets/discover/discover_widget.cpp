/*
 * Discover Widget - Implementation
 */

#include "discover_widget.h"
#include "analysis/function_detector.h"
#include "analysis/string_detector.h"
#include "analysis/structure_detector.h"
#include "analysis/crypto_detector.h"
#include "analysis/entropy_analyzer.h"

#include <QtWidgets/QApplication>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QTabBar>
#include <QtGui/QClipboard>

using namespace BinaryNinja;

namespace Armv5UI
{

// ============================================================================
// FunctionDetectorTab
// ============================================================================

FunctionDetectorTab::FunctionDetectorTab(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void FunctionDetectorTab::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void FunctionDetectorTab::refresh()
{
	// Re-run detection if we have data
	if (m_data)
		onRunClicked();
}

QWidget* FunctionDetectorTab::createSettingsWidget()
{
	m_settings = new DetectorSettingsWidget(this);
	
	// Add Global tab
	m_settings->addGlobalTab();
	
	// Add Prologue tab
	m_settings->addTab("Prologue", {
		{"PUSH {regs, lr}", 1.50, 0.50},
		{"SUB sp, sp, #imm", 0.80, 0.50},
		{"MOV r11, sp (frame)", 0.60, 0.50},
		{"STMFD sp!, {regs}", 1.20, 0.50},
		{"GCC prologue pattern", 1.30, 0.50},
		{"ARMCC prologue pattern", 1.30, 0.50},
		{"IAR prologue pattern", 1.30, 0.50},
	});
	
	// Add Call Targets tab
	m_settings->addTab("Call", {
		{"BL target", 2.00, 0.30},
		{"BLX target", 2.00, 0.30},
		{"Indirect call target", 1.00, 0.40},
		{"High xref density", 1.20, 0.50},
		{"Pointer table entry", 1.50, 0.40},
		{"Vector table target", 2.50, 0.30},
	});
	
	// Add Structural tab
	m_settings->addTab("Structural", {
		{"After BX LR / POP {pc}", 1.30, 0.50},
		{"After tail call", 1.00, 0.50},
		{"Alignment boundary", 0.30, 0.50},
		{"After literal pool", 1.40, 0.50},
		{"After padding", 1.20, 0.50},
	});
	
	// Add Advanced tab
	m_settings->addTab("Advanced", {
		{"Thunk pattern (LDR pc)", 1.80, 0.50},
		{"Trampoline pattern", 1.50, 0.50},
		{"Switch/case handler", 1.00, 0.40},
		{"Interrupt prologue", 1.50, 0.50},
		{"Task entry pattern", 1.50, 0.50},
		{"Callback pattern", 1.00, 0.50},
		{"Instruction sequence", 0.80, 0.50},
		{"Entropy transition", 0.70, 0.50},
	});
	
	// Add Penalties tab
	m_settings->addTab("Penalties", {
		{"Mid-instruction", 1.00, 0.00},
		{"Inside existing function", 0.80, 0.00},
		{"Data region", 0.90, 0.00},
		{"Invalid instruction", 0.50, 0.00},
		{"Unlikely pattern", 0.30, 0.00},
	});
	
	return m_settings;
}

QWidget* FunctionDetectorTab::createFilterBar()
{
	m_filterBar = new FilterBar(this);
	m_filterBar->addScoreFilter(0.0, 1.0, 0.0);
	m_filterBar->addStatusFilter({"All", "New", "Existing"});
	m_filterBar->addModeFilter({"All", "ARM", "Thumb"});
	m_filterBar->addSearchBox("Filter by address...");
	m_filterBar->addPresetButton("New Only", "Show only new functions");
	m_filterBar->addPresetButton("High Conf", "Show high confidence results");
	return m_filterBar;
}

QWidget* FunctionDetectorTab::createResultsView()
{
	m_model = new FunctionResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);

	// Native BN tree view styling
	m_treeView->setFont(getMonospaceFont(this));
	m_treeView->setRootIsDecorated(true);
	m_treeView->setUniformRowHeights(true);
	m_treeView->setSortingEnabled(true);
	m_treeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setAllColumnsShowFocus(true);
	m_treeView->setExpandsOnDoubleClick(false);

	// Header configuration
	m_treeView->header()->setSectionResizeMode(QHeaderView::Interactive);
	m_treeView->header()->setStretchLastSection(true);

	// Set column widths
	m_treeView->setColumnWidth(FunctionResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(FunctionResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(FunctionResultsModel::ColSize, 50);
	m_treeView->setColumnWidth(FunctionResultsModel::ColScore, 55);
	m_treeView->setColumnWidth(FunctionResultsModel::ColMode, 28);
	m_treeView->setColumnWidth(FunctionResultsModel::ColStatus, 55);
	m_treeView->setColumnWidth(FunctionResultsModel::ColXrefs, 45);
	m_treeView->setColumnWidth(FunctionResultsModel::ColCallees, 45);

	// Default sort by address ascending
	m_treeView->sortByColumn(FunctionResultsModel::ColAddress, Qt::AscendingOrder);

	return m_treeView;
}

void FunctionDetectorTab::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &FunctionDetectorTab::onRunClicked);
		connect(m_controlBar, &AnalysisControlBar::stopClicked, this, &FunctionDetectorTab::onStopClicked);
		connect(m_controlBar, &AnalysisControlBar::resetClicked, this, &FunctionDetectorTab::onResetClicked);
		connect(m_controlBar, &AnalysisControlBar::applyClicked, this, &FunctionDetectorTab::onApplyClicked);
		connect(m_controlBar, &AnalysisControlBar::exportClicked, this, &FunctionDetectorTab::onExportClicked);
	}
	
	if (m_filterBar)
	{
		connect(m_filterBar, &FilterBar::filtersChanged, this, &FunctionDetectorTab::onFiltersChanged);
		connect(m_filterBar, &FilterBar::presetClicked, [this](const QString& preset) {
			if (preset == "New Only")
				m_model->selectNewOnly();
			else if (preset == "High Conf")
				m_model->selectByScore(m_settings ? m_settings->highConfidenceScore() : 0.8);
			updateStatusBar();
		});
	}
	
	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &FunctionDetectorTab::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &FunctionDetectorTab::onItemDoubleClicked);
	}
	
	if (m_model)
	{
		connect(m_model, &QAbstractItemModel::dataChanged, this, &FunctionDetectorTab::onSelectionChanged);
	}
	
	// Keyboard shortcuts
	auto* selectAll = new QShortcut(QKeySequence::SelectAll, m_treeView);
	connect(selectAll, &QShortcut::activated, [this]() {
		m_model->selectAll();
		updateStatusBar();
	});
	
	auto* invert = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_I), m_treeView);
	connect(invert, &QShortcut::activated, [this]() {
		m_model->invertSelection();
		updateStatusBar();
	});
	
	auto* copy = new QShortcut(QKeySequence::Copy, m_treeView);
	connect(copy, &QShortcut::activated, this, &FunctionDetectorTab::copySelectedToClipboard);
}

void FunctionDetectorTab::onRunClicked()
{
	if (!m_data || m_running)
		return;
	
	m_running = true;
	m_controlBar->setRunning(true);
	m_statusBar->setStatus("Scanning...");
	m_statusBar->setProgress(0);
	QApplication::processEvents();
	
	// Build settings from UI
	Armv5Analysis::FunctionDetectionSettings settings;
	if (m_settings)
	{
		settings.minimumScore = m_settings->minimumScore();
		settings.highConfidenceScore = m_settings->highConfidenceScore();
		settings.scanExecutableOnly = m_settings->scanExecutableOnly();
		settings.respectExistingFunctions = m_settings->respectExistingFunctions();
		settings.detectArmFunctions = m_settings->detectArmFunctions();
		settings.detectThumbFunctions = m_settings->detectThumbFunctions();
		settings.alignmentPreference = m_settings->alignmentPreference();
		
		// TODO: Map detector settings to actual FunctionDetectionSettings
	}
	
	// Run detection
	Armv5Analysis::FunctionDetector detector(m_data);
	auto results = detector.Detect(settings);
	
	m_statusBar->setProgress(80);
	QApplication::processEvents();
	
	// Populate model
	populateResults(results);
	
	m_statusBar->setProgress(-1);
	m_running = false;
	m_controlBar->setRunning(false);
	
	// Auto-select high confidence new functions
	m_model->selectByScore(settings.highConfidenceScore);
	
	updateStatusBar();
}

void FunctionDetectorTab::onStopClicked()
{
	m_running = false;
	m_controlBar->setRunning(false);
	m_statusBar->setStatus("Stopped");
	m_statusBar->setProgress(-1);
}

void FunctionDetectorTab::onResetClicked()
{
	m_model->clear();
	m_preview->clear();
	m_statusBar->setStatus("Ready to scan");
	m_statusBar->setSummary("");
	m_controlBar->setSelectionCount(0);
}

void FunctionDetectorTab::onApplyClicked()
{
	if (!m_data)
		return;
	
	auto selected = m_model->getSelectedItems();
	if (selected.empty())
		return;
	
	size_t created = 0;
	auto platform = m_data->GetDefaultPlatform();
	
	for (const auto& item : selected)
	{
		if (item.isNew)
		{
			m_data->CreateUserFunction(platform, item.address);
			created++;
		}
	}
	
	QMessageBox::information(this, "Apply", 
		QString("Created %1 function(s).").arg(created));
	
	emit analysisApplied(created);
	
	// Refresh to update status
	onRunClicked();
}

void FunctionDetectorTab::onExportClicked()
{
	QString filename = QFileDialog::getSaveFileName(this, "Export Function Candidates",
		QString(), "CSV Files (*.csv);;JSON Files (*.json)");

	if (filename.isEmpty())
		return;

	auto items = m_model->getSelectedItems();
	if (items.empty())
	{
		// Export all filtered items if none selected
		for (int i = 0; i < m_model->filteredCount(); ++i)
		{
			if (auto* item = m_model->itemAt(i))
				items.push_back(*item);
		}
	}

	if (items.empty())
	{
		QMessageBox::information(this, "Export", "No results to export.");
		return;
	}

	QFile file(filename);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
	{
		QMessageBox::warning(this, "Export Error",
			QString("Could not open file for writing:\n%1").arg(filename));
		return;
	}

	QTextStream out(&file);

	if (filename.endsWith(".json", Qt::CaseInsensitive))
	{
		// JSON export
		out << "{\n  \"functions\": [\n";
		for (size_t i = 0; i < items.size(); ++i)
		{
			const auto& item = items[i];
			out << "    {\n";
			out << QString("      \"address\": \"0x%1\",\n").arg(item.address, 8, 16, QChar('0'));
			out << QString("      \"size\": %1,\n").arg(item.size);
			out << QString("      \"score\": %1,\n").arg(item.score, 0, 'f', 3);
			out << QString("      \"mode\": \"%1\",\n").arg(item.isThumb ? "Thumb" : "ARM");
			out << QString("      \"status\": \"%1\",\n").arg(item.isNew ? "New" : "Existing");
			out << QString("      \"xrefs\": %1,\n").arg(item.xrefCount);
			out << QString("      \"callees\": %1\n").arg(item.calleeCount);
			out << "    }";
			if (i < items.size() - 1)
				out << ",";
			out << "\n";
		}
		out << "  ]\n}\n";
	}
	else
	{
		// CSV export
		out << "Address,Size,Score,Mode,Status,XRefs,Callees\n";
		for (const auto& item : items)
		{
			out << QString("0x%1,").arg(item.address, 8, 16, QChar('0'));
			out << QString("%1,").arg(item.size);
			out << QString("%1,").arg(item.score, 0, 'f', 3);
			out << QString("%1,").arg(item.isThumb ? "Thumb" : "ARM");
			out << QString("%1,").arg(item.isNew ? "New" : "Existing");
			out << QString("%1,").arg(item.xrefCount);
			out << QString("%1\n").arg(item.calleeCount);
		}
	}

	file.close();
	QMessageBox::information(this, "Export Complete",
		QString("Exported %1 function candidate(s) to:\n%2").arg(items.size()).arg(filename));
}

void FunctionDetectorTab::onFiltersChanged()
{
	if (!m_model || !m_filterBar)
		return;
	
	m_model->setMinScore(m_filterBar->scoreFilter());
	m_model->setStatusFilter(m_filterBar->statusFilterIndex());
	m_model->setModeFilter(m_filterBar->modeFilterIndex());
	m_model->setSearchText(m_filterBar->searchText());
	m_model->applyFilters();
	
	updateStatusBar();
}

void FunctionDetectorTab::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;  // Ignore detail rows
	
	// Toggle expansion on click
	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);
	
	// Show preview
	if (auto* item = m_model->itemAt(index.row()))
	{
		if (m_preview)
			m_preview->showDisassembly(item->address, item->isThumb);
	}
}

void FunctionDetectorTab::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;
	
	if (auto* item = m_model->itemAt(index.row()))
	{
		navigateToAddress(item->address);
	}
}

void FunctionDetectorTab::onSelectionChanged()
{
	updateStatusBar();
}

void FunctionDetectorTab::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;
	
	int total = m_model->totalCount();
	int filtered = m_model->filteredCount();
	int selected = m_model->selectedCount();
	
	if (m_running)
		m_statusBar->setStatus("Scanning...");
	else if (total == 0)
		m_statusBar->setStatus("Ready to scan");
	else
		m_statusBar->setStatus("Complete");
	
	QString summary;
	if (filtered != total)
		summary = QString("Showing: %1/%2 | Selected: %3").arg(filtered).arg(total).arg(selected);
	else
		summary = QString("Found: %1 | Selected: %2").arg(total).arg(selected);
	m_statusBar->setSummary(summary);
	
	m_controlBar->setSelectionCount(selected);
}

void FunctionDetectorTab::copySelectedToClipboard()
{
	auto selected = m_model->getSelectedItems();
	if (selected.empty())
		return;
	
	QString text;
	for (const auto& item : selected)
	{
		text += QString("0x%1\t%2\t%3\t%4\n")
			.arg(item.address, 8, 16, QChar('0'))
			.arg(item.size)
			.arg(item.score, 0, 'f', 2)
			.arg(item.isThumb ? "Thumb" : "ARM");
	}
	
	QApplication::clipboard()->setText(text);
}

void FunctionDetectorTab::populateResults(const std::vector<Armv5Analysis::FunctionCandidate>& candidates)
{
	// Get existing functions for comparison
	std::set<uint64_t> existingFuncs;
	std::map<uint64_t, Ref<Function>> funcMap;
	for (auto& f : m_data->GetAnalysisFunctionList())
	{
		existingFuncs.insert(f->GetStart());
		funcMap[f->GetStart()] = f;
	}
	
	std::vector<FunctionResultItem> items;
	items.reserve(candidates.size());
	
	for (const auto& c : candidates)
	{
		FunctionResultItem item;
		item.address = c.address;
		item.score = c.score;
		item.isThumb = c.isThumb;
		item.isNew = existingFuncs.find(c.address) == existingFuncs.end();
		item.selected = item.isNew && item.score >= (m_settings ? m_settings->highConfidenceScore() : 0.8);
		
		// Get size and xref info
		auto it = funcMap.find(c.address);
		if (it != funcMap.end())
		{
			auto ranges = it->second->GetAddressRanges();
			if (!ranges.empty())
				item.size = ranges.back().end - c.address;
			item.calleeCount = static_cast<int>(it->second->GetCallSites().size());
		}
		item.xrefCount = static_cast<int>(m_data->GetCodeReferences(c.address).size());
		
		// Build category scores from source scores
		for (const auto& [source, score] : c.sourceScores)
		{
			QString sourceName = QString::fromUtf8(Armv5Analysis::DetectionSourceToString(source));
			QString category;
			
			// Categorize by source type
			if (sourceName.contains("prologue", Qt::CaseInsensitive) || 
				sourceName.contains("PUSH", Qt::CaseInsensitive) ||
				sourceName.contains("SUB", Qt::CaseInsensitive) ||
				sourceName.contains("STMFD", Qt::CaseInsensitive))
				category = "Prologue";
			else if (sourceName.contains("BL", Qt::CaseInsensitive) ||
				sourceName.contains("call", Qt::CaseInsensitive) ||
				sourceName.contains("target", Qt::CaseInsensitive))
				category = "Call";
			else if (sourceName.contains("After", Qt::CaseInsensitive) ||
				sourceName.contains("align", Qt::CaseInsensitive) ||
				sourceName.contains("padding", Qt::CaseInsensitive))
				category = "Structural";
			else
				category = "Advanced";
			
			item.categoryScores[category] += score;
			item.sourceScores.push_back({sourceName, category, score});
		}
		
		items.push_back(item);
	}
	
	m_model->setResults(items);
}

// ============================================================================
// StringDetectorTab
// ============================================================================

StringDetectorTab::StringDetectorTab(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void StringDetectorTab::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void StringDetectorTab::refresh()
{
	if (m_data)
		onRunClicked();
}

QWidget* StringDetectorTab::createSettingsWidget()
{
	m_settingsWidget = new QWidget(this);
	QHBoxLayout* layout = new QHBoxLayout(m_settingsWidget);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(8);

	m_detectAscii = new QCheckBox("ASCII", m_settingsWidget);
	m_detectAscii->setChecked(true);
	m_detectAscii->setToolTip("Detect ASCII (single-byte) strings");
	layout->addWidget(m_detectAscii);

	m_detectUtf8 = new QCheckBox("UTF-8", m_settingsWidget);
	m_detectUtf8->setChecked(true);
	m_detectUtf8->setToolTip("Detect UTF-8 encoded strings");
	layout->addWidget(m_detectUtf8);

	m_detectUtf16 = new QCheckBox("UTF-16", m_settingsWidget);
	m_detectUtf16->setChecked(true);
	m_detectUtf16->setToolTip("Detect UTF-16 (wide character) strings");
	layout->addWidget(m_detectUtf16);

	m_detectUnreferenced = new QCheckBox("Unreferenced", m_settingsWidget);
	m_detectUnreferenced->setChecked(true);
	m_detectUnreferenced->setToolTip("Find strings without cross-references");
	layout->addWidget(m_detectUnreferenced);

	m_categorize = new QCheckBox("Categorize", m_settingsWidget);
	m_categorize->setChecked(true);
	m_categorize->setToolTip("Categorize strings (paths, URLs, errors, etc.)");
	layout->addWidget(m_categorize);

	layout->addWidget(new QLabel("Min:", m_settingsWidget));
	m_minLength = new QSpinBox(m_settingsWidget);
	m_minLength->setRange(2, 100);
	m_minLength->setValue(4);
	m_minLength->setMaximumWidth(50);
	m_minLength->setToolTip("Minimum string length");
	layout->addWidget(m_minLength);

	layout->addWidget(new QLabel("Conf:", m_settingsWidget));
	m_minConfidence = new QDoubleSpinBox(m_settingsWidget);
	m_minConfidence->setRange(0.0, 1.0);
	m_minConfidence->setValue(0.5);
	m_minConfidence->setSingleStep(0.1);
	m_minConfidence->setMaximumWidth(55);
	m_minConfidence->setToolTip("Minimum confidence threshold");
	layout->addWidget(m_minConfidence);

	layout->addStretch();

	return m_settingsWidget;
}

QWidget* StringDetectorTab::createFilterBar()
{
	m_filterBar = new FilterBar(this);
	m_filterBar->addSearchBox("Search strings...");
	m_filterBar->addCustomCombo("Category", {"All", "Error", "Debug", "Path", "URL", "Version", "Format", "Crypto", "Hardware", "RTOS"});
	m_filterBar->addStatusFilter({"All", "New", "Existing"});
	return m_filterBar;
}

QWidget* StringDetectorTab::createResultsView()
{
	m_model = new StringResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);

	// Native BN tree view styling
	m_treeView->setFont(getMonospaceFont(this));
	m_treeView->setRootIsDecorated(true);
	m_treeView->setUniformRowHeights(true);
	m_treeView->setSortingEnabled(true);
	m_treeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setAllColumnsShowFocus(true);
	m_treeView->setExpandsOnDoubleClick(false);

	// Header configuration
	m_treeView->header()->setSectionResizeMode(QHeaderView::Interactive);
	m_treeView->header()->setStretchLastSection(true);

	m_treeView->setColumnWidth(StringResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(StringResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(StringResultsModel::ColLength, 45);
	m_treeView->setColumnWidth(StringResultsModel::ColEncoding, 55);
	m_treeView->setColumnWidth(StringResultsModel::ColCategory, 70);
	m_treeView->setColumnWidth(StringResultsModel::ColConfidence, 45);

	m_treeView->sortByColumn(StringResultsModel::ColAddress, Qt::AscendingOrder);

	return m_treeView;
}

void StringDetectorTab::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &StringDetectorTab::onRunClicked);
		connect(m_controlBar, &AnalysisControlBar::applyClicked, this, &StringDetectorTab::onApplyClicked);
		connect(m_controlBar, &AnalysisControlBar::exportClicked, this, &StringDetectorTab::onExportClicked);
	}

	if (m_filterBar)
	{
		connect(m_filterBar, &FilterBar::filtersChanged, this, &StringDetectorTab::onFiltersChanged);
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &StringDetectorTab::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &StringDetectorTab::onItemDoubleClicked);
	}
}

void StringDetectorTab::onRunClicked()
{
	if (!m_data)
		return;

	m_statusBar->setStatus("Scanning...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	// Build settings from UI
	Armv5Analysis::StringDetectionSettings settings;
	settings.minLength = m_minLength->value();
	settings.detectAscii = m_detectAscii->isChecked();
	settings.detectUtf8 = m_detectUtf8->isChecked();
	settings.detectUtf16 = m_detectUtf16->isChecked();
	settings.findUnreferenced = m_detectUnreferenced->isChecked();
	settings.categorizeStrings = m_categorize->isChecked();
	settings.minConfidence = m_minConfidence->value();

	// Run detection
	Armv5Analysis::StringDetector detector(m_data);
	auto results = detector.Detect(settings);

	// Populate model
	populateResults(results);

	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

void StringDetectorTab::onApplyClicked()
{
	if (!m_data || !m_model)
		return;

	auto selected = m_model->getSelectedItems();
	if (selected.empty())
	{
		QMessageBox::information(this, "Apply", "No strings selected.");
		return;
	}

	size_t created = 0;
	for (const auto& item : selected)
	{
		if (item.isNew)
		{
			// Define string at address
			m_data->DefineDataVariable(item.address, Type::ArrayType(Type::IntegerType(1, false), item.length));
			created++;
		}
	}

	QMessageBox::information(this, "Apply",
		QString("Defined %1 string(s).").arg(created));

	emit analysisApplied(created);
}

void StringDetectorTab::onExportClicked()
{
	QString filename = QFileDialog::getSaveFileName(this, "Export Detected Strings",
		QString(), "CSV Files (*.csv);;JSON Files (*.json)");

	if (filename.isEmpty())
		return;

	auto items = m_model->getSelectedItems();
	if (items.empty())
	{
		for (int i = 0; i < m_model->filteredCount(); ++i)
		{
			if (auto* item = m_model->itemAt(i))
				items.push_back(*item);
		}
	}

	if (items.empty())
	{
		QMessageBox::information(this, "Export", "No results to export.");
		return;
	}

	QFile file(filename);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
	{
		QMessageBox::warning(this, "Export Error",
			QString("Could not open file for writing:\n%1").arg(filename));
		return;
	}

	QTextStream out(&file);

	if (filename.endsWith(".json", Qt::CaseInsensitive))
	{
		out << "{\n  \"strings\": [\n";
		for (size_t i = 0; i < items.size(); ++i)
		{
			const auto& item = items[i];
			QString escaped = item.content;
			escaped.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
			out << "    {\n";
			out << QString("      \"address\": \"0x%1\",\n").arg(item.address, 8, 16, QChar('0'));
			out << QString("      \"length\": %1,\n").arg(item.length);
			out << QString("      \"encoding\": \"%1\",\n").arg(item.encoding);
			out << QString("      \"category\": \"%1\",\n").arg(item.category);
			out << QString("      \"confidence\": %1,\n").arg(item.confidence, 0, 'f', 3);
			out << QString("      \"content\": \"%1\"\n").arg(escaped);
			out << "    }";
			if (i < items.size() - 1)
				out << ",";
			out << "\n";
		}
		out << "  ]\n}\n";
	}
	else
	{
		out << "Address,Length,Encoding,Category,Confidence,Content\n";
		for (const auto& item : items)
		{
			QString escaped = item.content;
			escaped.replace("\"", "\"\"");
			out << QString("0x%1,").arg(item.address, 8, 16, QChar('0'));
			out << QString("%1,").arg(item.length);
			out << QString("%1,").arg(item.encoding);
			out << QString("%1,").arg(item.category);
			out << QString("%1,").arg(item.confidence, 0, 'f', 3);
			out << QString("\"%1\"\n").arg(escaped);
		}
	}

	file.close();
	QMessageBox::information(this, "Export Complete",
		QString("Exported %1 string(s) to:\n%2").arg(items.size()).arg(filename));
}

void StringDetectorTab::onFiltersChanged()
{
	if (!m_model || !m_filterBar)
		return;

	m_model->setCategoryFilter(m_filterBar->customComboIndex("Category"));
	m_model->setStatusFilter(m_filterBar->statusFilterIndex());
	m_model->setSearchText(m_filterBar->searchText());
	m_model->applyFilters();

	updateStatusBar();
}

void StringDetectorTab::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);

	if (auto* item = m_model->itemAt(index.row()))
	{
		if (m_preview)
			m_preview->showString(item->address, item->length);
	}
}

void StringDetectorTab::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (auto* item = m_model->itemAt(index.row()))
		navigateToAddress(item->address);
}

void StringDetectorTab::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int filtered = m_model->filteredCount();
	int selected = m_model->selectedCount();

	QString summary;
	if (filtered != total)
		summary = QString("Showing: %1/%2 | Selected: %3").arg(filtered).arg(total).arg(selected);
	else
		summary = QString("Found: %1 | Selected: %2").arg(total).arg(selected);
	m_statusBar->setSummary(summary);

	m_controlBar->setSelectionCount(selected);
}

void StringDetectorTab::populateResults(const std::vector<Armv5Analysis::DetectedString>& strings)
{
	// Get existing strings for comparison
	std::set<uint64_t> existingStrings;
	for (auto& strRef : m_data->GetStrings())
		existingStrings.insert(strRef.start);

	std::vector<StringResultItem> items;
	items.reserve(strings.size());

	for (const auto& s : strings)
	{
		StringResultItem item;
		item.address = s.address;
		item.length = s.length;
		item.content = QString::fromStdString(s.content);
		item.encoding = QString::fromUtf8(Armv5Analysis::StringDetector::EncodingToString(s.encoding));
		item.category = QString::fromUtf8(Armv5Analysis::StringDetector::CategoryToString(s.category));
		item.confidence = s.confidence;
		item.hasXrefs = s.hasXrefs;
		item.isNew = existingStrings.find(s.address) == existingStrings.end();
		item.selected = item.isNew && item.confidence >= 0.7;
		item.categoryReason = QString::fromStdString(s.categoryReason);
		items.push_back(item);
	}

	m_model->setResults(items);
}

// ============================================================================
// StructureDetectorTab
// ============================================================================

StructureDetectorTab::StructureDetectorTab(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void StructureDetectorTab::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void StructureDetectorTab::refresh()
{
	if (m_data)
		onRunClicked();
}

QWidget* StructureDetectorTab::createSettingsWidget()
{
	m_settingsWidget = new QWidget(this);
	QHBoxLayout* layout = new QHBoxLayout(m_settingsWidget);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(8);

	m_detectVtables = new QCheckBox("VTables", m_settingsWidget);
	m_detectVtables->setChecked(true);
	m_detectVtables->setToolTip("Detect C++ virtual function tables");
	layout->addWidget(m_detectVtables);

	m_detectJumpTables = new QCheckBox("Jump Tables", m_settingsWidget);
	m_detectJumpTables->setChecked(true);
	m_detectJumpTables->setToolTip("Detect switch statement jump tables");
	layout->addWidget(m_detectJumpTables);

	m_detectFuncTables = new QCheckBox("Func Ptrs", m_settingsWidget);
	m_detectFuncTables->setChecked(true);
	m_detectFuncTables->setToolTip("Detect arrays of function pointers");
	layout->addWidget(m_detectFuncTables);

	m_detectPtrArrays = new QCheckBox("Ptr Arrays", m_settingsWidget);
	m_detectPtrArrays->setChecked(true);
	m_detectPtrArrays->setToolTip("Detect generic pointer arrays");
	layout->addWidget(m_detectPtrArrays);

	m_detectIntArrays = new QCheckBox("Int Arrays", m_settingsWidget);
	m_detectIntArrays->setChecked(false);
	m_detectIntArrays->setToolTip("Detect integer arrays (noisy)");
	layout->addWidget(m_detectIntArrays);

	layout->addWidget(new QLabel("Min:", m_settingsWidget));
	m_minElements = new QSpinBox(m_settingsWidget);
	m_minElements->setRange(2, 50);
	m_minElements->setValue(3);
	m_minElements->setMaximumWidth(50);
	m_minElements->setToolTip("Minimum number of elements");
	layout->addWidget(m_minElements);

	layout->addWidget(new QLabel("Conf:", m_settingsWidget));
	m_minConfidence = new QDoubleSpinBox(m_settingsWidget);
	m_minConfidence->setRange(0.0, 1.0);
	m_minConfidence->setValue(0.5);
	m_minConfidence->setSingleStep(0.1);
	m_minConfidence->setMaximumWidth(55);
	m_minConfidence->setToolTip("Minimum confidence threshold");
	layout->addWidget(m_minConfidence);

	layout->addStretch();

	return m_settingsWidget;
}

QWidget* StructureDetectorTab::createResultsView()
{
	m_model = new StructureResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);

	// Native BN tree view styling
	m_treeView->setFont(getMonospaceFont(this));
	m_treeView->setRootIsDecorated(true);
	m_treeView->setUniformRowHeights(true);
	m_treeView->setSortingEnabled(true);
	m_treeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setAllColumnsShowFocus(true);
	m_treeView->setExpandsOnDoubleClick(false);

	// Header configuration
	m_treeView->header()->setSectionResizeMode(QHeaderView::Interactive);
	m_treeView->header()->setStretchLastSection(true);

	m_treeView->setColumnWidth(StructureResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(StructureResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(StructureResultsModel::ColType, 80);
	m_treeView->setColumnWidth(StructureResultsModel::ColElements, 60);
	m_treeView->setColumnWidth(StructureResultsModel::ColSize, 60);
	m_treeView->setColumnWidth(StructureResultsModel::ColConfidence, 45);

	m_treeView->sortByColumn(StructureResultsModel::ColAddress, Qt::AscendingOrder);

	return m_treeView;
}

void StructureDetectorTab::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &StructureDetectorTab::onRunClicked);
		connect(m_controlBar, &AnalysisControlBar::applyClicked, this, &StructureDetectorTab::onApplyClicked);
		connect(m_controlBar, &AnalysisControlBar::exportClicked, this, &StructureDetectorTab::onExportClicked);
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &StructureDetectorTab::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &StructureDetectorTab::onItemDoubleClicked);
	}
}

void StructureDetectorTab::onRunClicked()
{
	if (!m_data)
		return;

	m_statusBar->setStatus("Scanning...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	// Build settings from UI
	Armv5Analysis::StructureDetectionSettings settings;
	settings.detectVtables = m_detectVtables->isChecked();
	settings.detectJumpTables = m_detectJumpTables->isChecked();
	settings.detectFunctionTables = m_detectFuncTables->isChecked();
	settings.detectPointerArrays = m_detectPtrArrays->isChecked();
	settings.detectIntegerArrays = m_detectIntArrays->isChecked();
	settings.minElements = m_minElements->value();
	settings.minConfidence = m_minConfidence->value();

	// Run detection
	Armv5Analysis::StructureDetector detector(m_data);
	auto results = detector.Detect(settings);

	// Populate model
	populateResults(results);

	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

void StructureDetectorTab::onApplyClicked()
{
	if (!m_data || !m_model)
		return;

	auto selected = m_model->getSelectedItems();
	if (selected.empty())
	{
		QMessageBox::information(this, "Apply", "No structures selected.");
		return;
	}

	size_t created = 0;
	auto platform = m_data->GetDefaultPlatform();

	for (const auto& item : selected)
	{
		// For function tables, create functions at targets
		if (item.type == "FunctionTable" || item.type == "VTable")
		{
			for (uint64_t target : item.elements)
			{
				if (!m_data->GetAnalysisFunction(platform, target))
				{
					m_data->CreateUserFunction(platform, target);
					created++;
				}
			}
		}
	}

	QMessageBox::information(this, "Apply",
		QString("Created %1 function(s) from structure targets.").arg(created));

	emit analysisApplied(created);
}

void StructureDetectorTab::onExportClicked()
{
	QString filename = QFileDialog::getSaveFileName(this, "Export Detected Structures",
		QString(), "CSV Files (*.csv);;JSON Files (*.json)");

	if (filename.isEmpty())
		return;

	auto items = m_model->getSelectedItems();
	if (items.empty())
	{
		for (int i = 0; i < m_model->filteredCount(); ++i)
		{
			if (auto* item = m_model->itemAt(i))
				items.push_back(*item);
		}
	}

	if (items.empty())
	{
		QMessageBox::information(this, "Export", "No results to export.");
		return;
	}

	QFile file(filename);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
	{
		QMessageBox::warning(this, "Export Error",
			QString("Could not open file for writing:\n%1").arg(filename));
		return;
	}

	QTextStream out(&file);

	if (filename.endsWith(".json", Qt::CaseInsensitive))
	{
		out << "{\n  \"structures\": [\n";
		for (size_t i = 0; i < items.size(); ++i)
		{
			const auto& item = items[i];
			out << "    {\n";
			out << QString("      \"address\": \"0x%1\",\n").arg(item.address, 8, 16, QChar('0'));
			out << QString("      \"type\": \"%1\",\n").arg(item.type);
			out << QString("      \"elements\": %1,\n").arg(item.elementCount);
			out << QString("      \"size\": %1,\n").arg(item.size);
			out << QString("      \"confidence\": %1,\n").arg(item.confidence, 0, 'f', 3);
			out << "      \"targets\": [";
			for (size_t j = 0; j < item.elements.size(); ++j)
			{
				out << QString("\"0x%1\"").arg(item.elements[j], 8, 16, QChar('0'));
				if (j < item.elements.size() - 1)
					out << ", ";
			}
			out << "],\n";
			out << QString("      \"description\": \"%1\"\n").arg(item.description);
			out << "    }";
			if (i < items.size() - 1)
				out << ",";
			out << "\n";
		}
		out << "  ]\n}\n";
	}
	else
	{
		out << "Address,Type,Elements,Size,Confidence,Description\n";
		for (const auto& item : items)
		{
			out << QString("0x%1,").arg(item.address, 8, 16, QChar('0'));
			out << QString("%1,").arg(item.type);
			out << QString("%1,").arg(item.elementCount);
			out << QString("%1,").arg(item.size);
			out << QString("%1,").arg(item.confidence, 0, 'f', 3);
			out << QString("\"%1\"\n").arg(item.description);
		}
	}

	file.close();
	QMessageBox::information(this, "Export Complete",
		QString("Exported %1 structure(s) to:\n%2").arg(items.size()).arg(filename));
}

void StructureDetectorTab::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);

	if (auto* item = m_model->itemAt(index.row()))
	{
		if (m_preview)
			m_preview->showHex(item->address, std::min<size_t>(item->size, 128));
	}
}

void StructureDetectorTab::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (auto* item = m_model->itemAt(index.row()))
		navigateToAddress(item->address);
}

void StructureDetectorTab::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int filtered = m_model->filteredCount();
	int selected = m_model->selectedCount();

	QString summary;
	if (filtered != total)
		summary = QString("Showing: %1/%2 | Selected: %3").arg(filtered).arg(total).arg(selected);
	else
		summary = QString("Found: %1 | Selected: %2").arg(total).arg(selected);
	m_statusBar->setSummary(summary);

	m_controlBar->setSelectionCount(selected);
}

void StructureDetectorTab::populateResults(const std::vector<Armv5Analysis::DetectedStructure>& structures)
{
	std::vector<StructureResultItem> items;
	items.reserve(structures.size());

	for (const auto& s : structures)
	{
		StructureResultItem item;
		item.address = s.address;
		item.size = s.size;
		item.type = QString::fromUtf8(Armv5Analysis::StructureDetector::TypeToString(s.type));
		item.elementCount = s.elementCount;
		item.confidence = s.confidence;
		item.description = QString::fromStdString(s.description);
		item.isNew = s.isNew;
		item.selected = item.isNew && item.confidence >= 0.7;

		for (uint64_t elem : s.elements)
			item.elements.push_back(elem);
		for (const auto& name : s.elementNames)
			item.elementNames.push_back(QString::fromStdString(name));

		items.push_back(item);
	}

	m_model->setResults(items);
}

// ============================================================================
// CryptoDetectorTab
// ============================================================================

CryptoDetectorTab::CryptoDetectorTab(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void CryptoDetectorTab::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void CryptoDetectorTab::refresh()
{
	if (m_data)
		onRunClicked();
}

QWidget* CryptoDetectorTab::createSettingsWidget()
{
	m_settingsWidget = new QWidget(this);
	QHBoxLayout* layout = new QHBoxLayout(m_settingsWidget);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(8);

	m_detectAES = new QCheckBox("AES", m_settingsWidget);
	m_detectAES->setChecked(true);
	m_detectAES->setToolTip("Detect AES S-boxes and key schedule constants");
	layout->addWidget(m_detectAES);

	m_detectDES = new QCheckBox("DES", m_settingsWidget);
	m_detectDES->setChecked(true);
	m_detectDES->setToolTip("Detect DES S-boxes and permutation tables");
	layout->addWidget(m_detectDES);

	m_detectSHA = new QCheckBox("SHA", m_settingsWidget);
	m_detectSHA->setChecked(true);
	m_detectSHA->setToolTip("Detect SHA-1/SHA-256/SHA-512 constants");
	layout->addWidget(m_detectSHA);

	m_detectMD5 = new QCheckBox("MD5", m_settingsWidget);
	m_detectMD5->setChecked(true);
	m_detectMD5->setToolTip("Detect MD5 sine table constants");
	layout->addWidget(m_detectMD5);

	m_detectCRC = new QCheckBox("CRC", m_settingsWidget);
	m_detectCRC->setChecked(true);
	m_detectCRC->setToolTip("Detect CRC-16/CRC-32 lookup tables");
	layout->addWidget(m_detectCRC);

	m_detectTEA = new QCheckBox("TEA", m_settingsWidget);
	m_detectTEA->setChecked(true);
	m_detectTEA->setToolTip("Detect TEA/XTEA delta constants");
	layout->addWidget(m_detectTEA);

	m_detectBlowfish = new QCheckBox("Blowfish", m_settingsWidget);
	m_detectBlowfish->setChecked(true);
	m_detectBlowfish->setToolTip("Detect Blowfish P-array and S-boxes");
	layout->addWidget(m_detectBlowfish);

	m_detectChaCha = new QCheckBox("ChaCha", m_settingsWidget);
	m_detectChaCha->setChecked(true);
	m_detectChaCha->setToolTip("Detect ChaCha20/Salsa20 constants");
	layout->addWidget(m_detectChaCha);

	layout->addWidget(new QLabel("Conf:", m_settingsWidget));
	m_minConfidence = new QDoubleSpinBox(m_settingsWidget);
	m_minConfidence->setRange(0.0, 1.0);
	m_minConfidence->setValue(0.7);
	m_minConfidence->setSingleStep(0.1);
	m_minConfidence->setMaximumWidth(55);
	m_minConfidence->setToolTip("Minimum confidence threshold");
	layout->addWidget(m_minConfidence);

	layout->addStretch();

	return m_settingsWidget;
}

QWidget* CryptoDetectorTab::createResultsView()
{
	m_model = new CryptoResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);

	// Native BN tree view styling
	m_treeView->setFont(getMonospaceFont(this));
	m_treeView->setUniformRowHeights(true);
	m_treeView->setSortingEnabled(true);
	m_treeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setAllColumnsShowFocus(true);
	m_treeView->setExpandsOnDoubleClick(false);

	// Header configuration
	m_treeView->header()->setSectionResizeMode(QHeaderView::Interactive);
	m_treeView->header()->setStretchLastSection(true);

	m_treeView->setColumnWidth(CryptoResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(CryptoResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(CryptoResultsModel::ColAlgorithm, 80);
	m_treeView->setColumnWidth(CryptoResultsModel::ColConstType, 80);
	m_treeView->setColumnWidth(CryptoResultsModel::ColSize, 55);
	m_treeView->setColumnWidth(CryptoResultsModel::ColConfidence, 45);

	m_treeView->sortByColumn(CryptoResultsModel::ColConfidence, Qt::DescendingOrder);

	return m_treeView;
}

void CryptoDetectorTab::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &CryptoDetectorTab::onRunClicked);
		connect(m_controlBar, &AnalysisControlBar::exportClicked, this, &CryptoDetectorTab::onExportClicked);
		m_controlBar->setApplyVisible(false);  // No apply for crypto - just for identification
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &CryptoDetectorTab::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &CryptoDetectorTab::onItemDoubleClicked);
	}
}

void CryptoDetectorTab::onRunClicked()
{
	if (!m_data)
		return;

	m_statusBar->setStatus("Scanning...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	// Build settings from UI
	Armv5Analysis::CryptoDetectionSettings settings;
	settings.detectAES = m_detectAES->isChecked();
	settings.detectDES = m_detectDES->isChecked();
	settings.detectSHA = m_detectSHA->isChecked();
	settings.detectMD5 = m_detectMD5->isChecked();
	settings.detectCRC = m_detectCRC->isChecked();
	settings.detectTEA = m_detectTEA->isChecked();
	settings.detectBlowfish = m_detectBlowfish->isChecked();
	settings.detectChaCha = m_detectChaCha->isChecked();
	settings.minConfidence = m_minConfidence->value();

	// Run detection
	Armv5Analysis::CryptoDetector detector(m_data);
	auto results = detector.Detect(settings);

	// Populate model
	populateResults(results);

	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

void CryptoDetectorTab::onExportClicked()
{
	QString filename = QFileDialog::getSaveFileName(this, "Export Crypto Constants",
		QString(), "CSV Files (*.csv);;JSON Files (*.json)");

	if (filename.isEmpty())
		return;

	std::vector<CryptoResultItem> items;
	for (int i = 0; i < m_model->filteredCount(); ++i)
	{
		if (auto* item = m_model->itemAt(i))
			items.push_back(*item);
	}

	if (items.empty())
	{
		QMessageBox::information(this, "Export", "No results to export.");
		return;
	}

	QFile file(filename);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
	{
		QMessageBox::warning(this, "Export Error",
			QString("Could not open file for writing:\n%1").arg(filename));
		return;
	}

	QTextStream out(&file);

	if (filename.endsWith(".json", Qt::CaseInsensitive))
	{
		out << "{\n  \"crypto_constants\": [\n";
		for (size_t i = 0; i < items.size(); ++i)
		{
			const auto& item = items[i];
			out << "    {\n";
			out << QString("      \"address\": \"0x%1\",\n").arg(item.address, 8, 16, QChar('0'));
			out << QString("      \"algorithm\": \"%1\",\n").arg(item.algorithm);
			out << QString("      \"type\": \"%1\",\n").arg(item.constantType);
			out << QString("      \"size\": %1,\n").arg(item.size);
			out << QString("      \"confidence\": %1,\n").arg(item.confidence, 0, 'f', 3);
			out << QString("      \"partial\": %1,\n").arg(item.isPartialMatch ? "true" : "false");
			out << QString("      \"description\": \"%1\"\n").arg(item.description);
			out << "    }";
			if (i < items.size() - 1)
				out << ",";
			out << "\n";
		}
		out << "  ]\n}\n";
	}
	else
	{
		out << "Address,Algorithm,Type,Size,Confidence,Partial,Description\n";
		for (const auto& item : items)
		{
			out << QString("0x%1,").arg(item.address, 8, 16, QChar('0'));
			out << QString("%1,").arg(item.algorithm);
			out << QString("%1,").arg(item.constantType);
			out << QString("%1,").arg(item.size);
			out << QString("%1,").arg(item.confidence, 0, 'f', 3);
			out << QString("%1,").arg(item.isPartialMatch ? "Yes" : "No");
			out << QString("\"%1\"\n").arg(item.description);
		}
	}

	file.close();
	QMessageBox::information(this, "Export Complete",
		QString("Exported %1 crypto constant(s) to:\n%2").arg(items.size()).arg(filename));
}

void CryptoDetectorTab::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid())
		return;

	if (auto* item = m_model->itemAt(index.row()))
	{
		if (m_preview)
			m_preview->showHex(item->address, std::min<size_t>(item->size, 128));
	}
}

void CryptoDetectorTab::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid())
		return;

	if (auto* item = m_model->itemAt(index.row()))
		navigateToAddress(item->address);
}

void CryptoDetectorTab::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int filtered = m_model->filteredCount();

	QString summary;
	if (filtered != total)
		summary = QString("Showing: %1/%2").arg(filtered).arg(total);
	else
		summary = QString("Found: %1 crypto constants").arg(total);
	m_statusBar->setSummary(summary);
}

void CryptoDetectorTab::populateResults(const std::vector<Armv5Analysis::CryptoConstant>& constants)
{
	std::vector<CryptoResultItem> items;
	items.reserve(constants.size());

	for (const auto& c : constants)
	{
		CryptoResultItem item;
		item.address = c.address;
		item.algorithm = QString::fromUtf8(Armv5Analysis::CryptoDetector::AlgorithmToString(c.algorithm));
		item.constantType = QString::fromUtf8(Armv5Analysis::CryptoDetector::ConstTypeToString(c.constType));
		item.size = c.size;
		item.confidence = c.confidence;
		item.description = QString::fromStdString(c.description);
		item.isPartialMatch = c.isPartialMatch;
		item.selected = false;
		items.push_back(item);
	}

	m_model->setResults(items);
}

// ============================================================================
// EntropyAnalyzerTab
// ============================================================================

EntropyAnalyzerTab::EntropyAnalyzerTab(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void EntropyAnalyzerTab::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to analyze" : "No binary loaded");
}

void EntropyAnalyzerTab::refresh()
{
	if (m_data)
		onRunClicked();
}

QWidget* EntropyAnalyzerTab::createSettingsWidget()
{
	m_settingsWidget = new QWidget(this);
	QHBoxLayout* layout = new QHBoxLayout(m_settingsWidget);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(8);

	layout->addWidget(new QLabel("High:", m_settingsWidget));
	m_highThreshold = new QDoubleSpinBox(m_settingsWidget);
	m_highThreshold->setRange(5.0, 8.0);
	m_highThreshold->setValue(7.5);
	m_highThreshold->setSingleStep(0.1);
	m_highThreshold->setMaximumWidth(55);
	m_highThreshold->setToolTip("High entropy threshold (typically >7.5 for encrypted/compressed)");
	layout->addWidget(m_highThreshold);

	layout->addWidget(new QLabel("Low:", m_settingsWidget));
	m_lowThreshold = new QDoubleSpinBox(m_settingsWidget);
	m_lowThreshold->setRange(0.0, 5.0);
	m_lowThreshold->setValue(4.0);
	m_lowThreshold->setSingleStep(0.5);
	m_lowThreshold->setMaximumWidth(55);
	m_lowThreshold->setToolTip("Low entropy threshold (typically <4.0 for text/strings)");
	layout->addWidget(m_lowThreshold);

	layout->addWidget(new QLabel("Block:", m_settingsWidget));
	m_blockSize = new QSpinBox(m_settingsWidget);
	m_blockSize->setRange(64, 4096);
	m_blockSize->setValue(256);
	m_blockSize->setMaximumWidth(60);
	m_blockSize->setToolTip("Analysis block size in bytes");
	layout->addWidget(m_blockSize);

	layout->addWidget(new QLabel("Min:", m_settingsWidget));
	m_minRegionSize = new QSpinBox(m_settingsWidget);
	m_minRegionSize->setRange(128, 8192);
	m_minRegionSize->setValue(512);
	m_minRegionSize->setMaximumWidth(60);
	m_minRegionSize->setToolTip("Minimum region size to report");
	layout->addWidget(m_minRegionSize);

	m_skipCode = new QCheckBox("Skip Code", m_settingsWidget);
	m_skipCode->setToolTip("Skip executable sections");
	layout->addWidget(m_skipCode);

	m_mergeRegions = new QCheckBox("Merge", m_settingsWidget);
	m_mergeRegions->setChecked(true);
	m_mergeRegions->setToolTip("Merge adjacent regions of same type");
	layout->addWidget(m_mergeRegions);

	layout->addStretch();

	return m_settingsWidget;
}

QWidget* EntropyAnalyzerTab::createResultsView()
{
	m_model = new EntropyResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);

	// Native BN tree view styling
	m_treeView->setFont(getMonospaceFont(this));
	m_treeView->setUniformRowHeights(true);
	m_treeView->setSortingEnabled(true);
	m_treeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setAllColumnsShowFocus(true);
	m_treeView->setExpandsOnDoubleClick(false);

	// Header configuration
	m_treeView->header()->setSectionResizeMode(QHeaderView::Interactive);
	m_treeView->header()->setStretchLastSection(true);

	m_treeView->setColumnWidth(EntropyResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(EntropyResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(EntropyResultsModel::ColSize, 70);
	m_treeView->setColumnWidth(EntropyResultsModel::ColEntropy, 60);
	m_treeView->setColumnWidth(EntropyResultsModel::ColType, 100);

	m_treeView->sortByColumn(EntropyResultsModel::ColEntropy, Qt::DescendingOrder);

	return m_treeView;
}

void EntropyAnalyzerTab::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &EntropyAnalyzerTab::onRunClicked);
		connect(m_controlBar, &AnalysisControlBar::exportClicked, this, &EntropyAnalyzerTab::onExportClicked);
		m_controlBar->setApplyVisible(false);  // No apply for entropy - informational only
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &EntropyAnalyzerTab::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &EntropyAnalyzerTab::onItemDoubleClicked);
	}
}

void EntropyAnalyzerTab::onRunClicked()
{
	if (!m_data)
		return;

	m_statusBar->setStatus("Analyzing entropy...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	// Build settings from UI
	Armv5Analysis::EntropyAnalysisSettings settings;
	settings.blockSize = m_blockSize->value();
	settings.minRegionSize = m_minRegionSize->value();
	settings.highEntropyThreshold = m_highThreshold->value();
	settings.lowEntropyThreshold = m_lowThreshold->value();
	settings.mergeAdjacentRegions = m_mergeRegions->isChecked();
	settings.skipCodeSections = m_skipCode->isChecked();

	// Run analysis
	Armv5Analysis::EntropyAnalyzer analyzer(m_data);
	auto results = analyzer.Analyze(settings);

	// Populate model
	populateResults(results);

	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

void EntropyAnalyzerTab::onExportClicked()
{
	QString filename = QFileDialog::getSaveFileName(this, "Export Entropy Analysis",
		QString(), "CSV Files (*.csv);;JSON Files (*.json)");

	if (filename.isEmpty())
		return;

	std::vector<EntropyResultItem> items;
	for (int i = 0; i < m_model->filteredCount(); ++i)
	{
		if (auto* item = m_model->itemAt(i))
			items.push_back(*item);
	}

	if (items.empty())
	{
		QMessageBox::information(this, "Export", "No results to export.");
		return;
	}

	QFile file(filename);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
	{
		QMessageBox::warning(this, "Export Error",
			QString("Could not open file for writing:\n%1").arg(filename));
		return;
	}

	QTextStream out(&file);

	if (filename.endsWith(".json", Qt::CaseInsensitive))
	{
		out << "{\n  \"entropy_regions\": [\n";
		for (size_t i = 0; i < items.size(); ++i)
		{
			const auto& item = items[i];
			out << "    {\n";
			out << QString("      \"address\": \"0x%1\",\n").arg(item.address, 8, 16, QChar('0'));
			out << QString("      \"size\": %1,\n").arg(item.size);
			out << QString("      \"entropy\": %1,\n").arg(item.entropy, 0, 'f', 4);
			out << QString("      \"type\": \"%1\",\n").arg(item.regionType);
			out << QString("      \"description\": \"%1\"\n").arg(item.description);
			out << "    }";
			if (i < items.size() - 1)
				out << ",";
			out << "\n";
		}
		out << "  ]\n}\n";
	}
	else
	{
		out << "Address,Size,Entropy,Type,Description\n";
		for (const auto& item : items)
		{
			out << QString("0x%1,").arg(item.address, 8, 16, QChar('0'));
			out << QString("%1,").arg(item.size);
			out << QString("%1,").arg(item.entropy, 0, 'f', 4);
			out << QString("%1,").arg(item.regionType);
			out << QString("\"%1\"\n").arg(item.description);
		}
	}

	file.close();
	QMessageBox::information(this, "Export Complete",
		QString("Exported %1 entropy region(s) to:\n%2").arg(items.size()).arg(filename));
}

void EntropyAnalyzerTab::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid())
		return;

	if (auto* item = m_model->itemAt(index.row()))
	{
		if (m_preview)
			m_preview->showHex(item->address, std::min<size_t>(item->size, 128));
	}
}

void EntropyAnalyzerTab::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid())
		return;

	if (auto* item = m_model->itemAt(index.row()))
		navigateToAddress(item->address);
}

void EntropyAnalyzerTab::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int filtered = m_model->filteredCount();

	QString summary;
	if (filtered != total)
		summary = QString("Showing: %1/%2 regions").arg(filtered).arg(total);
	else
		summary = QString("Found: %1 regions").arg(total);
	m_statusBar->setSummary(summary);
}

void EntropyAnalyzerTab::populateResults(const std::vector<Armv5Analysis::EntropyRegion>& regions)
{
	std::vector<EntropyResultItem> items;
	items.reserve(regions.size());

	for (const auto& r : regions)
	{
		EntropyResultItem item;
		item.address = r.address;
		item.size = r.size;
		item.entropy = r.entropy;
		item.regionType = QString::fromUtf8(Armv5Analysis::EntropyAnalyzer::RegionTypeToString(r.type));
		item.description = QString::fromStdString(r.description);
		item.selected = false;
		items.push_back(item);
	}

	m_model->setResults(items);
}

// ============================================================================
// DiscoverWidget
// ============================================================================

DiscoverWidget::DiscoverWidget(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void DiscoverWidget::setupUI()
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Tab bar header - centered
	QWidget* tabBarContainer = new QWidget(this);
	QHBoxLayout* tabBarLayout = new QHBoxLayout(tabBarContainer);
	tabBarLayout->setContentsMargins(0, 0, 0, 0);
	tabBarLayout->setSpacing(0);

	m_tabs = new QTabWidget(this);
	m_tabs->setDocumentMode(true);
	// Use native BN styling - no custom stylesheet

	// Extract tab bar and center it
	QTabBar* tabBar = m_tabs->tabBar();
	tabBar->setExpanding(false);
	tabBar->setParent(tabBarContainer);  // Reparent to our container
	tabBarLayout->addStretch();
	tabBarLayout->addWidget(tabBar);
	tabBarLayout->addStretch();

	layout->addWidget(tabBarContainer);

	// Create tabs
	m_functionsTab = new FunctionDetectorTab(this);
	m_stringsTab = new StringDetectorTab(this);
	m_structuresTab = new StructureDetectorTab(this);
	m_cryptoTab = new CryptoDetectorTab(this);
	m_entropyTab = new EntropyAnalyzerTab(this);
	
	m_tabs->addTab(m_functionsTab, "Functions");
	m_tabs->addTab(m_stringsTab, "Strings");
	m_tabs->addTab(m_structuresTab, "Structures");
	m_tabs->addTab(m_cryptoTab, "Crypto");
	m_tabs->addTab(m_entropyTab, "Entropy");
	
	layout->addWidget(m_tabs);
	
	// Forward signals
	connect(m_functionsTab, &FunctionDetectorTab::addressSelected, this, &DiscoverWidget::addressSelected);
	connect(m_functionsTab, &FunctionDetectorTab::analysisApplied, this, &DiscoverWidget::analysisApplied);
	connect(m_stringsTab, &StringDetectorTab::addressSelected, this, &DiscoverWidget::addressSelected);
	connect(m_structuresTab, &StructureDetectorTab::addressSelected, this, &DiscoverWidget::addressSelected);
	connect(m_cryptoTab, &CryptoDetectorTab::addressSelected, this, &DiscoverWidget::addressSelected);
	connect(m_entropyTab, &EntropyAnalyzerTab::addressSelected, this, &DiscoverWidget::addressSelected);
}

void DiscoverWidget::setBinaryView(BinaryViewRef data)
{
	m_data = data;
	m_functionsTab->setBinaryView(data);
	m_stringsTab->setBinaryView(data);
	m_structuresTab->setBinaryView(data);
	m_cryptoTab->setBinaryView(data);
	m_entropyTab->setBinaryView(data);
}

void DiscoverWidget::refresh()
{
	// Refresh the current tab
	int idx = m_tabs->currentIndex();
	switch (idx)
	{
	case 0: m_functionsTab->refresh(); break;
	case 1: m_stringsTab->refresh(); break;
	case 2: m_structuresTab->refresh(); break;
	case 3: m_cryptoTab->refresh(); break;
	case 4: m_entropyTab->refresh(); break;
	}
}

}  // namespace Armv5UI
