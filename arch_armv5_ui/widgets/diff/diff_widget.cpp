/*
 * Firmware Diff Widget Implementation
 */

#include "diff_widget.h"
#include "binaryninjaapi.h"
#include "theme.h"

#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QApplication>
#include <QtWidgets/QScrollBar>
#include <QtGui/QTextCursor>

#include <algorithm>
#include <set>
#include <map>

using namespace BinaryNinja;

namespace Armv5UI
{

// ============================================================================
// DiffResultsModel
// ============================================================================

DiffResultsModel::DiffResultsModel(QObject* parent)
	: TreeResultsModel(parent)
{
	setColumns({"", "Δ", "Address", "Name", "Change", "Size Δ", "Detail"},
		{24, 24, 85, 140, 70, 60, -1});
}

void DiffResultsModel::setDiffs(const std::vector<FunctionDiff>& diffs)
{
	beginResetModel();
	m_allDiffs = diffs;
	applyFilters();
	endResetModel();
}

const FunctionDiff* DiffResultsModel::getDiffAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return nullptr;
	return &m_allDiffs[m_filteredIndices[row]];
}

std::vector<FunctionDiff> DiffResultsModel::getSelectedDiffs() const
{
	std::vector<FunctionDiff> result;
	for (int idx : m_filteredIndices)
	{
		if (m_allDiffs[idx].selected)
			result.push_back(m_allDiffs[idx]);
	}
	return result;
}

void DiffResultsModel::setTypeFilter(int filter)
{
	m_typeFilter = filter;
}

void DiffResultsModel::setSearchText(const QString& text)
{
	m_searchText = text.toLower();
}

void DiffResultsModel::applyFilters()
{
	beginResetModel();
	m_filteredIndices.clear();
	
	for (size_t i = 0; i < m_allDiffs.size(); i++)
	{
		const auto& d = m_allDiffs[i];
		
		// Type filter
		if (m_typeFilter > 0)
		{
			if (m_typeFilter == 1 && d.type != DiffType::Added) continue;
			if (m_typeFilter == 2 && d.type != DiffType::Removed) continue;
			if (m_typeFilter == 3 && d.type != DiffType::Modified) continue;
		}
		
		// Exclude unchanged unless showing all
		if (m_typeFilter == 0 && d.type == DiffType::Unchanged)
			continue;
		
		// Search filter
		if (!m_searchText.isEmpty())
		{
			if (!d.name.toLower().contains(m_searchText))
				continue;
		}
		
		m_filteredIndices.push_back(static_cast<int>(i));
	}
	
	endResetModel();
}

void DiffResultsModel::sort(int column, Qt::SortOrder order)
{
	beginResetModel();
	
	std::sort(m_filteredIndices.begin(), m_filteredIndices.end(),
		[this, column, order](int a, int b) {
			const auto& dA = m_allDiffs[a];
			const auto& dB = m_allDiffs[b];
			
			bool less = false;
			switch (column)
			{
			case ColChange:
				less = static_cast<int>(dA.type) < static_cast<int>(dB.type);
				break;
			case ColAddress:
				less = dA.baseAddress < dB.baseAddress;
				break;
			case ColName:
				less = dA.name < dB.name;
				break;
			case ColSizeDelta:
				less = dA.sizeDelta < dB.sizeDelta;
				break;
			default:
				less = dA.baseAddress < dB.baseAddress;
				break;
			}
			
			return order == Qt::AscendingOrder ? less : !less;
		});
	
	endResetModel();
}

int DiffResultsModel::itemCount() const
{
	return static_cast<int>(m_filteredIndices.size());
}

bool DiffResultsModel::isItemSelected(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return false;
	return m_allDiffs[m_filteredIndices[row]].selected;
}

void DiffResultsModel::setItemSelected(int row, bool selected)
{
	if (row >= 0 && row < static_cast<int>(m_filteredIndices.size()))
		m_allDiffs[m_filteredIndices[row]].selected = selected;
}

uint64_t DiffResultsModel::itemAddress(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	return m_allDiffs[m_filteredIndices[row]].baseAddress;
}

QString DiffResultsModel::typeString(DiffType type) const
{
	switch (type)
	{
	case DiffType::Added: return "Added";
	case DiffType::Removed: return "Removed";
	case DiffType::Modified: return "Modified";
	case DiffType::Unchanged: return "Same";
	default: return "?";
	}
}

QString DiffResultsModel::typeIcon(DiffType type) const
{
	switch (type)
	{
	case DiffType::Added: return "+";
	case DiffType::Removed: return "-";
	case DiffType::Modified: return "~";
	case DiffType::Unchanged: return "=";
	default: return "?";
	}
}

QColor DiffResultsModel::typeColor(DiffType type) const
{
	switch (type)
	{
	case DiffType::Added: return getThemeColor(GreenStandardHighlightColor);
	case DiffType::Removed: return getThemeColor(RedStandardHighlightColor);
	case DiffType::Modified: return getThemeColor(YellowStandardHighlightColor);
	default: return getThemeColor(CommentColor);
	}
}

QVariant DiffResultsModel::itemData(int row, int column, int role) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& d = m_allDiffs[m_filteredIndices[row]];

	if (role == Qt::DisplayRole)
	{
		switch (column)
		{
		case ColChange:
			return typeIcon(d.type);
		case ColAddress:
			if (d.type == DiffType::Removed)
				return QString("0x%1").arg(d.baseAddress, 8, 16, QChar('0'));
			return QString("0x%1").arg(d.compareAddress > 0 ? d.compareAddress : d.baseAddress, 8, 16, QChar('0'));
		case ColName:
			return d.name;
		case ColChange2:
			return typeString(d.type);
		case ColSizeDelta:
			if (d.sizeDelta == 0)
				return "-";
			return QString("%1%2").arg(d.sizeDelta > 0 ? "+" : "").arg(d.sizeDelta);
		case ColDetail:
			return d.changeDetail;
		default:
			return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		if (column == ColChange || column == ColChange2 || column == ColSizeDelta)
			return typeColor(d.type);
	}
	else if (role == Qt::BackgroundRole)
	{
		if (d.selected)
			return getThemeColor(SelectionColor);
	}
	else if (role == Qt::TextAlignmentRole)
	{
		if (column == ColChange || column == ColSizeDelta)
			return static_cast<int>(Qt::AlignCenter);
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(d.baseAddress);
	}

	return QVariant();
}

QVariant DiffResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& d = m_allDiffs[m_filteredIndices[parentRow]];

	if (role == Qt::DisplayRole && column == ColName)
	{
		if (d.type == DiffType::Modified && detailRow < static_cast<int>(d.changedByteRanges.size()))
		{
			const auto& range = d.changedByteRanges[detailRow];
			return QString("Bytes changed: 0x%1-0x%2")
				.arg(range.first, 8, 16, QChar('0'))
				.arg(range.second, 8, 16, QChar('0'));
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		return getThemeColor(CommentColor);
	}

	return QVariant();
}

int DiffResultsModel::detailRowCount(int parentRow) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	
	const auto& d = m_allDiffs[m_filteredIndices[parentRow]];
	return static_cast<int>(d.changedByteRanges.size());
}

// ============================================================================
// SideBySideView
// ============================================================================

SideBySideView::SideBySideView(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void SideBySideView::setupUI()
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Styled headers
	QWidget* headerBar = new QWidget(this);
	headerBar->setStyleSheet(
		"QWidget {"
		"  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #353535, stop:1 #2a2a2a);"
		"  border-bottom: 1px solid #1a1a1a;"
		"}"
	);
	QHBoxLayout* headerLayout = new QHBoxLayout(headerBar);
	headerLayout->setContentsMargins(8, 4, 8, 4);
	headerLayout->setSpacing(8);

	m_baseLabel = new QLabel("Base", this);
	m_baseLabel->setStyleSheet("font-weight: bold; font-size: 11px; color: #ffffff; background: transparent; border: none; padding: 2px;");
	m_compareLabel = new QLabel("Compare", this);
	m_compareLabel->setStyleSheet("font-weight: bold; font-size: 11px; color: #ffffff; background: transparent; border: none; padding: 2px;");
	headerLayout->addWidget(m_baseLabel, 1);
	headerLayout->addWidget(m_compareLabel, 1);
	layout->addWidget(headerBar);

	// Splitter with two text views
	m_splitter = new QSplitter(Qt::Horizontal, this);
	m_splitter->setStyleSheet(
		"QSplitter::handle { background-color: #3a3a3a; width: 2px; }"
	);

	m_baseView = new QTextEdit(this);
	m_baseView->setReadOnly(true);
	m_baseView->setFont(getMonospaceFont(this));
	m_baseView->setLineWrapMode(QTextEdit::NoWrap);
	m_baseView->setStyleSheet(
		"QTextEdit {"
		"  background-color: #1e1e1e;"
		"  color: #cccccc;"
		"  border: none;"
		"  font-size: 11px;"
		"}"
	);

	m_compareView = new QTextEdit(this);
	m_compareView->setReadOnly(true);
	m_compareView->setFont(getMonospaceFont(this));
	m_compareView->setLineWrapMode(QTextEdit::NoWrap);
	m_compareView->setStyleSheet(
		"QTextEdit {"
		"  background-color: #1e1e1e;"
		"  color: #cccccc;"
		"  border: none;"
		"  font-size: 11px;"
		"}"
	);

	m_splitter->addWidget(m_baseView);
	m_splitter->addWidget(m_compareView);
	m_splitter->setStretchFactor(0, 1);
	m_splitter->setStretchFactor(1, 1);

	layout->addWidget(m_splitter);

	// Sync scrolling
	connect(m_baseView->verticalScrollBar(), &QScrollBar::valueChanged,
		m_compareView->verticalScrollBar(), &QScrollBar::setValue);
	connect(m_compareView->verticalScrollBar(), &QScrollBar::valueChanged,
		m_baseView->verticalScrollBar(), &QScrollBar::setValue);
}

void SideBySideView::setBinaryViews(BinaryViewRef base, BinaryViewRef compare)
{
	m_baseData = base;
	m_compareData = compare;
}

void SideBySideView::showDiff(const FunctionDiff& diff)
{
	m_baseLabel->setText(QString("Base: 0x%1").arg(diff.baseAddress, 8, 16, QChar('0')));
	m_compareLabel->setText(QString("Compare: 0x%1").arg(diff.compareAddress, 8, 16, QChar('0')));

	if (m_baseData && diff.baseAddress > 0)
		showDisassembly(m_baseView, m_baseData, diff.baseAddress, false);
	else
		m_baseView->clear();

	if (m_compareData && diff.compareAddress > 0)
		showDisassembly(m_compareView, m_compareData, diff.compareAddress, false);
	else
		m_compareView->clear();

	highlightChanges();
}

void SideBySideView::clear()
{
	m_baseView->clear();
	m_compareView->clear();
	m_baseLabel->setText("Base");
	m_compareLabel->setText("Compare");
}

void SideBySideView::showDisassembly(QTextEdit* view, BinaryViewRef data, uint64_t address, bool isThumb)
{
	if (!data)
		return;

	Ref<Architecture> arch = data->GetDefaultArchitecture();
	if (!arch)
		return;

	if (isThumb)
	{
		uint64_t ta = address | 1;
		auto t = arch->GetAssociatedArchitectureByAddress(ta);
		if (t)
			arch = t;
	}

	view->clear();
	QTextCursor cursor = view->textCursor();
	uint64_t addr = address;
	int lineCount = 30;

	for (int i = 0; i < lineCount; i++)
	{
		DataBuffer buf = data->ReadBuffer(addr, 4);
		if (buf.GetLength() < 2)
			break;

		InstructionInfo info;
		if (!arch->GetInstructionInfo(static_cast<const uint8_t*>(buf.GetData()),
			addr, buf.GetLength(), info))
			break;

		std::vector<InstructionTextToken> tokens;
		if (!arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()),
			addr, info.length, tokens))
			break;

		QTextCharFormat addrFmt;
		addrFmt.setForeground(getTokenColor(view, AddressDisplayToken));
		cursor.insertText(QString("0x%1  ").arg(addr, 8, 16, QChar('0')), addrFmt);

		for (const auto& tok : tokens)
		{
			QTextCharFormat tokFmt;
			tokFmt.setForeground(getTokenColor(view, tok.type));
			cursor.insertText(QString::fromStdString(tok.text), tokFmt);
		}
		cursor.insertText("\n");
		addr += info.length;
	}
}

void SideBySideView::highlightChanges()
{
	// TODO: Highlight differing instructions
}

// ============================================================================
// FirmwareDiffWidget
// ============================================================================

FirmwareDiffWidget::FirmwareDiffWidget(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
	setupConnections();
}

void FirmwareDiffWidget::setupUI()
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Styled header: Base and compare file selection
	QWidget* headerBar = new QWidget(this);
	headerBar->setStyleSheet(
		"QWidget {"
		"  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3a3c3e, stop:1 #2a2c2e);"
		"  border-bottom: 1px solid #1a1a1a;"
		"}"
		"QLabel { color: #cccccc; font-size: 11px; background: transparent; border: none; }"
	);
	QHBoxLayout* headerLayout = new QHBoxLayout(headerBar);
	headerLayout->setContentsMargins(8, 6, 8, 6);
	headerLayout->setSpacing(8);

	m_baseLabel = new QLabel("Base: (current)", this);
	m_baseLabel->setStyleSheet("color: #ffffff; font-weight: bold; font-size: 11px; background: transparent; border: none;");
	headerLayout->addWidget(m_baseLabel);

	QLabel* compareLabel = new QLabel("Compare:", this);
	compareLabel->setStyleSheet("color: #aaaaaa; font-size: 11px; background: transparent; border: none;");
	headerLayout->addWidget(compareLabel);

	m_compareEdit = new QLineEdit(this);
	m_compareEdit->setReadOnly(true);
	m_compareEdit->setPlaceholderText("No file loaded");
	m_compareEdit->setStyleSheet(
		"QLineEdit {"
		"  background-color: #1e1e1e;"
		"  color: #cccccc;"
		"  border: 1px solid #3a3a3a;"
		"  border-radius: 3px;"
		"  padding: 4px 8px;"
		"  font-size: 11px;"
		"}"
	);
	headerLayout->addWidget(m_compareEdit, 1);

	m_loadButton = new QPushButton("Load...", this);
	m_loadButton->setMaximumWidth(70);
	m_loadButton->setStyleSheet(
		"QPushButton {"
		"  background-color: #3a3c3e;"
		"  color: #cccccc;"
		"  border: 1px solid #4a4a4a;"
		"  border-radius: 3px;"
		"  padding: 4px 12px;"
		"  font-size: 11px;"
		"}"
		"QPushButton:hover { background-color: #4a4c4e; color: #ffffff; }"
		"QPushButton:pressed { background-color: #2a2c2e; }"
	);
	headerLayout->addWidget(m_loadButton);

	layout->addWidget(headerBar);

	// Control bar
	m_controlBar = new AnalysisControlBar(this);
	m_controlBar->setApplyVisible(false);
	layout->addWidget(m_controlBar);

	// Filter bar
	m_filterBar = new FilterBar(this);
	m_filterBar->addCustomCombo("Change", {"All Changes", "Added", "Removed", "Modified"});
	m_filterBar->addSearchBox("Search functions...");
	m_filterBar->addPresetButton("Modified", "Show only modified functions");
	layout->addWidget(m_filterBar);

	// Splitter: Results + Side-by-side
	QSplitter* mainSplitter = new QSplitter(Qt::Vertical, this);
	mainSplitter->setStyleSheet(
		"QSplitter::handle { background-color: #3a3a3a; height: 2px; }"
	);

	// Styled results tree
	m_model = new DiffResultsModel(this);
	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);
	m_treeView->setAlternatingRowColors(true);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setSortingEnabled(true);
	m_treeView->setRootIsDecorated(true);
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

	m_treeView->setColumnWidth(DiffResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(DiffResultsModel::ColChange, 24);
	m_treeView->setColumnWidth(DiffResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(DiffResultsModel::ColName, 140);
	m_treeView->setColumnWidth(DiffResultsModel::ColChange2, 70);
	m_treeView->setColumnWidth(DiffResultsModel::ColSizeDelta, 60);
	m_treeView->header()->setStretchLastSection(true);

	m_treeView->sortByColumn(DiffResultsModel::ColChange, Qt::AscendingOrder);
	mainSplitter->addWidget(m_treeView);

	// Side-by-side view
	m_sideBySideView = new SideBySideView(this);
	m_sideBySideView->setMinimumHeight(150);
	mainSplitter->addWidget(m_sideBySideView);

	mainSplitter->setStretchFactor(0, 2);
	mainSplitter->setStretchFactor(1, 1);
	layout->addWidget(mainSplitter, 1);

	// Status bar
	m_statusBar = new AnalysisStatusBar(this);
	m_statusBar->setStatus("Load a comparison file to begin");
	layout->addWidget(m_statusBar);
}

void FirmwareDiffWidget::setupConnections()
{
	connect(m_loadButton, &QPushButton::clicked, this, &FirmwareDiffWidget::onLoadCompareClicked);
	connect(m_controlBar, &AnalysisControlBar::runClicked, this, &FirmwareDiffWidget::onAnalyzeClicked);
	connect(m_controlBar, &AnalysisControlBar::resetClicked, this, &FirmwareDiffWidget::onResetClicked);
	connect(m_filterBar, &FilterBar::filtersChanged, this, &FirmwareDiffWidget::onFiltersChanged);
	connect(m_filterBar, &FilterBar::presetClicked, [this](const QString& preset) {
		if (preset == "Modified")
		{
			// Set filter to Modified only
			// Would need to access the combo box directly
		}
	});
	connect(m_treeView, &QTreeView::clicked, this, &FirmwareDiffWidget::onItemClicked);
	connect(m_treeView, &QTreeView::doubleClicked, this, &FirmwareDiffWidget::onItemDoubleClicked);
}

void FirmwareDiffWidget::setBinaryView(BinaryViewRef data)
{
	m_baseData = data;
	m_sideBySideView->setBinaryViews(m_baseData, m_compareData);
	
	if (data)
	{
		QString filename = QString::fromStdString(data->GetFile()->GetOriginalFilename());
		m_baseLabel->setText(QString("Base: %1").arg(QFileInfo(filename).fileName()));
	}
}

void FirmwareDiffWidget::refresh()
{
	if (m_baseData && m_compareData)
		performDiff();
}

void FirmwareDiffWidget::onLoadCompareClicked()
{
	QString filename = QFileDialog::getOpenFileName(this, "Load Comparison Binary",
		QString(), "Binary Files (*.bin *.elf *.axf);;All Files (*)");

	if (filename.isEmpty())
		return;

	// Load the comparison binary using Binary Ninja's file opening API
	Ref<FileMetadata> meta = new FileMetadata();
	Ref<BinaryData> bd = new BinaryData(meta, filename.toStdString());
	if (!bd || bd->GetLength() == 0)
	{
		QMessageBox::warning(this, "Error", "Failed to load comparison file");
		return;
	}

	// Get the same view type as base, or fall back to Raw
	std::string viewType = m_baseData ? m_baseData->GetTypeName() : "Raw";
	Ref<BinaryView> rawView = meta->GetViewOfType(viewType);
	if (!rawView)
		rawView = bd;  // Use raw binary data as fallback

	m_compareData = rawView;
	m_compareFilename = filename;
	m_compareEdit->setText(QFileInfo(filename).fileName());
	m_sideBySideView->setBinaryViews(m_baseData, m_compareData);
	m_statusBar->setStatus("Ready to analyze");
}

void FirmwareDiffWidget::onAnalyzeClicked()
{
	performDiff();
}

void FirmwareDiffWidget::onResetClicked()
{
	m_model->setDiffs({});
	m_sideBySideView->clear();
	m_statusBar->setStatus("Load a comparison file to begin");
	m_statusBar->setSummary("");
}

void FirmwareDiffWidget::onFiltersChanged()
{
	m_model->setTypeFilter(m_filterBar->customComboIndex("Change"));
	m_model->setSearchText(m_filterBar->searchText());
	m_model->applyFilters();
	updateStatusBar();
}

void FirmwareDiffWidget::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);

	if (auto* diff = m_model->getDiffAt(index.row()))
	{
		m_sideBySideView->showDiff(*diff);
	}
}

void FirmwareDiffWidget::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (auto* diff = m_model->getDiffAt(index.row()))
	{
		emit addressSelected(diff->baseAddress > 0 ? diff->baseAddress : diff->compareAddress);
	}
}

void FirmwareDiffWidget::onViewModeChanged(int index)
{
	Q_UNUSED(index);
}

void FirmwareDiffWidget::updateStatusBar()
{
	if (!m_model)
		return;

	int total = m_model->totalCount();
	int added = 0, removed = 0, modified = 0;

	for (int i = 0; i < total; i++)
	{
		const auto* d = m_model->getDiffAt(i);
		if (!d) continue;
		switch (d->type)
		{
		case DiffType::Added: added++; break;
		case DiffType::Removed: removed++; break;
		case DiffType::Modified: modified++; break;
		default: break;
		}
	}

	m_statusBar->setSummary(QString("Added: %1 | Modified: %2 | Removed: %3")
		.arg(added).arg(modified).arg(removed));
}

void FirmwareDiffWidget::performDiff()
{
	if (!m_baseData || !m_compareData)
	{
		QMessageBox::warning(this, "Error", "Please load both base and comparison binaries");
		return;
	}

	m_statusBar->setStatus("Analyzing...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	auto diffs = diffFunctions();
	m_model->setDiffs(diffs);

	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

std::vector<FunctionDiff> FirmwareDiffWidget::diffFunctions()
{
	std::vector<FunctionDiff> diffs;

	// Build maps of functions by name
	std::map<std::string, Ref<Function>> baseFuncs;
	std::map<std::string, Ref<Function>> compareFuncs;

	for (auto& f : m_baseData->GetAnalysisFunctionList())
	{
		std::string name = f->GetSymbol()->GetShortName();
		baseFuncs[name] = f;
	}

	for (auto& f : m_compareData->GetAnalysisFunctionList())
	{
		std::string name = f->GetSymbol()->GetShortName();
		compareFuncs[name] = f;
	}

	// Find added, removed, modified
	for (const auto& [name, baseFunc] : baseFuncs)
	{
		FunctionDiff diff;
		diff.name = QString::fromStdString(name);
		diff.baseAddress = baseFunc->GetStart();

		auto ranges = baseFunc->GetAddressRanges();
		if (!ranges.empty())
			diff.baseSizeBytes = static_cast<int>(ranges.back().end - diff.baseAddress);

		auto it = compareFuncs.find(name);
		if (it == compareFuncs.end())
		{
			// Removed in comparison
			diff.type = DiffType::Removed;
			diff.changeDetail = "Function removed";
		}
		else
		{
			diff.compareAddress = it->second->GetStart();
			auto compareRanges = it->second->GetAddressRanges();
			if (!compareRanges.empty())
				diff.compareSizeBytes = static_cast<int>(compareRanges.back().end - diff.compareAddress);
			diff.sizeDelta = diff.compareSizeBytes - diff.baseSizeBytes;

			// Check if modified
			detectModifications(diff);
		}

		diffs.push_back(diff);
	}

	// Find added functions (in compare but not in base)
	for (const auto& [name, compareFunc] : compareFuncs)
	{
		if (baseFuncs.find(name) == baseFuncs.end())
		{
			FunctionDiff diff;
			diff.name = QString::fromStdString(name);
			diff.compareAddress = compareFunc->GetStart();
			diff.type = DiffType::Added;
			diff.changeDetail = "New function";

			auto ranges = compareFunc->GetAddressRanges();
			if (!ranges.empty())
				diff.compareSizeBytes = static_cast<int>(ranges.back().end - diff.compareAddress);
			diff.sizeDelta = diff.compareSizeBytes;

			diffs.push_back(diff);
		}
	}

	// Sort by type (added, modified, removed) then by name
	std::sort(diffs.begin(), diffs.end(), [](const FunctionDiff& a, const FunctionDiff& b) {
		if (a.type != b.type)
			return static_cast<int>(a.type) < static_cast<int>(b.type);
		return a.name < b.name;
	});

	return diffs;
}

void FirmwareDiffWidget::matchFunctionsByName(std::vector<FunctionDiff>& diffs)
{
	Q_UNUSED(diffs);
	// Already done in diffFunctions
}

void FirmwareDiffWidget::matchFunctionsByAddress(std::vector<FunctionDiff>& diffs)
{
	Q_UNUSED(diffs);
	// TODO: Fallback matching by address for unnamed functions
}

void FirmwareDiffWidget::detectModifications(FunctionDiff& diff)
{
	if (diff.baseAddress == 0 || diff.compareAddress == 0)
		return;

	// Compare function bytes
	size_t checkSize = std::min(static_cast<size_t>(diff.baseSizeBytes), 
		static_cast<size_t>(diff.compareSizeBytes));
	if (checkSize == 0)
		checkSize = 256;  // Default check size

	DataBuffer baseBytes = m_baseData->ReadBuffer(diff.baseAddress, checkSize);
	DataBuffer compareBytes = m_compareData->ReadBuffer(diff.compareAddress, checkSize);

	if (baseBytes.GetLength() != compareBytes.GetLength())
	{
		diff.type = DiffType::Modified;
		diff.changeDetail = "Size changed";
		return;
	}

	// Byte-by-byte comparison
	const uint8_t* basePtr = static_cast<const uint8_t*>(baseBytes.GetData());
	const uint8_t* comparePtr = static_cast<const uint8_t*>(compareBytes.GetData());
	bool hasDiff = false;
	uint64_t rangeStart = 0;
	bool inRange = false;

	for (size_t i = 0; i < baseBytes.GetLength(); i++)
	{
		if (basePtr[i] != comparePtr[i])
		{
			hasDiff = true;
			if (!inRange)
			{
				rangeStart = i;
				inRange = true;
			}
		}
		else if (inRange)
		{
			diff.changedByteRanges.push_back({
				diff.baseAddress + rangeStart,
				diff.baseAddress + i - 1
			});
			inRange = false;
		}
	}

	if (inRange)
	{
		diff.changedByteRanges.push_back({
			diff.baseAddress + rangeStart,
			diff.baseAddress + baseBytes.GetLength() - 1
		});
	}

	if (hasDiff)
	{
		diff.type = DiffType::Modified;
		diff.changeDetail = QString("%1 byte range(s) changed").arg(diff.changedByteRanges.size());
	}
	else
	{
		diff.type = DiffType::Unchanged;
	}
}

}  // namespace Armv5UI
