/*
 * Vector Table Widget Implementation
 */

#include "vector_table.h"
#include "binaryninjaapi.h"
#include "theme.h"

#include <QtWidgets/QHeaderView>
#include <QtWidgets/QFormLayout>
#include <QtGui/QColor>
#include <QtWidgets/QApplication>

using namespace BinaryNinja;

namespace Armv5UI
{

// Standard ARM exception vector names
static const char* kVectorNames[] = {
	"Reset",
	"Undefined",
	"SWI",
	"Prefetch Abort",
	"Data Abort",
	"Reserved",
	"IRQ",
	"FIQ"
};

static const char* kHandlerSymbols[] = {
	"reset_handler",
	"undef_handler",
	"swi_handler",
	"prefetch_abort_handler",
	"data_abort_handler",
	"reserved_handler",
	"irq_handler",
	"fiq_handler"
};

// ============================================================================
// VectorResultsModel
// ============================================================================

VectorResultsModel::VectorResultsModel(QObject* parent)
	: TreeResultsModel(parent)
{
	setColumns({"", "#", "Vector", "Vec Addr", "Handler", "Handler Addr", "Mode"},
		{24, 24, 90, 75, 120, 85, 50});
}

void VectorResultsModel::setVectors(const std::vector<VectorEntryRowData>& vectors)
{
	beginResetModel();
	m_vectors = vectors;
	endResetModel();
}

const VectorEntryRowData* VectorResultsModel::getVectorAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_vectors.size()))
		return nullptr;
	return &m_vectors[row];
}

std::vector<VectorEntryRowData> VectorResultsModel::getSelectedVectors() const
{
	std::vector<VectorEntryRowData> result;
	for (const auto& v : m_vectors)
	{
		if (v.selected && v.hasHandler)
			result.push_back(v);
	}
	return result;
}

void VectorResultsModel::sort(int column, Qt::SortOrder order)
{
	beginResetModel();
	std::sort(m_vectors.begin(), m_vectors.end(),
		[column, order](const VectorEntryRowData& a, const VectorEntryRowData& b) {
			bool less = false;
			switch (column)
			{
			case ColIndex:
				less = a.vectorIndex < b.vectorIndex;
				break;
			case ColVecAddr:
				less = a.vectorAddress < b.vectorAddress;
				break;
			case ColHandlerAddr:
				less = a.handlerAddress < b.handlerAddress;
				break;
			default:
				less = a.vectorIndex < b.vectorIndex;
				break;
			}
			return order == Qt::AscendingOrder ? less : !less;
		});
	endResetModel();
}

int VectorResultsModel::itemCount() const
{
	return static_cast<int>(m_vectors.size());
}

bool VectorResultsModel::isItemSelected(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_vectors.size()))
		return false;
	return m_vectors[row].selected;
}

void VectorResultsModel::setItemSelected(int row, bool selected)
{
	if (row >= 0 && row < static_cast<int>(m_vectors.size()))
		m_vectors[row].selected = selected;
}

void VectorResultsModel::setSelected(int row, bool selected)
{
	setItemSelected(row, selected);
}

void VectorResultsModel::selectMissing()
{
	for (size_t i = 0; i < m_vectors.size(); i++)
	{
		if (!m_vectors[i].hasHandler)
			m_vectors[i].selected = true;
	}
}

uint64_t VectorResultsModel::itemAddress(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_vectors.size()))
		return 0;
	return m_vectors[row].hasHandler ? m_vectors[row].handlerAddress : m_vectors[row].vectorAddress;
}

QVariant VectorResultsModel::itemData(int row, int column, int role) const
{
	if (row < 0 || row >= static_cast<int>(m_vectors.size()))
		return QVariant();

	const VectorEntryRowData& vec = m_vectors[row];

	if (role == Qt::DisplayRole)
	{
		switch (column)
		{
		case ColIndex:
			return vec.vectorIndex;
		case ColVector:
			return QString::fromStdString(vec.vectorName);
		case ColVecAddr:
			return QString("0x%1").arg(vec.vectorAddress, 8, 16, QChar('0'));
		case ColHandler:
			return QString::fromStdString(vec.handlerName);
		case ColHandlerAddr:
			if (vec.hasHandler)
				return QString("0x%1").arg(vec.handlerAddress, 8, 16, QChar('0'));
			return QString("-");
		case ColMode:
			if (vec.hasHandler)
				return vec.isThumb ? "T" : "A";
			return QString("-");
		default:
			return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		if (!vec.hasHandler)
			return getThemeColor(CommentColor);
		
		// Color by vector type
		if (vec.vectorIndex == 6 || vec.vectorIndex == 7)  // IRQ/FIQ
			return getThemeColor(RedStandardHighlightColor);
		else if (vec.vectorIndex == 0)  // Reset
			return getThemeColor(BlueStandardHighlightColor);
		else if (vec.vectorIndex == 2)  // SWI
			return getThemeColor(OrangeStandardHighlightColor);
		
		return QVariant();
	}
	else if (role == Qt::BackgroundRole)
	{
		if (vec.selected)
			return getThemeColor(SelectionColor);
	}
	else if (role == Qt::TextAlignmentRole)
	{
		if (column == ColIndex || column == ColMode)
			return static_cast<int>(Qt::AlignCenter);
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(vec.handlerAddress);
	}

	return QVariant();
}

QVariant VectorResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_vectors.size()))
		return QVariant();

	const VectorEntryRowData& vec = m_vectors[parentRow];

	// Detail rows:
	// 0: Instruction at vector
	// 1: Handler info (if handler exists)
	// 2: Xref count

	if (role == Qt::DisplayRole)
	{
		if (detailRow == 0 && column == ColVector)
		{
			if (!vec.instructionText.empty())
				return QString("Instruction: %1").arg(QString::fromStdString(vec.instructionText));
			return QString("Instruction: (not decoded)");
		}
		else if (detailRow == 1 && column == ColVector && vec.hasHandler)
		{
			if (vec.isFunction)
				return QString("Size: %1 bytes").arg(vec.handlerSize);
			return QString("Not a defined function");
		}
		else if (detailRow == 2 && column == ColVector && vec.hasHandler)
		{
			return QString("Xrefs: %1").arg(vec.xrefCount);
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		return getThemeColor(CommentColor);
	}

	return QVariant();
}

int VectorResultsModel::detailRowCount(int parentRow) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_vectors.size()))
		return 0;
	
	const VectorEntryRowData& vec = m_vectors[parentRow];
	return vec.hasHandler ? 3 : 1;  // Instruction + handler info + xrefs, or just instruction
}

// ============================================================================
// VectorTableWidget
// ============================================================================

VectorTableWidget::VectorTableWidget(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void VectorTableWidget::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void VectorTableWidget::refresh()
{
	if (m_data)
		scanVectorTable();
}

void VectorTableWidget::refresh(BinaryViewRef data)
{
	setBinaryView(data);
	refresh();
}

QWidget* VectorTableWidget::createSettingsWidget()
{
	m_settingsWidget = new QWidget(this);
	QHBoxLayout* layout = new QHBoxLayout(m_settingsWidget);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(8);

	layout->addWidget(new QLabel("Base offset:", m_settingsWidget));
	m_imageBaseOffset = new QSpinBox(m_settingsWidget);
	m_imageBaseOffset->setRange(0, 0xFFFF);
	m_imageBaseOffset->setValue(0);
	m_imageBaseOffset->setPrefix("0x");
	m_imageBaseOffset->setDisplayIntegerBase(16);
	m_imageBaseOffset->setMaximumWidth(70);
	layout->addWidget(m_imageBaseOffset);

	m_scanAltLocations = new QCheckBox("Scan alternate locations", m_settingsWidget);
	m_scanAltLocations->setToolTip("Search for vector tables at non-standard addresses");
	layout->addWidget(m_scanAltLocations);

	m_analyzeHandlers = new QCheckBox("Analyze handlers", m_settingsWidget);
	m_analyzeHandlers->setChecked(true);
	m_analyzeHandlers->setToolTip("Decode instructions and analyze handler functions");
	layout->addWidget(m_analyzeHandlers);

	layout->addStretch();

	return m_settingsWidget;
}

QWidget* VectorTableWidget::createFilterBar()
{
	m_filterBar = new FilterBar(this);
	m_filterBar->addStatusFilter({"All", "Has Handler", "Missing Handler"});
	m_filterBar->addSearchBox("Filter vectors...");
	m_filterBar->addPresetButton("Select All", "Select all handlers");
	m_filterBar->addPresetButton("Select IRQ", "Select IRQ/FIQ handlers");
	return m_filterBar;
}

QWidget* VectorTableWidget::createResultsView()
{
	m_model = new VectorResultsModel(this);

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
	m_treeView->setColumnWidth(VectorResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(VectorResultsModel::ColIndex, 24);
	m_treeView->setColumnWidth(VectorResultsModel::ColVector, 90);
	m_treeView->setColumnWidth(VectorResultsModel::ColVecAddr, 75);
	m_treeView->setColumnWidth(VectorResultsModel::ColHandler, 120);
	m_treeView->setColumnWidth(VectorResultsModel::ColHandlerAddr, 85);
	m_treeView->header()->setStretchLastSection(true);

	// Default sort by index
	m_treeView->sortByColumn(VectorResultsModel::ColIndex, Qt::AscendingOrder);

	return m_treeView;
}

void VectorTableWidget::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &VectorTableWidget::onRunClicked);
		connect(m_controlBar, &AnalysisControlBar::resetClicked, this, &VectorTableWidget::onResetClicked);
		connect(m_controlBar, &AnalysisControlBar::applyClicked, this, &VectorTableWidget::onApplyClicked);
	}

	if (m_filterBar)
	{
		connect(m_filterBar, &FilterBar::filtersChanged, this, &VectorTableWidget::onFiltersChanged);
		connect(m_filterBar, &FilterBar::presetClicked, [this](const QString& preset) {
			if (preset == "Select All")
				m_model->selectAll();
			else if (preset == "Select IRQ")
			{
				m_model->selectNone();
				// Select vectors 6 and 7 (IRQ/FIQ)
				for (int i = 0; i < m_model->totalCount(); i++)
				{
					const auto* vec = m_model->getVectorAt(i);
					if (vec && (vec->vectorIndex == 6 || vec->vectorIndex == 7))
						m_model->setSelected(i, true);
				}
			}
			updateStatusBar();
		});
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &VectorTableWidget::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &VectorTableWidget::onItemDoubleClicked);
	}

	if (m_model)
	{
		connect(m_model, &QAbstractItemModel::dataChanged, this, &VectorTableWidget::onSelectionChanged);
	}
}

void VectorTableWidget::onRunClicked()
{
	scanVectorTable();
}

void VectorTableWidget::onResetClicked()
{
	m_model->setVectors({});
	if (m_preview)
		m_preview->clear();
	m_statusBar->setStatus("Ready to scan");
	m_statusBar->setSummary("");
	m_controlBar->setSelectionCount(0);
}

void VectorTableWidget::onApplyClicked()
{
	if (!m_data)
		return;

	auto selected = m_model->getSelectedVectors();
	if (selected.empty())
		return;

	size_t created = 0;
	auto platform = m_data->GetDefaultPlatform();

	for (const auto& vec : selected)
	{
		if (!vec.isFunction && vec.hasHandler)
		{
			m_data->CreateUserFunction(platform, vec.handlerAddress);
			created++;
		}
	}

	emit analysisApplied(created);
	scanVectorTable();  // Refresh
}

void VectorTableWidget::onFiltersChanged()
{
	// TODO: Implement filtering
	updateStatusBar();
}

void VectorTableWidget::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	// Toggle expansion
	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);

	// Show preview
	if (auto* vec = m_model->getVectorAt(index.row()))
	{
		if (m_preview && vec->hasHandler)
			m_preview->showDisassembly(vec->handlerAddress, vec->isThumb);
	}
}

void VectorTableWidget::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	const VectorEntryRowData* vec = m_model->getVectorAt(index.row());
	if (vec && vec->hasHandler)
	{
		emit handlerSelected(vec->handlerAddress);
		navigateToAddress(vec->handlerAddress);
	}
}

void VectorTableWidget::onSelectionChanged()
{
	updateStatusBar();
}

void VectorTableWidget::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int selected = m_model->selectedCount();
	int handlers = 0;
	
	for (int i = 0; i < total; i++)
	{
		const auto* vec = m_model->getVectorAt(i);
		if (vec && vec->hasHandler)
			handlers++;
	}

	m_statusBar->setSummary("Handlers", handlers, "Selected", selected);
	m_controlBar->setSelectionCount(selected);
}

void VectorTableWidget::scanVectorTable()
{
	if (!m_data)
	{
		m_model->setVectors({});
		m_statusBar->setStatus("No data");
		return;
	}

	m_statusBar->setStatus("Scanning...");
	QApplication::processEvents();

	std::vector<VectorEntryRowData> vectors;
	int foundHandlers = 0;

	// Get image base (vector table typically at base)
	uint64_t imageBase = m_data->GetStart();
	if (m_imageBaseOffset)
		imageBase += m_imageBaseOffset->value();

	// Look for the 8 standard ARM exception vectors
	for (int i = 0; i < 8; i++)
	{
		VectorEntryRowData vec;
		vec.vectorIndex = i;
		vec.vectorName = kVectorNames[i];
		vec.vectorAddress = imageBase + (i * 4);
		vec.handlerAddress = 0;
		vec.handlerName = "(not found)";
		vec.isThumb = false;
		vec.hasHandler = false;
		vec.selected = false;

		// Parse the instruction at the vector location
		if (m_analyzeHandlers && m_analyzeHandlers->isChecked())
			parseVectorInstruction(vec);

		// Try to find the handler by symbol name
		auto symbols = m_data->GetSymbolsByName(kHandlerSymbols[i]);
		if (!symbols.empty())
		{
			Ref<Symbol> sym = symbols[0];
			vec.handlerAddress = sym->GetAddress();
			vec.handlerName = sym->GetShortName();
			vec.hasHandler = true;
			foundHandlers++;

			// Check if it's a Thumb function
			Ref<Function> func = m_data->GetAnalysisFunction(
				m_data->GetDefaultPlatform(), vec.handlerAddress);
			if (func)
			{
				vec.isFunction = true;
				Ref<Architecture> arch = func->GetArchitecture();
				vec.isThumb = arch && (arch->GetName() == "armv5t");
				
				auto ranges = func->GetAddressRanges();
				if (!ranges.empty())
					vec.handlerSize = ranges.back().end - vec.handlerAddress;
			}
			else
			{
				// Check Thumb bit in address
				vec.isThumb = (vec.handlerAddress & 1) != 0;
				vec.handlerAddress &= ~1ULL;  // Clear Thumb bit for display
			}

			// Get xref count
			vec.xrefCount = static_cast<int>(m_data->GetCodeReferences(vec.handlerAddress).size());
		}

		vectors.push_back(vec);
	}

	m_model->setVectors(vectors);
	
	// Auto-select handlers that aren't defined as functions
	for (int i = 0; i < m_model->totalCount(); i++)
	{
		const auto* v = m_model->getVectorAt(i);
		if (v && v->hasHandler && !v->isFunction)
			m_model->setSelected(i, true);
	}

	m_statusBar->setStatus("Complete");
	m_statusBar->setSummary("Handlers", foundHandlers, "Selected", m_model->selectedCount());
	m_controlBar->setSelectionCount(m_model->selectedCount());
}

void VectorTableWidget::parseVectorInstruction(VectorEntryRowData& vec)
{
	if (!m_data)
		return;

	// Read the instruction at the vector address
	DataBuffer buf = m_data->ReadBuffer(vec.vectorAddress, 4);
	if (buf.GetLength() < 4)
		return;

	Ref<Architecture> arch = m_data->GetDefaultArchitecture();
	if (!arch)
		return;

	std::vector<InstructionTextToken> tokens;
	InstructionInfo info;
	
	if (arch->GetInstructionInfo(static_cast<const uint8_t*>(buf.GetData()),
		vec.vectorAddress, buf.GetLength(), info))
	{
		arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()),
			vec.vectorAddress, info.length, tokens);

		std::string text;
		for (const auto& tok : tokens)
			text += tok.text;
		vec.instructionText = text;

		// Try to determine handler from branch target
		if (!vec.hasHandler && info.branchCount > 0)
		{
			for (size_t i = 0; i < info.branchCount; i++)
			{
				if (info.branchTarget[i] != 0 && info.branchTarget[i] != vec.vectorAddress)
				{
					vec.handlerAddress = info.branchTarget[i];
					vec.hasHandler = true;
					
					// Look for symbol at target
					Ref<Symbol> sym = m_data->GetSymbolByAddress(vec.handlerAddress);
					if (sym)
						vec.handlerName = sym->GetShortName();
					else
						vec.handlerName = QString("sub_%1").arg(vec.handlerAddress, 8, 16, QChar('0')).toStdString();
					
					// Check Thumb bit
					vec.isThumb = (vec.handlerAddress & 1) != 0;
					vec.handlerAddress &= ~1ULL;
					break;
				}
			}
		}
	}
}

}  // namespace Armv5UI
