/*
 * Function Table Widget Implementation
 */

#include "function_table.h"
#include "binaryninjaapi.h"
#include "theme.h"

#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>

using namespace BinaryNinja;

namespace Armv5UI
{

// ============================================================================
// ExistingFunctionModel
// ============================================================================

ExistingFunctionModel::ExistingFunctionModel(QObject* parent) : QAbstractTableModel(parent) {}

int ExistingFunctionModel::rowCount(const QModelIndex&) const { return static_cast<int>(m_functions.size()); }
int ExistingFunctionModel::columnCount(const QModelIndex&) const { return ColCount; }

QVariant ExistingFunctionModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid()) return QVariant();
	int row = index.row();
	if (row < 0 || row >= static_cast<int>(m_functions.size())) return QVariant();
	const auto& f = m_functions[row];
	
	if (role == Qt::DisplayRole)
	{
		switch (index.column())
		{
		case ColAddress: return QString("0x%1").arg(f.address, 8, 16, QChar('0'));
		case ColName: return f.name;
		case ColSize: return f.size > 0 ? QString::number(f.size) : "?";
		case ColCalls: return f.callCount > 0 ? QString::number(f.callCount) : "-";
		default: return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		if (index.column() == ColCalls && f.callCount == 0)
			return getThemeColor(OrangeStandardHighlightColor);
		return QVariant();
	}
	else if (role == Qt::TextAlignmentRole)
	{
		if (index.column() == ColSize || index.column() == ColCalls)
			return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
		return QVariant();
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(f.address);
	}
	else if (role == Qt::UserRole + 1)
	{
		return f.name;
	}
	return QVariant();
}

QVariant ExistingFunctionModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return QVariant();
	switch (section)
	{
	case ColAddress: return "Address";
	case ColName: return "Name";
	case ColSize: return "Size";
	case ColCalls: return "Refs";
	default: return QVariant();
	}
}

void ExistingFunctionModel::refresh(BinaryViewRef data)
{
	beginResetModel();
	m_functions.clear();
	
	if (data)
	{
		for (const auto& func : data->GetAnalysisFunctionList())
		{
			FunctionInfo info;
			info.address = func->GetStart();
			
			auto sym = data->GetSymbolByAddress(info.address);
			if (sym)
				info.name = QString::fromStdString(sym->GetShortName());
			else
				info.name = QString("sub_%1").arg(info.address, 0, 16);
			
			auto ranges = func->GetAddressRanges();
			info.size = 0;
			if (!ranges.empty())
				info.size = ranges.back().end - info.address;
			
			info.callCount = static_cast<int>(data->GetCodeReferences(info.address).size());
			
			m_functions.push_back(info);
		}
	}
	
	endResetModel();
}

uint64_t ExistingFunctionModel::getAddressAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_functions.size())) return 0;
	return m_functions[row].address;
}

// ============================================================================
// ExistingFunctionFilterProxy
// ============================================================================

ExistingFunctionFilterProxy::ExistingFunctionFilterProxy(QObject* parent) : QSortFilterProxyModel(parent)
{
	setFilterCaseSensitivity(Qt::CaseInsensitive);
}

void ExistingFunctionFilterProxy::setSearchText(const QString& text)
{
	m_search = text;
	beginResetModel();
	endResetModel();
}

bool ExistingFunctionFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
{
	if (m_search.isEmpty()) return true;
	
	QAbstractItemModel* model = sourceModel();
	QString addr = model->data(model->index(sourceRow, ExistingFunctionModel::ColAddress, sourceParent)).toString();
	QString name = model->data(model->index(sourceRow, 0, sourceParent), Qt::UserRole + 1).toString();
	
	return addr.contains(m_search, Qt::CaseInsensitive) || name.contains(m_search, Qt::CaseInsensitive);
}

// ============================================================================
// FunctionTableWidget
// ============================================================================

FunctionTableWidget::FunctionTableWidget(QWidget* parent) : QWidget(parent), m_data(nullptr)
{
	QVBoxLayout* lay = new QVBoxLayout(this);
	lay->setContentsMargins(0, 0, 0, 0);
	lay->setSpacing(0);

	// Styled search bar
	QWidget* searchBar = new QWidget();
	searchBar->setStyleSheet(
		"QWidget {"
		"  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #353535, stop:1 #2a2a2a);"
		"  border-bottom: 1px solid #1a1a1a;"
		"}"
	);
	QHBoxLayout* searchRow = new QHBoxLayout(searchBar);
	searchRow->setContentsMargins(8, 6, 8, 6);
	searchRow->setSpacing(8);

	QLabel* searchLabel = new QLabel("Search:");
	searchLabel->setStyleSheet("QLabel { color: #aaaaaa; font-size: 11px; background: transparent; border: none; }");
	searchRow->addWidget(searchLabel);

	m_search = new QLineEdit();
	m_search->setPlaceholderText("Filter by name or address...");
	m_search->setStyleSheet(
		"QLineEdit {"
		"  background-color: #1e1e1e;"
		"  color: #cccccc;"
		"  border: 1px solid #3a3a3a;"
		"  border-radius: 3px;"
		"  padding: 4px 8px;"
		"  font-size: 11px;"
		"}"
		"QLineEdit:focus { border-color: #ffcc00; }"
	);
	searchRow->addWidget(m_search, 1);
	lay->addWidget(searchBar);

	// Styled table
	m_table = new QTableView();
	m_table->setAlternatingRowColors(true);
	m_table->setSelectionMode(QAbstractItemView::SingleSelection);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSortingEnabled(true);
	m_table->verticalHeader()->hide();
	m_table->verticalHeader()->setDefaultSectionSize(22);
	m_table->horizontalHeader()->setHighlightSections(false);
	m_table->setStyleSheet(
		"QTableView {"
		"  background-color: #1e1e1e;"
		"  alternate-background-color: #252525;"
		"  color: #cccccc;"
		"  gridline-color: #2a2a2a;"
		"  border: none;"
		"  font-size: 11px;"
		"}"
		"QTableView::item:selected {"
		"  background-color: #3a4a5a;"
		"  color: #ffffff;"
		"}"
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

	m_model = new ExistingFunctionModel(this);
	m_proxy = new ExistingFunctionFilterProxy(this);
	m_proxy->setSourceModel(m_model);
	m_table->setModel(m_proxy);

	m_table->setColumnWidth(ExistingFunctionModel::ColAddress, 85);
	m_table->setColumnWidth(ExistingFunctionModel::ColSize, 55);
	m_table->setColumnWidth(ExistingFunctionModel::ColCalls, 45);
	m_table->horizontalHeader()->setStretchLastSection(true);

	lay->addWidget(m_table, 1);

	// Connections
	connect(m_table, &QTableView::doubleClicked, this, &FunctionTableWidget::onRowDoubleClicked);
	connect(m_search, &QLineEdit::textChanged, this, &FunctionTableWidget::onSearchChanged);
}

void FunctionTableWidget::refresh(BinaryViewRef data)
{
	m_data = data;
	m_model->refresh(data);
}

void FunctionTableWidget::highlightAddress(uint64_t /*address*/)
{
	// TODO: Select the row with the given address
}

void FunctionTableWidget::onRowDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid()) return;
	QModelIndex srcIdx = m_proxy->mapToSource(index);
	uint64_t addr = m_model->getAddressAt(srcIdx.row());
	if (addr != 0) emit functionSelected(addr);
}

void FunctionTableWidget::onSearchChanged(const QString& text)
{
	m_proxy->setSearchText(text);
}

}
