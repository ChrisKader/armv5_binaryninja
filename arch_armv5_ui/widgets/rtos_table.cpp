/*
 * RTOS Table Widget Implementation
 */

#include "rtos_table.h"
#include "binaryninjaapi.h"

#include <QtWidgets/QHeaderView>

using namespace BinaryNinja;

namespace Armv5UI
{

// ============================================================================
// RTOSTableModel
// ============================================================================

RTOSTableModel::RTOSTableModel(QObject* parent)
	: QAbstractTableModel(parent)
{
}

int RTOSTableModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return static_cast<int>(m_tasks.size());
}

int RTOSTableModel::columnCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return ColCount;
}

QVariant RTOSTableModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid())
		return QVariant();

	int row = index.row();
	if (row < 0 || row >= static_cast<int>(m_tasks.size()))
		return QVariant();

	const RTOSTaskRowData& task = m_tasks[row];

	if (role == Qt::DisplayRole)
	{
		switch (index.column())
		{
		case ColName:
			return QString::fromStdString(task.name);
		case ColEntry:
			return QString("0x%1").arg(task.entryPoint, 8, 16, QChar('0'));
		case ColTCB:
			if (task.tcbAddress != 0)
				return QString("0x%1").arg(task.tcbAddress, 8, 16, QChar('0'));
			return QString("-");
		case ColPriority:
			return static_cast<int>(task.priority);
		case ColStack:
			if (task.stackSize != 0)
				return QString("%1").arg(task.stackSize);
			return QString("-");
		default:
			return QVariant();
		}
	}
	else if (role == Qt::UserRole)
	{
		// Store entry point for selection
		return static_cast<qulonglong>(task.entryPoint);
	}
	else if (role == Qt::UserRole + 1)
	{
		// Store TCB address
		return static_cast<qulonglong>(task.tcbAddress);
	}

	return QVariant();
}

QVariant RTOSTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
		return QVariant();

	switch (section)
	{
	case ColName:
		return "Task Name";
	case ColEntry:
		return "Entry Point";
	case ColTCB:
		return "TCB Address";
	case ColPriority:
		return "Priority";
	case ColStack:
		return "Stack Size";
	default:
		return QVariant();
	}
}

void RTOSTableModel::setTasks(const std::vector<RTOSTaskRowData>& tasks)
{
	beginResetModel();
	m_tasks = tasks;
	endResetModel();
}

void RTOSTableModel::setRTOSType(const std::string& type)
{
	m_rtosType = type;
}

// ============================================================================
// RTOSTableWidget
// ============================================================================

RTOSTableWidget::RTOSTableWidget(QWidget* parent)
	: QWidget(parent)
	, m_statusLabel(nullptr)
	, m_tableView(nullptr)
	, m_model(nullptr)
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Styled status header
	m_statusLabel = new QLabel("No RTOS detected", this);
	m_statusLabel->setStyleSheet(
		"QLabel {"
		"  font-weight: bold;"
		"  font-size: 11px;"
		"  color: #ffffff;"
		"  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3a3c3e, stop:1 #2a2c2e);"
		"  border-bottom: 1px solid #1a1a1a;"
		"  padding: 6px 8px;"
		"}"
	);
	layout->addWidget(m_statusLabel);

	// Styled table view
	m_tableView = new QTableView(this);
	m_tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_tableView->setSelectionMode(QAbstractItemView::SingleSelection);
	m_tableView->setSortingEnabled(true);
	m_tableView->setAlternatingRowColors(true);
	m_tableView->horizontalHeader()->setStretchLastSection(true);
	m_tableView->verticalHeader()->hide();
	m_tableView->verticalHeader()->setDefaultSectionSize(22);
	m_tableView->setStyleSheet(
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

	m_model = new RTOSTableModel(this);
	m_tableView->setModel(m_model);

	layout->addWidget(m_tableView, 1);

	// Connect signals
	connect(m_tableView, &QTableView::doubleClicked, this, &RTOSTableWidget::onRowDoubleClicked);

	setLayout(layout);
}

void RTOSTableWidget::refresh(BinaryViewRef data)
{
	if (!data)
	{
		m_statusLabel->setText("No RTOS detected");
		m_model->setTasks({});
		return;
	}

	// Check for RTOS detection results by looking for known symbols/types
	// This is a simplified approach - in production, we'd cache the RTOSDetector results

	std::vector<RTOSTaskRowData> tasks;
	std::string rtosType = "Unknown";

	// Look for functions with task-entry calling convention
	auto funcs = data->GetAnalysisFunctionList();
	for (const auto& func : funcs)
	{
		if (!func)
			continue;

		auto ccConf = func->GetCallingConvention();
		if (!ccConf.GetValue())
			continue;

		if (ccConf.GetValue()->GetName() == "task-entry")
		{
			RTOSTaskRowData task;
			task.entryPoint = func->GetStart();

			// Try to get name from symbol
			Ref<Symbol> sym = func->GetSymbol();
			if (sym)
				task.name = sym->GetShortName();
			else
				task.name = "task_" + std::to_string(task.entryPoint);

			task.tcbAddress = 0;  // Would need to look up from annotations
			task.priority = 0;
			task.stackSize = 0;

			tasks.push_back(task);
		}
	}

	// Determine RTOS type from defined types
	auto types = data->GetTypes();
	for (const auto& typePair : types)
	{
		std::string name = typePair.first.GetString();
		if (name.find("tskTaskControlBlock") != std::string::npos)
		{
			rtosType = "FreeRTOS";
			break;
		}
		else if (name.find("TX_THREAD") != std::string::npos)
		{
			rtosType = "ThreadX";
			break;
		}
		else if (name.find("NU_TASK") != std::string::npos)
		{
			rtosType = "Nucleus PLUS";
			break;
		}
		else if (name.find("OS_TCB") != std::string::npos)
		{
			rtosType = "uC/OS-II";
			break;
		}
		else if (name.find("k_thread") != std::string::npos)
		{
			rtosType = "Zephyr";
			break;
		}
	}

	if (tasks.empty())
	{
		if (rtosType != "Unknown")
			m_statusLabel->setText(QString("RTOS: %1 (no tasks found)").arg(QString::fromStdString(rtosType)));
		else
			m_statusLabel->setText("No RTOS detected");
	}
	else
	{
		m_statusLabel->setText(QString("RTOS: %1 (%2 tasks)")
			.arg(QString::fromStdString(rtosType))
			.arg(tasks.size()));
	}

	m_model->setRTOSType(rtosType);
	m_model->setTasks(tasks);
	m_tableView->resizeColumnsToContents();
}

void RTOSTableWidget::onRowDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid())
		return;

	qulonglong entry = m_model->data(index, Qt::UserRole).toULongLong();
	qulonglong tcb = m_model->data(index, Qt::UserRole + 1).toULongLong();
	emit taskSelected(entry, tcb);
}

}
