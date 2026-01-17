/*
 * RTOS Table Widget
 *
 * Displays detected RTOS tasks with their entry points, priorities, and TCB addresses.
 */

#pragma once

#include "uitypes.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QTableView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtCore/QAbstractTableModel>

#include <vector>

namespace Armv5UI
{

/**
 * Data for a single RTOS task row.
 */
struct RTOSTaskRowData
{
	std::string name;
	uint64_t entryPoint;
	uint64_t tcbAddress;
	uint32_t priority;
	uint32_t stackSize;
};

/**
 * Table model for RTOS tasks.
 */
class RTOSTableModel : public QAbstractTableModel
{
	Q_OBJECT

public:
	enum Column
	{
		ColName = 0,
		ColEntry,
		ColTCB,
		ColPriority,
		ColStack,
		ColCount
	};

	explicit RTOSTableModel(QObject* parent = nullptr);

	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

	void setTasks(const std::vector<RTOSTaskRowData>& tasks);
	void setRTOSType(const std::string& type);

private:
	std::vector<RTOSTaskRowData> m_tasks;
	std::string m_rtosType;
};

/**
 * RTOS table widget.
 */
class RTOSTableWidget : public QWidget
{
	Q_OBJECT

public:
	explicit RTOSTableWidget(QWidget* parent = nullptr);

	void refresh(BinaryViewRef data);

Q_SIGNALS:
	void taskSelected(uint64_t entryPoint, uint64_t tcbAddress);

private Q_SLOTS:
	void onRowDoubleClicked(const QModelIndex& index);

private:
	QLabel* m_statusLabel;
	QTableView* m_tableView;
	RTOSTableModel* m_model;
};

}
