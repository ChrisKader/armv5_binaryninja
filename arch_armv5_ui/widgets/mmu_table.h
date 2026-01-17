/*
 * MMU Table Widget
 *
 * Displays memory regions and segments from MMU/firmware analysis.
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
 * Data for a single memory region row.
 */
struct MemoryRegionRowData
{
	uint64_t start;
	uint64_t end;
	uint64_t size;
	std::string name;
	std::string permissions;  // r/w/x
	std::string type;         // RAM, ROM, MMIO, etc.
	bool isAutoCreated;
};

/**
 * Table model for memory regions.
 */
class MemoryRegionModel : public QAbstractTableModel
{
	Q_OBJECT

public:
	enum Column
	{
		ColStart = 0,
		ColEnd,
		ColSize,
		ColName,
		ColPerms,
		ColType,
		ColCount
	};

	explicit MemoryRegionModel(QObject* parent = nullptr);

	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

	void setRegions(const std::vector<MemoryRegionRowData>& regions);
	const MemoryRegionRowData* getRegionAt(int row) const;

private:
	std::vector<MemoryRegionRowData> m_regions;
};

/**
 * MMU/Memory regions table widget.
 */
class MMUTableWidget : public QWidget
{
	Q_OBJECT

public:
	explicit MMUTableWidget(QWidget* parent = nullptr);

	void refresh(BinaryViewRef data);

Q_SIGNALS:
	void regionSelected(uint64_t address);

private Q_SLOTS:
	void onRowDoubleClicked(const QModelIndex& index);

private:
	QLabel* m_statusLabel;
	QTableView* m_tableView;
	MemoryRegionModel* m_model;
};

}
