/*
 * MMU Table Widget Implementation
 */

#include "mmu_table.h"
#include "binaryninjaapi.h"

#include <QtWidgets/QHeaderView>
#include <QtGui/QColor>

using namespace BinaryNinja;

namespace Armv5UI
{

// ============================================================================
// MemoryRegionModel
// ============================================================================

MemoryRegionModel::MemoryRegionModel(QObject* parent)
	: QAbstractTableModel(parent)
{
}

int MemoryRegionModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return static_cast<int>(m_regions.size());
}

int MemoryRegionModel::columnCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return ColCount;
}

QVariant MemoryRegionModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid())
		return QVariant();

	int row = index.row();
	if (row < 0 || row >= static_cast<int>(m_regions.size()))
		return QVariant();

	const MemoryRegionRowData& region = m_regions[row];

	if (role == Qt::DisplayRole)
	{
		switch (index.column())
		{
		case ColStart:
			return QString("0x%1").arg(region.start, 8, 16, QChar('0'));
		case ColEnd:
			return QString("0x%1").arg(region.end, 8, 16, QChar('0'));
		case ColSize:
			if (region.size >= 1024 * 1024)
				return QString("%1 MB").arg(region.size / (1024 * 1024));
			else if (region.size >= 1024)
				return QString("%1 KB").arg(region.size / 1024);
			else
				return QString("%1 B").arg(region.size);
		case ColName:
			return QString::fromStdString(region.name);
		case ColPerms:
			return QString::fromStdString(region.permissions);
		case ColType:
			return QString::fromStdString(region.type);
		default:
			return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		// Color by type
		if (region.type == "MMIO")
			return QColor(255, 150, 100);  // Orange for MMIO
		else if (region.type == "ROM")
			return QColor(100, 200, 255);  // Light blue for ROM
		else if (region.type == "RAM")
			return QColor(100, 255, 150);  // Light green for RAM
		return QVariant();
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(region.start);
	}

	return QVariant();
}

QVariant MemoryRegionModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
		return QVariant();

	switch (section)
	{
	case ColStart:
		return "Start";
	case ColEnd:
		return "End";
	case ColSize:
		return "Size";
	case ColName:
		return "Name";
	case ColPerms:
		return "Perms";
	case ColType:
		return "Type";
	default:
		return QVariant();
	}
}

void MemoryRegionModel::setRegions(const std::vector<MemoryRegionRowData>& regions)
{
	beginResetModel();
	m_regions = regions;
	endResetModel();
}

const MemoryRegionRowData* MemoryRegionModel::getRegionAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_regions.size()))
		return nullptr;
	return &m_regions[row];
}

// ============================================================================
// MMUTableWidget
// ============================================================================

MMUTableWidget::MMUTableWidget(QWidget* parent)
	: QWidget(parent)
	, m_statusLabel(nullptr)
	, m_tableView(nullptr)
	, m_model(nullptr)
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Styled status header
	m_statusLabel = new QLabel("Memory Regions", this);
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

	// Model
	m_model = new MemoryRegionModel(this);
	m_tableView->setModel(m_model);

	layout->addWidget(m_tableView, 1);

	// Connect signals
	connect(m_tableView, &QTableView::doubleClicked, this, &MMUTableWidget::onRowDoubleClicked);

	setLayout(layout);
}

void MMUTableWidget::refresh(BinaryViewRef data)
{
	if (!data)
	{
		m_model->setRegions({});
		m_statusLabel->setText("Memory Regions: No data");
		return;
	}

	std::vector<MemoryRegionRowData> regions;

	// Get segments from the BinaryView
	auto segments = data->GetSegments();
	for (const auto& seg : segments)
	{
		if (!seg)
			continue;

		MemoryRegionRowData row;
		row.start = seg->GetStart();
		row.end = seg->GetEnd();
		row.size = seg->GetLength();
		row.isAutoCreated = seg->IsAutoDefined();

		// Build permissions string
		std::string perms;
		uint32_t flags = seg->GetFlags();
		perms += (flags & SegmentReadable) ? "r" : "-";
		perms += (flags & SegmentWritable) ? "w" : "-";
		perms += (flags & SegmentExecutable) ? "x" : "-";
		row.permissions = perms;

		// Try to determine type from name or flags
		// Segments don't have names directly, but we can check sections
		row.name = "";
		row.type = "Unknown";

		// Check if this looks like MMIO (typically non-file-backed, RW, non-executable)
		if (seg->GetDataLength() == 0)
		{
			if ((flags & SegmentWritable) && !(flags & SegmentExecutable))
				row.type = "MMIO";
			else
				row.type = "RAM";
		}
		else
		{
			if (flags & SegmentExecutable)
				row.type = "ROM";
			else if (flags & SegmentWritable)
				row.type = "RAM";
			else
				row.type = "ROM";
		}

		// Try to get name from sections
		auto sections = data->GetSectionsAt(row.start);
		for (const auto& sec : sections)
		{
			if (sec && !sec->GetName().empty())
			{
				row.name = sec->GetName();
				break;
			}
		}

		// If no section name, generate one
		if (row.name.empty())
		{
			char buf[32];
			snprintf(buf, sizeof(buf), "seg_%08llx", (unsigned long long)row.start);
			row.name = buf;
		}

		regions.push_back(row);
	}

	// Sort by start address
	std::sort(regions.begin(), regions.end(),
		[](const MemoryRegionRowData& a, const MemoryRegionRowData& b) {
			return a.start < b.start;
		});

	m_model->setRegions(regions);
	m_statusLabel->setText(QString("Memory Regions: %1").arg(regions.size()));
	m_tableView->resizeColumnsToContents();
}

void MMUTableWidget::onRowDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid())
		return;

	qulonglong addr = m_model->data(index, Qt::UserRole).toULongLong();
	emit regionSelected(addr);
}

}
