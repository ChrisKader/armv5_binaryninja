/*
 * Function Results Model - Implementation
 */

#include "function_results_model.h"
#include "theme.h"

#include <algorithm>

namespace Armv5UI
{

FunctionResultsModel::FunctionResultsModel(QObject* parent)
	: TreeResultsModel(parent)
{
	setColumns({"", "Address", "Size", "Score", "M", "Status", "Xrefs", "Calls", "Sources"},
		{24, 85, 50, 55, 28, 55, 45, 45, -1});
}

void FunctionResultsModel::setResults(const std::vector<FunctionResultItem>& results)
{
	beginResetModel();
	m_allResults = results;
	rebuildFilteredIndices();
	endResetModel();
}

void FunctionResultsModel::clear()
{
	beginResetModel();
	m_allResults.clear();
	m_filteredIndices.clear();
	endResetModel();
}

void FunctionResultsModel::setMinScore(double minScore)
{
	m_minScore = minScore;
}

void FunctionResultsModel::setStatusFilter(int filter)
{
	m_statusFilter = filter;
}

void FunctionResultsModel::setModeFilter(int filter)
{
	m_modeFilter = filter;
}

void FunctionResultsModel::setSearchText(const QString& text)
{
	m_searchText = text.toLower();
}

void FunctionResultsModel::rebuildFilteredIndices()
{
	m_filteredIndices.clear();

	for (size_t i = 0; i < m_allResults.size(); i++)
	{
		const auto& item = m_allResults[i];

		// Score filter
		if (item.score < m_minScore)
			continue;

		// Status filter
		if (m_statusFilter == 1 && !item.isNew)
			continue;
		if (m_statusFilter == 2 && item.isNew)
			continue;

		// Mode filter
		if (m_modeFilter == 1 && item.isThumb)
			continue;
		if (m_modeFilter == 2 && !item.isThumb)
			continue;

		// Search filter
		if (!m_searchText.isEmpty())
		{
			QString addr = QString("0x%1").arg(item.address, 8, 16, QChar('0')).toLower();
			if (!addr.contains(m_searchText))
				continue;
		}

		m_filteredIndices.push_back(static_cast<int>(i));
	}
}

void FunctionResultsModel::applyFilters()
{
	beginResetModel();
	rebuildFilteredIndices();
	endResetModel();
}

void FunctionResultsModel::selectByScore(double minScore)
{
	for (int idx : m_filteredIndices)
	{
		m_allResults[idx].selected = (m_allResults[idx].score >= minScore && m_allResults[idx].isNew);
	}
	emit dataChanged(index(0, 0), index(itemCount() - 1, 0), {Qt::CheckStateRole});
}

void FunctionResultsModel::selectNewOnly()
{
	for (int idx : m_filteredIndices)
	{
		m_allResults[idx].selected = m_allResults[idx].isNew;
	}
	emit dataChanged(index(0, 0), index(itemCount() - 1, 0), {Qt::CheckStateRole});
}

std::vector<FunctionResultItem> FunctionResultsModel::getSelectedItems() const
{
	std::vector<FunctionResultItem> result;
	for (int idx : m_filteredIndices)
	{
		if (m_allResults[idx].selected)
			result.push_back(m_allResults[idx]);
	}
	return result;
}

void FunctionResultsModel::sort(int column, Qt::SortOrder order)
{
	beginResetModel();
	
	std::sort(m_filteredIndices.begin(), m_filteredIndices.end(),
		[this, column, order](int a, int b) {
			const auto& itemA = m_allResults[a];
			const auto& itemB = m_allResults[b];
			
			bool less = false;
			switch (column)
			{
			case ColAddress:
				less = itemA.address < itemB.address;
				break;
			case ColSize:
				less = itemA.size < itemB.size;
				break;
			case ColScore:
				less = itemA.score < itemB.score;
				break;
			case ColMode:
				less = itemA.isThumb < itemB.isThumb;
				break;
			case ColStatus:
				less = itemA.isNew < itemB.isNew;
				break;
			case ColXrefs:
				less = itemA.xrefCount < itemB.xrefCount;
				break;
			case ColCallees:
				less = itemA.calleeCount < itemB.calleeCount;
				break;
			default:
				less = itemA.address < itemB.address;
				break;
			}
			
			return order == Qt::AscendingOrder ? less : !less;
		});
	
	endResetModel();
}

const FunctionResultItem* FunctionResultsModel::itemAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return nullptr;
	return &m_allResults[m_filteredIndices[row]];
}

int FunctionResultsModel::itemCount() const
{
	return static_cast<int>(m_filteredIndices.size());
}

bool FunctionResultsModel::isItemSelected(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return false;
	return m_allResults[m_filteredIndices[row]].selected;
}

void FunctionResultsModel::setItemSelected(int row, bool selected)
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return;
	m_allResults[m_filteredIndices[row]].selected = selected;
}

uint64_t FunctionResultsModel::itemAddress(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	return m_allResults[m_filteredIndices[row]].address;
}

QString FunctionResultsModel::sourcesAbbreviation(const FunctionResultItem& item) const
{
	QStringList abbrevs;
	for (const auto& [cat, score] : item.categoryScores)
	{
		if (score > 0)
		{
			if (cat == "Call") abbrevs << "C";
			else if (cat == "Prologue") abbrevs << "P";
			else if (cat == "Structural") abbrevs << "S";
			else if (cat == "Advanced") abbrevs << "A";
			else abbrevs << cat.left(1);
		}
	}
	return abbrevs.join(",");
}

QColor FunctionResultsModel::scoreColor(double score) const
{
	if (score >= m_highThreshold)
		return getThemeColor(GreenStandardHighlightColor);
	if (score >= m_medThreshold)
		return getThemeColor(YellowStandardHighlightColor);
	return getThemeColor(OrangeStandardHighlightColor);
}

QVariant FunctionResultsModel::itemData(int row, int column, int role) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();
	
	const auto& item = m_allResults[m_filteredIndices[row]];
	
	if (role == Qt::DisplayRole)
	{
		switch (column)
		{
		case ColAddress:
			return QString("0x%1").arg(item.address, 8, 16, QChar('0'));
		case ColSize:
			return item.size > 0 ? QString::number(item.size) : "?";
		case ColScore:
			return QString::number(item.score, 'f', 2);
		case ColMode:
			return item.isThumb ? "T" : "A";
		case ColStatus:
			return item.isNew ? "New" : "Exists";
		case ColXrefs:
			return item.xrefCount > 0 ? QString::number(item.xrefCount) : "-";
		case ColCallees:
			return item.calleeCount > 0 ? QString::number(item.calleeCount) : "-";
		case ColSources:
			return sourcesAbbreviation(item);
		default:
			return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		if (column == ColScore)
			return scoreColor(item.score);
		if (column == ColStatus)
			return item.isNew ? getThemeColor(GreenStandardHighlightColor) : getThemeColor(CommentColor);
		if (column == ColXrefs && item.xrefCount == 0)
			return getThemeColor(RedStandardHighlightColor);
	}
	else if (role == Qt::BackgroundRole)
	{
		if (item.selected)
			return getThemeColor(SelectionColor);
	}
	else if (role == Qt::TextAlignmentRole)
	{
		if (column == ColSize || column == ColScore || column == ColXrefs || column == ColCallees)
			return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
		if (column == ColMode)
			return static_cast<int>(Qt::AlignCenter);
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(item.address);
	}
	else if (role == Qt::UserRole + 1)
	{
		return item.isThumb;
	}
	
	return QVariant();
}

QVariant FunctionResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();
	
	const auto& item = m_allResults[m_filteredIndices[parentRow]];
	
	// Build detail rows from source scores
	std::vector<std::pair<QString, double>> details;
	
	// First add category totals
	for (const auto& [cat, score] : item.categoryScores)
	{
		if (score > 0)
			details.push_back({cat, score});
	}
	
	// Then add individual sources indented
	for (const auto& src : item.sourceScores)
	{
		if (src.score > 0)
			details.push_back({"  " + src.name, src.score});
	}
	
	if (detailRow < 0 || detailRow >= static_cast<int>(details.size()))
		return QVariant();
	
	const auto& detail = details[detailRow];
	
	if (role == Qt::DisplayRole)
	{
		if (column == 1)  // Under address column
			return detail.first;
		if (column == 3)  // Under score column
			return QString::number(detail.second, 'f', 2);
	}
	else if (role == Qt::ForegroundRole)
	{
		if (column == 3)
			return scoreColor(detail.second);
		return getThemeColor(CommentColor);
	}
	
	return QVariant();
}

int FunctionResultsModel::detailRowCount(int parentRow) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	
	const auto& item = m_allResults[m_filteredIndices[parentRow]];
	
	int count = 0;
	for (const auto& [cat, score] : item.categoryScores)
		if (score > 0) count++;
	count += static_cast<int>(item.sourceScores.size());
	
	return count;
}

}  // namespace Armv5UI
