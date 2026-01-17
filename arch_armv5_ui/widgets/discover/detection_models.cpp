/*
 * Detection Models - Implementation
 */

#include "detection_models.h"
#include "theme.h"

#include <algorithm>

using namespace BinaryNinja;

namespace Armv5UI
{

// ============================================================================
// StringResultsModel
// ============================================================================

StringResultsModel::StringResultsModel(QObject* parent)
	: TreeResultsModel(parent)
{
	setColumns({"", "Address", "Len", "Enc", "Category", "Conf", "Content"},
		{24, 85, 45, 55, 70, 45, -1});
}

void StringResultsModel::setResults(const std::vector<StringResultItem>& results)
{
	beginResetModel();
	m_allResults = results;
	rebuildFilteredIndices();
	endResetModel();
}

void StringResultsModel::clear()
{
	beginResetModel();
	m_allResults.clear();
	m_filteredIndices.clear();
	endResetModel();
}

void StringResultsModel::setCategoryFilter(int filter)
{
	m_categoryFilter = filter;
}

void StringResultsModel::setStatusFilter(int filter)
{
	m_statusFilter = filter;
}

void StringResultsModel::setSearchText(const QString& text)
{
	m_searchText = text.toLower();
}

void StringResultsModel::rebuildFilteredIndices()
{
	m_filteredIndices.clear();

	static const QStringList categories = {"All", "Error", "Debug", "Path", "URL", "Version", "Format", "Crypto", "Hardware", "RTOS"};

	for (size_t i = 0; i < m_allResults.size(); i++)
	{
		const auto& item = m_allResults[i];

		// Category filter
		if (m_categoryFilter > 0 && m_categoryFilter < categories.size())
		{
			if (!item.category.contains(categories[m_categoryFilter], Qt::CaseInsensitive))
				continue;
		}

		// Status filter
		if (m_statusFilter == 1 && !item.isNew)
			continue;
		if (m_statusFilter == 2 && item.isNew)
			continue;

		// Search filter
		if (!m_searchText.isEmpty())
		{
			if (!item.content.toLower().contains(m_searchText) &&
				!QString("0x%1").arg(item.address, 8, 16, QChar('0')).contains(m_searchText))
				continue;
		}

		m_filteredIndices.push_back(static_cast<int>(i));
	}
}

void StringResultsModel::applyFilters()
{
	beginResetModel();
	rebuildFilteredIndices();
	endResetModel();
}

void StringResultsModel::selectByCategory(const QString& category)
{
	for (auto& item : m_allResults)
	{
		if (item.category.contains(category, Qt::CaseInsensitive))
			item.selected = true;
	}
}

void StringResultsModel::selectNewOnly()
{
	for (auto& item : m_allResults)
		item.selected = item.isNew;
}

std::vector<StringResultItem> StringResultsModel::getSelectedItems() const
{
	std::vector<StringResultItem> result;
	for (const auto& item : m_allResults)
	{
		if (item.selected)
			result.push_back(item);
	}
	return result;
}

void StringResultsModel::sort(int column, Qt::SortOrder order)
{
	beginResetModel();
	std::sort(m_filteredIndices.begin(), m_filteredIndices.end(),
		[this, column, order](int a, int b) {
			const auto& itemA = m_allResults[a];
			const auto& itemB = m_allResults[b];

			bool less = false;
			switch (column)
			{
			case ColAddress: less = itemA.address < itemB.address; break;
			case ColLength: less = itemA.length < itemB.length; break;
			case ColEncoding: less = itemA.encoding < itemB.encoding; break;
			case ColCategory: less = itemA.category < itemB.category; break;
			case ColConfidence: less = itemA.confidence < itemB.confidence; break;
			case ColContent: less = itemA.content < itemB.content; break;
			default: less = itemA.address < itemB.address; break;
			}

			return order == Qt::AscendingOrder ? less : !less;
		});
	endResetModel();
}

const StringResultItem* StringResultsModel::itemAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return nullptr;
	return &m_allResults[m_filteredIndices[row]];
}

QVariant StringResultsModel::itemData(int row, int column, int role) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& item = m_allResults[m_filteredIndices[row]];

	if (role == Qt::DisplayRole)
	{
		switch (column)
		{
		case ColAddress: return QString("0x%1").arg(item.address, 8, 16, QChar('0'));
		case ColLength: return static_cast<int>(item.length);
		case ColEncoding: return item.encoding;
		case ColCategory: return item.category;
		case ColConfidence: return QString::number(item.confidence, 'f', 2);
		case ColContent: return item.content.left(100);
		default: return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		if (column == ColCategory)
		{
			if (item.category == "Error") return getThemeColor(RedStandardHighlightColor);
			if (item.category == "Debug") return getThemeColor(YellowStandardHighlightColor);
			if (item.category == "Path") return getThemeColor(GreenStandardHighlightColor);
			if (item.category == "URL") return getThemeColor(BlueStandardHighlightColor);
			if (item.category == "Crypto") return getThemeColor(OrangeStandardHighlightColor);
		}
	}
	else if (role == Qt::BackgroundRole)
	{
		if (item.selected)
			return getThemeColor(SelectionColor);
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(item.address);
	}
	else if (role == Qt::ToolTipRole)
	{
		return item.categoryReason;
	}

	return QVariant();
}

QVariant StringResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& item = m_allResults[m_filteredIndices[parentRow]];

	if (role == Qt::DisplayRole && detailRow == 0 && column == ColContent)
	{
		return QString("Full: %1").arg(item.content);
	}
	else if (role == Qt::ForegroundRole)
	{
		return getThemeColor(CommentColor);
	}

	return QVariant();
}

int StringResultsModel::detailRowCount(int parentRow) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	return 1;
}

bool StringResultsModel::isItemSelected(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return false;
	return m_allResults[m_filteredIndices[row]].selected;
}

void StringResultsModel::setItemSelected(int row, bool selected)
{
	if (row >= 0 && row < static_cast<int>(m_filteredIndices.size()))
		m_allResults[m_filteredIndices[row]].selected = selected;
}

uint64_t StringResultsModel::itemAddress(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	return m_allResults[m_filteredIndices[row]].address;
}

int StringResultsModel::itemCount() const
{
	return static_cast<int>(m_filteredIndices.size());
}

// ============================================================================
// StructureResultsModel
// ============================================================================

StructureResultsModel::StructureResultsModel(QObject* parent)
	: TreeResultsModel(parent)
{
	setColumns({"", "Address", "Type", "Elements", "Size", "Conf", "Description"},
		{24, 85, 80, 60, 60, 45, -1});
}

void StructureResultsModel::setResults(const std::vector<StructureResultItem>& results)
{
	beginResetModel();
	m_allResults = results;
	rebuildFilteredIndices();
	endResetModel();
}

void StructureResultsModel::clear()
{
	beginResetModel();
	m_allResults.clear();
	m_filteredIndices.clear();
	endResetModel();
}

void StructureResultsModel::setTypeFilter(int filter)
{
	m_typeFilter = filter;
}

void StructureResultsModel::setSearchText(const QString& text)
{
	m_searchText = text.toLower();
}

void StructureResultsModel::rebuildFilteredIndices()
{
	m_filteredIndices.clear();

	static const QStringList types = {"All", "VTable", "JumpTable", "FuncTable", "PtrArray", "IntArray"};

	for (size_t i = 0; i < m_allResults.size(); i++)
	{
		const auto& item = m_allResults[i];

		// Type filter
		if (m_typeFilter > 0 && m_typeFilter < types.size())
		{
			if (!item.type.contains(types[m_typeFilter], Qt::CaseInsensitive))
				continue;
		}

		// Search filter
		if (!m_searchText.isEmpty())
		{
			if (!item.description.toLower().contains(m_searchText) &&
				!QString("0x%1").arg(item.address, 8, 16, QChar('0')).contains(m_searchText))
				continue;
		}

		m_filteredIndices.push_back(static_cast<int>(i));
	}
}

void StructureResultsModel::applyFilters()
{
	beginResetModel();
	rebuildFilteredIndices();
	endResetModel();
}

void StructureResultsModel::selectByType(const QString& type)
{
	for (auto& item : m_allResults)
	{
		if (item.type.contains(type, Qt::CaseInsensitive))
			item.selected = true;
	}
}

std::vector<StructureResultItem> StructureResultsModel::getSelectedItems() const
{
	std::vector<StructureResultItem> result;
	for (const auto& item : m_allResults)
	{
		if (item.selected)
			result.push_back(item);
	}
	return result;
}

void StructureResultsModel::sort(int column, Qt::SortOrder order)
{
	beginResetModel();
	std::sort(m_filteredIndices.begin(), m_filteredIndices.end(),
		[this, column, order](int a, int b) {
			const auto& itemA = m_allResults[a];
			const auto& itemB = m_allResults[b];

			bool less = false;
			switch (column)
			{
			case ColAddress: less = itemA.address < itemB.address; break;
			case ColType: less = itemA.type < itemB.type; break;
			case ColElements: less = itemA.elementCount < itemB.elementCount; break;
			case ColSize: less = itemA.size < itemB.size; break;
			case ColConfidence: less = itemA.confidence < itemB.confidence; break;
			default: less = itemA.address < itemB.address; break;
			}

			return order == Qt::AscendingOrder ? less : !less;
		});
	endResetModel();
}

const StructureResultItem* StructureResultsModel::itemAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return nullptr;
	return &m_allResults[m_filteredIndices[row]];
}

QVariant StructureResultsModel::itemData(int row, int column, int role) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& item = m_allResults[m_filteredIndices[row]];

	if (role == Qt::DisplayRole)
	{
		switch (column)
		{
		case ColAddress: return QString("0x%1").arg(item.address, 8, 16, QChar('0'));
		case ColType: return item.type;
		case ColElements: return static_cast<int>(item.elementCount);
		case ColSize: return static_cast<int>(item.size);
		case ColConfidence: return QString::number(item.confidence, 'f', 2);
		case ColDescription: return item.description;
		default: return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		if (column == ColType)
		{
			if (item.type == "VTable") return getThemeColor(BlueStandardHighlightColor);
			if (item.type == "JumpTable") return getThemeColor(GreenStandardHighlightColor);
			if (item.type == "FunctionTable") return getThemeColor(OrangeStandardHighlightColor);
		}
	}
	else if (role == Qt::BackgroundRole)
	{
		if (item.selected)
			return getThemeColor(SelectionColor);
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(item.address);
	}

	return QVariant();
}

QVariant StructureResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& item = m_allResults[m_filteredIndices[parentRow]];

	if (role == Qt::DisplayRole && column == ColDescription)
	{
		if (detailRow < static_cast<int>(item.elements.size()))
		{
			QString name = detailRow < static_cast<int>(item.elementNames.size()) ?
				item.elementNames[detailRow] : "";
			return QString("  [%1] 0x%2 %3")
				.arg(detailRow)
				.arg(item.elements[detailRow], 8, 16, QChar('0'))
				.arg(name);
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		return getThemeColor(CommentColor);
	}

	return QVariant();
}

int StructureResultsModel::detailRowCount(int parentRow) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	return std::min(static_cast<int>(m_allResults[m_filteredIndices[parentRow]].elements.size()), 10);
}

bool StructureResultsModel::isItemSelected(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return false;
	return m_allResults[m_filteredIndices[row]].selected;
}

void StructureResultsModel::setItemSelected(int row, bool selected)
{
	if (row >= 0 && row < static_cast<int>(m_filteredIndices.size()))
		m_allResults[m_filteredIndices[row]].selected = selected;
}

uint64_t StructureResultsModel::itemAddress(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	return m_allResults[m_filteredIndices[row]].address;
}

int StructureResultsModel::itemCount() const
{
	return static_cast<int>(m_filteredIndices.size());
}

// ============================================================================
// CryptoResultsModel
// ============================================================================

CryptoResultsModel::CryptoResultsModel(QObject* parent)
	: TreeResultsModel(parent)
{
	setColumns({"", "Address", "Algorithm", "Type", "Size", "Conf", "Description"},
		{24, 85, 80, 80, 55, 45, -1});
}

void CryptoResultsModel::setResults(const std::vector<CryptoResultItem>& results)
{
	beginResetModel();
	m_allResults = results;
	rebuildFilteredIndices();
	endResetModel();
}

void CryptoResultsModel::clear()
{
	beginResetModel();
	m_allResults.clear();
	m_filteredIndices.clear();
	endResetModel();
}

void CryptoResultsModel::setAlgorithmFilter(int filter)
{
	m_algorithmFilter = filter;
}

void CryptoResultsModel::setSearchText(const QString& text)
{
	m_searchText = text.toLower();
}

void CryptoResultsModel::rebuildFilteredIndices()
{
	m_filteredIndices.clear();

	static const QStringList algos = {"All", "AES", "DES", "SHA", "MD5", "CRC", "Other"};

	for (size_t i = 0; i < m_allResults.size(); i++)
	{
		const auto& item = m_allResults[i];

		// Algorithm filter
		if (m_algorithmFilter > 0 && m_algorithmFilter < algos.size())
		{
			if (!item.algorithm.contains(algos[m_algorithmFilter], Qt::CaseInsensitive))
				continue;
		}

		// Search filter
		if (!m_searchText.isEmpty())
		{
			if (!item.description.toLower().contains(m_searchText) &&
				!item.algorithm.toLower().contains(m_searchText))
				continue;
		}

		m_filteredIndices.push_back(static_cast<int>(i));
	}
}

void CryptoResultsModel::applyFilters()
{
	beginResetModel();
	rebuildFilteredIndices();
	endResetModel();
}

std::vector<CryptoResultItem> CryptoResultsModel::getSelectedItems() const
{
	std::vector<CryptoResultItem> result;
	for (const auto& item : m_allResults)
	{
		if (item.selected)
			result.push_back(item);
	}
	return result;
}

void CryptoResultsModel::sort(int column, Qt::SortOrder order)
{
	beginResetModel();
	std::sort(m_filteredIndices.begin(), m_filteredIndices.end(),
		[this, column, order](int a, int b) {
			const auto& itemA = m_allResults[a];
			const auto& itemB = m_allResults[b];

			bool less = false;
			switch (column)
			{
			case ColAddress: less = itemA.address < itemB.address; break;
			case ColAlgorithm: less = itemA.algorithm < itemB.algorithm; break;
			case ColConstType: less = itemA.constantType < itemB.constantType; break;
			case ColSize: less = itemA.size < itemB.size; break;
			case ColConfidence: less = itemA.confidence < itemB.confidence; break;
			default: less = itemA.address < itemB.address; break;
			}

			return order == Qt::AscendingOrder ? less : !less;
		});
	endResetModel();
}

const CryptoResultItem* CryptoResultsModel::itemAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return nullptr;
	return &m_allResults[m_filteredIndices[row]];
}

QColor CryptoResultsModel::algorithmColor(const QString& algo) const
{
	if (algo.contains("AES", Qt::CaseInsensitive)) return getThemeColor(BlueStandardHighlightColor);
	if (algo.contains("DES", Qt::CaseInsensitive)) return getThemeColor(RedStandardHighlightColor);
	if (algo.contains("SHA", Qt::CaseInsensitive)) return getThemeColor(GreenStandardHighlightColor);
	if (algo.contains("MD5", Qt::CaseInsensitive)) return getThemeColor(OrangeStandardHighlightColor);
	if (algo.contains("CRC", Qt::CaseInsensitive)) return getThemeColor(YellowStandardHighlightColor);
	return getThemeColor(StringColor);
}

QVariant CryptoResultsModel::itemData(int row, int column, int role) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& item = m_allResults[m_filteredIndices[row]];

	if (role == Qt::DisplayRole)
	{
		switch (column)
		{
		case ColAddress: return QString("0x%1").arg(item.address, 8, 16, QChar('0'));
		case ColAlgorithm: return item.algorithm;
		case ColConstType: return item.constantType;
		case ColSize: return static_cast<int>(item.size);
		case ColConfidence: return QString::number(item.confidence, 'f', 2);
		case ColDescription: return item.description;
		default: return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		if (column == ColAlgorithm)
			return algorithmColor(item.algorithm);
		if (column == ColConfidence && item.isPartialMatch)
			return getThemeColor(YellowStandardHighlightColor);
	}
	else if (role == Qt::BackgroundRole)
	{
		if (item.selected)
			return getThemeColor(SelectionColor);
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(item.address);
	}
	else if (role == Qt::ToolTipRole)
	{
		return item.isPartialMatch ? "Partial match" : "Full match";
	}

	return QVariant();
}

QVariant CryptoResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	Q_UNUSED(parentRow);
	Q_UNUSED(detailRow);
	Q_UNUSED(column);
	Q_UNUSED(role);
	return QVariant();
}

int CryptoResultsModel::detailRowCount(int parentRow) const
{
	Q_UNUSED(parentRow);
	return 0;
}

bool CryptoResultsModel::isItemSelected(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return false;
	return m_allResults[m_filteredIndices[row]].selected;
}

void CryptoResultsModel::setItemSelected(int row, bool selected)
{
	if (row >= 0 && row < static_cast<int>(m_filteredIndices.size()))
		m_allResults[m_filteredIndices[row]].selected = selected;
}

uint64_t CryptoResultsModel::itemAddress(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	return m_allResults[m_filteredIndices[row]].address;
}

int CryptoResultsModel::itemCount() const
{
	return static_cast<int>(m_filteredIndices.size());
}

// ============================================================================
// EntropyResultsModel
// ============================================================================

EntropyResultsModel::EntropyResultsModel(QObject* parent)
	: TreeResultsModel(parent)
{
	setColumns({"", "Address", "Size", "Entropy", "Type", "Description"},
		{24, 85, 70, 60, 80, -1});
}

void EntropyResultsModel::setResults(const std::vector<EntropyResultItem>& results)
{
	beginResetModel();
	m_allResults = results;
	rebuildFilteredIndices();
	endResetModel();
}

void EntropyResultsModel::clear()
{
	beginResetModel();
	m_allResults.clear();
	m_filteredIndices.clear();
	endResetModel();
}

void EntropyResultsModel::setTypeFilter(int filter)
{
	m_typeFilter = filter;
}

void EntropyResultsModel::setMinEntropy(double minEntropy)
{
	m_minEntropy = minEntropy;
}

void EntropyResultsModel::rebuildFilteredIndices()
{
	m_filteredIndices.clear();

	static const QStringList types = {"All", "Encrypted", "Compressed", "Code", "Text", "Padding"};

	for (size_t i = 0; i < m_allResults.size(); i++)
	{
		const auto& item = m_allResults[i];

		// Entropy filter
		if (item.entropy < m_minEntropy)
			continue;

		// Type filter
		if (m_typeFilter > 0 && m_typeFilter < types.size())
		{
			if (!item.regionType.contains(types[m_typeFilter], Qt::CaseInsensitive))
				continue;
		}

		m_filteredIndices.push_back(static_cast<int>(i));
	}
}

void EntropyResultsModel::applyFilters()
{
	beginResetModel();
	rebuildFilteredIndices();
	endResetModel();
}

std::vector<EntropyResultItem> EntropyResultsModel::getSelectedItems() const
{
	std::vector<EntropyResultItem> result;
	for (const auto& item : m_allResults)
	{
		if (item.selected)
			result.push_back(item);
	}
	return result;
}

void EntropyResultsModel::sort(int column, Qt::SortOrder order)
{
	beginResetModel();
	std::sort(m_filteredIndices.begin(), m_filteredIndices.end(),
		[this, column, order](int a, int b) {
			const auto& itemA = m_allResults[a];
			const auto& itemB = m_allResults[b];

			bool less = false;
			switch (column)
			{
			case ColAddress: less = itemA.address < itemB.address; break;
			case ColSize: less = itemA.size < itemB.size; break;
			case ColEntropy: less = itemA.entropy < itemB.entropy; break;
			case ColType: less = itemA.regionType < itemB.regionType; break;
			default: less = itemA.entropy < itemB.entropy; break;
			}

			return order == Qt::AscendingOrder ? less : !less;
		});
	endResetModel();
}

const EntropyResultItem* EntropyResultsModel::itemAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return nullptr;
	return &m_allResults[m_filteredIndices[row]];
}

QColor EntropyResultsModel::entropyColor(double entropy) const
{
	if (entropy >= 7.5) return getThemeColor(RedStandardHighlightColor);
	if (entropy >= 6.5) return getThemeColor(OrangeStandardHighlightColor);
	if (entropy >= 5.0) return getThemeColor(YellowStandardHighlightColor);
	if (entropy >= 3.0) return getThemeColor(GreenStandardHighlightColor);
	return getThemeColor(BlueStandardHighlightColor);
}

QVariant EntropyResultsModel::itemData(int row, int column, int role) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& item = m_allResults[m_filteredIndices[row]];

	if (role == Qt::DisplayRole)
	{
		switch (column)
		{
		case ColAddress: return QString("0x%1").arg(item.address, 8, 16, QChar('0'));
		case ColSize:
		{
			if (item.size >= 1024 * 1024)
				return QString("%1 MB").arg(item.size / (1024 * 1024));
			else if (item.size >= 1024)
				return QString("%1 KB").arg(item.size / 1024);
			return QString("%1 B").arg(item.size);
		}
		case ColEntropy: return QString::number(item.entropy, 'f', 2);
		case ColType: return item.regionType;
		case ColDescription: return item.description;
		default: return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		if (column == ColEntropy)
			return entropyColor(item.entropy);
		if (column == ColType)
		{
			if (item.regionType.contains("Encrypted")) return getThemeColor(RedStandardHighlightColor);
			if (item.regionType.contains("Compressed")) return getThemeColor(OrangeStandardHighlightColor);
			if (item.regionType.contains("Code")) return getThemeColor(BlueStandardHighlightColor);
		}
	}
	else if (role == Qt::BackgroundRole)
	{
		if (item.selected)
			return getThemeColor(SelectionColor);
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(item.address);
	}

	return QVariant();
}

QVariant EntropyResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	Q_UNUSED(parentRow);
	Q_UNUSED(detailRow);
	Q_UNUSED(column);
	Q_UNUSED(role);
	return QVariant();
}

int EntropyResultsModel::detailRowCount(int parentRow) const
{
	Q_UNUSED(parentRow);
	return 0;
}

bool EntropyResultsModel::isItemSelected(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return false;
	return m_allResults[m_filteredIndices[row]].selected;
}

void EntropyResultsModel::setItemSelected(int row, bool selected)
{
	if (row >= 0 && row < static_cast<int>(m_filteredIndices.size()))
		m_allResults[m_filteredIndices[row]].selected = selected;
}

uint64_t EntropyResultsModel::itemAddress(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	return m_allResults[m_filteredIndices[row]].address;
}

int EntropyResultsModel::itemCount() const
{
	return static_cast<int>(m_filteredIndices.size());
}

}  // namespace Armv5UI
