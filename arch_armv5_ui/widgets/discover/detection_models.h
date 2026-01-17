/*
 * Detection Models
 *
 * Tree models for detection results: Strings, Structures, Crypto, Entropy
 */

#pragma once

#include "../common/analysis_widgets.h"
#include "analysis/string_detector.h"
#include "analysis/structure_detector.h"
#include "analysis/crypto_detector.h"
#include "analysis/entropy_analyzer.h"

#include <vector>

namespace Armv5UI
{

// ============================================================================
// String Results Model
// ============================================================================

struct StringResultItem
{
	uint64_t address = 0;
	size_t length = 0;
	QString content;
	QString encoding;
	QString category;
	double confidence = 0.0;
	bool hasXrefs = false;
	bool isNew = true;
	bool selected = false;
	QString categoryReason;
};

class StringResultsModel : public TreeResultsModel
{
	Q_OBJECT

public:
	enum Column {
		ColSelect = 0,
		ColAddress,
		ColLength,
		ColEncoding,
		ColCategory,
		ColConfidence,
		ColContent,
		ColCount
	};

	explicit StringResultsModel(QObject* parent = nullptr);

	void setResults(const std::vector<StringResultItem>& results);
	void clear();

	// Filtering
	void setCategoryFilter(int filter);
	void setStatusFilter(int filter);
	void setSearchText(const QString& text);
	void applyFilters();

	// Selection
	void selectByCategory(const QString& category);
	void selectNewOnly();
	std::vector<StringResultItem> getSelectedItems() const;

	void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

	const StringResultItem* itemAt(int row) const;
	int totalCount() const { return static_cast<int>(m_allResults.size()); }
	int filteredCount() const { return static_cast<int>(m_filteredIndices.size()); }

protected:
	QVariant itemData(int row, int column, int role) const override;
	QVariant detailData(int parentRow, int detailRow, int column, int role) const override;
	int detailRowCount(int parentRow) const override;
	bool isItemSelected(int row) const override;
	void setItemSelected(int row, bool selected) override;
	uint64_t itemAddress(int row) const override;
	int itemCount() const override;

private:
	void rebuildFilteredIndices();

	std::vector<StringResultItem> m_allResults;
	std::vector<int> m_filteredIndices;
	int m_categoryFilter = 0;
	int m_statusFilter = 0;
	QString m_searchText;
};

// ============================================================================
// Structure Results Model
// ============================================================================

struct StructureResultItem
{
	uint64_t address = 0;
	size_t size = 0;
	QString type;
	size_t elementCount = 0;
	double confidence = 0.0;
	QString description;
	bool isNew = true;
	bool selected = false;
	std::vector<uint64_t> elements;
	std::vector<QString> elementNames;
};

class StructureResultsModel : public TreeResultsModel
{
	Q_OBJECT

public:
	enum Column {
		ColSelect = 0,
		ColAddress,
		ColType,
		ColElements,
		ColSize,
		ColConfidence,
		ColDescription,
		ColCount
	};

	explicit StructureResultsModel(QObject* parent = nullptr);

	void setResults(const std::vector<StructureResultItem>& results);
	void clear();

	void setTypeFilter(int filter);
	void setSearchText(const QString& text);
	void applyFilters();

	void selectByType(const QString& type);
	std::vector<StructureResultItem> getSelectedItems() const;

	void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

	const StructureResultItem* itemAt(int row) const;
	int totalCount() const { return static_cast<int>(m_allResults.size()); }
	int filteredCount() const { return static_cast<int>(m_filteredIndices.size()); }

protected:
	QVariant itemData(int row, int column, int role) const override;
	QVariant detailData(int parentRow, int detailRow, int column, int role) const override;
	int detailRowCount(int parentRow) const override;
	bool isItemSelected(int row) const override;
	void setItemSelected(int row, bool selected) override;
	uint64_t itemAddress(int row) const override;
	int itemCount() const override;

private:
	void rebuildFilteredIndices();

	std::vector<StructureResultItem> m_allResults;
	std::vector<int> m_filteredIndices;
	int m_typeFilter = 0;
	QString m_searchText;
};

// ============================================================================
// Crypto Results Model
// ============================================================================

struct CryptoResultItem
{
	uint64_t address = 0;
	QString algorithm;
	QString constantType;
	size_t size = 0;
	double confidence = 0.0;
	QString description;
	bool isPartialMatch = false;
	bool selected = false;
};

class CryptoResultsModel : public TreeResultsModel
{
	Q_OBJECT

public:
	enum Column {
		ColSelect = 0,
		ColAddress,
		ColAlgorithm,
		ColConstType,
		ColSize,
		ColConfidence,
		ColDescription,
		ColCount
	};

	explicit CryptoResultsModel(QObject* parent = nullptr);

	void setResults(const std::vector<CryptoResultItem>& results);
	void clear();

	void setAlgorithmFilter(int filter);
	void setSearchText(const QString& text);
	void applyFilters();

	std::vector<CryptoResultItem> getSelectedItems() const;

	void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

	const CryptoResultItem* itemAt(int row) const;
	int totalCount() const { return static_cast<int>(m_allResults.size()); }
	int filteredCount() const { return static_cast<int>(m_filteredIndices.size()); }

protected:
	QVariant itemData(int row, int column, int role) const override;
	QVariant detailData(int parentRow, int detailRow, int column, int role) const override;
	int detailRowCount(int parentRow) const override;
	bool isItemSelected(int row) const override;
	void setItemSelected(int row, bool selected) override;
	uint64_t itemAddress(int row) const override;
	int itemCount() const override;

private:
	void rebuildFilteredIndices();
	QColor algorithmColor(const QString& algo) const;

	std::vector<CryptoResultItem> m_allResults;
	std::vector<int> m_filteredIndices;
	int m_algorithmFilter = 0;
	QString m_searchText;
};

// ============================================================================
// Entropy Results Model
// ============================================================================

struct EntropyResultItem
{
	uint64_t address = 0;
	size_t size = 0;
	double entropy = 0.0;
	QString regionType;
	QString description;
	bool selected = false;
};

class EntropyResultsModel : public TreeResultsModel
{
	Q_OBJECT

public:
	enum Column {
		ColSelect = 0,
		ColAddress,
		ColSize,
		ColEntropy,
		ColType,
		ColDescription,
		ColCount
	};

	explicit EntropyResultsModel(QObject* parent = nullptr);

	void setResults(const std::vector<EntropyResultItem>& results);
	void clear();

	void setTypeFilter(int filter);
	void setMinEntropy(double minEntropy);
	void applyFilters();

	std::vector<EntropyResultItem> getSelectedItems() const;

	void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

	const EntropyResultItem* itemAt(int row) const;
	int totalCount() const { return static_cast<int>(m_allResults.size()); }
	int filteredCount() const { return static_cast<int>(m_filteredIndices.size()); }

protected:
	QVariant itemData(int row, int column, int role) const override;
	QVariant detailData(int parentRow, int detailRow, int column, int role) const override;
	int detailRowCount(int parentRow) const override;
	bool isItemSelected(int row) const override;
	void setItemSelected(int row, bool selected) override;
	uint64_t itemAddress(int row) const override;
	int itemCount() const override;

private:
	void rebuildFilteredIndices();
	QColor entropyColor(double entropy) const;

	std::vector<EntropyResultItem> m_allResults;
	std::vector<int> m_filteredIndices;
	int m_typeFilter = 0;
	double m_minEntropy = 0.0;
};

}  // namespace Armv5UI
