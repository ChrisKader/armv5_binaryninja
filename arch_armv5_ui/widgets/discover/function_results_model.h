/*
 * Function Results Model
 *
 * Tree model for function detection results with expandable score breakdowns.
 */

#pragma once

#include "../common/analysis_widgets.h"
#include "analysis/function_detector.h"

#include <vector>
#include <map>

namespace Armv5UI
{

// Score breakdown for a single detection source
struct SourceScore
{
	QString name;
	QString category;  // Prologue, Call, Structural, Advanced
	double score;
};

// Function candidate with full score breakdown
struct FunctionResultItem
{
	uint64_t address = 0;
	size_t size = 0;
	double score = 0.0;
	bool isThumb = false;
	bool isNew = true;
	bool selected = false;
	int xrefCount = 0;
	int calleeCount = 0;
	
	// Score breakdown by category
	std::map<QString, double> categoryScores;  // Prologue: 0.6, Call: 0.8, etc.
	std::vector<SourceScore> sourceScores;     // Individual detector scores
};

class FunctionResultsModel : public TreeResultsModel
{
	Q_OBJECT

public:
	enum Column {
		ColSelect = 0,
		ColAddress,
		ColSize,
		ColScore,
		ColMode,
		ColStatus,
		ColXrefs,
		ColCallees,
		ColSources,
		ColCount
	};

	explicit FunctionResultsModel(QObject* parent = nullptr);

	// Set data
	void setResults(const std::vector<FunctionResultItem>& results);
	void clear();

	// Filtering
	void setMinScore(double minScore);
	void setStatusFilter(int filter);  // 0=All, 1=New, 2=Existing
	void setModeFilter(int filter);    // 0=All, 1=ARM, 2=Thumb
	void setSearchText(const QString& text);
	void applyFilters();

	// Selection
	void selectByScore(double minScore);
	void selectNewOnly();
	std::vector<FunctionResultItem> getSelectedItems() const;
	
	// Sorting
	void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

	// Access
	const FunctionResultItem* itemAt(int row) const;
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
	QString sourcesAbbreviation(const FunctionResultItem& item) const;
	QColor scoreColor(double score) const;

	std::vector<FunctionResultItem> m_allResults;
	std::vector<int> m_filteredIndices;
	
	// Filter state
	double m_minScore = 0.0;
	int m_statusFilter = 0;
	int m_modeFilter = 0;
	QString m_searchText;
	
	// Thresholds for coloring
	double m_highThreshold = 0.8;
	double m_medThreshold = 0.5;
};

}  // namespace Armv5UI
