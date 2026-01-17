/*
 * Firmware Diff Widget
 *
 * Compare two firmware versions side-by-side:
 * - Load second binary for comparison
 * - Function-level diff (new, removed, modified)
 * - Byte-level patch highlighting
 * - Security focus: "What changed between versions?"
 *
 * Why innovative: Essential for vuln research, patch analysis, no good tool exists
 */

#pragma once

#include "../common/analysis_widgets.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLineEdit>

#include <vector>

namespace Armv5UI
{

// ============================================================================
// Diff Types
// ============================================================================

enum class DiffType
{
	Added,      // New in comparison binary
	Removed,    // Missing in comparison binary
	Modified,   // Changed between versions
	Unchanged   // Same in both
};

struct FunctionDiff
{
	uint64_t baseAddress = 0;
	uint64_t compareAddress = 0;
	QString name;
	DiffType type = DiffType::Unchanged;
	int baseSizeBytes = 0;
	int compareSizeBytes = 0;
	int sizeDelta = 0;
	QString changeDetail;
	bool selected = false;
	
	// Detailed changes
	std::vector<std::pair<uint64_t, uint64_t>> changedByteRanges;
};

struct ByteDiff
{
	uint64_t baseAddress = 0;
	uint64_t compareAddress = 0;
	size_t length = 0;
	DiffType type = DiffType::Modified;
	QString description;
};

// ============================================================================
// DiffResultsModel
// ============================================================================

class DiffResultsModel : public TreeResultsModel
{
	Q_OBJECT

public:
	enum Column
	{
		ColSelect = 0,
		ColChange,
		ColAddress,
		ColName,
		ColChange2,
		ColSizeDelta,
		ColDetail,
		ColCount
	};

	explicit DiffResultsModel(QObject* parent = nullptr);

	void setDiffs(const std::vector<FunctionDiff>& diffs);
	const FunctionDiff* getDiffAt(int row) const;
	std::vector<FunctionDiff> getSelectedDiffs() const;
	int totalCount() const { return static_cast<int>(m_filteredIndices.size()); }
	
	// Filtering
	void setTypeFilter(int filter);  // 0=All, 1=Added, 2=Removed, 3=Modified
	void setSearchText(const QString& text);
	void applyFilters();

	void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

protected:
	QVariant itemData(int row, int column, int role) const override;
	QVariant detailData(int parentRow, int detailRow, int column, int role) const override;
	int detailRowCount(int parentRow) const override;
	bool isItemSelected(int row) const override;
	void setItemSelected(int row, bool selected) override;
	uint64_t itemAddress(int row) const override;
	int itemCount() const override;

private:
	QString typeString(DiffType type) const;
	QString typeIcon(DiffType type) const;
	QColor typeColor(DiffType type) const;

	std::vector<FunctionDiff> m_allDiffs;
	std::vector<int> m_filteredIndices;
	
	int m_typeFilter = 0;
	QString m_searchText;
};

// ============================================================================
// SideBySideView - Side-by-side disassembly comparison
// ============================================================================

class SideBySideView : public QWidget
{
	Q_OBJECT

public:
	explicit SideBySideView(QWidget* parent = nullptr);

	void setBinaryViews(BinaryViewRef base, BinaryViewRef compare);
	void showDiff(const FunctionDiff& diff);
	void clear();

private:
	void setupUI();
	void showDisassembly(QTextEdit* view, BinaryViewRef data, uint64_t address, bool isThumb);
	void highlightChanges();

	BinaryViewRef m_baseData;
	BinaryViewRef m_compareData;
	
	QLabel* m_baseLabel;
	QLabel* m_compareLabel;
	QTextEdit* m_baseView;
	QTextEdit* m_compareView;
	QSplitter* m_splitter;
};

// ============================================================================
// FirmwareDiffWidget
// ============================================================================

class FirmwareDiffWidget : public QWidget
{
	Q_OBJECT

public:
	explicit FirmwareDiffWidget(QWidget* parent = nullptr);

	void setBinaryView(BinaryViewRef data);
	void refresh();

Q_SIGNALS:
	void addressSelected(uint64_t address);

private Q_SLOTS:
	void onLoadCompareClicked();
	void onAnalyzeClicked();
	void onResetClicked();
	void onFiltersChanged();
	void onItemClicked(const QModelIndex& index);
	void onItemDoubleClicked(const QModelIndex& index);
	void onViewModeChanged(int index);

private:
	void setupUI();
	void setupConnections();
	void updateStatusBar();
	void performDiff();
	
	// Diff algorithms
	std::vector<FunctionDiff> diffFunctions();
	void matchFunctionsByName(std::vector<FunctionDiff>& diffs);
	void matchFunctionsByAddress(std::vector<FunctionDiff>& diffs);
	void detectModifications(FunctionDiff& diff);

	BinaryViewRef m_baseData;
	BinaryViewRef m_compareData;
	QString m_compareFilename;
	
	// Header
	QLabel* m_baseLabel;
	QLineEdit* m_compareEdit;
	QPushButton* m_loadButton;
	
	// Control bar
	AnalysisControlBar* m_controlBar;
	
	// Filter bar
	FilterBar* m_filterBar;
	
	// Results
	DiffResultsModel* m_model;
	QTreeView* m_treeView;
	
	// View modes
	QTabWidget* m_viewTabs;
	SideBySideView* m_sideBySideView;
	
	// Status
	AnalysisStatusBar* m_statusBar;
};

}  // namespace Armv5UI
