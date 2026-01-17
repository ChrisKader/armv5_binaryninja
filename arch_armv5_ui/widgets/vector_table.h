/*
 * Vector Table Widget
 *
 * Displays the ARM exception vector table and handlers with:
 * - Consistent UX pattern (control bar, filter bar, status bar, preview)
 * - Checkbox selection for batch operations
 * - Expandable rows for handler details
 * - Double-click navigation
 */

#pragma once

#include "common/analysis_widgets.h"
#include "uitypes.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QSpinBox>
#include <QtCore/QAbstractTableModel>

#include <vector>

namespace Armv5UI
{

/**
 * Data for a single vector entry.
 */
struct VectorEntryRowData
{
	int vectorIndex = 0;
	std::string vectorName;
	uint64_t vectorAddress = 0;
	uint64_t handlerAddress = 0;
	std::string handlerName;
	bool isThumb = false;
	bool hasHandler = false;
	bool selected = false;
	
	// Additional details for expansion
	std::string instructionText;  // What's at the vector location (e.g., "B handler")
	size_t handlerSize = 0;
	int xrefCount = 0;
	bool isFunction = false;
};

/**
 * Tree model for vector entries with expandable details.
 */
class VectorResultsModel : public TreeResultsModel
{
	Q_OBJECT

public:
	enum Column
	{
		ColSelect = 0,
		ColIndex,
		ColVector,
		ColVecAddr,
		ColHandler,
		ColHandlerAddr,
		ColMode,
		ColCount
	};

	explicit VectorResultsModel(QObject* parent = nullptr);

	void setVectors(const std::vector<VectorEntryRowData>& vectors);
	const VectorEntryRowData* getVectorAt(int row) const;
	std::vector<VectorEntryRowData> getSelectedVectors() const;
	int totalCount() const { return static_cast<int>(m_vectors.size()); }
	
	// Selection
	void selectMissing();  // Select entries without handlers
	void setSelected(int row, bool selected);

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
	std::vector<VectorEntryRowData> m_vectors;
};

/**
 * Vector table display widget with consistent UX.
 */
class VectorTableWidget : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit VectorTableWidget(QWidget* parent = nullptr);

	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;
	
	// Legacy API for backward compatibility
	void refresh(BinaryViewRef data);

Q_SIGNALS:
	void handlerSelected(uint64_t address);

private Q_SLOTS:
	void onRunClicked();
	void onResetClicked();
	void onApplyClicked();
	void onFiltersChanged();
	void onItemClicked(const QModelIndex& index);
	void onItemDoubleClicked(const QModelIndex& index);
	void onSelectionChanged();

protected:
	QWidget* createSettingsWidget() override;
	QWidget* createFilterBar() override;
	QWidget* createResultsView() override;

private:
	void setupConnections();
	void updateStatusBar();
	void scanVectorTable();
	void parseVectorInstruction(VectorEntryRowData& vec);

	// Settings
	QWidget* m_settingsWidget = nullptr;
	QSpinBox* m_imageBaseOffset = nullptr;
	QCheckBox* m_scanAltLocations = nullptr;
	QCheckBox* m_analyzeHandlers = nullptr;
	
	VectorResultsModel* m_model = nullptr;
	QTreeView* m_treeView = nullptr;
};

}  // namespace Armv5UI
