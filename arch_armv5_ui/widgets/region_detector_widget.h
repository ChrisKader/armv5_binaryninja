/*
 * Region Detector Widget
 *
 * UI for advanced region detection with:
 * - Consistent UX pattern (control bar, filter bar, status bar, preview)
 * - Tunable heuristics with presets
 * - Expandable rows for region details
 * - Checkbox selection for batch operations
 */

#pragma once

#include "common/analysis_widgets.h"
#include "uitypes.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSlider>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QSplitter>
#include <QtCore/QAbstractTableModel>

#include <vector>

namespace Armv5UI
{

// Forward declare the engine types
struct DetectedRegionUI
{
	uint64_t start = 0;
	uint64_t end = 0;
	QString type;
	QString confidence;
	QString name;
	QString description;
	double entropy = 0.0;
	double codeDensity = 0.0;
	double stringDensity = 0.0;
	uint32_t alignment = 0;
	bool readable = true;
	bool writable = false;
	bool executable = false;
	bool selected = false;
};

/**
 * Tree model for detected regions with expandable details
 */
class RegionResultsModel : public TreeResultsModel
{
	Q_OBJECT

public:
	enum Column
	{
		ColSelect = 0,
		ColStart,
		ColEnd,
		ColSize,
		ColType,
		ColName,
		ColEntropy,
		ColCodeDens,
		ColConfidence,
		ColCount
	};

	explicit RegionResultsModel(QObject* parent = nullptr);

	void setRegions(const std::vector<DetectedRegionUI>& regions);
	std::vector<DetectedRegionUI> getSelectedRegions() const;
	const DetectedRegionUI* getRegionAt(int row) const;
	int totalCount() const { return static_cast<int>(m_regions.size()); }
	
	// Selection methods
	void selectByType(const QString& type);
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
	std::vector<DetectedRegionUI> m_regions;
};

/**
 * Region detector widget with consistent UX
 */
class RegionDetectorWidget : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit RegionDetectorWidget(QWidget* parent = nullptr);

	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

Q_SIGNALS:
	void regionSelected(uint64_t address);
	void regionsApplied();

private Q_SLOTS:
	void onRunClicked();
	void onResetClicked();
	void onApplyClicked();
	void onFiltersChanged();
	void onPresetChanged(int index);
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
	void applyPreset(int index);
	void scanRegions();

	// Settings panel
	QWidget* m_settingsPanel = nullptr;
	QComboBox* m_presetCombo = nullptr;
	
	// Entropy settings
	QDoubleSpinBox* m_codeEntropyMin = nullptr;
	QDoubleSpinBox* m_codeEntropyMax = nullptr;
	QDoubleSpinBox* m_compressedEntropyMin = nullptr;
	
	// Code density
	QDoubleSpinBox* m_minCodeDensity = nullptr;
	
	// Size thresholds
	QSpinBox* m_minRegionSize = nullptr;
	QSpinBox* m_minCodeRegion = nullptr;
	QSpinBox* m_paddingThreshold = nullptr;
	
	// Alignment
	QComboBox* m_preferredAlignment = nullptr;
	QCheckBox* m_useAlignmentHints = nullptr;
	
	// Detection toggles
	QCheckBox* m_detectLiteralPools = nullptr;
	QCheckBox* m_detectMMIO = nullptr;
	QCheckBox* m_mergeRegions = nullptr;
	
	// Window settings
	QSpinBox* m_windowSize = nullptr;
	QSpinBox* m_windowStep = nullptr;
	
	// Results
	RegionResultsModel* m_model = nullptr;
	QTreeView* m_treeView = nullptr;
};

}  // namespace Armv5UI
