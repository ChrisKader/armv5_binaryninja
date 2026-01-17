/*
 * Discover Widget
 *
 * Main analysis widget with consistent UX across all detection tabs:
 * - Functions: Multi-heuristic function detection
 * - Strings: String detection and categorization
 * - Structures: VTable/jump table/pointer array detection
 * - Crypto: Cryptographic constant detection
 * - Entropy: High-entropy region analysis
 */

#pragma once

#include "../common/analysis_widgets.h"
#include "function_results_model.h"
#include "detection_models.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QSplitter>

namespace Armv5UI
{

// ============================================================================
// FunctionDetectorTab - Function detection with full settings
// ============================================================================

class FunctionDetectorTab : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit FunctionDetectorTab(QWidget* parent = nullptr);
	
	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

private Q_SLOTS:
	void onRunClicked();
	void onStopClicked();
	void onResetClicked();
	void onApplyClicked();
	void onExportClicked();
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
	void copySelectedToClipboard();
	
	// Convert from analysis results to UI model
	void populateResults(const std::vector<Armv5Analysis::FunctionCandidate>& candidates);

	DetectorSettingsWidget* m_settings = nullptr;
	FunctionResultsModel* m_model = nullptr;
	QTreeView* m_treeView = nullptr;
	
	bool m_running = false;
};

// ============================================================================
// StringDetectorTab - String detection
// ============================================================================

class StringDetectorTab : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit StringDetectorTab(QWidget* parent = nullptr);

	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

private Q_SLOTS:
	void onRunClicked();
	void onApplyClicked();
	void onExportClicked();
	void onFiltersChanged();
	void onItemClicked(const QModelIndex& index);
	void onItemDoubleClicked(const QModelIndex& index);

protected:
	QWidget* createSettingsWidget() override;
	QWidget* createFilterBar() override;
	QWidget* createResultsView() override;

private:
	void setupConnections();
	void updateStatusBar();
	void populateResults(const std::vector<Armv5Analysis::DetectedString>& strings);

	QWidget* m_settingsWidget = nullptr;
	QTreeView* m_treeView = nullptr;
	StringResultsModel* m_model = nullptr;

	// Settings controls
	QCheckBox* m_detectAscii = nullptr;
	QCheckBox* m_detectUtf8 = nullptr;
	QCheckBox* m_detectUtf16 = nullptr;
	QCheckBox* m_detectUnreferenced = nullptr;
	QCheckBox* m_categorize = nullptr;
	QSpinBox* m_minLength = nullptr;
	QDoubleSpinBox* m_minConfidence = nullptr;
};

// ============================================================================
// StructureDetectorTab - Structure/VTable detection
// ============================================================================

class StructureDetectorTab : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit StructureDetectorTab(QWidget* parent = nullptr);

	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

private Q_SLOTS:
	void onRunClicked();
	void onApplyClicked();
	void onExportClicked();
	void onItemClicked(const QModelIndex& index);
	void onItemDoubleClicked(const QModelIndex& index);

protected:
	QWidget* createSettingsWidget() override;
	QWidget* createResultsView() override;

private:
	void setupConnections();
	void updateStatusBar();
	void populateResults(const std::vector<Armv5Analysis::DetectedStructure>& structures);

	QWidget* m_settingsWidget = nullptr;
	QTreeView* m_treeView = nullptr;
	StructureResultsModel* m_model = nullptr;

	QCheckBox* m_detectVtables = nullptr;
	QCheckBox* m_detectJumpTables = nullptr;
	QCheckBox* m_detectFuncTables = nullptr;
	QCheckBox* m_detectPtrArrays = nullptr;
	QCheckBox* m_detectIntArrays = nullptr;
	QSpinBox* m_minElements = nullptr;
	QDoubleSpinBox* m_minConfidence = nullptr;
};

// ============================================================================
// CryptoDetectorTab - Crypto constant detection
// ============================================================================

class CryptoDetectorTab : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit CryptoDetectorTab(QWidget* parent = nullptr);

	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

private Q_SLOTS:
	void onRunClicked();
	void onExportClicked();
	void onItemClicked(const QModelIndex& index);
	void onItemDoubleClicked(const QModelIndex& index);

protected:
	QWidget* createSettingsWidget() override;
	QWidget* createResultsView() override;

private:
	void setupConnections();
	void updateStatusBar();
	void populateResults(const std::vector<Armv5Analysis::CryptoConstant>& constants);

	QWidget* m_settingsWidget = nullptr;
	QTreeView* m_treeView = nullptr;
	CryptoResultsModel* m_model = nullptr;

	QCheckBox* m_detectAES = nullptr;
	QCheckBox* m_detectDES = nullptr;
	QCheckBox* m_detectSHA = nullptr;
	QCheckBox* m_detectMD5 = nullptr;
	QCheckBox* m_detectCRC = nullptr;
	QCheckBox* m_detectTEA = nullptr;
	QCheckBox* m_detectBlowfish = nullptr;
	QCheckBox* m_detectChaCha = nullptr;
	QDoubleSpinBox* m_minConfidence = nullptr;
};

// ============================================================================
// EntropyAnalyzerTab - Entropy analysis
// ============================================================================

class EntropyAnalyzerTab : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit EntropyAnalyzerTab(QWidget* parent = nullptr);

	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

private Q_SLOTS:
	void onRunClicked();
	void onExportClicked();
	void onItemClicked(const QModelIndex& index);
	void onItemDoubleClicked(const QModelIndex& index);

protected:
	QWidget* createSettingsWidget() override;
	QWidget* createResultsView() override;

private:
	void setupConnections();
	void updateStatusBar();
	void populateResults(const std::vector<Armv5Analysis::EntropyRegion>& regions);

	QWidget* m_settingsWidget = nullptr;
	QTreeView* m_treeView = nullptr;
	EntropyResultsModel* m_model = nullptr;

	QDoubleSpinBox* m_highThreshold = nullptr;
	QDoubleSpinBox* m_lowThreshold = nullptr;
	QSpinBox* m_blockSize = nullptr;
	QSpinBox* m_minRegionSize = nullptr;
	QCheckBox* m_skipCode = nullptr;
	QCheckBox* m_mergeRegions = nullptr;
};

// ============================================================================
// DiscoverWidget - Main container with tabs
// ============================================================================

class DiscoverWidget : public QWidget
{
	Q_OBJECT

public:
	explicit DiscoverWidget(QWidget* parent = nullptr);
	
	void setBinaryView(BinaryViewRef data);
	void refresh();

Q_SIGNALS:
	void addressSelected(uint64_t address);
	void analysisApplied(size_t count);

private:
	void setupUI();

	BinaryViewRef m_data;
	QTabWidget* m_tabs;
	
	FunctionDetectorTab* m_functionsTab;
	StringDetectorTab* m_stringsTab;
	StructureDetectorTab* m_structuresTab;
	CryptoDetectorTab* m_cryptoTab;
	EntropyAnalyzerTab* m_entropyTab;
};

}  // namespace Armv5UI
