/*
 * Shared Analysis Widgets
 *
 * Reusable UI components for consistent UX across all analysis tabs:
 * - AnalysisControlBar: Run/Stop/Reset/Apply/Log/Export buttons
 * - FilterBar: Collapsible filter controls
 * - TreeResultsModel: Expandable tree view with checkbox selection
 * - ContextPreview: Disassembly/hex/string preview pane
 * - AnalysisStatusBar: Status text, progress bar, summary counts
 * - DetectorSettingsWidget: Tabbed settings with weight/threshold controls
 */

#pragma once

#include "binaryninjaapi.h"
#include "uitypes.h"
#include "theme.h"
#include "fontsettings.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QSlider>
#include <QtWidgets/QDial>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QStyle>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMenu>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QSplitter>
#include <QtGui/QAction>
#include <QtGui/QClipboard>
#include <QtGui/QShortcut>
#include <QtGui/QPainter>
#include <QtGui/QMouseEvent>
#include <QtCore/QAbstractItemModel>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QSettings>
#include <QtCore/QTimer>
#include <QtGui/QKeySequence>

#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace Armv5UI
{

// ============================================================================
// AnalysisControlBar - QToolBar with actions like BN's workflow monitor
// ============================================================================

class AnalysisControlBar : public QToolBar
{
	Q_OBJECT

public:
	explicit AnalysisControlBar(QWidget* parent = nullptr);

	void setRunning(bool running);
	void setApplyEnabled(bool enabled);
	void setSelectionCount(int count);
	void setApplyVisible(bool visible);
	void setLogChecked(bool checked);

Q_SIGNALS:
	void runClicked();
	void stopClicked();
	void resetClicked();
	void applyClicked();
	void logToggled(bool checked);
	void exportClicked();

private:
	void setupActions();

	QAction* m_runAction;
	QAction* m_stopAction;
	QAction* m_resetAction;
	QAction* m_applyAction;
	QAction* m_logAction;
	QAction* m_exportAction;
	bool m_running = false;
};

// ============================================================================
// FilterBar - Collapsible filter controls
// ============================================================================

class FilterBar : public QWidget
{
	Q_OBJECT

public:
	explicit FilterBar(QWidget* parent = nullptr);

	void setCollapsed(bool collapsed);
	bool isCollapsed() const { return m_collapsed; }

	// Add filter controls dynamically
	void addScoreFilter(double min = 0.0, double max = 1.0, double value = 0.0);
	void addStatusFilter(const QStringList& options);
	void addModeFilter(const QStringList& options);
	void addSearchBox(const QString& placeholder = "Search...");
	void addCustomCombo(const QString& label, const QStringList& options);

	// Get filter values
	double scoreFilter() const;
	int statusFilterIndex() const;
	int modeFilterIndex() const;
	QString searchText() const;
	int customComboIndex(const QString& label) const;

	// Quick filter presets
	void addPresetButton(const QString& text, const QString& tooltip);

Q_SIGNALS:
	void filtersChanged();
	void presetClicked(const QString& preset);

private Q_SLOTS:
	void toggleCollapsed();
	void onFilterChanged();

private:
	void setupUI();

	QToolButton* m_collapseBtn;
	QWidget* m_content;
	QHBoxLayout* m_contentLayout;
	bool m_collapsed = false;

	QDoubleSpinBox* m_scoreFilter = nullptr;
	QComboBox* m_statusFilter = nullptr;
	QComboBox* m_modeFilter = nullptr;
	QLineEdit* m_searchBox = nullptr;
	std::map<QString, QComboBox*> m_customCombos;
};

// ============================================================================
// TreeResultsModel - Base class for expandable tree results
// ============================================================================

struct TreeNodeData
{
	enum Type { Root, Item, Detail };
	Type type = Item;
	int row = 0;
	bool selected = false;
	bool expanded = false;
	uint64_t address = 0;
	QVariantMap data;  // Flexible data storage
};

class TreeResultsModel : public QAbstractItemModel
{
	Q_OBJECT

public:
	explicit TreeResultsModel(QObject* parent = nullptr);
	virtual ~TreeResultsModel();

	// QAbstractItemModel interface
	QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
	QModelIndex parent(const QModelIndex& child) const override;
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

	// Column configuration
	void setColumns(const QStringList& headers, const std::vector<int>& widths = {});
	
	// Data management
	void clear();
	void beginUpdate();
	void endUpdate();
	
	// Selection helpers
	void selectAll();
	void selectNone();
	void invertSelection();
	std::vector<uint64_t> getSelectedAddresses() const;
	int selectedCount() const;
	
	// Sorting
	void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

	// Public accessors for helpers (ContextMenuHelper, KeyboardShortcutMixin)
	virtual bool isItemSelected(int row) const = 0;
	virtual void setItemSelected(int row, bool selected) = 0;
	virtual uint64_t itemAddress(int row) const = 0;
	virtual int itemCount() const = 0;

protected:
	// Override these in subclasses
	virtual QVariant itemData(int row, int column, int role) const = 0;
	virtual QVariant detailData(int parentRow, int detailRow, int column, int role) const;
	virtual int detailRowCount(int parentRow) const { return 0; }

	QStringList m_headers;
	std::vector<int> m_columnWidths;
};

// ============================================================================
// ContextPreview - Disassembly/hex/string preview
// ============================================================================

class ContextPreview : public QWidget
{
	Q_OBJECT

public:
	explicit ContextPreview(QWidget* parent = nullptr);

	void setBinaryView(BinaryViewRef data);
	
	// Show different content types
	void showDisassembly(uint64_t address, bool isThumb = false, int lineCount = 10);
	void showHex(uint64_t address, size_t length);
	void showString(uint64_t address, size_t length);
	void showStructure(uint64_t address, size_t size);
	void showCustom(const QString& title, const QString& content);
	void clear();

private:
	QColor tokenColor(BNInstructionTextTokenType type) const;

	BinaryViewRef m_data;
	QLabel* m_headerLabel;
	QTextEdit* m_textEdit;
};

// ============================================================================
// AnalysisStatusBar - Status + progress + summary
// ============================================================================

class AnalysisStatusBar : public QWidget
{
	Q_OBJECT

public:
	explicit AnalysisStatusBar(QWidget* parent = nullptr);

	void setStatus(const QString& status);
	void setProgress(int percent);  // -1 to hide
	void setPhase(int current, int total, const QString& phaseName);
	void setSummary(const QString& summary);
	void setSummary(int total, int selected);
	void setSummary(const QString& label1, int count1, const QString& label2, int count2);

	void setCancelVisible(bool visible);
	void setRunning(bool running);

Q_SIGNALS:
	void cancelClicked();

private:
	void setupUI();

	QLabel* m_statusLabel;
	QLabel* m_phaseLabel;
	QProgressBar* m_progress;
	QToolButton* m_cancelButton;
	QLabel* m_summaryLabel;
	bool m_running = false;
};

// ============================================================================
// CockpitPanel - Metal panel container with screws and engraved lines
// ============================================================================

class CockpitPanel : public QWidget
{
	Q_OBJECT

public:
	explicit CockpitPanel(QWidget* parent = nullptr);

	void setTitle(const QString& title);
	QLayout* contentLayout() { return m_contentLayout; }

protected:
	void paintEvent(QPaintEvent* event) override;

private:
	void drawScrew(QPainter& p, int x, int y, int size);
	void drawEngravedLine(QPainter& p, int x1, int y1, int x2, int y2);

	QString m_title;
	QVBoxLayout* m_contentLayout;
};

// ============================================================================
// CockpitKnob - Vertical cockpit-style control: Label / Display / Knob
// ============================================================================

class CockpitKnob : public QWidget
{
	Q_OBJECT

public:
	CockpitKnob(const QString& label, double minVal, double maxVal, double value,
		const QString& tooltip = QString(), QWidget* parent = nullptr);

	double value() const;
	void setValue(double val);
	void setRange(double min, double max);

Q_SIGNALS:
	void valueChanged(double value);

protected:
	void paintEvent(QPaintEvent* event) override;

private:
	void setupUI(const QString& label, const QString& tooltip);
	void updateDisplay();

	QString m_labelText;
	QLabel* m_labelWidget;
	QLabel* m_display;
	QDial* m_dial;
	double m_min;
	double m_max;
};

// ============================================================================
// CockpitPushButton - Boeing-style illuminated push button with LED bar
// ============================================================================

class CockpitPushButton : public QWidget
{
	Q_OBJECT

public:
	CockpitPushButton(const QString& label, bool checked = false,
		const QString& tooltip = QString(), QWidget* parent = nullptr);

	bool isChecked() const;
	void setChecked(bool checked);

Q_SIGNALS:
	void toggled(bool checked);

protected:
	void paintEvent(QPaintEvent* event) override;
	void mousePressEvent(QMouseEvent* event) override;
	void mouseReleaseEvent(QMouseEvent* event) override;

private:
	QString m_label;
	bool m_checked;
	bool m_pressed;
};

// ============================================================================
// DetectorRowWidget - Single detector with cockpit-style controls
// ============================================================================

class DetectorRowWidget : public QWidget
{
	Q_OBJECT

public:
	DetectorRowWidget(const QString& name, double weight, double threshold,
		bool enabled = true, bool useKnobs = true, QWidget* parent = nullptr);

	bool isEnabled() const;
	double weight() const;
	double threshold() const;

	void setEnabled(bool enabled);
	void setWeight(double weight);
	void setThreshold(double threshold);
	void setUseKnobs(bool useKnobs);

Q_SIGNALS:
	void settingsChanged();

protected:
	void paintEvent(QPaintEvent* event) override;

private:
	void setupUI(bool useKnobs);

	QString m_name;
	CockpitPushButton* m_enableButton = nullptr;
	CockpitKnob* m_weightKnob = nullptr;
	CockpitKnob* m_threshKnob = nullptr;
	bool m_useKnobs;
};

// ============================================================================
// DetectorSettingsWidget - Tabbed settings container
// ============================================================================

class DetectorSettingsWidget : public QWidget
{
	Q_OBJECT

public:
	explicit DetectorSettingsWidget(QWidget* parent = nullptr);

	// Preset management
	void loadPreset(const QString& name);
	QStringList availablePresets() const;
	QString currentPreset() const;

	// Add tabs with detector rows
	void addTab(const QString& name, const std::vector<std::tuple<QString, double, double>>& detectors);
	void addGlobalTab();  // Standard global settings

	// Global settings accessors
	double minimumScore() const;
	double highConfidenceScore() const;
	bool scanExecutableOnly() const;
	bool respectExistingFunctions() const;
	bool detectArmFunctions() const;
	bool detectThumbFunctions() const;
	int alignmentPreference() const;

	// Detector settings
	bool isDetectorEnabled(const QString& tab, const QString& detector) const;
	double detectorWeight(const QString& tab, const QString& detector) const;
	double detectorThreshold(const QString& tab, const QString& detector) const;

	// Control style
	void setUseKnobs(bool useKnobs);
	bool useKnobs() const { return m_useKnobs; }

Q_SIGNALS:
	void settingsChanged();
	void presetChanged(const QString& name);

private Q_SLOTS:
	void onPresetSelected(int index);
	void onSettingChanged();

private:
	void setupUI();
	void createGlobalTab();

	QComboBox* m_presetCombo;
	QTabWidget* m_tabs;
	bool m_useKnobs = true;

	// Global settings widgets
	QDoubleSpinBox* m_minScore = nullptr;
	QDoubleSpinBox* m_highConfScore = nullptr;
	QCheckBox* m_scanExecOnly = nullptr;
	QCheckBox* m_respectExisting = nullptr;
	QCheckBox* m_detectArm = nullptr;
	QCheckBox* m_detectThumb = nullptr;
	QComboBox* m_alignPref = nullptr;

	// Detector row widgets by tab/name
	std::map<QString, std::map<QString, DetectorRowWidget*>> m_detectorRows;
};

// ============================================================================
// HighlightingItemDelegate - Highlight search matches in tree cells
// ============================================================================

class HighlightingItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

public:
	explicit HighlightingItemDelegate(QObject* parent = nullptr);

	void setSearchTerm(const QString& term);
	QString searchTerm() const { return m_searchTerm; }

	void paint(QPainter* painter, const QStyleOptionViewItem& option,
		const QModelIndex& index) const override;

private:
	QString m_searchTerm;
	QColor m_highlightColor;
};

// ============================================================================
// ColumnSettings - Persist column widths and sort order
// ============================================================================

class ColumnSettings
{
public:
	static ColumnSettings& instance();

	void saveColumnWidths(const QString& widgetId, const QHeaderView* header);
	void restoreColumnWidths(const QString& widgetId, QHeaderView* header);
	void saveSortColumn(const QString& widgetId, int column, Qt::SortOrder order);
	std::pair<int, Qt::SortOrder> loadSortColumn(const QString& widgetId);

private:
	ColumnSettings() = default;
	QSettings m_settings{"Armv5Plugin", "ColumnSettings"};
};

// ============================================================================
// ContextMenuHelper - Build context menus for tree views
// ============================================================================

class ContextMenuHelper : public QObject
{
	Q_OBJECT

public:
	explicit ContextMenuHelper(QTreeView* treeView, TreeResultsModel* model,
		QWidget* parent = nullptr);

	void setNavigationCallback(std::function<void(uint64_t)> callback);
	void setCreateFunctionCallback(std::function<void(uint64_t, bool)> callback);
	void setApplyCallback(std::function<void()> callback);

Q_SIGNALS:
	void navigateRequested(uint64_t address);
	void createFunctionRequested(uint64_t address, bool isThumb);
	void applyRequested();

private Q_SLOTS:
	void showContextMenu(const QPoint& pos);

private:
	void copyAddresses();
	void copyRowData();

	QTreeView* m_treeView;
	TreeResultsModel* m_model;
	std::function<void(uint64_t)> m_navigateCallback;
	std::function<void(uint64_t, bool)> m_createFunctionCallback;
	std::function<void()> m_applyCallback;
};

// ============================================================================
// KeyboardShortcutMixin - Add standard shortcuts to any widget
// ============================================================================

class KeyboardShortcutMixin
{
public:
	void setupStandardShortcuts(QWidget* widget, TreeResultsModel* model,
		std::function<void()> copyCallback = nullptr);

	// Extended shortcuts for tree navigation
	void setupTreeShortcuts(QWidget* widget, QTreeView* treeView, TreeResultsModel* model,
		std::function<void(uint64_t)> navigateCallback = nullptr);

private:
	QShortcut* m_selectAllShortcut = nullptr;
	QShortcut* m_invertShortcut = nullptr;
	QShortcut* m_copyShortcut = nullptr;
	QShortcut* m_enterShortcut = nullptr;
	QShortcut* m_spaceShortcut = nullptr;
	QShortcut* m_escapeShortcut = nullptr;
	QShortcut* m_findShortcut = nullptr;
};

// ============================================================================
// AnalysisTabBase - Base class for analysis tabs with consistent UX
// ============================================================================

class AnalysisTabBase : public QWidget
{
	Q_OBJECT

public:
	explicit AnalysisTabBase(QWidget* parent = nullptr);
	virtual ~AnalysisTabBase() = default;

	virtual void setBinaryView(BinaryViewRef data);
	virtual void refresh() = 0;

Q_SIGNALS:
	void addressSelected(uint64_t address);
	void analysisApplied(size_t count);

protected:
	// Subclasses override these to customize
	virtual QWidget* createSettingsWidget() { return nullptr; }
	virtual QWidget* createControlBar();
	virtual QWidget* createFilterBar() { return nullptr; }
	virtual QWidget* createResultsView() = 0;
	virtual QWidget* createPreview();
	virtual QWidget* createStatusBar();

	// Standard layout assembly
	void setupStandardLayout();

	// Navigation
	void navigateToAddress(uint64_t address);

	BinaryViewRef m_data;
	AnalysisControlBar* m_controlBar = nullptr;
	FilterBar* m_filterBar = nullptr;
	ContextPreview* m_preview = nullptr;
	AnalysisStatusBar* m_statusBar = nullptr;
};

}  // namespace Armv5UI
