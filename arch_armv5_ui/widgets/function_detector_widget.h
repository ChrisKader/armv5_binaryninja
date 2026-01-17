/*
 * Advanced Analysis Widget
 *
 * Comprehensive firmware analysis UI with:
 * - Multi-heuristic function detection
 * - String detection and categorization  
 * - Structure/VTable/Array detection
 * - Crypto constant detection
 * - Entropy/dead code analysis
 *
 * UI Features:
 * - Consistent layout across all tabs
 * - QDial knobs for threshold values
 * - Icon toolbar buttons
 * - Double-click navigation
 * - Collapsible settings groups
 */

#pragma once

#include "uitypes.h"
#include "common/analysis_widgets.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QTableView>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QToolBar>
#include <QtCore/QAbstractTableModel>
#include <QtCore/QSortFilterProxyModel>

#include <vector>
#include <memory>

namespace Armv5UI
{

// ============================================================================
// Common Structures
// ============================================================================

enum class DetectionCategory { Prologue, CallTarget, Structural, Advanced, Penalty };

struct SourceDetail {
	QString name;
	double contribution;
	DetectionCategory category;
};

// ============================================================================
// Function Detection Models
// ============================================================================

struct FunctionCandidateUI {
	uint64_t address;
	uint64_t estimatedEnd;
	size_t estimatedSize;
	bool isThumb;
	double score;
	std::vector<SourceDetail> sources;
	QStringList warnings;
	bool selected;
	bool isNew;
	int callCount;
	int calleeCount;
};

class FunctionTableModel : public QAbstractTableModel
{
	Q_OBJECT
public:
	enum Column { ColSelect, ColAddress, ColSize, ColScore, ColMode, ColStatus, ColCalls, ColCallees, ColSources, ColCount };
	
	explicit FunctionTableModel(QObject* parent = nullptr);
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	
	void setCandidates(const std::vector<FunctionCandidateUI>& candidates);
	void setThresholds(double minScore, double highScore);
	std::vector<FunctionCandidateUI> getSelectedCandidates() const;
	const FunctionCandidateUI* getCandidateAt(int row) const;
	void selectByScore(double minScore);
	void selectAll(bool select);
	void selectNewOnly();

private:
	std::vector<FunctionCandidateUI> m_candidates;
	double m_minScore = 0.4, m_highScore = 0.8;
};

class FunctionFilterProxy : public QSortFilterProxyModel
{
	Q_OBJECT
public:
	explicit FunctionFilterProxy(QObject* parent = nullptr);
	void setFilters(double minScore, bool newOnly, int mode, const QString& search);
protected:
	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
private:
	double m_minScore = 0.0;
	bool m_newOnly = false;
	int m_modeFilter = 0;
	QString m_searchText;
};

// ============================================================================
// String Detection Models
// ============================================================================

struct StringCandidateUI {
	uint64_t address;
	size_t length;
	size_t definedLength;  // Length if already defined
	QString content;
	QString encoding;
	QString category;
	double confidence;
	bool hasXrefs;
	int xrefCount;
	bool selected;
	bool isNew;
	bool lengthMismatch;  // True if defined length != detected length
};

class StringTableModel : public QAbstractTableModel
{
	Q_OBJECT
public:
	enum Column { ColSelect, ColAddress, ColLength, ColDefined, ColXrefs, ColEncoding, ColCategory, ColContent, ColCount };
	
	explicit StringTableModel(QObject* parent = nullptr);
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	
	void setCandidates(const std::vector<StringCandidateUI>& candidates);
	std::vector<StringCandidateUI> getSelectedCandidates() const;
	const StringCandidateUI* getCandidateAt(int row) const;
	void selectAll(bool select);

private:
	std::vector<StringCandidateUI> m_candidates;
};

class StringFilterProxy : public QSortFilterProxyModel
{
	Q_OBJECT
public:
	explicit StringFilterProxy(QObject* parent = nullptr);
	void setFilters(const QString& search, const QString& category, int statusFilter, bool lengthMismatchOnly);
protected:
	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
private:
	QString m_search;
	QString m_category;
	int m_statusFilter = 0;  // 0=all, 1=new only, 2=existing only, 3=length mismatch
	bool m_lengthMismatchOnly = false;
};

// ============================================================================
// Structure Detection Models
// ============================================================================

struct StructureCandidateUI {
	uint64_t address;
	QString type;
	size_t size;
	size_t elementCount;
	double confidence;
	QString description;
	QStringList elements;
	bool selected;
	bool isNew;
	int functionsDiscovered;
};

class StructureTableModel : public QAbstractTableModel
{
	Q_OBJECT
public:
	enum Column { ColSelect, ColAddress, ColType, ColElements, ColSize, ColFuncs, ColDescription, ColCount };
	
	explicit StructureTableModel(QObject* parent = nullptr);
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	
	void setCandidates(const std::vector<StructureCandidateUI>& candidates);
	std::vector<StructureCandidateUI> getSelectedCandidates() const;
	const StructureCandidateUI* getCandidateAt(int row) const;
	void selectAll(bool select);

private:
	std::vector<StructureCandidateUI> m_candidates;
};

// ============================================================================
// Crypto Detection Models
// ============================================================================

struct CryptoCandidateUI {
	uint64_t address;
	QString algorithm;
	QString constType;
	size_t size;
	double confidence;
	QString description;
	int xrefCount;
	bool selected;
};

class CryptoTableModel : public QAbstractTableModel
{
	Q_OBJECT
public:
	enum Column { ColSelect, ColAddress, ColAlgorithm, ColType, ColSize, ColConf, ColXrefs, ColDescription, ColCount };
	
	explicit CryptoTableModel(QObject* parent = nullptr);
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	
	void setCandidates(const std::vector<CryptoCandidateUI>& candidates);
	const CryptoCandidateUI* getCandidateAt(int row) const;

private:
	std::vector<CryptoCandidateUI> m_candidates;
};

// ============================================================================
// Entropy/Dead Code Models
// ============================================================================

struct EntropyRegionUI {
	uint64_t address;
	size_t size;
	double entropy;
	QString type;
	QString description;
};

struct DeadFunctionUI {
	uint64_t address;
	QString name;
	size_t size;
	QString reason;
};

class EntropyTableModel : public QAbstractTableModel
{
	Q_OBJECT
public:
	enum Column { ColAddress, ColSize, ColEntropy, ColType, ColDescription, ColCount };
	
	explicit EntropyTableModel(QObject* parent = nullptr);
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	
	void setRegions(const std::vector<EntropyRegionUI>& regions);
	const EntropyRegionUI* getRegionAt(int row) const;

private:
	std::vector<EntropyRegionUI> m_regions;
};

// LabeledDial replaced by CockpitKnob from analysis_widgets.h

// ============================================================================
// Collapsible Group Box
// ============================================================================

class CollapsibleGroup : public QWidget
{
	Q_OBJECT
public:
	CollapsibleGroup(const QString& title, QWidget* parent = nullptr);
	void setContent(QWidget* content);
	void setCollapsed(bool collapsed);
	bool isCollapsed() const { return m_collapsed; }

private Q_SLOTS:
	void toggleCollapsed();

private:
	QToolButton* m_toggleBtn;
	QWidget* m_content;
	bool m_collapsed;
};

// ============================================================================
// Disassembly Preview Widget
// ============================================================================

class DisassemblyPreviewWidget : public QWidget
{
	Q_OBJECT
public:
	explicit DisassemblyPreviewWidget(QWidget* parent = nullptr);
	void setBinaryView(BinaryViewRef data);
	void showAddress(uint64_t address, bool isThumb, int lineCount = 10);
	void showString(uint64_t address, size_t length);
	void showStructure(uint64_t address, size_t size);
	void showCryptoConstant(uint64_t address, size_t size, const QString& algorithm);
	void showEntropyRegion(uint64_t address, size_t size, double entropy);
	void clear();

private:
	QColor tokenColor(BNInstructionTextTokenType type) const;
	BinaryViewRef m_data;
	QTextEdit* m_textEdit;
	QLabel* m_headerLabel;
};

// ============================================================================
// Main Widget
// ============================================================================

class FunctionDetectorWidget : public QWidget
{
	Q_OBJECT

public:
	explicit FunctionDetectorWidget(QWidget* parent = nullptr);
	void setBinaryView(BinaryViewRef data);
	void refresh();

Q_SIGNALS:
	void addressSelected(uint64_t address);
	void analysisApplied(size_t count);

private Q_SLOTS:
	void onRunAll();
	void onDetectFunctions();
	void onApplyFunctions();
	void onDetectStrings();
	void onApplyStrings();
	void onDetectStructures();
	void onApplyStructures();
	void onDetectCrypto();
	void onDetectEntropy();
	void onFunctionClicked(const QModelIndex& index);
	void onFunctionDoubleClicked(const QModelIndex& index);
	void onStringClicked(const QModelIndex& index);
	void onStringDoubleClicked(const QModelIndex& index);
	void onStructureClicked(const QModelIndex& index);
	void onStructureDoubleClicked(const QModelIndex& index);
	void onCryptoClicked(const QModelIndex& index);
	void onCryptoDoubleClicked(const QModelIndex& index);
	void onEntropyClicked(const QModelIndex& index);
	void onEntropyDoubleClicked(const QModelIndex& index);
	void onFunctionFilterChanged();
	void onStringFilterChanged();
	void onExportResults();
	void navigateToAddress(uint64_t address);

private:
	void setupUI();
	QWidget* createFunctionsTab();
	QWidget* createStringsTab();
	QWidget* createStructuresTab();
	QWidget* createCryptoTab();
	QWidget* createEntropyTab();
	QWidget* createSettingsTab();
	QToolBar* createToolbar();
	QWidget* createFilterBar(QLineEdit*& search, QComboBox*& filter1, QComboBox*& filter2, 
		QCheckBox*& check, QPushButton*& applyBtn);

	BinaryViewRef m_data;
	QTabWidget* m_mainTabs;
	QToolBar* m_toolbar;
	
	// Function detection controls
	QComboBox* m_presetCombo;
	CockpitKnob* m_minScoreDial;
	CockpitKnob* m_highScoreDial;
	QCheckBox* m_execOnly;
	QCheckBox* m_respectExisting;
	QCheckBox* m_detectArm;
	QCheckBox* m_detectThumb;
	CockpitKnob* m_midInstrPenalty;
	CockpitKnob* m_insideFuncPenalty;
	
	// Function results
	QPushButton* m_detectFuncBtn;
	QPushButton* m_applyFuncBtn;
	QLabel* m_funcStats;
	QTableView* m_funcTable;
	FunctionTableModel* m_funcModel;
	FunctionFilterProxy* m_funcProxy;
	QLineEdit* m_funcSearch;
	QDoubleSpinBox* m_funcFilterScore;
	QCheckBox* m_funcFilterNew;
	QComboBox* m_funcFilterMode;
	
	// String detection controls
	QCheckBox* m_strUnreferenced;
	QCheckBox* m_strInCode;
	QSpinBox* m_strMinLen;
	QSpinBox* m_strMaxLen;
	QCheckBox* m_strAscii;
	QCheckBox* m_strUtf16;
	
	// String results
	QPushButton* m_detectStrBtn;
	QPushButton* m_applyStrBtn;
	QLabel* m_strStats;
	QTableView* m_strTable;
	StringTableModel* m_strModel;
	StringFilterProxy* m_strProxy;
	QLineEdit* m_strSearch;
	QComboBox* m_strFilterCategory;
	QComboBox* m_strFilterStatus;
	QCheckBox* m_strFilterMismatch;
	
	// Structure detection controls
	QCheckBox* m_structVtables;
	QCheckBox* m_structJumpTables;
	QCheckBox* m_structFuncTables;
	QCheckBox* m_structPtrArrays;
	QSpinBox* m_structMinElems;
	
	// Structure results
	QPushButton* m_detectStructBtn;
	QPushButton* m_applyStructBtn;
	QLabel* m_structStats;
	QTableView* m_structTable;
	StructureTableModel* m_structModel;
	
	// Crypto detection
	QCheckBox* m_cryptoAES;
	QCheckBox* m_cryptoDES;
	QCheckBox* m_cryptoSHA;
	QCheckBox* m_cryptoMD5;
	QCheckBox* m_cryptoCRC;
	QCheckBox* m_cryptoOther;
	QPushButton* m_detectCryptoBtn;
	QLabel* m_cryptoStats;
	QTableView* m_cryptoTable;
	CryptoTableModel* m_cryptoModel;
	
	// Entropy analysis
	CockpitKnob* m_entropyThreshold;
	QSpinBox* m_entropyBlockSize;
	QCheckBox* m_entropySkipCode;
	QPushButton* m_detectEntropyBtn;
	QLabel* m_entropyStats;
	QTableView* m_entropyTable;
	EntropyTableModel* m_entropyModel;
	
	// Preview
	DisassemblyPreviewWidget* m_preview;
};

}
