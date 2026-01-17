/*
 * Security Scanner Widget
 *
 * Automated security analysis for firmware:
 * - Credentials: Find hardcoded passwords, API keys, certificates
 * - Crypto: Detect weak crypto (ECB, static IVs, weak RNG)
 * - Patterns: Command injection, format strings, buffer issues
 * - Backdoors: Suspicious auth bypasses, hidden commands
 *
 * Why innovative: No RE tool does this comprehensively for ARM firmware
 */

#pragma once

#include "../common/analysis_widgets.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QDoubleSpinBox>

#include <vector>

namespace Armv5UI
{

// ============================================================================
// Security Finding Types
// ============================================================================

enum class FindingSeverity
{
	Info,
	Low,
	Medium,
	High,
	Critical
};

enum class FindingType
{
	Credential,
	CryptoWeakness,
	VulnPattern,
	Backdoor,
	Sensitive
};

struct SecurityFinding
{
	uint64_t address = 0;
	FindingSeverity severity = FindingSeverity::Info;
	FindingType type = FindingType::Sensitive;
	QString title;
	QString description;
	QString context;
	QString suggestion;
	bool selected = false;
	
	// Details for expansion
	std::vector<uint64_t> references;  // Where this is referenced
	QString matchedPattern;
	QString rawData;
};

// ============================================================================
// SecurityResultsModel
// ============================================================================

class SecurityResultsModel : public TreeResultsModel
{
	Q_OBJECT

public:
	enum Column
	{
		ColSelect = 0,
		ColAddress,
		ColSeverity,
		ColType,
		ColTitle,
		ColCount
	};

	explicit SecurityResultsModel(QObject* parent = nullptr);

	void setFindings(const std::vector<SecurityFinding>& findings);
	const SecurityFinding* getFindingAt(int row) const;
	std::vector<SecurityFinding> getSelectedFindings() const;
	
	// Filtering
	void setMinSeverity(int minSeverity);
	void setTypeFilter(int typeFilter);
	void setSearchText(const QString& text);
	void applyFilters();
	int totalCount() const { return static_cast<int>(m_filteredIndices.size()); }

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
	QString severityString(FindingSeverity sev) const;
	QString typeString(FindingType type) const;
	QColor severityColor(FindingSeverity sev) const;

	std::vector<SecurityFinding> m_allFindings;
	std::vector<int> m_filteredIndices;
	
	int m_minSeverity = 0;
	int m_typeFilter = 0;
	QString m_searchText;
};

// ============================================================================
// CredentialDetectorTab
// ============================================================================

class CredentialDetectorTab : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit CredentialDetectorTab(QWidget* parent = nullptr);
	
	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

private Q_SLOTS:
	void onRunClicked();
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
	void scanForCredentials();

	QWidget* m_settingsWidget = nullptr;
	QCheckBox* m_detectPasswords = nullptr;
	QCheckBox* m_detectApiKeys = nullptr;
	QCheckBox* m_detectCerts = nullptr;
	QCheckBox* m_detectTokens = nullptr;
	QSpinBox* m_minLength = nullptr;
	QCheckBox* m_checkEntropy = nullptr;
	QDoubleSpinBox* m_entropyThreshold = nullptr;

	SecurityResultsModel* m_model = nullptr;
	QTreeView* m_treeView = nullptr;
};

// ============================================================================
// CryptoAnalyzerTab
// ============================================================================

class CryptoAnalyzerTab : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit CryptoAnalyzerTab(QWidget* parent = nullptr);
	
	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

private Q_SLOTS:
	void onRunClicked();
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
	void scanForCryptoIssues();

	QWidget* m_settingsWidget = nullptr;
	QCheckBox* m_detectWeakAlgo = nullptr;
	QCheckBox* m_detectStaticIV = nullptr;
	QCheckBox* m_detectHardcodedKey = nullptr;
	QCheckBox* m_detectWeakRNG = nullptr;
	QCheckBox* m_detectECB = nullptr;

	SecurityResultsModel* m_model = nullptr;
	QTreeView* m_treeView = nullptr;
};

// ============================================================================
// PatternDetectorTab
// ============================================================================

class PatternDetectorTab : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit PatternDetectorTab(QWidget* parent = nullptr);
	
	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

private Q_SLOTS:
	void onRunClicked();
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
	void scanForVulnPatterns();

	QWidget* m_settingsWidget = nullptr;
	QCheckBox* m_detectCmdInjection = nullptr;
	QCheckBox* m_detectFormatString = nullptr;
	QCheckBox* m_detectBufferOverflow = nullptr;
	QCheckBox* m_detectIntOverflow = nullptr;
	QCheckBox* m_detectUseAfterFree = nullptr;

	SecurityResultsModel* m_model = nullptr;
	QTreeView* m_treeView = nullptr;
};

// ============================================================================
// BackdoorDetectorTab
// ============================================================================

class BackdoorDetectorTab : public AnalysisTabBase
{
	Q_OBJECT

public:
	explicit BackdoorDetectorTab(QWidget* parent = nullptr);
	
	void setBinaryView(BinaryViewRef data) override;
	void refresh() override;

private Q_SLOTS:
	void onRunClicked();
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
	void scanForBackdoors();

	QWidget* m_settingsWidget = nullptr;
	QCheckBox* m_detectAuthBypass = nullptr;
	QCheckBox* m_detectHiddenCmd = nullptr;
	QCheckBox* m_detectDebugAccess = nullptr;
	QCheckBox* m_detectMagicValues = nullptr;

	SecurityResultsModel* m_model = nullptr;
	QTreeView* m_treeView = nullptr;
};

// ============================================================================
// SecurityScannerWidget - Main container
// ============================================================================

class SecurityScannerWidget : public QWidget
{
	Q_OBJECT

public:
	explicit SecurityScannerWidget(QWidget* parent = nullptr);
	
	void setBinaryView(BinaryViewRef data);
	void refresh();

Q_SIGNALS:
	void addressSelected(uint64_t address);

private:
	void setupUI();

	BinaryViewRef m_data;
	QTabWidget* m_tabs;
	
	CredentialDetectorTab* m_credentialsTab;
	CryptoAnalyzerTab* m_cryptoTab;
	PatternDetectorTab* m_patternsTab;
	BackdoorDetectorTab* m_backdoorsTab;
};

}  // namespace Armv5UI
