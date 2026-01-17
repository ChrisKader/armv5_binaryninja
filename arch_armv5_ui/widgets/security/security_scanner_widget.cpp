/*
 * Security Scanner Widget Implementation
 */

#include "security_scanner_widget.h"
#include "binaryninjaapi.h"
#include "theme.h"

#include <QtWidgets/QApplication>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QFormLayout>
#include <QtCore/QRegularExpression>

#include <cmath>
#include <algorithm>
#include <set>

using namespace BinaryNinja;

namespace Armv5UI
{

// Common credential patterns
static const QStringList kPasswordPatterns = {
	"password", "passwd", "pwd", "secret", "private_key",
	"api_key", "apikey", "auth_token", "access_token",
	"bearer", "credential", "admin", "root", "default"
};

// Common crypto function names
static const QStringList kCryptoFunctions = {
	"aes_encrypt", "aes_decrypt", "des_encrypt", "des_decrypt",
	"md5", "sha1", "sha256", "hmac", "rsa_encrypt", "rsa_decrypt",
	"rand", "srand", "random", "arc4random"
};

// Dangerous function patterns
static const QStringList kDangerousFunctions = {
	"system", "exec", "popen", "sprintf", "strcpy", "strcat",
	"gets", "scanf", "printf", "memcpy", "memmove"
};

// ============================================================================
// SecurityResultsModel
// ============================================================================

SecurityResultsModel::SecurityResultsModel(QObject* parent)
	: TreeResultsModel(parent)
{
	setColumns({"", "Address", "Severity", "Type", "Finding"},
		{24, 85, 55, 70, -1});
}

void SecurityResultsModel::setFindings(const std::vector<SecurityFinding>& findings)
{
	beginResetModel();
	m_allFindings = findings;
	applyFilters();
	endResetModel();
}

const SecurityFinding* SecurityResultsModel::getFindingAt(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return nullptr;
	return &m_allFindings[m_filteredIndices[row]];
}

std::vector<SecurityFinding> SecurityResultsModel::getSelectedFindings() const
{
	std::vector<SecurityFinding> result;
	for (int idx : m_filteredIndices)
	{
		if (m_allFindings[idx].selected)
			result.push_back(m_allFindings[idx]);
	}
	return result;
}

void SecurityResultsModel::setMinSeverity(int minSeverity)
{
	m_minSeverity = minSeverity;
}

void SecurityResultsModel::setTypeFilter(int typeFilter)
{
	m_typeFilter = typeFilter;
}

void SecurityResultsModel::setSearchText(const QString& text)
{
	m_searchText = text.toLower();
}

void SecurityResultsModel::applyFilters()
{
	beginResetModel();
	m_filteredIndices.clear();
	
	for (size_t i = 0; i < m_allFindings.size(); i++)
	{
		const auto& f = m_allFindings[i];
		
		// Severity filter
		if (static_cast<int>(f.severity) < m_minSeverity)
			continue;
		
		// Type filter
		if (m_typeFilter > 0 && static_cast<int>(f.type) != (m_typeFilter - 1))
			continue;
		
		// Search filter
		if (!m_searchText.isEmpty())
		{
			if (!f.title.toLower().contains(m_searchText) &&
				!f.description.toLower().contains(m_searchText))
				continue;
		}
		
		m_filteredIndices.push_back(static_cast<int>(i));
	}
	
	endResetModel();
}

void SecurityResultsModel::sort(int column, Qt::SortOrder order)
{
	beginResetModel();
	
	std::sort(m_filteredIndices.begin(), m_filteredIndices.end(),
		[this, column, order](int a, int b) {
			const auto& fA = m_allFindings[a];
			const auto& fB = m_allFindings[b];
			
			bool less = false;
			switch (column)
			{
			case ColAddress:
				less = fA.address < fB.address;
				break;
			case ColSeverity:
				less = fA.severity < fB.severity;
				break;
			case ColType:
				less = fA.type < fB.type;
				break;
			case ColTitle:
				less = fA.title < fB.title;
				break;
			default:
				less = fA.address < fB.address;
				break;
			}
			
			return order == Qt::AscendingOrder ? less : !less;
		});
	
	endResetModel();
}

int SecurityResultsModel::itemCount() const
{
	return static_cast<int>(m_filteredIndices.size());
}

bool SecurityResultsModel::isItemSelected(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return false;
	return m_allFindings[m_filteredIndices[row]].selected;
}

void SecurityResultsModel::setItemSelected(int row, bool selected)
{
	if (row >= 0 && row < static_cast<int>(m_filteredIndices.size()))
		m_allFindings[m_filteredIndices[row]].selected = selected;
}

uint64_t SecurityResultsModel::itemAddress(int row) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	return m_allFindings[m_filteredIndices[row]].address;
}

QString SecurityResultsModel::severityString(FindingSeverity sev) const
{
	switch (sev)
	{
	case FindingSeverity::Info: return "INFO";
	case FindingSeverity::Low: return "LOW";
	case FindingSeverity::Medium: return "MED";
	case FindingSeverity::High: return "HIGH";
	case FindingSeverity::Critical: return "CRIT";
	default: return "?";
	}
}

QString SecurityResultsModel::typeString(FindingType type) const
{
	switch (type)
	{
	case FindingType::Credential: return "Credential";
	case FindingType::CryptoWeakness: return "Crypto";
	case FindingType::VulnPattern: return "Pattern";
	case FindingType::Backdoor: return "Backdoor";
	case FindingType::Sensitive: return "Sensitive";
	default: return "Other";
	}
}

QColor SecurityResultsModel::severityColor(FindingSeverity sev) const
{
	switch (sev)
	{
	case FindingSeverity::Critical: return getThemeColor(RedStandardHighlightColor);
	case FindingSeverity::High: return getThemeColor(OrangeStandardHighlightColor);
	case FindingSeverity::Medium: return getThemeColor(YellowStandardHighlightColor);
	case FindingSeverity::Low: return getThemeColor(BlueStandardHighlightColor);
	default: return getThemeColor(CommentColor);
	}
}

QVariant SecurityResultsModel::itemData(int row, int column, int role) const
{
	if (row < 0 || row >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& f = m_allFindings[m_filteredIndices[row]];

	if (role == Qt::DisplayRole)
	{
		switch (column)
		{
		case ColAddress:
			return QString("0x%1").arg(f.address, 8, 16, QChar('0'));
		case ColSeverity:
			return severityString(f.severity);
		case ColType:
			return typeString(f.type);
		case ColTitle:
			return f.title;
		default:
			return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		if (column == ColSeverity)
			return severityColor(f.severity);
	}
	else if (role == Qt::BackgroundRole)
	{
		if (f.selected)
			return getThemeColor(SelectionColor);
	}
	else if (role == Qt::UserRole)
	{
		return static_cast<qulonglong>(f.address);
	}
	else if (role == Qt::ToolTipRole)
	{
		return f.description;
	}

	return QVariant();
}

QVariant SecurityResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return QVariant();

	const auto& f = m_allFindings[m_filteredIndices[parentRow]];

	// Detail rows:
	// 0: Context
	// 1: Suggestion
	// 2: Raw data (if any)

	if (role == Qt::DisplayRole)
	{
		if (detailRow == 0 && column == ColTitle)
		{
			return f.context.isEmpty() ? "No context" : QString("Context: %1").arg(f.context);
		}
		else if (detailRow == 1 && column == ColTitle)
		{
			return f.suggestion.isEmpty() ? "" : QString("Suggestion: %1").arg(f.suggestion);
		}
		else if (detailRow == 2 && column == ColTitle && !f.rawData.isEmpty())
		{
			return QString("Data: %1").arg(f.rawData.left(60));
		}
	}
	else if (role == Qt::ForegroundRole)
	{
		return getThemeColor(CommentColor);
	}

	return QVariant();
}

int SecurityResultsModel::detailRowCount(int parentRow) const
{
	if (parentRow < 0 || parentRow >= static_cast<int>(m_filteredIndices.size()))
		return 0;
	
	const auto& f = m_allFindings[m_filteredIndices[parentRow]];
	int count = 2;  // Context and suggestion
	if (!f.rawData.isEmpty())
		count++;
	return count;
}

// ============================================================================
// CredentialDetectorTab
// ============================================================================

CredentialDetectorTab::CredentialDetectorTab(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void CredentialDetectorTab::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void CredentialDetectorTab::refresh()
{
	if (m_data)
		scanForCredentials();
}

QWidget* CredentialDetectorTab::createSettingsWidget()
{
	m_settingsWidget = new QWidget(this);
	QHBoxLayout* layout = new QHBoxLayout(m_settingsWidget);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(8);

	m_detectPasswords = new QCheckBox("Passwords", m_settingsWidget);
	m_detectPasswords->setChecked(true);
	m_detectPasswords->setToolTip("Detect hardcoded passwords in strings");
	layout->addWidget(m_detectPasswords);

	m_detectApiKeys = new QCheckBox("API Keys", m_settingsWidget);
	m_detectApiKeys->setChecked(true);
	m_detectApiKeys->setToolTip("Detect API keys and access tokens");
	layout->addWidget(m_detectApiKeys);

	m_detectCerts = new QCheckBox("Certs/Keys", m_settingsWidget);
	m_detectCerts->setChecked(true);
	m_detectCerts->setToolTip("Detect embedded certificates and private keys");
	layout->addWidget(m_detectCerts);

	m_detectTokens = new QCheckBox("Tokens", m_settingsWidget);
	m_detectTokens->setChecked(true);
	m_detectTokens->setToolTip("Detect session tokens and authentication tokens");
	layout->addWidget(m_detectTokens);

	layout->addWidget(new QLabel("Min len:", m_settingsWidget));
	m_minLength = new QSpinBox(m_settingsWidget);
	m_minLength->setRange(4, 64);
	m_minLength->setValue(8);
	m_minLength->setMaximumWidth(50);
	layout->addWidget(m_minLength);

	m_checkEntropy = new QCheckBox("Entropy", m_settingsWidget);
	m_checkEntropy->setChecked(true);
	m_checkEntropy->setToolTip("Use entropy to find high-randomness strings");
	layout->addWidget(m_checkEntropy);

	layout->addStretch();

	return m_settingsWidget;
}

QWidget* CredentialDetectorTab::createFilterBar()
{
	m_filterBar = new FilterBar(this);
	m_filterBar->addCustomCombo("Severity", {"All", "Info+", "Low+", "Medium+", "High+", "Critical"});
	m_filterBar->addSearchBox("Search findings...");
	return m_filterBar;
}

QWidget* CredentialDetectorTab::createResultsView()
{
	m_model = new SecurityResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);
	m_treeView->setAlternatingRowColors(true);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setSortingEnabled(true);
	m_treeView->setRootIsDecorated(true);
	m_treeView->setExpandsOnDoubleClick(false);

	m_treeView->setColumnWidth(SecurityResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(SecurityResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(SecurityResultsModel::ColSeverity, 55);
	m_treeView->setColumnWidth(SecurityResultsModel::ColType, 70);
	m_treeView->header()->setStretchLastSection(true);

	// Default sort by severity descending
	m_treeView->sortByColumn(SecurityResultsModel::ColSeverity, Qt::DescendingOrder);

	return m_treeView;
}

void CredentialDetectorTab::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &CredentialDetectorTab::onRunClicked);
		m_controlBar->setApplyVisible(false);  // No apply for security findings
	}

	if (m_filterBar)
	{
		connect(m_filterBar, &FilterBar::filtersChanged, this, &CredentialDetectorTab::onFiltersChanged);
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &CredentialDetectorTab::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &CredentialDetectorTab::onItemDoubleClicked);
	}
}

void CredentialDetectorTab::onRunClicked()
{
	scanForCredentials();
}

void CredentialDetectorTab::onFiltersChanged()
{
	if (m_filterBar)
	{
		m_model->setMinSeverity(m_filterBar->customComboIndex("Severity"));
		m_model->setSearchText(m_filterBar->searchText());
		m_model->applyFilters();
	}
	updateStatusBar();
}

void CredentialDetectorTab::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);

	if (auto* finding = m_model->getFindingAt(index.row()))
	{
		if (m_preview)
			m_preview->showString(finding->address, 64);
	}
}

void CredentialDetectorTab::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (auto* finding = m_model->getFindingAt(index.row()))
		navigateToAddress(finding->address);
}

void CredentialDetectorTab::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int high = 0;
	for (int i = 0; i < total; i++)
	{
		const auto* f = m_model->getFindingAt(i);
		if (f && (f->severity == FindingSeverity::High || f->severity == FindingSeverity::Critical))
			high++;
	}

	m_statusBar->setSummary("Issues", total, "High", high);
}

void CredentialDetectorTab::scanForCredentials()
{
	if (!m_data)
		return;

	m_statusBar->setStatus("Scanning...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	std::vector<SecurityFinding> findings;
	int minLen = m_minLength->value();

	// Scan all strings in the binary
	for (auto& strRef : m_data->GetStrings())
	{
		if (strRef.length < static_cast<size_t>(minLen))
			continue;

		DataBuffer buf = m_data->ReadBuffer(strRef.start, strRef.length);
		QString str = QString::fromUtf8(static_cast<const char*>(buf.GetData()), buf.GetLength());
		QString strLower = str.toLower();

		// Check for password patterns
		if (m_detectPasswords->isChecked())
		{
			for (const QString& pattern : kPasswordPatterns)
			{
				if (strLower.contains(pattern))
				{
					SecurityFinding f;
					f.address = strRef.start;
					f.type = FindingType::Credential;
					f.title = QString("Potential credential: %1").arg(str.left(32));
					f.description = QString("String contains '%1' pattern").arg(pattern);
					f.rawData = str.left(64);
					f.context = QString("Found in string at 0x%1").arg(strRef.start, 8, 16, QChar('0'));
					f.suggestion = "Review if this is a hardcoded credential";

					// Determine severity based on pattern
					if (pattern == "password" || pattern == "secret" || pattern == "private_key")
						f.severity = FindingSeverity::High;
					else if (pattern == "api_key" || pattern == "auth_token")
						f.severity = FindingSeverity::High;
					else
						f.severity = FindingSeverity::Medium;

					findings.push_back(f);
					break;
				}
			}
		}

		// Check for high-entropy strings (potential keys/tokens)
		if (m_checkEntropy->isChecked() && str.length() >= 16)
		{
			// Calculate entropy
			std::map<char, int> freq;
			for (QChar c : str)
				freq[c.toLatin1()]++;

			double entropy = 0.0;
			for (const auto& [c, count] : freq)
			{
				double p = static_cast<double>(count) / str.length();
				if (p > 0)
					entropy -= p * std::log2(p);
			}

			// High entropy (> 4.0 bits/char) suggests randomness
			if (entropy > 4.0 && str.length() >= 20)
			{
				SecurityFinding f;
				f.address = strRef.start;
				f.type = FindingType::Credential;
				f.title = QString("High-entropy string (%.2f bits)").arg(entropy);
				f.description = "String has high entropy, may be a key or token";
				f.rawData = str.left(48);
				f.severity = (entropy > 5.0 && str.length() >= 32) ? FindingSeverity::High : FindingSeverity::Medium;
				f.suggestion = "Check if this is a hardcoded cryptographic key or API token";
				findings.push_back(f);
			}
		}
	}

	// Check for certificate patterns
	if (m_detectCerts->isChecked())
	{
		// Search for PEM headers
		std::vector<std::string> pemPatterns = {
			"-----BEGIN CERTIFICATE-----",
			"-----BEGIN RSA PRIVATE KEY-----",
			"-----BEGIN PRIVATE KEY-----",
			"-----BEGIN PUBLIC KEY-----"
		};

		for (const auto& pattern : pemPatterns)
		{
			uint64_t addr = 0;
			while (addr < m_data->GetLength())
			{
				size_t foundAddr = 0;
				DataBuffer searchBuf(reinterpret_cast<const uint8_t*>(pattern.data()), pattern.size());
				// Simple search - in production would use proper find
				break;  // Placeholder
			}
		}
	}

	m_model->setFindings(findings);
	
	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

// ============================================================================
// CryptoAnalyzerTab
// ============================================================================

CryptoAnalyzerTab::CryptoAnalyzerTab(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void CryptoAnalyzerTab::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void CryptoAnalyzerTab::refresh()
{
	if (m_data)
		scanForCryptoIssues();
}

QWidget* CryptoAnalyzerTab::createSettingsWidget()
{
	m_settingsWidget = new QWidget(this);
	QHBoxLayout* layout = new QHBoxLayout(m_settingsWidget);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(8);

	m_detectWeakAlgo = new QCheckBox("Weak Algorithms", m_settingsWidget);
	m_detectWeakAlgo->setChecked(true);
	m_detectWeakAlgo->setToolTip("MD5, SHA1, DES, RC4");
	layout->addWidget(m_detectWeakAlgo);

	m_detectStaticIV = new QCheckBox("Static IVs", m_settingsWidget);
	m_detectStaticIV->setChecked(true);
	m_detectStaticIV->setToolTip("Detect hardcoded initialization vectors");
	layout->addWidget(m_detectStaticIV);

	m_detectHardcodedKey = new QCheckBox("Hardcoded Keys", m_settingsWidget);
	m_detectHardcodedKey->setChecked(true);
	m_detectHardcodedKey->setToolTip("Detect hardcoded encryption keys");
	layout->addWidget(m_detectHardcodedKey);

	m_detectWeakRNG = new QCheckBox("Weak RNG", m_settingsWidget);
	m_detectWeakRNG->setChecked(true);
	m_detectWeakRNG->setToolTip("rand(), srand() usage");
	layout->addWidget(m_detectWeakRNG);

	m_detectECB = new QCheckBox("ECB Mode", m_settingsWidget);
	m_detectECB->setChecked(true);
	m_detectECB->setToolTip("Detect ECB mode usage (insecure for most applications)");
	layout->addWidget(m_detectECB);

	layout->addStretch();

	return m_settingsWidget;
}

QWidget* CryptoAnalyzerTab::createFilterBar()
{
	m_filterBar = new FilterBar(this);
	m_filterBar->addCustomCombo("Severity", {"All", "Info+", "Low+", "Medium+", "High+", "Critical"});
	m_filterBar->addSearchBox("Search findings...");
	return m_filterBar;
}

QWidget* CryptoAnalyzerTab::createResultsView()
{
	m_model = new SecurityResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);
	m_treeView->setAlternatingRowColors(true);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setSortingEnabled(true);
	m_treeView->setRootIsDecorated(true);
	m_treeView->setExpandsOnDoubleClick(false);

	m_treeView->setColumnWidth(SecurityResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(SecurityResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(SecurityResultsModel::ColSeverity, 55);
	m_treeView->setColumnWidth(SecurityResultsModel::ColType, 70);
	m_treeView->header()->setStretchLastSection(true);

	m_treeView->sortByColumn(SecurityResultsModel::ColSeverity, Qt::DescendingOrder);

	return m_treeView;
}

void CryptoAnalyzerTab::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &CryptoAnalyzerTab::onRunClicked);
		m_controlBar->setApplyVisible(false);
	}

	if (m_filterBar)
	{
		connect(m_filterBar, &FilterBar::filtersChanged, this, &CryptoAnalyzerTab::onFiltersChanged);
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &CryptoAnalyzerTab::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &CryptoAnalyzerTab::onItemDoubleClicked);
	}
}

void CryptoAnalyzerTab::onRunClicked()
{
	scanForCryptoIssues();
}

void CryptoAnalyzerTab::onFiltersChanged()
{
	if (m_filterBar)
	{
		m_model->setMinSeverity(m_filterBar->customComboIndex("Severity"));
		m_model->setSearchText(m_filterBar->searchText());
		m_model->applyFilters();
	}
	updateStatusBar();
}

void CryptoAnalyzerTab::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);

	if (auto* finding = m_model->getFindingAt(index.row()))
	{
		if (m_preview)
			m_preview->showDisassembly(finding->address, false);
	}
}

void CryptoAnalyzerTab::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (auto* finding = m_model->getFindingAt(index.row()))
		navigateToAddress(finding->address);
}

void CryptoAnalyzerTab::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int high = 0;
	for (int i = 0; i < total; i++)
	{
		const auto* f = m_model->getFindingAt(i);
		if (f && (f->severity == FindingSeverity::High || f->severity == FindingSeverity::Critical))
			high++;
	}

	m_statusBar->setSummary("Issues", total, "High", high);
}

void CryptoAnalyzerTab::scanForCryptoIssues()
{
	if (!m_data)
		return;

	m_statusBar->setStatus("Scanning...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	std::vector<SecurityFinding> findings;

	// Look for weak crypto function imports/calls
	for (auto& func : m_data->GetAnalysisFunctionList())
	{
		QString funcName = QString::fromStdString(func->GetSymbol()->GetShortName());
		QString funcNameLower = funcName.toLower();

		// Check for weak hash functions
		if (m_detectWeakAlgo->isChecked())
		{
			if (funcNameLower.contains("md5") && !funcNameLower.contains("md5_check"))
			{
				SecurityFinding f;
				f.address = func->GetStart();
				f.type = FindingType::CryptoWeakness;
				f.severity = FindingSeverity::Medium;
				f.title = QString("Weak hash: %1").arg(funcName);
				f.description = "MD5 is cryptographically broken";
				f.suggestion = "Replace with SHA-256 or SHA-3";
				findings.push_back(f);
			}
			
			if (funcNameLower.contains("sha1") && !funcNameLower.contains("sha1_check"))
			{
				SecurityFinding f;
				f.address = func->GetStart();
				f.type = FindingType::CryptoWeakness;
				f.severity = FindingSeverity::Medium;
				f.title = QString("Weak hash: %1").arg(funcName);
				f.description = "SHA-1 has known collision attacks";
				f.suggestion = "Replace with SHA-256 or SHA-3";
				findings.push_back(f);
			}

			if (funcNameLower.contains("des") && !funcNameLower.contains("3des"))
			{
				SecurityFinding f;
				f.address = func->GetStart();
				f.type = FindingType::CryptoWeakness;
				f.severity = FindingSeverity::High;
				f.title = QString("Weak cipher: %1").arg(funcName);
				f.description = "DES has 56-bit keys, easily brute-forced";
				f.suggestion = "Replace with AES-128 or AES-256";
				findings.push_back(f);
			}
		}

		// Check for weak RNG
		if (m_detectWeakRNG->isChecked())
		{
			if (funcNameLower == "rand" || funcNameLower == "srand" || funcNameLower == "random")
			{
				SecurityFinding f;
				f.address = func->GetStart();
				f.type = FindingType::CryptoWeakness;
				f.severity = FindingSeverity::High;
				f.title = QString("Weak RNG: %1").arg(funcName);
				f.description = "Standard rand() is not cryptographically secure";
				f.suggestion = "Use a CSPRNG (e.g., /dev/urandom, BCryptGenRandom)";
				findings.push_back(f);
			}
		}
	}

	m_model->setFindings(findings);
	
	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

// ============================================================================
// PatternDetectorTab
// ============================================================================

PatternDetectorTab::PatternDetectorTab(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void PatternDetectorTab::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void PatternDetectorTab::refresh()
{
	if (m_data)
		scanForVulnPatterns();
}

QWidget* PatternDetectorTab::createSettingsWidget()
{
	m_settingsWidget = new QWidget(this);
	QHBoxLayout* layout = new QHBoxLayout(m_settingsWidget);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(8);

	m_detectCmdInjection = new QCheckBox("Cmd Injection", m_settingsWidget);
	m_detectCmdInjection->setChecked(true);
	m_detectCmdInjection->setToolTip("Detect system(), popen(), exec() calls with potential user input");
	layout->addWidget(m_detectCmdInjection);

	m_detectFormatString = new QCheckBox("Format String", m_settingsWidget);
	m_detectFormatString->setChecked(true);
	m_detectFormatString->setToolTip("Detect printf-family calls with non-literal format strings");
	layout->addWidget(m_detectFormatString);

	m_detectBufferOverflow = new QCheckBox("Buffer Overflow", m_settingsWidget);
	m_detectBufferOverflow->setChecked(true);
	m_detectBufferOverflow->setToolTip("Detect strcpy(), strcat(), gets() and similar unsafe functions");
	layout->addWidget(m_detectBufferOverflow);

	m_detectIntOverflow = new QCheckBox("Integer Overflow", m_settingsWidget);
	m_detectIntOverflow->setChecked(true);
	m_detectIntOverflow->setToolTip("Detect arithmetic operations without overflow checks");
	layout->addWidget(m_detectIntOverflow);

	m_detectUseAfterFree = new QCheckBox("Use After Free", m_settingsWidget);
	m_detectUseAfterFree->setChecked(false);
	m_detectUseAfterFree->setToolTip("Requires deeper analysis");
	layout->addWidget(m_detectUseAfterFree);

	layout->addStretch();

	return m_settingsWidget;
}

QWidget* PatternDetectorTab::createFilterBar()
{
	m_filterBar = new FilterBar(this);
	m_filterBar->addCustomCombo("Severity", {"All", "Info+", "Low+", "Medium+", "High+", "Critical"});
	m_filterBar->addSearchBox("Search findings...");
	return m_filterBar;
}

QWidget* PatternDetectorTab::createResultsView()
{
	m_model = new SecurityResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);
	m_treeView->setAlternatingRowColors(true);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setSortingEnabled(true);
	m_treeView->setRootIsDecorated(true);
	m_treeView->setExpandsOnDoubleClick(false);

	m_treeView->setColumnWidth(SecurityResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(SecurityResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(SecurityResultsModel::ColSeverity, 55);
	m_treeView->setColumnWidth(SecurityResultsModel::ColType, 70);
	m_treeView->header()->setStretchLastSection(true);

	m_treeView->sortByColumn(SecurityResultsModel::ColSeverity, Qt::DescendingOrder);

	return m_treeView;
}

void PatternDetectorTab::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &PatternDetectorTab::onRunClicked);
		m_controlBar->setApplyVisible(false);
	}

	if (m_filterBar)
	{
		connect(m_filterBar, &FilterBar::filtersChanged, this, &PatternDetectorTab::onFiltersChanged);
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &PatternDetectorTab::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &PatternDetectorTab::onItemDoubleClicked);
	}
}

void PatternDetectorTab::onRunClicked()
{
	scanForVulnPatterns();
}

void PatternDetectorTab::onFiltersChanged()
{
	if (m_filterBar)
	{
		m_model->setMinSeverity(m_filterBar->customComboIndex("Severity"));
		m_model->setSearchText(m_filterBar->searchText());
		m_model->applyFilters();
	}
	updateStatusBar();
}

void PatternDetectorTab::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);

	if (auto* finding = m_model->getFindingAt(index.row()))
	{
		if (m_preview)
			m_preview->showDisassembly(finding->address, false);
	}
}

void PatternDetectorTab::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (auto* finding = m_model->getFindingAt(index.row()))
		navigateToAddress(finding->address);
}

void PatternDetectorTab::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int high = 0;
	for (int i = 0; i < total; i++)
	{
		const auto* f = m_model->getFindingAt(i);
		if (f && (f->severity == FindingSeverity::High || f->severity == FindingSeverity::Critical))
			high++;
	}

	m_statusBar->setSummary("Issues", total, "High", high);
}

void PatternDetectorTab::scanForVulnPatterns()
{
	if (!m_data)
		return;

	m_statusBar->setStatus("Scanning...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	std::vector<SecurityFinding> findings;

	// Look for dangerous function calls
	for (auto& func : m_data->GetAnalysisFunctionList())
	{
		QString funcName = QString::fromStdString(func->GetSymbol()->GetShortName());
		QString funcNameLower = funcName.toLower();

		// Command injection sinks
		if (m_detectCmdInjection->isChecked())
		{
			if (funcNameLower == "system" || funcNameLower == "popen" || 
				funcNameLower == "execve" || funcNameLower == "execl")
			{
				SecurityFinding f;
				f.address = func->GetStart();
				f.type = FindingType::VulnPattern;
				f.severity = FindingSeverity::High;
				f.title = QString("Command execution: %1").arg(funcName);
				f.description = "Function executes shell commands";
				f.suggestion = "Check if user input reaches this function";
				findings.push_back(f);
			}
		}

		// Format string issues
		if (m_detectFormatString->isChecked())
		{
			if (funcNameLower == "printf" || funcNameLower == "sprintf" ||
				funcNameLower == "fprintf" || funcNameLower == "snprintf")
			{
				// Would need call site analysis to detect vuln pattern
				// For now, flag all uses
			}
		}

		// Buffer overflow sinks
		if (m_detectBufferOverflow->isChecked())
		{
			if (funcNameLower == "strcpy" || funcNameLower == "strcat" ||
				funcNameLower == "gets" || funcNameLower == "sprintf")
			{
				SecurityFinding f;
				f.address = func->GetStart();
				f.type = FindingType::VulnPattern;
				f.severity = FindingSeverity::High;
				f.title = QString("Unsafe function: %1").arg(funcName);
				f.description = "Function doesn't check buffer bounds";
				f.suggestion = QString("Replace with %1_s or %1n variant")
					.arg(funcName.left(funcName.length() > 6 ? 6 : funcName.length() - 1));
				findings.push_back(f);
			}
		}
	}

	m_model->setFindings(findings);
	
	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

// ============================================================================
// BackdoorDetectorTab
// ============================================================================

BackdoorDetectorTab::BackdoorDetectorTab(QWidget* parent)
	: AnalysisTabBase(parent)
{
	setupStandardLayout();
	setupConnections();
}

void BackdoorDetectorTab::setBinaryView(BinaryViewRef data)
{
	AnalysisTabBase::setBinaryView(data);
	if (m_statusBar)
		m_statusBar->setStatus(data ? "Ready to scan" : "No binary loaded");
}

void BackdoorDetectorTab::refresh()
{
	if (m_data)
		scanForBackdoors();
}

QWidget* BackdoorDetectorTab::createSettingsWidget()
{
	m_settingsWidget = new QWidget(this);
	QHBoxLayout* layout = new QHBoxLayout(m_settingsWidget);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(8);

	m_detectAuthBypass = new QCheckBox("Auth Bypass", m_settingsWidget);
	m_detectAuthBypass->setChecked(true);
	m_detectAuthBypass->setToolTip("Detect authentication bypass patterns and hardcoded credentials");
	layout->addWidget(m_detectAuthBypass);

	m_detectHiddenCmd = new QCheckBox("Hidden Commands", m_settingsWidget);
	m_detectHiddenCmd->setChecked(true);
	m_detectHiddenCmd->setToolTip("Detect undocumented command handlers and service modes");
	layout->addWidget(m_detectHiddenCmd);

	m_detectDebugAccess = new QCheckBox("Debug Access", m_settingsWidget);
	m_detectDebugAccess->setChecked(true);
	m_detectDebugAccess->setToolTip("Detect debug interfaces and test access points");
	layout->addWidget(m_detectDebugAccess);

	m_detectMagicValues = new QCheckBox("Magic Values", m_settingsWidget);
	m_detectMagicValues->setChecked(true);
	m_detectMagicValues->setToolTip("Hardcoded comparison values");
	layout->addWidget(m_detectMagicValues);

	layout->addStretch();

	return m_settingsWidget;
}

QWidget* BackdoorDetectorTab::createFilterBar()
{
	m_filterBar = new FilterBar(this);
	m_filterBar->addCustomCombo("Severity", {"All", "Info+", "Low+", "Medium+", "High+", "Critical"});
	m_filterBar->addSearchBox("Search findings...");
	return m_filterBar;
}

QWidget* BackdoorDetectorTab::createResultsView()
{
	m_model = new SecurityResultsModel(this);

	m_treeView = new QTreeView(this);
	m_treeView->setModel(m_model);
	m_treeView->setAlternatingRowColors(true);
	m_treeView->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_treeView->setSortingEnabled(true);
	m_treeView->setRootIsDecorated(true);
	m_treeView->setExpandsOnDoubleClick(false);

	m_treeView->setColumnWidth(SecurityResultsModel::ColSelect, 24);
	m_treeView->setColumnWidth(SecurityResultsModel::ColAddress, 85);
	m_treeView->setColumnWidth(SecurityResultsModel::ColSeverity, 55);
	m_treeView->setColumnWidth(SecurityResultsModel::ColType, 70);
	m_treeView->header()->setStretchLastSection(true);

	m_treeView->sortByColumn(SecurityResultsModel::ColSeverity, Qt::DescendingOrder);

	return m_treeView;
}

void BackdoorDetectorTab::setupConnections()
{
	if (m_controlBar)
	{
		connect(m_controlBar, &AnalysisControlBar::runClicked, this, &BackdoorDetectorTab::onRunClicked);
		m_controlBar->setApplyVisible(false);
	}

	if (m_filterBar)
	{
		connect(m_filterBar, &FilterBar::filtersChanged, this, &BackdoorDetectorTab::onFiltersChanged);
	}

	if (m_treeView)
	{
		connect(m_treeView, &QTreeView::clicked, this, &BackdoorDetectorTab::onItemClicked);
		connect(m_treeView, &QTreeView::doubleClicked, this, &BackdoorDetectorTab::onItemDoubleClicked);
	}
}

void BackdoorDetectorTab::onRunClicked()
{
	scanForBackdoors();
}

void BackdoorDetectorTab::onFiltersChanged()
{
	if (m_filterBar)
	{
		m_model->setMinSeverity(m_filterBar->customComboIndex("Severity"));
		m_model->setSearchText(m_filterBar->searchText());
		m_model->applyFilters();
	}
	updateStatusBar();
}

void BackdoorDetectorTab::onItemClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (m_treeView->isExpanded(index))
		m_treeView->collapse(index);
	else
		m_treeView->expand(index);

	if (auto* finding = m_model->getFindingAt(index.row()))
	{
		if (m_preview)
			m_preview->showDisassembly(finding->address, false);
	}
}

void BackdoorDetectorTab::onItemDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || index.internalId() != 0)
		return;

	if (auto* finding = m_model->getFindingAt(index.row()))
		navigateToAddress(finding->address);
}

void BackdoorDetectorTab::updateStatusBar()
{
	if (!m_statusBar || !m_model)
		return;

	int total = m_model->totalCount();
	int high = 0;
	for (int i = 0; i < total; i++)
	{
		const auto* f = m_model->getFindingAt(i);
		if (f && (f->severity == FindingSeverity::High || f->severity == FindingSeverity::Critical))
			high++;
	}

	m_statusBar->setSummary("Issues", total, "High", high);
}

void BackdoorDetectorTab::scanForBackdoors()
{
	if (!m_data)
		return;

	m_statusBar->setStatus("Scanning...");
	m_controlBar->setRunning(true);
	QApplication::processEvents();

	std::vector<SecurityFinding> findings;

	// Look for backdoor patterns in strings
	QStringList backdoorPatterns = {
		"backdoor", "debug_mode", "test_mode", "factory_mode",
		"hidden", "secret_cmd", "shell", "root_shell",
		"enable_debug", "developer", "maintenance"
	};

	for (auto& strRef : m_data->GetStrings())
	{
		if (strRef.length < 4)
			continue;

		DataBuffer buf = m_data->ReadBuffer(strRef.start, strRef.length);
		QString str = QString::fromUtf8(static_cast<const char*>(buf.GetData()), buf.GetLength());
		QString strLower = str.toLower();

		for (const QString& pattern : backdoorPatterns)
		{
			if (strLower.contains(pattern))
			{
				SecurityFinding f;
				f.address = strRef.start;
				f.type = FindingType::Backdoor;
				f.severity = FindingSeverity::High;
				f.title = QString("Suspicious string: %1").arg(str.left(32));
				f.description = QString("String contains backdoor-like pattern '%1'").arg(pattern);
				f.rawData = str.left(64);
				f.suggestion = "Review code referencing this string for backdoor functionality";
				findings.push_back(f);
				break;
			}
		}
	}

	// Look for debug functions
	if (m_detectDebugAccess->isChecked())
	{
		for (auto& func : m_data->GetAnalysisFunctionList())
		{
			QString funcName = QString::fromStdString(func->GetSymbol()->GetShortName());
			QString funcNameLower = funcName.toLower();

			if (funcNameLower.contains("debug") || funcNameLower.contains("test_") ||
				funcNameLower.contains("_debug") || funcNameLower.contains("enable_shell"))
			{
				SecurityFinding f;
				f.address = func->GetStart();
				f.type = FindingType::Backdoor;
				f.severity = FindingSeverity::Medium;
				f.title = QString("Debug function: %1").arg(funcName);
				f.description = "Function name suggests debug/test functionality";
				f.suggestion = "Verify this is disabled in production";
				findings.push_back(f);
			}
		}
	}

	m_model->setFindings(findings);
	
	m_statusBar->setStatus("Complete");
	m_controlBar->setRunning(false);
	updateStatusBar();
}

// ============================================================================
// SecurityScannerWidget
// ============================================================================

SecurityScannerWidget::SecurityScannerWidget(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void SecurityScannerWidget::setupUI()
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Use native BN styling - no custom stylesheet
	m_tabs = new QTabWidget(this);
	m_tabs->setDocumentMode(true);

	m_credentialsTab = new CredentialDetectorTab(this);
	m_cryptoTab = new CryptoAnalyzerTab(this);
	m_patternsTab = new PatternDetectorTab(this);
	m_backdoorsTab = new BackdoorDetectorTab(this);

	m_tabs->addTab(m_credentialsTab, "Credentials");
	m_tabs->addTab(m_cryptoTab, "Crypto");
	m_tabs->addTab(m_patternsTab, "Patterns");
	m_tabs->addTab(m_backdoorsTab, "Backdoors");

	layout->addWidget(m_tabs);

	// Forward signals
	connect(m_credentialsTab, &CredentialDetectorTab::addressSelected, this, &SecurityScannerWidget::addressSelected);
	connect(m_cryptoTab, &CryptoAnalyzerTab::addressSelected, this, &SecurityScannerWidget::addressSelected);
	connect(m_patternsTab, &PatternDetectorTab::addressSelected, this, &SecurityScannerWidget::addressSelected);
	connect(m_backdoorsTab, &BackdoorDetectorTab::addressSelected, this, &SecurityScannerWidget::addressSelected);
}

void SecurityScannerWidget::setBinaryView(BinaryViewRef data)
{
	m_data = data;
	m_credentialsTab->setBinaryView(data);
	m_cryptoTab->setBinaryView(data);
	m_patternsTab->setBinaryView(data);
	m_backdoorsTab->setBinaryView(data);
}

void SecurityScannerWidget::refresh()
{
	int idx = m_tabs->currentIndex();
	switch (idx)
	{
	case 0: m_credentialsTab->refresh(); break;
	case 1: m_cryptoTab->refresh(); break;
	case 2: m_patternsTab->refresh(); break;
	case 3: m_backdoorsTab->refresh(); break;
	}
}

}  // namespace Armv5UI
