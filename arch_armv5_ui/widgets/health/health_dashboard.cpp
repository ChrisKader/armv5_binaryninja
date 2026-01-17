/*
 * Health Dashboard Widget Implementation
 */

#include "health_dashboard.h"
#include "binaryninjaapi.h"
#include "theme.h"

#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QStyle>
#include <QtWidgets/QApplication>
#include <QtGui/QPainter>

#include <algorithm>
#include <set>

using namespace BinaryNinja;

namespace Armv5UI
{

// ============================================================================
// MetricCard
// ============================================================================

MetricCard::MetricCard(const QString& title, QWidget* parent)
	: QFrame(parent)
{
	setFrameStyle(QFrame::StyledPanel | QFrame::Raised);
	setMinimumWidth(120);
	setMaximumHeight(80);
	setupUI();
	m_titleLabel->setText(title);
}

void MetricCard::setupUI()
{
	setStyleSheet(
		"MetricCard {"
		"  background-color: #2a2a2a;"
		"  border: 1px solid #3a3a3a;"
		"  border-radius: 4px;"
		"}"
	);

	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(8, 6, 8, 6);
	layout->setSpacing(2);

	m_titleLabel = new QLabel(this);
	m_titleLabel->setStyleSheet("font-size: 10px; color: #888888; background: transparent;");
	layout->addWidget(m_titleLabel);

	m_valueLabel = new QLabel("--", this);
	m_valueLabel->setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff; background: transparent;");
	layout->addWidget(m_valueLabel);

	m_progressBar = new QProgressBar(this);
	m_progressBar->setMaximumHeight(6);
	m_progressBar->setTextVisible(false);
	m_progressBar->setStyleSheet(
		"QProgressBar {"
		"  background-color: #1e1e1e;"
		"  border: none;"
		"  border-radius: 3px;"
		"}"
		"QProgressBar::chunk {"
		"  background-color: #ffcc00;"
		"  border-radius: 3px;"
		"}"
	);
	m_progressBar->hide();
	layout->addWidget(m_progressBar);

	m_subtextLabel = new QLabel(this);
	m_subtextLabel->setStyleSheet("font-size: 9px; color: #666666; background: transparent;");
	m_subtextLabel->hide();
	layout->addWidget(m_subtextLabel);
}

void MetricCard::setValue(int value)
{
	m_valueLabel->setText(QString::number(value));
}

void MetricCard::setValue(double value, const QString& suffix)
{
	m_valueLabel->setText(QString::number(value, 'f', 1) + suffix);
}

void MetricCard::setValue(const QString& value)
{
	m_valueLabel->setText(value);
}

void MetricCard::setProgress(double percent)
{
	m_progressBar->setValue(static_cast<int>(percent));
	m_progressBar->show();
}

void MetricCard::setColor(const QColor& color)
{
	m_valueLabel->setStyleSheet(QString("font-size: 18px; font-weight: bold; color: %1;")
		.arg(color.name()));
}

void MetricCard::setSubtext(const QString& text)
{
	m_subtextLabel->setText(text);
	m_subtextLabel->setVisible(!text.isEmpty());
}

// ============================================================================
// CoveragePanel
// ============================================================================

CoveragePanel::CoveragePanel(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void CoveragePanel::setupUI()
{
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);

	QLabel* title = new QLabel("COVERAGE", this);
	title->setStyleSheet(
		"font-weight: bold; font-size: 11px; color: #ffcc00;"
		"padding: 6px 8px;"
		"background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #353535, stop:1 #2a2a2a);"
		"border-bottom: 1px solid #1a1a1a;"
	);
	mainLayout->addWidget(title);

	// Cards
	QHBoxLayout* cardLayout = new QHBoxLayout();
	cardLayout->setSpacing(4);

	m_totalCard = new MetricCard("Total", this);
	cardLayout->addWidget(m_totalCard);

	m_codeCard = new MetricCard("Code", this);
	cardLayout->addWidget(m_codeCard);

	m_dataCard = new MetricCard("Data", this);
	cardLayout->addWidget(m_dataCard);

	m_unknownCard = new MetricCard("Unknown", this);
	cardLayout->addWidget(m_unknownCard);

	mainLayout->addLayout(cardLayout);

	// Memory map visualization
	m_memoryMap = new QWidget(this);
	m_memoryMap->setMinimumHeight(20);
	m_memoryMap->setMaximumHeight(20);
	mainLayout->addWidget(m_memoryMap);
}

void CoveragePanel::setMetrics(const CoverageMetrics& metrics)
{
	m_metrics = metrics;

	// Format size
	auto formatSize = [](uint64_t bytes) -> QString {
		if (bytes >= 1024 * 1024)
			return QString("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 1);
		if (bytes >= 1024)
			return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
		return QString("%1 B").arg(bytes);
	};

	m_totalCard->setValue(formatSize(metrics.totalBytes));

	m_codeCard->setValue(metrics.codePercent(), "%");
	m_codeCard->setSubtext(formatSize(metrics.codeBytes));
	m_codeCard->setProgress(metrics.codePercent());
	m_codeCard->setColor(getThemeColor(BlueStandardHighlightColor));

	m_dataCard->setValue(metrics.dataPercent(), "%");
	m_dataCard->setSubtext(formatSize(metrics.dataBytes));
	m_dataCard->setProgress(metrics.dataPercent());
	m_dataCard->setColor(getThemeColor(GreenStandardHighlightColor));

	m_unknownCard->setValue(metrics.unknownPercent(), "%");
	m_unknownCard->setSubtext(formatSize(metrics.unknownBytes));
	m_unknownCard->setProgress(metrics.unknownPercent());
	if (metrics.unknownPercent() > 30)
		m_unknownCard->setColor(getThemeColor(RedStandardHighlightColor));
	else if (metrics.unknownPercent() > 15)
		m_unknownCard->setColor(getThemeColor(YellowStandardHighlightColor));

	updateMemoryMap();
}

void CoveragePanel::updateMemoryMap()
{
	m_memoryMap->update();
}

// ============================================================================
// ComplexityPanel
// ============================================================================

ComplexityPanel::ComplexityPanel(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void ComplexityPanel::setupUI()
{
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);

	QLabel* title = new QLabel("COMPLEXITY DISTRIBUTION", this);
	title->setStyleSheet(
		"font-weight: bold; font-size: 11px; color: #ffcc00;"
		"padding: 6px 8px;"
		"background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #353535, stop:1 #2a2a2a);"
		"border-bottom: 1px solid #1a1a1a;"
	);
	mainLayout->addWidget(title);

	// Cards
	QHBoxLayout* cardLayout = new QHBoxLayout();
	cardLayout->setSpacing(4);

	m_totalCard = new MetricCard("Functions", this);
	cardLayout->addWidget(m_totalCard);

	m_simpleCard = new MetricCard("Simple", this);
	cardLayout->addWidget(m_simpleCard);

	m_mediumCard = new MetricCard("Medium", this);
	cardLayout->addWidget(m_mediumCard);

	m_complexCard = new MetricCard("Complex", this);
	cardLayout->addWidget(m_complexCard);

	mainLayout->addLayout(cardLayout);

	// Most complex function
	m_mostComplexLabel = new QLabel(this);
	m_mostComplexLabel->setStyleSheet("font-size: 10px; padding: 6px 8px; color: #aaaaaa; background: #2a2a2a; border-radius: 3px;");
	m_mostComplexLabel->setCursor(Qt::PointingHandCursor);
	mainLayout->addWidget(m_mostComplexLabel);

	// Histogram placeholder
	m_histogramWidget = new QWidget(this);
	m_histogramWidget->setMinimumHeight(40);
	m_histogramWidget->setMaximumHeight(40);
	mainLayout->addWidget(m_histogramWidget);
}

void ComplexityPanel::setMetrics(const ComplexityMetrics& metrics)
{
	m_metrics = metrics;

	m_totalCard->setValue(metrics.totalFunctions);

	m_simpleCard->setValue(metrics.simpleFunctions);
	m_simpleCard->setColor(getThemeColor(GreenStandardHighlightColor));
	m_simpleCard->setSubtext(QString("< 10 blocks"));

	m_mediumCard->setValue(metrics.mediumFunctions);
	m_mediumCard->setColor(getThemeColor(YellowStandardHighlightColor));
	m_mediumCard->setSubtext(QString("10-50 blocks"));

	m_complexCard->setValue(metrics.complexFunctions);
	m_complexCard->setColor(getThemeColor(OrangeStandardHighlightColor));
	m_complexCard->setSubtext(QString("> 50 blocks"));

	if (!metrics.mostComplexFunction.isEmpty())
	{
		m_mostComplexLabel->setText(QString("Most complex: %1 (%2 blocks)")
			.arg(metrics.mostComplexFunction)
			.arg(metrics.mostComplexBlocks));
	}
	else
	{
		m_mostComplexLabel->setText("Most complex: (none)");
	}

	updateHistogram();
}

void ComplexityPanel::updateHistogram()
{
	m_histogramWidget->update();
}

// ============================================================================
// QualityPanel
// ============================================================================

QualityPanel::QualityPanel(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void QualityPanel::setupUI()
{
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);

	QLabel* title = new QLabel("ISSUES", this);
	title->setStyleSheet(
		"font-weight: bold; font-size: 11px; color: #ffcc00;"
		"padding: 6px 8px;"
		"background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #353535, stop:1 #2a2a2a);"
		"border-bottom: 1px solid #1a1a1a;"
	);
	mainLayout->addWidget(title);

	// Cards
	QHBoxLayout* cardLayout = new QHBoxLayout();
	cardLayout->setSpacing(4);

	m_orphanCard = new MetricCard("Orphans", this);
	m_orphanCard->setSubtext("No callers");
	cardLayout->addWidget(m_orphanCard);

	m_unreachableCard = new MetricCard("Unreachable", this);
	m_unreachableCard->setSubtext("Dead paths");
	cardLayout->addWidget(m_unreachableCard);

	m_suspiciousCard = new MetricCard("Suspicious", this);
	m_suspiciousCard->setSubtext("Patterns");
	cardLayout->addWidget(m_suspiciousCard);

	m_deadCodeCard = new MetricCard("Dead Code", this);
	m_deadCodeCard->setSubtext("Unused");
	cardLayout->addWidget(m_deadCodeCard);

	mainLayout->addLayout(cardLayout);

	// Styled issue table
	m_issueTable = new QTableWidget(this);
	m_issueTable->setColumnCount(3);
	m_issueTable->setHorizontalHeaderLabels({"Address", "Type", "Description"});
	m_issueTable->horizontalHeader()->setStretchLastSection(true);
	m_issueTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_issueTable->setMaximumHeight(100);
	m_issueTable->verticalHeader()->hide();
	m_issueTable->verticalHeader()->setDefaultSectionSize(22);
	m_issueTable->setStyleSheet(
		"QTableWidget {"
		"  background-color: #1e1e1e;"
		"  alternate-background-color: #252525;"
		"  color: #cccccc;"
		"  gridline-color: #2a2a2a;"
		"  border: 1px solid #3a3a3a;"
		"  font-size: 11px;"
		"}"
		"QTableWidget::item:selected {"
		"  background-color: #3a4a5a;"
		"  color: #ffffff;"
		"}"
		"QHeaderView::section {"
		"  background-color: #2a2a2a;"
		"  color: #aaaaaa;"
		"  border: none;"
		"  border-bottom: 1px solid #3a3a3a;"
		"  padding: 4px 8px;"
		"  font-size: 11px;"
		"  font-weight: bold;"
		"}"
	);
	m_issueTable->hide();  // Show only if issues exist
	mainLayout->addWidget(m_issueTable);
}

void QualityPanel::setMetrics(const QualityMetrics& metrics)
{
	m_metrics = metrics;

	m_orphanCard->setValue(metrics.orphanFunctions);
	if (metrics.orphanFunctions > 10)
		m_orphanCard->setColor(getThemeColor(YellowStandardHighlightColor));
	else
		m_orphanCard->setColor(getThemeColor(GreenStandardHighlightColor));

	m_unreachableCard->setValue(metrics.unreachableCode);
	if (metrics.unreachableCode > 0)
		m_unreachableCard->setColor(getThemeColor(YellowStandardHighlightColor));
	else
		m_unreachableCard->setColor(getThemeColor(GreenStandardHighlightColor));

	m_suspiciousCard->setValue(metrics.suspiciousPatterns);
	if (metrics.suspiciousPatterns > 0)
		m_suspiciousCard->setColor(getThemeColor(OrangeStandardHighlightColor));
	else
		m_suspiciousCard->setColor(getThemeColor(GreenStandardHighlightColor));

	m_deadCodeCard->setValue(metrics.deadCode);
	if (metrics.deadCode > 0)
		m_deadCodeCard->setColor(getThemeColor(YellowStandardHighlightColor));
	else
		m_deadCodeCard->setColor(getThemeColor(GreenStandardHighlightColor));

	// Populate issue table
	if (!metrics.issues.empty())
	{
		m_issueTable->setRowCount(static_cast<int>(metrics.issues.size()));
		for (size_t i = 0; i < metrics.issues.size() && i < 10; i++)
		{
			const auto& [addr, desc] = metrics.issues[i];
			m_issueTable->setItem(i, 0, new QTableWidgetItem(
				QString("0x%1").arg(addr, 8, 16, QChar('0'))));
			m_issueTable->setItem(i, 1, new QTableWidgetItem("Warning"));
			m_issueTable->setItem(i, 2, new QTableWidgetItem(desc));
		}
		m_issueTable->show();
	}
	else
	{
		m_issueTable->hide();
	}
}

// ============================================================================
// ProgressPanel
// ============================================================================

ProgressPanel::ProgressPanel(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void ProgressPanel::setupUI()
{
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);

	QLabel* title = new QLabel("ANALYSIS PROGRESS", this);
	title->setStyleSheet(
		"font-weight: bold; font-size: 11px; color: #ffcc00;"
		"padding: 6px 8px;"
		"background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #353535, stop:1 #2a2a2a);"
		"border-bottom: 1px solid #1a1a1a;"
	);
	mainLayout->addWidget(title);

	// Cards
	QHBoxLayout* cardLayout = new QHBoxLayout();
	cardLayout->setSpacing(4);

	m_sessionCard = new MetricCard("Session", this);
	cardLayout->addWidget(m_sessionCard);

	m_namedCard = new MetricCard("Named", this);
	cardLayout->addWidget(m_namedCard);

	m_typedCard = new MetricCard("Typed", this);
	cardLayout->addWidget(m_typedCard);

	m_commentedCard = new MetricCard("Comments", this);
	cardLayout->addWidget(m_commentedCard);

	mainLayout->addLayout(cardLayout);
}

void ProgressPanel::setMetrics(const ProgressMetrics& metrics)
{
	m_metrics = metrics;

	// Format duration
	auto secs = metrics.sessionDuration.count();
	QString durStr;
	if (secs >= 3600)
		durStr = QString("%1h %2m").arg(secs / 3600).arg((secs % 3600) / 60);
	else if (secs >= 60)
		durStr = QString("%1m %2s").arg(secs / 60).arg(secs % 60);
	else
		durStr = QString("%1s").arg(secs);
	m_sessionCard->setValue(durStr);

	m_namedCard->setValue(metrics.namingPercent(), "%");
	m_namedCard->setSubtext(QString("%1/%2").arg(metrics.namedFunctions).arg(metrics.totalFunctions));
	m_namedCard->setProgress(metrics.namingPercent());
	if (metrics.namingPercent() >= 50)
		m_namedCard->setColor(getThemeColor(GreenStandardHighlightColor));
	else if (metrics.namingPercent() >= 25)
		m_namedCard->setColor(getThemeColor(YellowStandardHighlightColor));

	m_typedCard->setValue(metrics.typedFunctions);
	m_typedCard->setSubtext("functions");

	m_commentedCard->setValue(metrics.commentedFunctions);
	m_commentedCard->setSubtext("functions");
}

// ============================================================================
// HealthDashboard
// ============================================================================

HealthDashboard::HealthDashboard(QWidget* parent)
	: QWidget(parent)
	, m_sessionStart(std::chrono::steady_clock::now())
{
	setupUI();
}

void HealthDashboard::setupUI()
{
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->setSpacing(0);

	// Styled header with score and refresh
	QWidget* headerBar = new QWidget(this);
	headerBar->setStyleSheet(
		"QWidget {"
		"  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3a3c3e, stop:1 #2a2c2e);"
		"  border-bottom: 1px solid #1a1a1a;"
		"}"
	);
	QHBoxLayout* headerLayout = new QHBoxLayout(headerBar);
	headerLayout->setContentsMargins(8, 8, 8, 8);
	headerLayout->setSpacing(8);

	m_healthScoreLabel = new QLabel("FIRMWARE HEALTH SCORE: --/100", this);
	m_healthScoreLabel->setStyleSheet("font-weight: bold; font-size: 14px; color: #ffffff; background: transparent;");
	headerLayout->addWidget(m_healthScoreLabel);

	headerLayout->addStretch();

	m_refreshButton = new QToolButton(this);
	m_refreshButton->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
	m_refreshButton->setToolTip("Refresh metrics");
	m_refreshButton->setAutoRaise(true);
	m_refreshButton->setStyleSheet(
		"QToolButton {"
		"  background: transparent;"
		"  border: 1px solid transparent;"
		"  border-radius: 3px;"
		"  padding: 4px;"
		"}"
		"QToolButton:hover {"
		"  background-color: #4a4c4e;"
		"  border-color: #5a5a5a;"
		"}"
	);
	connect(m_refreshButton, &QToolButton::clicked, this, &HealthDashboard::onRefreshClicked);
	headerLayout->addWidget(m_refreshButton);

	mainLayout->addWidget(headerBar);

	// Styled scroll area for panels
	QScrollArea* scroll = new QScrollArea(this);
	scroll->setWidgetResizable(true);
	scroll->setFrameShape(QFrame::NoFrame);
	scroll->setStyleSheet(
		"QScrollArea { background-color: #252525; border: none; }"
		"QScrollBar:vertical {"
		"  background-color: #252525;"
		"  width: 12px;"
		"  margin: 0;"
		"}"
		"QScrollBar::handle:vertical {"
		"  background-color: #3a3a3a;"
		"  min-height: 20px;"
		"  border-radius: 4px;"
		"  margin: 2px;"
		"}"
		"QScrollBar::handle:vertical:hover { background-color: #4a4a4a; }"
		"QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
	);

	QWidget* content = new QWidget();
	content->setStyleSheet("background-color: #252525;");
	QVBoxLayout* contentLayout = new QVBoxLayout(content);
	contentLayout->setContentsMargins(8, 8, 8, 8);
	contentLayout->setSpacing(12);

	// Panels
	m_coveragePanel = new CoveragePanel(content);
	contentLayout->addWidget(m_coveragePanel);

	m_complexityPanel = new ComplexityPanel(content);
	connect(m_complexityPanel, &ComplexityPanel::functionClicked,
		this, &HealthDashboard::addressSelected);
	contentLayout->addWidget(m_complexityPanel);

	m_qualityPanel = new QualityPanel(content);
	connect(m_qualityPanel, &QualityPanel::issueClicked,
		this, &HealthDashboard::addressSelected);
	contentLayout->addWidget(m_qualityPanel);

	m_progressPanel = new ProgressPanel(content);
	contentLayout->addWidget(m_progressPanel);

	contentLayout->addStretch();
	scroll->setWidget(content);
	mainLayout->addWidget(scroll);
}

void HealthDashboard::setBinaryView(BinaryViewRef data)
{
	m_data = data;
	if (data)
		refresh();
}

void HealthDashboard::refresh()
{
	computeMetrics();
}

void HealthDashboard::onRefreshClicked()
{
	refresh();
}

void HealthDashboard::computeMetrics()
{
	if (!m_data)
		return;

	QApplication::setOverrideCursor(Qt::WaitCursor);

	auto coverage = computeCoverage();
	auto complexity = computeComplexity();
	auto quality = computeQuality();
	auto progress = computeProgress();

	m_coveragePanel->setMetrics(coverage);
	m_complexityPanel->setMetrics(complexity);
	m_qualityPanel->setMetrics(quality);
	m_progressPanel->setMetrics(progress);

	// Compute overall health score (0-100)
	int score = 0;

	// Coverage contribution (max 30)
	score += static_cast<int>(30 * (1.0 - coverage.unknownPercent() / 100.0));

	// Complexity contribution (max 20)
	double complexRatio = complexity.totalFunctions > 0 ?
		(double)complexity.complexFunctions / complexity.totalFunctions : 0;
	score += static_cast<int>(20 * (1.0 - complexRatio));

	// Quality contribution (max 30)
	int totalIssues = quality.orphanFunctions + quality.unreachableCode + 
		quality.suspiciousPatterns + quality.deadCode;
	score += std::max(0, 30 - totalIssues / 2);

	// Progress contribution (max 20)
	score += static_cast<int>(20 * progress.namingPercent() / 100.0);

	score = std::min(100, std::max(0, score));

	QString scoreColor;
	if (score >= 75)
		scoreColor = getThemeColor(GreenStandardHighlightColor).name();
	else if (score >= 50)
		scoreColor = getThemeColor(YellowStandardHighlightColor).name();
	else
		scoreColor = getThemeColor(OrangeStandardHighlightColor).name();

	m_healthScoreLabel->setText(QString("FIRMWARE HEALTH SCORE: <span style='color: %1'>%2</span>/100")
		.arg(scoreColor).arg(score));

	QApplication::restoreOverrideCursor();
}

CoverageMetrics HealthDashboard::computeCoverage()
{
	CoverageMetrics m;

	// Get binary size
	m.totalBytes = m_data->GetLength();

	// Get segments to determine code/data
	for (auto& seg : m_data->GetSegments())
	{
		uint64_t size = seg->GetLength();
		auto flags = seg->GetFlags();

		if (flags & SegmentExecutable)
			m.codeBytes += size;
		else if (flags & SegmentWritable)
			m.dataBytes += size;
		else if (flags & SegmentReadable)
			m.dataBytes += size;
	}

	// Get function coverage
	for (auto& func : m_data->GetAnalysisFunctionList())
	{
		auto ranges = func->GetAddressRanges();
		for (const auto& range : ranges)
			m.functionBytes += range.end - range.start;
	}

	// Unknown is what's left
	m.unknownBytes = m.totalBytes - m.codeBytes - m.dataBytes;
	if (m.unknownBytes > m.totalBytes)
		m.unknownBytes = 0;

	return m;
}

ComplexityMetrics HealthDashboard::computeComplexity()
{
	ComplexityMetrics m;

	for (auto& func : m_data->GetAnalysisFunctionList())
	{
		m.totalFunctions++;

		int blockCount = static_cast<int>(func->GetBasicBlocks().size());

		if (blockCount < 10)
			m.simpleFunctions++;
		else if (blockCount <= 50)
			m.mediumFunctions++;
		else
			m.complexFunctions++;

		m.avgComplexity += blockCount;

		if (blockCount > m.mostComplexBlocks)
		{
			m.mostComplexBlocks = blockCount;
			m.mostComplexAddress = func->GetStart();
			m.mostComplexFunction = QString::fromStdString(func->GetSymbol()->GetShortName());
		}
	}

	if (m.totalFunctions > 0)
		m.avgComplexity /= m.totalFunctions;

	return m;
}

QualityMetrics HealthDashboard::computeQuality()
{
	QualityMetrics m;

	// Count orphan functions (no callers)
	for (auto& func : m_data->GetAnalysisFunctionList())
	{
		// Get code references to function start to find callers
		auto callers = m_data->GetCodeReferences(func->GetStart());
		if (callers.empty())
		{
			m.orphanFunctions++;
			
			// Don't flag entry points as orphans
			auto sym = func->GetSymbol();
			QString name = QString::fromStdString(sym->GetShortName());
			if (!name.contains("entry") && !name.contains("main") && 
				!name.contains("reset") && !name.contains("handler"))
			{
				if (m.issues.size() < 50)
				{
					m.issues.push_back({func->GetStart(),
						QString("Orphan function: %1").arg(name)});
				}
			}
		}

		// Check for unnamed functions (sub_XXXX pattern)
		QString name = QString::fromStdString(func->GetSymbol()->GetShortName());
		if (name.startsWith("sub_") || name.startsWith("func_"))
			m.unnamedFunctions++;

		// Check for empty functions
		if (func->GetBasicBlocks().size() <= 1)
		{
			auto bbs = func->GetBasicBlocks();
			if (!bbs.empty() && bbs[0]->GetLength() <= 4)
			{
				m.suspiciousPatterns++;
				if (m.issues.size() < 50)
				{
					m.issues.push_back({func->GetStart(),
						QString("Possibly empty function: %1").arg(name)});
				}
			}
		}
	}

	return m;
}

ProgressMetrics HealthDashboard::computeProgress()
{
	ProgressMetrics m;

	auto now = std::chrono::steady_clock::now();
	m.sessionDuration = std::chrono::duration_cast<std::chrono::seconds>(now - m_sessionStart);

	for (auto& func : m_data->GetAnalysisFunctionList())
	{
		m.totalFunctions++;

		QString name = QString::fromStdString(func->GetSymbol()->GetShortName());
		if (!name.startsWith("sub_") && !name.startsWith("func_"))
			m.namedFunctions++;

		// Check if function has type info
		auto type = func->GetType();
		if (type && !type->GetParameters().empty())
			m.typedFunctions++;

		// Check for comments
		if (!func->GetComment().empty())
			m.commentedFunctions++;
	}

	return m;
}

}  // namespace Armv5UI
