/*
 * Health Dashboard Widget
 *
 * Bird's-eye view of analysis quality and firmware structure:
 * - Coverage: % of code analyzed, undefined regions
 * - Complexity: Function complexity distribution
 * - Quality: Dead code, orphan functions, suspicious patterns
 * - Progress: Track your RE session over time
 *
 * Why innovative: Gives overview no other tool provides
 */

#pragma once

#include "../common/analysis_widgets.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QLabel>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QFrame>
#include <QtCharts/QChartView>
#include <QtCharts/QBarSeries>
#include <QtCharts/QLineSeries>

#include <vector>
#include <chrono>

namespace Armv5UI
{

// ============================================================================
// Health Metrics
// ============================================================================

struct CoverageMetrics
{
	uint64_t totalBytes = 0;
	uint64_t codeBytes = 0;
	uint64_t dataBytes = 0;
	uint64_t unknownBytes = 0;
	uint64_t functionBytes = 0;
	
	double codePercent() const { return totalBytes > 0 ? 100.0 * codeBytes / totalBytes : 0; }
	double dataPercent() const { return totalBytes > 0 ? 100.0 * dataBytes / totalBytes : 0; }
	double unknownPercent() const { return totalBytes > 0 ? 100.0 * unknownBytes / totalBytes : 0; }
	double functionCoverage() const { return codeBytes > 0 ? 100.0 * functionBytes / codeBytes : 0; }
};

struct ComplexityMetrics
{
	int totalFunctions = 0;
	int simpleFunctions = 0;    // < 10 blocks
	int mediumFunctions = 0;    // 10-50 blocks
	int complexFunctions = 0;   // > 50 blocks
	
	QString mostComplexFunction;
	int mostComplexBlocks = 0;
	uint64_t mostComplexAddress = 0;
	
	double avgComplexity = 0.0;
	std::vector<int> complexityHistogram;  // Distribution
};

struct QualityMetrics
{
	int orphanFunctions = 0;     // No callers
	int unreachableCode = 0;     // No paths from entry
	int suspiciousPatterns = 0;  // e.g., empty functions, infinite loops
	int deadCode = 0;
	int unnamedFunctions = 0;
	int totalComments = 0;
	int totalTypes = 0;
	
	std::vector<std::pair<uint64_t, QString>> issues;
};

struct ProgressMetrics
{
	int namedFunctions = 0;
	int totalFunctions = 0;
	int typedFunctions = 0;
	int commentedFunctions = 0;
	
	std::chrono::steady_clock::time_point sessionStart;
	std::chrono::seconds sessionDuration{0};
	
	double namingPercent() const { return totalFunctions > 0 ? 100.0 * namedFunctions / totalFunctions : 0; }
};

// ============================================================================
// MetricCard - Single metric display with label, value, and optional bar
// ============================================================================

class MetricCard : public QFrame
{
	Q_OBJECT

public:
	MetricCard(const QString& title, QWidget* parent = nullptr);

	void setValue(int value);
	void setValue(double value, const QString& suffix = "%");
	void setValue(const QString& value);
	void setProgress(double percent);  // 0-100
	void setColor(const QColor& color);
	void setSubtext(const QString& text);

private:
	void setupUI();

	QLabel* m_titleLabel;
	QLabel* m_valueLabel;
	QLabel* m_subtextLabel;
	QProgressBar* m_progressBar;
};

// ============================================================================
// CoveragePanel - Memory coverage visualization
// ============================================================================

class CoveragePanel : public QWidget
{
	Q_OBJECT

public:
	explicit CoveragePanel(QWidget* parent = nullptr);

	void setMetrics(const CoverageMetrics& metrics);

private:
	void setupUI();
	void updateMemoryMap();

	MetricCard* m_totalCard;
	MetricCard* m_codeCard;
	MetricCard* m_dataCard;
	MetricCard* m_unknownCard;
	
	// Visual memory map
	QWidget* m_memoryMap;
	CoverageMetrics m_metrics;
};

// ============================================================================
// ComplexityPanel - Function complexity distribution
// ============================================================================

class ComplexityPanel : public QWidget
{
	Q_OBJECT

public:
	explicit ComplexityPanel(QWidget* parent = nullptr);

	void setMetrics(const ComplexityMetrics& metrics);

Q_SIGNALS:
	void functionClicked(uint64_t address);

private:
	void setupUI();
	void updateHistogram();

	MetricCard* m_totalCard;
	MetricCard* m_simpleCard;
	MetricCard* m_mediumCard;
	MetricCard* m_complexCard;
	
	QLabel* m_mostComplexLabel;
	QWidget* m_histogramWidget;
	ComplexityMetrics m_metrics;
};

// ============================================================================
// QualityPanel - Analysis quality issues
// ============================================================================

class QualityPanel : public QWidget
{
	Q_OBJECT

public:
	explicit QualityPanel(QWidget* parent = nullptr);

	void setMetrics(const QualityMetrics& metrics);

Q_SIGNALS:
	void issueClicked(uint64_t address);

private:
	void setupUI();

	MetricCard* m_orphanCard;
	MetricCard* m_unreachableCard;
	MetricCard* m_suspiciousCard;
	MetricCard* m_deadCodeCard;
	
	QTableWidget* m_issueTable;
	QualityMetrics m_metrics;
};

// ============================================================================
// ProgressPanel - RE session progress
// ============================================================================

class ProgressPanel : public QWidget
{
	Q_OBJECT

public:
	explicit ProgressPanel(QWidget* parent = nullptr);

	void setMetrics(const ProgressMetrics& metrics);

private:
	void setupUI();

	MetricCard* m_sessionCard;
	MetricCard* m_namedCard;
	MetricCard* m_typedCard;
	MetricCard* m_commentedCard;
	
	ProgressMetrics m_metrics;
};

// ============================================================================
// HealthDashboard - Main dashboard
// ============================================================================

class HealthDashboard : public QWidget
{
	Q_OBJECT

public:
	explicit HealthDashboard(QWidget* parent = nullptr);

	void setBinaryView(BinaryViewRef data);
	void refresh();

Q_SIGNALS:
	void addressSelected(uint64_t address);

private Q_SLOTS:
	void onRefreshClicked();

private:
	void setupUI();
	void computeMetrics();
	
	CoverageMetrics computeCoverage();
	ComplexityMetrics computeComplexity();
	QualityMetrics computeQuality();
	ProgressMetrics computeProgress();

	BinaryViewRef m_data;
	
	// Header
	QLabel* m_healthScoreLabel;
	QToolButton* m_refreshButton;
	
	// Panels
	CoveragePanel* m_coveragePanel;
	ComplexityPanel* m_complexityPanel;
	QualityPanel* m_qualityPanel;
	ProgressPanel* m_progressPanel;
	
	// Session tracking
	std::chrono::steady_clock::time_point m_sessionStart;
};

}  // namespace Armv5UI
