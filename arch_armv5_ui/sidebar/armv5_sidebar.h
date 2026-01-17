/*
 * ARMv5 Sidebar Widget
 *
 * Main sidebar panel for ARMv5 firmware analysis.
 */

#pragma once

#include "uitypes.h"
#include "sidebarwidget.h"

#include <QtWidgets/QTabWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

class ViewFrame;

namespace Armv5UI
{

class FunctionTableWidget;
class RTOSTableWidget;
class ScanControlsWidget;
class VectorTableWidget;
class RegionDetectorWidget;
class DiscoverWidget;
class SecurityScannerWidget;
class HealthDashboard;
class FirmwareDiffWidget;

/**
 * ARMv5 Sidebar Widget
 *
 * Provides a tabbed interface for:
 * - Functions: Table of discovered functions with calling convention info
 * - Discover: Multi-heuristic function/string/structure/crypto detection
 * - Vectors: Exception/interrupt handler analysis
 * - Regions: Memory region detection and typing
 * - RTOS: Table of detected RTOS tasks (if RTOS detected)
 * - Scans: Controls for running analysis scans
 */
class Armv5SidebarWidget : public SidebarWidget
{
	Q_OBJECT

public:
	Armv5SidebarWidget(ViewFrame* frame, BinaryViewRef data);
	~Armv5SidebarWidget() override;

	/**
	 * Called when the view changes (e.g., user switches tabs).
	 */
	void notifyViewChanged(ViewFrame* frame) override;

	/**
	 * Called when the current offset changes (user navigates).
	 */
	void notifyOffsetChanged(uint64_t offset) override;

	/**
	 * Refresh all data tables.
	 */
	void refreshData();

	/**
	 * Get the current BinaryView.
	 */
	BinaryViewRef getData() const { return m_data; }

private Q_SLOTS:
	void onRunAllScansClicked();
	void onDetectRTOSClicked();
	void onRefreshClicked();
	void onFunctionSelected(uint64_t address);

private:
	void setupUI();
	void connectSignals();

	ViewFrame* m_frame;
	BinaryViewRef m_data;

	// Tab widget
	QTabWidget* m_tabs;

	// Tab contents
	FunctionTableWidget* m_functionTable;
	DiscoverWidget* m_discoverWidget;
	SecurityScannerWidget* m_securityScanner;
	HealthDashboard* m_healthDashboard;
	FirmwareDiffWidget* m_diffWidget;
	RTOSTableWidget* m_rtosTable;
	VectorTableWidget* m_vectorTable;
	RegionDetectorWidget* m_regionDetector;
	ScanControlsWidget* m_scanControls;
};

}
