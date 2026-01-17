/*
 * Scan Controls Widget
 *
 * Provides buttons and status for running individual analysis scans.
 */

#pragma once

#include "uitypes.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QGroupBox>

namespace Armv5UI
{

/**
 * Scan controls widget.
 *
 * Provides buttons for running individual scans and displays
 * the last scan results.
 */
class ScanControlsWidget : public QWidget
{
	Q_OBJECT

public:
	explicit ScanControlsWidget(QWidget* parent = nullptr);

	void refresh(BinaryViewRef data);

private Q_SLOTS:
	void onPrologueScanClicked();
	void onCallTargetScanClicked();
	void onPointerScanClicked();
	void onOrphanScanClicked();
	void onCleanupClicked();

private:
	void setupUI();
	void updateStats();

	BinaryViewRef m_data;

	// Scan buttons
	QPushButton* m_prologueButton;
	QPushButton* m_callTargetButton;
	QPushButton* m_pointerButton;
	QPushButton* m_orphanButton;
	QPushButton* m_cleanupButton;

	// Status display
	QLabel* m_functionCountLabel;
	QLabel* m_architectureLabel;
	QLabel* m_viewTypeLabel;
};

}
