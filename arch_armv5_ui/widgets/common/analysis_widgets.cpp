/*
 * Shared Analysis Widgets - Implementation
 */

#include "analysis_widgets.h"
#include "armv5_theme.h"
#include "viewframe.h"

#include <QtWidgets/QStyle>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QSplitter>
#include <QtGui/QTextCursor>

using namespace BinaryNinja;

namespace Armv5UI
{

// ============================================================================
// AnalysisControlBar - QToolBar like BN's workflow monitor
// ============================================================================

AnalysisControlBar::AnalysisControlBar(QWidget* parent)
	: QToolBar(parent)
{
	setupActions();
}

void AnalysisControlBar::setupActions()
{
	// Configure toolbar style
	setIconSize(QSize(16, 16));
	setToolButtonStyle(Qt::ToolButtonIconOnly);
	setMovable(false);
	setFloatable(false);

	// Run action
	m_runAction = addAction("Run");
	m_runAction->setIcon(QIcon::fromTheme("media-playback-start",
		style()->standardIcon(QStyle::SP_MediaPlay)));
	m_runAction->setToolTip("Run analysis");
	connect(m_runAction, &QAction::triggered, this, &AnalysisControlBar::runClicked);

	// Stop action
	m_stopAction = addAction("Stop");
	m_stopAction->setIcon(QIcon::fromTheme("media-playback-stop",
		style()->standardIcon(QStyle::SP_MediaStop)));
	m_stopAction->setToolTip("Stop analysis");
	m_stopAction->setEnabled(false);
	connect(m_stopAction, &QAction::triggered, this, &AnalysisControlBar::stopClicked);

	// Reset action
	m_resetAction = addAction("Reset");
	m_resetAction->setIcon(QIcon::fromTheme("view-refresh",
		style()->standardIcon(QStyle::SP_BrowserReload)));
	m_resetAction->setToolTip("Clear results");
	connect(m_resetAction, &QAction::triggered, this, &AnalysisControlBar::resetClicked);

	addSeparator();

	// Spacer
	QWidget* spacer = new QWidget();
	spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
	addWidget(spacer);

	// Apply action
	m_applyAction = addAction("Apply");
	m_applyAction->setIcon(QIcon::fromTheme("dialog-ok-apply",
		style()->standardIcon(QStyle::SP_DialogApplyButton)));
	m_applyAction->setToolTip("Apply selected items");
	m_applyAction->setEnabled(false);
	connect(m_applyAction, &QAction::triggered, this, &AnalysisControlBar::applyClicked);

	// Log toggle action
	m_logAction = addAction("Log");
	m_logAction->setIcon(QIcon::fromTheme("view-list-details",
		style()->standardIcon(QStyle::SP_FileDialogDetailedView)));
	m_logAction->setToolTip("Toggle log panel");
	m_logAction->setCheckable(true);
	connect(m_logAction, &QAction::toggled, this, &AnalysisControlBar::logToggled);

	// Export action
	m_exportAction = addAction("Export");
	m_exportAction->setIcon(QIcon::fromTheme("document-save",
		style()->standardIcon(QStyle::SP_DialogSaveButton)));
	m_exportAction->setToolTip("Export results");
	connect(m_exportAction, &QAction::triggered, this, &AnalysisControlBar::exportClicked);
}

void AnalysisControlBar::setRunning(bool running)
{
	m_running = running;
	m_runAction->setEnabled(!running);
	m_stopAction->setEnabled(running);
	m_resetAction->setEnabled(!running);
}

void AnalysisControlBar::setApplyEnabled(bool enabled)
{
	m_applyAction->setEnabled(enabled);
}

void AnalysisControlBar::setSelectionCount(int count)
{
	if (count > 0)
		m_applyAction->setText(QString("Apply (%1)").arg(count));
	else
		m_applyAction->setText("Apply");
	m_applyAction->setEnabled(count > 0);
}

void AnalysisControlBar::setApplyVisible(bool visible)
{
	m_applyAction->setVisible(visible);
}

void AnalysisControlBar::setLogChecked(bool checked)
{
	m_logAction->setChecked(checked);
}

// ============================================================================
// FilterBar
// ============================================================================

FilterBar::FilterBar(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void FilterBar::setupUI()
{
	// Use native BN styling - no custom stylesheet
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->setSpacing(0);

	// Header with collapse button
	QHBoxLayout* headerLayout = new QHBoxLayout();
	headerLayout->setContentsMargins(4, 2, 4, 2);

	m_collapseBtn = new QToolButton(this);
	m_collapseBtn->setArrowType(Qt::DownArrow);
	m_collapseBtn->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
	m_collapseBtn->setText("Filters");
	m_collapseBtn->setAutoRaise(true);
	connect(m_collapseBtn, &QToolButton::clicked, this, &FilterBar::toggleCollapsed);
	headerLayout->addWidget(m_collapseBtn);
	headerLayout->addStretch();
	mainLayout->addLayout(headerLayout);

	// Content area - use native BN styling
	m_content = new QWidget(this);
	m_contentLayout = new QHBoxLayout(m_content);
	m_contentLayout->setContentsMargins(4, 2, 4, 4);
	m_contentLayout->setSpacing(8);
	m_contentLayout->addStretch();
	mainLayout->addWidget(m_content);
}

void FilterBar::setCollapsed(bool collapsed)
{
	m_collapsed = collapsed;
	m_collapseBtn->setArrowType(collapsed ? Qt::RightArrow : Qt::DownArrow);
	m_content->setVisible(!collapsed);
}

void FilterBar::toggleCollapsed()
{
	setCollapsed(!m_collapsed);
}

void FilterBar::addScoreFilter(double min, double max, double value)
{
	QLabel* label = new QLabel("Score >=", m_content);
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, label);

	m_scoreFilter = new QDoubleSpinBox(m_content);
	m_scoreFilter->setRange(min, max);
	m_scoreFilter->setValue(value);
	m_scoreFilter->setSingleStep(0.1);
	m_scoreFilter->setDecimals(2);
	m_scoreFilter->setMaximumWidth(60);
	connect(m_scoreFilter, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
		this, &FilterBar::onFilterChanged);
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, m_scoreFilter);
}

void FilterBar::addStatusFilter(const QStringList& options)
{
	QLabel* label = new QLabel("Status:", m_content);
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, label);

	m_statusFilter = new QComboBox(m_content);
	m_statusFilter->addItems(options);
	m_statusFilter->setMaximumWidth(80);
	connect(m_statusFilter, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &FilterBar::onFilterChanged);
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, m_statusFilter);
}

void FilterBar::addModeFilter(const QStringList& options)
{
	QLabel* label = new QLabel("Mode:", m_content);
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, label);

	m_modeFilter = new QComboBox(m_content);
	m_modeFilter->addItems(options);
	m_modeFilter->setMaximumWidth(70);
	connect(m_modeFilter, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &FilterBar::onFilterChanged);
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, m_modeFilter);
}

void FilterBar::addSearchBox(const QString& placeholder)
{
	m_searchBox = new QLineEdit(m_content);
	m_searchBox->setPlaceholderText(placeholder);
	m_searchBox->setMaximumWidth(150);
	m_searchBox->setClearButtonEnabled(true);
	connect(m_searchBox, &QLineEdit::textChanged, this, &FilterBar::onFilterChanged);
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, m_searchBox);
}

void FilterBar::addCustomCombo(const QString& label, const QStringList& options)
{
	QLabel* lbl = new QLabel(label + ":", m_content);
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, lbl);

	QComboBox* combo = new QComboBox(m_content);
	combo->addItems(options);
	combo->setMaximumWidth(100);
	connect(combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &FilterBar::onFilterChanged);
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, combo);
	m_customCombos[label] = combo;
}

void FilterBar::addPresetButton(const QString& text, const QString& tooltip)
{
	QToolButton* btn = new QToolButton(m_content);
	btn->setText(text);
	btn->setToolTip(tooltip);
	btn->setAutoRaise(true);
	connect(btn, &QToolButton::clicked, [this, text]() {
		emit presetClicked(text);
	});
	m_contentLayout->insertWidget(m_contentLayout->count() - 1, btn);
}

double FilterBar::scoreFilter() const
{
	return m_scoreFilter ? m_scoreFilter->value() : 0.0;
}

int FilterBar::statusFilterIndex() const
{
	return m_statusFilter ? m_statusFilter->currentIndex() : 0;
}

int FilterBar::modeFilterIndex() const
{
	return m_modeFilter ? m_modeFilter->currentIndex() : 0;
}

QString FilterBar::searchText() const
{
	return m_searchBox ? m_searchBox->text() : QString();
}

int FilterBar::customComboIndex(const QString& label) const
{
	auto it = m_customCombos.find(label);
	return it != m_customCombos.end() ? it->second->currentIndex() : 0;
}

void FilterBar::onFilterChanged()
{
	emit filtersChanged();
}

// ============================================================================
// TreeResultsModel
// ============================================================================

TreeResultsModel::TreeResultsModel(QObject* parent)
	: QAbstractItemModel(parent)
{
}

TreeResultsModel::~TreeResultsModel()
{
}

void TreeResultsModel::setColumns(const QStringList& headers, const std::vector<int>& widths)
{
	m_headers = headers;
	m_columnWidths = widths;
}

QModelIndex TreeResultsModel::index(int row, int column, const QModelIndex& parent) const
{
	if (!hasIndex(row, column, parent))
		return QModelIndex();

	if (!parent.isValid())
	{
		// Top-level item
		return createIndex(row, column, quintptr(0));
	}
	else if (parent.internalId() == 0)
	{
		// Detail row under top-level item
		// Encode parent row in internal ID
		return createIndex(row, column, quintptr(parent.row() + 1));
	}

	return QModelIndex();
}

QModelIndex TreeResultsModel::parent(const QModelIndex& child) const
{
	if (!child.isValid())
		return QModelIndex();

	quintptr id = child.internalId();
	if (id == 0)
		return QModelIndex();  // Top-level item has no parent

	// Detail row - parent is the item at row (id - 1)
	return createIndex(static_cast<int>(id - 1), 0, quintptr(0));
}

int TreeResultsModel::rowCount(const QModelIndex& parent) const
{
	if (!parent.isValid())
		return itemCount();

	if (parent.internalId() == 0)
		return detailRowCount(parent.row());

	return 0;
}

int TreeResultsModel::columnCount(const QModelIndex& parent) const
{
	Q_UNUSED(parent);
	return m_headers.size();
}

QVariant TreeResultsModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid())
		return QVariant();

	if (index.internalId() == 0)
	{
		// Top-level item
		if (role == Qt::CheckStateRole && index.column() == 0)
			return isItemSelected(index.row()) ? Qt::Checked : Qt::Unchecked;
		return itemData(index.row(), index.column(), role);
	}
	else
	{
		// Detail row
		int parentRow = static_cast<int>(index.internalId() - 1);
		return detailData(parentRow, index.row(), index.column(), role);
	}
}

bool TreeResultsModel::setData(const QModelIndex& index, const QVariant& value, int role)
{
	if (!index.isValid() || index.internalId() != 0)
		return false;

	if (role == Qt::CheckStateRole && index.column() == 0)
	{
		setItemSelected(index.row(), value.toInt() == Qt::Checked);
		emit dataChanged(index, index, {Qt::CheckStateRole, Qt::BackgroundRole});
		return true;
	}

	return false;
}

Qt::ItemFlags TreeResultsModel::flags(const QModelIndex& index) const
{
	Qt::ItemFlags f = QAbstractItemModel::flags(index);
	if (index.isValid() && index.internalId() == 0 && index.column() == 0)
		f |= Qt::ItemIsUserCheckable;
	return f;
}

QVariant TreeResultsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Horizontal && role == Qt::DisplayRole && section < m_headers.size())
		return m_headers[section];
	return QVariant();
}

QVariant TreeResultsModel::detailData(int parentRow, int detailRow, int column, int role) const
{
	Q_UNUSED(parentRow);
	Q_UNUSED(detailRow);
	Q_UNUSED(column);
	Q_UNUSED(role);
	return QVariant();
}

void TreeResultsModel::clear()
{
	beginResetModel();
	endResetModel();
}

void TreeResultsModel::beginUpdate()
{
	beginResetModel();
}

void TreeResultsModel::endUpdate()
{
	endResetModel();
}

void TreeResultsModel::selectAll()
{
	for (int i = 0; i < itemCount(); i++)
		setItemSelected(i, true);
	emit dataChanged(index(0, 0), index(itemCount() - 1, 0), {Qt::CheckStateRole});
}

void TreeResultsModel::selectNone()
{
	for (int i = 0; i < itemCount(); i++)
		setItemSelected(i, false);
	emit dataChanged(index(0, 0), index(itemCount() - 1, 0), {Qt::CheckStateRole});
}

void TreeResultsModel::invertSelection()
{
	for (int i = 0; i < itemCount(); i++)
		setItemSelected(i, !isItemSelected(i));
	emit dataChanged(index(0, 0), index(itemCount() - 1, 0), {Qt::CheckStateRole});
}

std::vector<uint64_t> TreeResultsModel::getSelectedAddresses() const
{
	std::vector<uint64_t> result;
	for (int i = 0; i < itemCount(); i++)
		if (isItemSelected(i))
			result.push_back(itemAddress(i));
	return result;
}

int TreeResultsModel::selectedCount() const
{
	int count = 0;
	for (int i = 0; i < itemCount(); i++)
		if (isItemSelected(i))
			count++;
	return count;
}

void TreeResultsModel::sort(int column, Qt::SortOrder order)
{
	Q_UNUSED(column);
	Q_UNUSED(order);
	// Subclasses should override this
}

// ============================================================================
// ContextPreview
// ============================================================================

ContextPreview::ContextPreview(QWidget* parent)
	: QWidget(parent)
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	m_headerLabel = new QLabel("Preview", this);
	layout->addWidget(m_headerLabel);

	m_textEdit = new QTextEdit(this);
	m_textEdit->setReadOnly(true);
	m_textEdit->setFont(getMonospaceFont(this));
	m_textEdit->setLineWrapMode(QTextEdit::NoWrap);
	layout->addWidget(m_textEdit);
}

void ContextPreview::setBinaryView(BinaryViewRef data)
{
	m_data = data;
}

QColor ContextPreview::tokenColor(BNInstructionTextTokenType type) const
{
	return getTokenColor(const_cast<ContextPreview*>(this), type);
}

void ContextPreview::showDisassembly(uint64_t address, bool isThumb, int lineCount)
{
	if (!m_data) return;

	m_headerLabel->setText(QString("Disassembly 0x%1 (%2)")
		.arg(address, 8, 16, QChar('0'))
		.arg(isThumb ? "Thumb" : "ARM"));

	Ref<Architecture> arch = m_data->GetDefaultArchitecture();
	if (!arch) return;

	if (isThumb)
	{
		uint64_t ta = address | 1;
		auto t = arch->GetAssociatedArchitectureByAddress(ta);
		if (t) arch = t;
	}

	m_textEdit->clear();
	QTextCursor cursor = m_textEdit->textCursor();
	uint64_t addr = address;

	for (int i = 0; i < lineCount; i++)
	{
		DataBuffer buf = m_data->ReadBuffer(addr, 4);
		if (buf.GetLength() < 2) break;

		InstructionInfo info;
		if (!arch->GetInstructionInfo(static_cast<const uint8_t*>(buf.GetData()),
			addr, buf.GetLength(), info))
			break;

		std::vector<InstructionTextToken> tokens;
		if (!arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()),
			addr, info.length, tokens))
			break;

		QTextCharFormat addrFmt;
		addrFmt.setForeground(tokenColor(AddressDisplayToken));
		cursor.insertText(QString("0x%1  ").arg(addr, 8, 16, QChar('0')), addrFmt);

		// Show hex opcode bytes
		QTextCharFormat hexFmt;
		hexFmt.setForeground(QColor(0x80, 0x80, 0x80));  // Gray for hex bytes
		QString hexBytes;
		const uint8_t* data = static_cast<const uint8_t*>(buf.GetData());
		for (size_t b = 0; b < info.length; b++)
			hexBytes += QString("%1 ").arg(data[b], 2, 16, QChar('0'));
		// Pad to fixed width (8 bytes max = 24 chars)
		cursor.insertText(hexBytes.leftJustified(12, ' '), hexFmt);

		for (const auto& tok : tokens)
		{
			QTextCharFormat tokFmt;
			tokFmt.setForeground(tokenColor(tok.type));
			cursor.insertText(QString::fromStdString(tok.text), tokFmt);
		}
		cursor.insertText("\n");
		addr += info.length;
	}
}

void ContextPreview::showHex(uint64_t address, size_t length)
{
	if (!m_data) return;

	m_headerLabel->setText(QString("Hex 0x%1 (%2 bytes)")
		.arg(address, 8, 16, QChar('0')).arg(length));

	DataBuffer buf = m_data->ReadBuffer(address, std::min(length, size_t(256)));
	QString hex;
	for (size_t i = 0; i < buf.GetLength(); i++)
	{
		if (i > 0 && i % 16 == 0) hex += "\n";
		else if (i > 0 && i % 8 == 0) hex += "  ";
		else if (i > 0) hex += " ";
		hex += QString("%1").arg(static_cast<const uint8_t*>(buf.GetData())[i], 2, 16, QChar('0'));
	}
	m_textEdit->setPlainText(hex);
}

void ContextPreview::showString(uint64_t address, size_t length)
{
	if (!m_data) return;

	m_headerLabel->setText(QString("String 0x%1 (%2 bytes)")
		.arg(address, 8, 16, QChar('0')).arg(length));

	DataBuffer buf = m_data->ReadBuffer(address, std::min(length + 1, size_t(512)));
	QString content;
	for (size_t i = 0; i < buf.GetLength(); i++)
	{
		uint8_t c = static_cast<const uint8_t*>(buf.GetData())[i];
		if (c == 0) break;
		if (c >= 0x20 && c < 0x7F)
			content += QChar(c);
		else
			content += QString("\\x%1").arg(c, 2, 16, QChar('0'));
	}
	m_textEdit->setPlainText(content);
}

void ContextPreview::showStructure(uint64_t address, size_t size)
{
	if (!m_data) return;

	m_headerLabel->setText(QString("Structure 0x%1 (%2 bytes)")
		.arg(address, 8, 16, QChar('0')).arg(size));

	m_textEdit->clear();
	QTextCursor cursor = m_textEdit->textCursor();

	for (size_t i = 0; i < std::min(size, size_t(64)); i += 4)
	{
		DataBuffer buf = m_data->ReadBuffer(address + i, 4);
		if (buf.GetLength() < 4) break;

		uint32_t val = *reinterpret_cast<const uint32_t*>(buf.GetData());

		QTextCharFormat addrFmt;
		addrFmt.setForeground(tokenColor(AddressDisplayToken));
		cursor.insertText(QString("[%1] ").arg(i, 3), addrFmt);

		QTextCharFormat valFmt;
		valFmt.setForeground(tokenColor(IntegerToken));
		cursor.insertText(QString("0x%1").arg(val, 8, 16, QChar('0')), valFmt);

		Ref<Symbol> sym = m_data->GetSymbolByAddress(val);
		if (sym)
		{
			QTextCharFormat symFmt;
			symFmt.setForeground(tokenColor(CodeSymbolToken));
			cursor.insertText("  " + QString::fromStdString(sym->GetShortName()), symFmt);
		}
		cursor.insertText("\n");
	}
}

void ContextPreview::showCustom(const QString& title, const QString& content)
{
	m_headerLabel->setText(title);
	m_textEdit->setPlainText(content);
}

void ContextPreview::clear()
{
	m_headerLabel->setText("Preview");
	m_textEdit->clear();
}

// ============================================================================
// AnalysisStatusBar
// ============================================================================

AnalysisStatusBar::AnalysisStatusBar(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void AnalysisStatusBar::setupUI()
{
	// Use native BN styling - no custom stylesheet
	QHBoxLayout* layout = new QHBoxLayout(this);
	layout->setContentsMargins(4, 2, 4, 2);
	layout->setSpacing(8);

	m_statusLabel = new QLabel("Ready", this);
	layout->addWidget(m_statusLabel);

	// Phase indicator (e.g., "2/8")
	m_phaseLabel = new QLabel(this);
	m_phaseLabel->setStyleSheet("QLabel { color: #888888; font-size: 10px; }");
	m_phaseLabel->hide();
	layout->addWidget(m_phaseLabel);

	m_progress = new QProgressBar(this);
	m_progress->setMaximumWidth(120);
	m_progress->setMaximumHeight(14);
	m_progress->setTextVisible(false);
	m_progress->hide();
	layout->addWidget(m_progress);

	// Cancel button
	m_cancelButton = new QToolButton(this);
	m_cancelButton->setIcon(QIcon::fromTheme("process-stop",
		style()->standardIcon(QStyle::SP_BrowserStop)));
	m_cancelButton->setToolTip("Cancel analysis");
	m_cancelButton->setAutoRaise(true);
	m_cancelButton->setIconSize(QSize(12, 12));
	m_cancelButton->hide();
	connect(m_cancelButton, &QToolButton::clicked, this, &AnalysisStatusBar::cancelClicked);
	layout->addWidget(m_cancelButton);

	layout->addStretch();

	m_summaryLabel = new QLabel(this);
	m_summaryLabel->setAlignment(Qt::AlignRight);
	layout->addWidget(m_summaryLabel);
}

void AnalysisStatusBar::setStatus(const QString& status)
{
	m_statusLabel->setText(status);
}

void AnalysisStatusBar::setProgress(int percent)
{
	if (percent < 0)
	{
		m_progress->hide();
	}
	else
	{
		m_progress->setValue(percent);
		m_progress->show();
	}
}

void AnalysisStatusBar::setPhase(int current, int total, const QString& phaseName)
{
	if (current > 0 && total > 0)
	{
		m_phaseLabel->setText(QString("%1/%2: %3").arg(current).arg(total).arg(phaseName));
		m_phaseLabel->show();
	}
	else
	{
		m_phaseLabel->hide();
	}
}

void AnalysisStatusBar::setCancelVisible(bool visible)
{
	m_cancelButton->setVisible(visible);
}

void AnalysisStatusBar::setRunning(bool running)
{
	m_running = running;
	m_cancelButton->setVisible(running);
	if (!running)
	{
		m_phaseLabel->hide();
		m_progress->hide();
	}
}

void AnalysisStatusBar::setSummary(const QString& summary)
{
	m_summaryLabel->setText(summary);
}

void AnalysisStatusBar::setSummary(int total, int selected)
{
	m_summaryLabel->setText(QString("Total: %1 | Selected: %2").arg(total).arg(selected));
}

void AnalysisStatusBar::setSummary(const QString& label1, int count1,
	const QString& label2, int count2)
{
	m_summaryLabel->setText(QString("%1: %2 | %3: %4")
		.arg(label1).arg(count1).arg(label2).arg(count2));
}

// ============================================================================
// CockpitPanel - Metal panel with screws and engraved lines
// ============================================================================

CockpitPanel::CockpitPanel(QWidget* parent)
	: QWidget(parent)
{
	m_contentLayout = new QVBoxLayout(this);
	m_contentLayout->setContentsMargins(16, 24, 16, 12);
	m_contentLayout->setSpacing(8);
}

void CockpitPanel::setTitle(const QString& title)
{
	m_title = title;
	update();
}

void CockpitPanel::paintEvent(QPaintEvent* event)
{
	Q_UNUSED(event);
	QPainter p(this);
	p.setRenderHint(QPainter::Antialiasing);

	int w = width();
	int h = height();

	// Metal panel background with subtle gradient
	QLinearGradient panelGrad(0, 0, 0, h);
	panelGrad.setColorAt(0.0, QColor(58, 60, 62));
	panelGrad.setColorAt(0.3, QColor(48, 50, 52));
	panelGrad.setColorAt(0.7, QColor(42, 44, 46));
	panelGrad.setColorAt(1.0, QColor(38, 40, 42));
	p.fillRect(rect(), panelGrad);

	// Beveled edge - top highlight
	p.setPen(QPen(QColor(80, 82, 84), 1));
	p.drawLine(1, 1, w - 2, 1);
	p.drawLine(1, 1, 1, h - 2);

	// Beveled edge - bottom shadow
	p.setPen(QPen(QColor(25, 27, 29), 1));
	p.drawLine(1, h - 1, w - 1, h - 1);
	p.drawLine(w - 1, 1, w - 1, h - 1);

	// Outer border
	p.setPen(QPen(QColor(20, 22, 24), 2));
	p.drawRect(0, 0, w - 1, h - 1);

	// Draw screws in corners
	int screwSize = 10;
	int screwMargin = 5;
	drawScrew(p, screwMargin, screwMargin, screwSize);
	drawScrew(p, w - screwMargin - screwSize, screwMargin, screwSize);
	drawScrew(p, screwMargin, h - screwMargin - screwSize, screwSize);
	drawScrew(p, w - screwMargin - screwSize, h - screwMargin - screwSize, screwSize);

	// Title at top - white text (Boeing style)
	if (!m_title.isEmpty())
	{
		QFont titleFont = font();
		titleFont.setPixelSize(11);
		titleFont.setBold(true);
		titleFont.setLetterSpacing(QFont::AbsoluteSpacing, 2);
		p.setFont(titleFont);

		// White text with subtle shadow
		p.setPen(QColor(20, 20, 20));
		p.drawText(QRect(0, 8, w, 14), Qt::AlignHCenter, m_title.toUpper());
		p.setPen(QColor(255, 255, 255));  // White text
		p.drawText(QRect(0, 7, w, 14), Qt::AlignHCenter, m_title.toUpper());
	}

	// White horizontal line below title
	if (!m_title.isEmpty())
	{
		p.setPen(QPen(QColor(255, 255, 255), 1));  // White line
		p.drawLine(20, 21, w - 20, 21);
	}
}

void CockpitPanel::drawScrew(QPainter& p, int x, int y, int size)
{
	// Outer recess shadow
	p.setBrush(QColor(20, 22, 24));
	p.setPen(Qt::NoPen);
	p.drawEllipse(x - 1, y - 1, size + 2, size + 2);

	// Screw head - metallic gradient
	QRadialGradient screwGrad(x + size/2 - 1, y + size/2 - 1, size/2);
	screwGrad.setColorAt(0.0, QColor(95, 97, 99));
	screwGrad.setColorAt(0.4, QColor(75, 77, 79));
	screwGrad.setColorAt(0.8, QColor(55, 57, 59));
	screwGrad.setColorAt(1.0, QColor(40, 42, 44));
	p.setBrush(screwGrad);
	p.setPen(QPen(QColor(30, 32, 34), 1));
	p.drawEllipse(x, y, size, size);

	// Phillips head slot - darker cross
	int cx = x + size / 2;
	int cy = y + size / 2;
	int slotLen = size / 3;
	p.setPen(QPen(QColor(25, 27, 29), 2));
	p.drawLine(cx - slotLen, cy, cx + slotLen, cy);
	p.drawLine(cx, cy - slotLen, cx, cy + slotLen);

	// Highlight arc on screw head
	p.setPen(QPen(QColor(110, 112, 114), 1));
	p.drawArc(x + 2, y + 2, size - 4, size - 4, 45 * 16, 90 * 16);
}

void CockpitPanel::drawEngravedLine(QPainter& p, int x1, int y1, int x2, int y2)
{
	// Shadow line (below)
	p.setPen(QPen(QColor(60, 62, 64), 1));
	p.drawLine(x1, y1 + 1, x2, y2 + 1);

	// Dark groove
	p.setPen(QPen(QColor(25, 27, 29), 1));
	p.drawLine(x1, y1, x2, y2);
}

// ============================================================================
// CockpitKnob - Label + Display + QDial knob
// ============================================================================

CockpitKnob::CockpitKnob(const QString& label, double minVal, double maxVal, double val,
	const QString& tooltip, QWidget* parent)
	: QWidget(parent)
	, m_labelText(label)
	, m_min(minVal)
	, m_max(maxVal)
{
	setupUI(label, tooltip);
	setValue(val);
}

void CockpitKnob::setupUI(const QString& label, const QString& tooltip)
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(2, 12, 2, 8);  // Extra top margin for connecting line, more bottom margin
	layout->setSpacing(0);
	layout->setAlignment(Qt::AlignHCenter);

	// White label (store pointer for paintEvent)
	m_labelWidget = new QLabel(label.toUpper(), this);
	m_labelWidget->setAlignment(Qt::AlignHCenter);
	m_labelWidget->setFixedHeight(12);
	m_labelWidget->setStyleSheet("QLabel { color: white; font-size: 9px; font-weight: bold; padding: 0px; margin: 0px; }");
	layout->addWidget(m_labelWidget);

	// Digital display - Yellow on black (tight spacing to label above)
	m_display = new QLabel("0.00", this);
	m_display->setAlignment(Qt::AlignHCenter);
	m_display->setFixedSize(44, 18);
	m_display->setStyleSheet(
		"QLabel {"
		"  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;"
		"  font-size: 11px;"
		"  font-weight: bold;"
		"  color: #ffcc00;"
		"  background-color: #000000;"
		"  border: 1px solid #333333;"
		"  border-radius: 1px;"
		"  padding: 1px 2px;"
		"  margin: 0px;"
		"}"
	);
	layout->addWidget(m_display, 0, Qt::AlignHCenter);

	// Add spacing between display and dial
	layout->addSpacing(4);

	// QDial knob - the actual knob with dot indicator
	m_dial = new QDial(this);
	m_dial->setRange(0, 100);
	m_dial->setFixedSize(40, 40);
	m_dial->setNotchesVisible(false);
	m_dial->setWrapping(false);
	layout->addWidget(m_dial, 0, Qt::AlignHCenter);

	if (!tooltip.isEmpty())
		setToolTip(tooltip);

	connect(m_dial, &QDial::valueChanged, [this](int) {
		updateDisplay();
		emit valueChanged(value());
	});

	setFixedSize(54, 105);
}

void CockpitKnob::paintEvent(QPaintEvent* event)
{
	QWidget::paintEvent(event);

	QPainter p(this);
	p.setRenderHint(QPainter::Antialiasing);
	p.setPen(QPen(QColor(255, 255, 255), 1));
	p.setBrush(Qt::NoBrush);

	int w = width();
	int cx = w / 2;

	// Line from top down to just above the label
	QRect labelRect = m_labelWidget->geometry();
	p.drawLine(cx, 0, cx, labelRect.top() - 2);

	// Line from below the label down to the dial circle
	QRect dialRect = m_dial->geometry();
	int circleMargin = 3;
	int circleTop = dialRect.top() - circleMargin;
	p.drawLine(cx, labelRect.bottom() + 3, cx, circleTop);

	// Circle outline around the dial knob
	p.drawEllipse(dialRect.adjusted(-circleMargin, -circleMargin, circleMargin, circleMargin));
}

double CockpitKnob::value() const
{
	return m_min + (m_max - m_min) * m_dial->value() / 100.0;
}

void CockpitKnob::setValue(double val)
{
	val = qBound(m_min, val, m_max);
	int dialVal = static_cast<int>((val - m_min) / (m_max - m_min) * 100.0);
	m_dial->setValue(dialVal);
	updateDisplay();
}

void CockpitKnob::setRange(double min, double max)
{
	double oldVal = value();
	m_min = min;
	m_max = max;
	setValue(oldVal);
}

void CockpitKnob::updateDisplay()
{
	m_display->setText(QString::number(value(), 'f', 2));
}

// ============================================================================
// CockpitPushButton - Boeing 737 style illuminated push button
// ============================================================================

CockpitPushButton::CockpitPushButton(const QString& label, bool checked,
	const QString& tooltip, QWidget* parent)
	: QWidget(parent)
	, m_label(label.left(6).toUpper())  // Max 6 chars
	, m_checked(checked)
	, m_pressed(false)
{
	setFixedSize(48, 42);
	setCursor(Qt::PointingHandCursor);
	if (!tooltip.isEmpty())
		setToolTip(tooltip);
}

bool CockpitPushButton::isChecked() const
{
	return m_checked;
}

void CockpitPushButton::setChecked(bool checked)
{
	if (m_checked != checked)
	{
		m_checked = checked;
		update();
		emit toggled(m_checked);
	}
}

void CockpitPushButton::paintEvent(QPaintEvent* event)
{
	Q_UNUSED(event);
	QPainter p(this);
	p.setRenderHint(QPainter::Antialiasing);

	int w = width();
	int h = height();
	int margin = 2;

	// Button background - darker when pressed
	QRect btnRect(margin, margin, w - margin * 2, h - margin * 2);

	QLinearGradient btnGrad(btnRect.topLeft(), btnRect.bottomLeft());
	if (m_pressed)
	{
		btnGrad.setColorAt(0.0, QColor(25, 25, 25));
		btnGrad.setColorAt(1.0, QColor(35, 35, 35));
	}
	else
	{
		btnGrad.setColorAt(0.0, QColor(50, 52, 54));
		btnGrad.setColorAt(0.3, QColor(42, 44, 46));
		btnGrad.setColorAt(0.7, QColor(35, 37, 39));
		btnGrad.setColorAt(1.0, QColor(30, 32, 34));
	}
	p.setBrush(btnGrad);
	p.setPen(QPen(QColor(20, 20, 20), 1));
	p.drawRoundedRect(btnRect, 3, 3);

	// Inner bevel
	if (!m_pressed)
	{
		p.setPen(QPen(QColor(70, 72, 74), 1));
		p.drawLine(btnRect.left() + 2, btnRect.top() + 1,
				   btnRect.right() - 2, btnRect.top() + 1);
		p.drawLine(btnRect.left() + 1, btnRect.top() + 2,
				   btnRect.left() + 1, btnRect.bottom() - 2);
	}

	// White label text - centered horizontally and vertically
	QFont labelFont = font();
	labelFont.setPixelSize(10);
	labelFont.setBold(true);
	p.setFont(labelFont);
	p.setPen(QColor(255, 255, 255));  // White text
	// Center in the button area above the LED bar
	QRect textRect(0, margin, w, h - margin - 12);
	p.drawText(textRect, Qt::AlignHCenter | Qt::AlignVCenter, m_label);

	// LED indicator bar at bottom
	int ledY = h - margin - 9;
	int ledW = w - margin * 2 - 6;
	int ledH = 6;
	int ledX = margin + 3;

	// LED housing with inset effect
	p.setBrush(QColor(10, 10, 10));
	p.setPen(QPen(QColor(5, 5, 5), 1));
	p.drawRoundedRect(ledX, ledY, ledW, ledH, 2, 2);

	// LED light
	if (m_checked)
	{
		// Glow effect
		p.setPen(Qt::NoPen);
		p.setBrush(QColor(50, 255, 50, 60));
		p.drawRoundedRect(ledX - 2, ledY - 2, ledW + 4, ledH + 4, 3, 3);

		// LED bar
		QLinearGradient ledGrad(ledX, ledY, ledX, ledY + ledH);
		ledGrad.setColorAt(0.0, QColor(120, 255, 120));
		ledGrad.setColorAt(0.4, QColor(80, 240, 80));
		ledGrad.setColorAt(0.6, QColor(50, 220, 50));
		ledGrad.setColorAt(1.0, QColor(40, 200, 40));
		p.setBrush(ledGrad);
		p.drawRoundedRect(ledX + 1, ledY + 1, ledW - 2, ledH - 2, 1, 1);
	}
	else
	{
		// Dim off state
		p.setBrush(QColor(30, 40, 30));
		p.setPen(Qt::NoPen);
		p.drawRoundedRect(ledX + 1, ledY + 1, ledW - 2, ledH - 2, 1, 1);
	}
}

void CockpitPushButton::mousePressEvent(QMouseEvent* event)
{
	if (event->button() == Qt::LeftButton)
	{
		m_pressed = true;
		update();
	}
	QWidget::mousePressEvent(event);
}

void CockpitPushButton::mouseReleaseEvent(QMouseEvent* event)
{
	if (event->button() == Qt::LeftButton && m_pressed)
	{
		m_pressed = false;
		if (rect().contains(event->pos()))
		{
			setChecked(!m_checked);
		}
		update();
	}
	QWidget::mouseReleaseEvent(event);
}

// ============================================================================
// DetectorRowWidget - Boeing 737 style detector control module
// Layout: Push button on top, weight + threshold knobs below
// ============================================================================

DetectorRowWidget::DetectorRowWidget(const QString& name, double weight, double threshold,
	bool enabled, bool useKnobs, QWidget* parent)
	: QWidget(parent)
	, m_name(name)
	, m_useKnobs(useKnobs)
{
	setupUI(useKnobs);
	setEnabled(enabled);
	setWeight(weight);
	setThreshold(threshold);
}

void DetectorRowWidget::setupUI(bool useKnobs)
{
	Q_UNUSED(useKnobs);

	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(4, 4, 4, 4);
	mainLayout->setSpacing(4);
	mainLayout->setAlignment(Qt::AlignHCenter);

	// Push button at top - extract first word only, no punctuation
	QString btnLabel = m_name.split(QRegularExpression("[^A-Za-z0-9]")).first().left(6).toUpper();
	m_enableButton = new CockpitPushButton(btnLabel, true, m_name, this);
	connect(m_enableButton, &CockpitPushButton::toggled, this, &DetectorRowWidget::settingsChanged);
	mainLayout->addWidget(m_enableButton, 0, Qt::AlignHCenter);

	// Knobs row below button
	QHBoxLayout* knobsLayout = new QHBoxLayout();
	knobsLayout->setContentsMargins(0, 0, 0, 0);
	knobsLayout->setSpacing(2);

	// Weight knob
	m_weightKnob = new CockpitKnob("WGHT", 0.0, 3.0, 1.0,
		"Detection weight multiplier (0-3x)", this);
	connect(m_weightKnob, &CockpitKnob::valueChanged, this, &DetectorRowWidget::settingsChanged);
	knobsLayout->addWidget(m_weightKnob);

	// Threshold knob
	m_threshKnob = new CockpitKnob("THRS", 0.0, 1.0, 0.5,
		"Minimum confidence threshold (0-1)", this);
	connect(m_threshKnob, &CockpitKnob::valueChanged, this, &DetectorRowWidget::settingsChanged);
	knobsLayout->addWidget(m_threshKnob);

	mainLayout->addLayout(knobsLayout);

	setFixedSize(110, 135);
}

void DetectorRowWidget::paintEvent(QPaintEvent* event)
{
	QWidget::paintEvent(event);

	QPainter p(this);
	p.setRenderHint(QPainter::Antialiasing);

	// Draw white connecting lines from button to knobs
	if (m_enableButton && m_weightKnob && m_threshKnob)
	{
		int btnCx = m_enableButton->x() + m_enableButton->width() / 2;
		int btnBottom = m_enableButton->y() + m_enableButton->height();

		int weightCx = m_weightKnob->x() + m_weightKnob->width() / 2;
		int threshCx = m_threshKnob->x() + m_threshKnob->width() / 2;
		int knobsTop = m_weightKnob->y();

		// White connecting lines
		p.setPen(QPen(QColor(255, 255, 255), 1));

		// Vertical line from button down to junction
		int junctionY = btnBottom + (knobsTop - btnBottom) / 2;
		p.drawLine(btnCx, btnBottom + 2, btnCx, junctionY);

		// Horizontal line across to both knobs
		p.drawLine(weightCx, junctionY, threshCx, junctionY);

		// Vertical lines down to the top of each knob widget (connects to knob's internal lines)
		p.drawLine(weightCx, junctionY, weightCx, knobsTop);
		p.drawLine(threshCx, junctionY, threshCx, knobsTop);
	}
}

bool DetectorRowWidget::isEnabled() const
{
	return m_enableButton ? m_enableButton->isChecked() : true;
}

double DetectorRowWidget::weight() const
{
	return m_weightKnob ? m_weightKnob->value() : 1.0;
}

double DetectorRowWidget::threshold() const
{
	return m_threshKnob ? m_threshKnob->value() : 0.5;
}

void DetectorRowWidget::setEnabled(bool enabled)
{
	if (m_enableButton)
		m_enableButton->setChecked(enabled);
}

void DetectorRowWidget::setWeight(double w)
{
	if (m_weightKnob)
		m_weightKnob->setValue(w);
}

void DetectorRowWidget::setThreshold(double t)
{
	if (m_threshKnob)
		m_threshKnob->setValue(t);
}

void DetectorRowWidget::setUseKnobs(bool useKnobs)
{
	Q_UNUSED(useKnobs);  // Always cockpit style now
}

// ============================================================================
// DetectorSettingsWidget
// ============================================================================

DetectorSettingsWidget::DetectorSettingsWidget(QWidget* parent)
	: QWidget(parent)
{
	setupUI();
}

void DetectorSettingsWidget::setupUI()
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(2);

	// Preset selector
	QHBoxLayout* presetLayout = new QHBoxLayout();
	presetLayout->setContentsMargins(4, 2, 4, 2);
	presetLayout->addWidget(new QLabel("Preset:", this));

	m_presetCombo = new QComboBox(this);
	m_presetCombo->addItems({"Default", "Aggressive", "Conservative", "Prologue Only", "Call Targets Only", "Custom"});
	m_presetCombo->setMaximumWidth(140);
	connect(m_presetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &DetectorSettingsWidget::onPresetSelected);
	presetLayout->addWidget(m_presetCombo);
	presetLayout->addStretch();
	layout->addLayout(presetLayout);

	// Tab widget for settings categories
	m_tabs = new QTabWidget(this);
	m_tabs->setDocumentMode(true);
	layout->addWidget(m_tabs);
}

void DetectorSettingsWidget::createGlobalTab()
{
	QWidget* tab = new QWidget();
	QFormLayout* form = new QFormLayout(tab);
	form->setContentsMargins(8, 8, 8, 8);

	m_minScore = new QDoubleSpinBox(tab);
	m_minScore->setRange(0.0, 1.0);
	m_minScore->setSingleStep(0.05);
	m_minScore->setValue(0.40);
	m_minScore->setToolTip("Minimum confidence score required to include a candidate in results. Lower values find more functions but may include false positives.");
	connect(m_minScore, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
		this, &DetectorSettingsWidget::onSettingChanged);
	form->addRow("Minimum Score:", m_minScore);

	m_highConfScore = new QDoubleSpinBox(tab);
	m_highConfScore->setRange(0.0, 1.0);
	m_highConfScore->setSingleStep(0.05);
	m_highConfScore->setValue(0.80);
	m_highConfScore->setToolTip("Score threshold for high-confidence results. Candidates above this score are highlighted and auto-selected.");
	connect(m_highConfScore, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
		this, &DetectorSettingsWidget::onSettingChanged);
	form->addRow("High Confidence Score:", m_highConfScore);

	m_scanExecOnly = new QCheckBox(tab);
	m_scanExecOnly->setChecked(true);
	m_scanExecOnly->setToolTip("Only scan regions marked as executable. Disable to scan all memory regions including data sections.");
	connect(m_scanExecOnly, &QCheckBox::toggled, this, &DetectorSettingsWidget::onSettingChanged);
	form->addRow("Scan Executable Only:", m_scanExecOnly);

	m_respectExisting = new QCheckBox(tab);
	m_respectExisting->setChecked(true);
	m_respectExisting->setToolTip("Skip addresses that are already defined as functions. Disable to re-analyze existing function boundaries.");
	connect(m_respectExisting, &QCheckBox::toggled, this, &DetectorSettingsWidget::onSettingChanged);
	form->addRow("Respect Existing Functions:", m_respectExisting);

	m_detectArm = new QCheckBox(tab);
	m_detectArm->setChecked(true);
	m_detectArm->setToolTip("Detect 32-bit ARM mode functions (4-byte aligned instructions).");
	connect(m_detectArm, &QCheckBox::toggled, this, &DetectorSettingsWidget::onSettingChanged);
	form->addRow("Detect ARM Functions:", m_detectArm);

	m_detectThumb = new QCheckBox(tab);
	m_detectThumb->setChecked(true);
	m_detectThumb->setToolTip("Detect 16-bit Thumb mode functions (2-byte aligned instructions).");
	connect(m_detectThumb, &QCheckBox::toggled, this, &DetectorSettingsWidget::onSettingChanged);
	form->addRow("Detect Thumb Functions:", m_detectThumb);

	m_alignPref = new QComboBox(tab);
	m_alignPref->addItems({"2 bytes", "4 bytes", "8 bytes", "16 bytes"});
	m_alignPref->setCurrentIndex(1);
	m_alignPref->setToolTip("Expected function alignment. ARM functions are typically 4-byte aligned. Use 2 bytes for Thumb-only code or mixed ARM/Thumb binaries.");
	connect(m_alignPref, QOverload<int>::of(&QComboBox::currentIndexChanged),
		this, &DetectorSettingsWidget::onSettingChanged);
	form->addRow("Alignment Preference:", m_alignPref);

	m_tabs->addTab(tab, "Global");
}

void DetectorSettingsWidget::addGlobalTab()
{
	createGlobalTab();
}

void DetectorSettingsWidget::addTab(const QString& name,
	const std::vector<std::tuple<QString, double, double>>& detectors)
{
	QWidget* tab = new QWidget();
	QVBoxLayout* layout = new QVBoxLayout(tab);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(2);

	QScrollArea* scroll = new QScrollArea(tab);
	scroll->setWidgetResizable(true);
	scroll->setFrameShape(QFrame::NoFrame);

	// Wrap content in CockpitPanel with title and screws
	CockpitPanel* panel = new CockpitPanel();
	panel->setTitle(name);

	QVBoxLayout* rowsLayout = new QVBoxLayout();
	rowsLayout->setContentsMargins(0, 0, 0, 0);
	rowsLayout->setSpacing(8);
	rowsLayout->setAlignment(Qt::AlignTop | Qt::AlignHCenter);

	// 4 modules per row, each row centered
	const int columns = 4;
	int col = 0;
	QHBoxLayout* currentRow = nullptr;

	for (const auto& [detName, weight, thresh] : detectors)
	{
		if (col == 0)
		{
			currentRow = new QHBoxLayout();
			currentRow->setContentsMargins(0, 0, 0, 0);
			currentRow->setSpacing(8);
			currentRow->setAlignment(Qt::AlignCenter);
			rowsLayout->addLayout(currentRow);
		}

		DetectorRowWidget* rowWidget = new DetectorRowWidget(detName, weight, thresh, true, m_useKnobs, panel);
		connect(rowWidget, &DetectorRowWidget::settingsChanged, this, &DetectorSettingsWidget::onSettingChanged);
		currentRow->addWidget(rowWidget, 0, Qt::AlignTop);
		m_detectorRows[name][detName] = rowWidget;

		col++;
		if (col >= columns)
			col = 0;
	}

	rowsLayout->addStretch();
	static_cast<QVBoxLayout*>(panel->contentLayout())->addLayout(rowsLayout);
	scroll->setWidget(panel);
	layout->addWidget(scroll);

	m_tabs->addTab(tab, name);
}

void DetectorSettingsWidget::loadPreset(const QString& name)
{
	int idx = m_presetCombo->findText(name);
	if (idx >= 0)
		m_presetCombo->setCurrentIndex(idx);
}

QStringList DetectorSettingsWidget::availablePresets() const
{
	QStringList presets;
	for (int i = 0; i < m_presetCombo->count(); i++)
		presets << m_presetCombo->itemText(i);
	return presets;
}

QString DetectorSettingsWidget::currentPreset() const
{
	return m_presetCombo->currentText();
}

double DetectorSettingsWidget::minimumScore() const
{
	return m_minScore ? m_minScore->value() : 0.4;
}

double DetectorSettingsWidget::highConfidenceScore() const
{
	return m_highConfScore ? m_highConfScore->value() : 0.8;
}

bool DetectorSettingsWidget::scanExecutableOnly() const
{
	return m_scanExecOnly ? m_scanExecOnly->isChecked() : true;
}

bool DetectorSettingsWidget::respectExistingFunctions() const
{
	return m_respectExisting ? m_respectExisting->isChecked() : true;
}

bool DetectorSettingsWidget::detectArmFunctions() const
{
	return m_detectArm ? m_detectArm->isChecked() : true;
}

bool DetectorSettingsWidget::detectThumbFunctions() const
{
	return m_detectThumb ? m_detectThumb->isChecked() : true;
}

int DetectorSettingsWidget::alignmentPreference() const
{
	if (!m_alignPref) return 4;
	int idx = m_alignPref->currentIndex();
	return (idx == 0) ? 2 : (idx == 1) ? 4 : (idx == 2) ? 8 : 16;
}

bool DetectorSettingsWidget::isDetectorEnabled(const QString& tab, const QString& detector) const
{
	auto tabIt = m_detectorRows.find(tab);
	if (tabIt == m_detectorRows.end()) return false;
	auto detIt = tabIt->second.find(detector);
	if (detIt == tabIt->second.end()) return false;
	return detIt->second->isEnabled();
}

double DetectorSettingsWidget::detectorWeight(const QString& tab, const QString& detector) const
{
	auto tabIt = m_detectorRows.find(tab);
	if (tabIt == m_detectorRows.end()) return 1.0;
	auto detIt = tabIt->second.find(detector);
	if (detIt == tabIt->second.end()) return 1.0;
	return detIt->second->weight();
}

double DetectorSettingsWidget::detectorThreshold(const QString& tab, const QString& detector) const
{
	auto tabIt = m_detectorRows.find(tab);
	if (tabIt == m_detectorRows.end()) return 0.5;
	auto detIt = tabIt->second.find(detector);
	if (detIt == tabIt->second.end()) return 0.5;
	return detIt->second->threshold();
}

void DetectorSettingsWidget::setUseKnobs(bool useKnobs)
{
	m_useKnobs = useKnobs;
	for (auto& [tabName, detectors] : m_detectorRows)
		for (auto& [detName, row] : detectors)
			row->setUseKnobs(useKnobs);
}

void DetectorSettingsWidget::onPresetSelected(int index)
{
	QString preset = m_presetCombo->itemText(index);
	emit presetChanged(preset);
	// TODO: Apply preset values
}

void DetectorSettingsWidget::onSettingChanged()
{
	m_presetCombo->setCurrentIndex(m_presetCombo->count() - 1);  // "Custom"
	emit settingsChanged();
}

// ============================================================================
// HighlightingItemDelegate - Highlight search matches in tree cells
// ============================================================================

HighlightingItemDelegate::HighlightingItemDelegate(QObject* parent)
	: QStyledItemDelegate(parent)
	, m_highlightColor(getThemeColor(YellowStandardHighlightColor))
{
}

void HighlightingItemDelegate::setSearchTerm(const QString& term)
{
	m_searchTerm = term;
}

void HighlightingItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
	const QModelIndex& index) const
{
	// If no search term or column 0 (checkbox), use default painting
	if (m_searchTerm.isEmpty() || index.column() == 0)
	{
		QStyledItemDelegate::paint(painter, option, index);
		return;
	}

	QString text = index.data(Qt::DisplayRole).toString();
	int matchIndex = text.indexOf(m_searchTerm, 0, Qt::CaseInsensitive);

	if (matchIndex < 0)
	{
		QStyledItemDelegate::paint(painter, option, index);
		return;
	}

	// Draw background
	QStyleOptionViewItem opt = option;
	initStyleOption(&opt, index);

	painter->save();

	// Draw selection/hover background
	if (opt.state & QStyle::State_Selected)
		painter->fillRect(opt.rect, opt.palette.highlight());
	else if (opt.state & QStyle::State_MouseOver)
		painter->fillRect(opt.rect, opt.palette.alternateBase());

	// Draw text with highlighting
	QRect textRect = opt.rect.adjusted(4, 0, -4, 0);
	QFontMetrics fm(opt.font);

	QString before = text.left(matchIndex);
	QString match = text.mid(matchIndex, m_searchTerm.length());
	QString after = text.mid(matchIndex + m_searchTerm.length());

	int xPos = textRect.left();

	// Draw before match
	if (!before.isEmpty())
	{
		painter->setPen(opt.palette.text().color());
		painter->drawText(xPos, textRect.top(), fm.horizontalAdvance(before), textRect.height(),
			Qt::AlignVCenter, before);
		xPos += fm.horizontalAdvance(before);
	}

	// Draw match with highlight
	if (!match.isEmpty())
	{
		int matchWidth = fm.horizontalAdvance(match);
		painter->fillRect(xPos, textRect.top() + 2, matchWidth, textRect.height() - 4,
			m_highlightColor);
		painter->setPen(Qt::black);
		painter->drawText(xPos, textRect.top(), matchWidth, textRect.height(),
			Qt::AlignVCenter, match);
		xPos += matchWidth;
	}

	// Draw after match
	if (!after.isEmpty())
	{
		painter->setPen(opt.palette.text().color());
		painter->drawText(xPos, textRect.top(), textRect.right() - xPos, textRect.height(),
			Qt::AlignVCenter, after);
	}

	painter->restore();
}

// ============================================================================
// ColumnSettings - Persist column widths and sort order
// ============================================================================

ColumnSettings& ColumnSettings::instance()
{
	static ColumnSettings inst;
	return inst;
}

void ColumnSettings::saveColumnWidths(const QString& widgetId, const QHeaderView* header)
{
	if (!header) return;

	QStringList widths;
	for (int i = 0; i < header->count(); i++)
		widths << QString::number(header->sectionSize(i));

	m_settings.setValue(widgetId + "/columnWidths", widths.join(","));
}

void ColumnSettings::restoreColumnWidths(const QString& widgetId, QHeaderView* header)
{
	if (!header) return;

	QString saved = m_settings.value(widgetId + "/columnWidths").toString();
	if (saved.isEmpty()) return;

	QStringList widths = saved.split(",");
	for (int i = 0; i < qMin(widths.size(), header->count()); i++)
	{
		bool ok;
		int w = widths[i].toInt(&ok);
		if (ok && w > 0)
			header->resizeSection(i, w);
	}
}

void ColumnSettings::saveSortColumn(const QString& widgetId, int column, Qt::SortOrder order)
{
	m_settings.setValue(widgetId + "/sortColumn", column);
	m_settings.setValue(widgetId + "/sortOrder", static_cast<int>(order));
}

std::pair<int, Qt::SortOrder> ColumnSettings::loadSortColumn(const QString& widgetId)
{
	int col = m_settings.value(widgetId + "/sortColumn", -1).toInt();
	int order = m_settings.value(widgetId + "/sortOrder", 0).toInt();
	return {col, static_cast<Qt::SortOrder>(order)};
}

// ============================================================================
// ContextMenuHelper - Build context menus for tree views
// ============================================================================

ContextMenuHelper::ContextMenuHelper(QTreeView* treeView, TreeResultsModel* model,
	QWidget* parent)
	: QObject(parent)
	, m_treeView(treeView)
	, m_model(model)
{
	if (treeView)
	{
		treeView->setContextMenuPolicy(Qt::CustomContextMenu);
		connect(treeView, &QTreeView::customContextMenuRequested,
			this, &ContextMenuHelper::showContextMenu);
	}
}

void ContextMenuHelper::setNavigationCallback(std::function<void(uint64_t)> callback)
{
	m_navigateCallback = callback;
}

void ContextMenuHelper::setCreateFunctionCallback(std::function<void(uint64_t, bool)> callback)
{
	m_createFunctionCallback = callback;
}

void ContextMenuHelper::setApplyCallback(std::function<void()> callback)
{
	m_applyCallback = callback;
}

void ContextMenuHelper::showContextMenu(const QPoint& pos)
{
	if (!m_treeView || !m_model) return;

	QModelIndex index = m_treeView->indexAt(pos);
	QMenu menu(m_treeView);

	// Selection actions
	QAction* selectAllAction = menu.addAction("Select All");
	connect(selectAllAction, &QAction::triggered, m_model, &TreeResultsModel::selectAll);

	QAction* selectNoneAction = menu.addAction("Select None");
	connect(selectNoneAction, &QAction::triggered, m_model, &TreeResultsModel::selectNone);

	QAction* invertAction = menu.addAction("Invert Selection");
	connect(invertAction, &QAction::triggered, m_model, &TreeResultsModel::invertSelection);

	menu.addSeparator();

	// Copy actions
	QAction* copyAddrAction = menu.addAction("Copy Address(es)");
	connect(copyAddrAction, &QAction::triggered, this, &ContextMenuHelper::copyAddresses);

	QAction* copyDataAction = menu.addAction("Copy Row Data");
	connect(copyDataAction, &QAction::triggered, this, &ContextMenuHelper::copyRowData);

	if (index.isValid())
	{
		menu.addSeparator();

		// Navigation
		QAction* navAction = menu.addAction("Navigate to Address");
		connect(navAction, &QAction::triggered, [this, index]() {
			uint64_t addr = m_model->itemAddress(index.row());
			if (m_navigateCallback)
				m_navigateCallback(addr);
			emit navigateRequested(addr);
		});

		// Create function
		if (m_createFunctionCallback)
		{
			QAction* createAction = menu.addAction("Create Function Here");
			connect(createAction, &QAction::triggered, [this, index]() {
				uint64_t addr = m_model->itemAddress(index.row());
				// TODO: Determine if Thumb from model data
				m_createFunctionCallback(addr, false);
				emit createFunctionRequested(addr, false);
			});
		}
	}

	// Apply action
	if (m_applyCallback && m_model->selectedCount() > 0)
	{
		menu.addSeparator();
		QAction* applyAction = menu.addAction(QString("Apply Selected (%1)")
			.arg(m_model->selectedCount()));
		connect(applyAction, &QAction::triggered, [this]() {
			if (m_applyCallback) m_applyCallback();
			emit applyRequested();
		});
	}

	menu.exec(m_treeView->viewport()->mapToGlobal(pos));
}

void ContextMenuHelper::copyAddresses()
{
	if (!m_model) return;

	auto addresses = m_model->getSelectedAddresses();
	if (addresses.empty()) return;

	QStringList lines;
	for (uint64_t addr : addresses)
		lines << QString("0x%1").arg(addr, 8, 16, QChar('0'));

	QApplication::clipboard()->setText(lines.join("\n"));
}

void ContextMenuHelper::copyRowData()
{
	if (!m_treeView || !m_model) return;

	QStringList lines;
	for (int row = 0; row < m_model->itemCount(); row++)
	{
		if (!m_model->isItemSelected(row)) continue;

		QStringList cols;
		for (int col = 0; col < m_model->columnCount(); col++)
		{
			QModelIndex idx = m_model->index(row, col);
			cols << idx.data(Qt::DisplayRole).toString();
		}
		lines << cols.join("\t");
	}

	QApplication::clipboard()->setText(lines.join("\n"));
}

// ============================================================================
// KeyboardShortcutMixin
// ============================================================================

void KeyboardShortcutMixin::setupStandardShortcuts(QWidget* widget, TreeResultsModel* model,
	std::function<void()> copyCallback)
{
	// Cmd+A: Select all
	m_selectAllShortcut = new QShortcut(QKeySequence::SelectAll, widget);
	QObject::connect(m_selectAllShortcut, &QShortcut::activated, [model]() {
		if (model) model->selectAll();
	});

	// Cmd+I: Invert selection
	m_invertShortcut = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_I), widget);
	QObject::connect(m_invertShortcut, &QShortcut::activated, [model]() {
		if (model) model->invertSelection();
	});

	// Cmd+C: Copy selected
	m_copyShortcut = new QShortcut(QKeySequence::Copy, widget);
	QObject::connect(m_copyShortcut, &QShortcut::activated, [copyCallback]() {
		if (copyCallback) copyCallback();
	});
}

void KeyboardShortcutMixin::setupTreeShortcuts(QWidget* widget, QTreeView* treeView,
	TreeResultsModel* model, std::function<void(uint64_t)> navigateCallback)
{
	// Enter/Return: Navigate to selected item
	m_enterShortcut = new QShortcut(QKeySequence(Qt::Key_Return), widget);
	QObject::connect(m_enterShortcut, &QShortcut::activated, [treeView, model, navigateCallback]() {
		if (!treeView || !model) return;
		QModelIndex current = treeView->currentIndex();
		if (current.isValid() && current.internalId() == 0)
		{
			uint64_t addr = model->itemAddress(current.row());
			if (navigateCallback) navigateCallback(addr);
		}
	});

	// Space: Toggle selection on current item
	m_spaceShortcut = new QShortcut(QKeySequence(Qt::Key_Space), widget);
	QObject::connect(m_spaceShortcut, &QShortcut::activated, [treeView, model]() {
		if (!treeView || !model) return;
		QModelIndex current = treeView->currentIndex();
		if (current.isValid() && current.internalId() == 0)
		{
			bool selected = model->isItemSelected(current.row());
			model->setItemSelected(current.row(), !selected);
		}
	});

	// Escape: Clear selection
	m_escapeShortcut = new QShortcut(QKeySequence(Qt::Key_Escape), widget);
	QObject::connect(m_escapeShortcut, &QShortcut::activated, [model]() {
		if (model) model->selectNone();
	});
}

// ============================================================================
// AnalysisTabBase
// ============================================================================

AnalysisTabBase::AnalysisTabBase(QWidget* parent)
	: QWidget(parent)
{
}

void AnalysisTabBase::setBinaryView(BinaryViewRef data)
{
	m_data = data;
	if (m_preview)
		m_preview->setBinaryView(data);
}

QWidget* AnalysisTabBase::createControlBar()
{
	m_controlBar = new AnalysisControlBar(this);
	return m_controlBar;
}

QWidget* AnalysisTabBase::createPreview()
{
	m_preview = new ContextPreview(this);
	return m_preview;
}

QWidget* AnalysisTabBase::createStatusBar()
{
	m_statusBar = new AnalysisStatusBar(this);
	return m_statusBar;
}

void AnalysisTabBase::setupStandardLayout()
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Settings widget (if any)
	QWidget* settings = createSettingsWidget();
	if (settings)
		layout->addWidget(settings);

	// Control bar
	QWidget* controlBar = createControlBar();
	if (controlBar)
		layout->addWidget(controlBar);

	// Filter bar (if any)
	QWidget* filterBar = createFilterBar();
	if (filterBar)
	{
		m_filterBar = qobject_cast<FilterBar*>(filterBar);
		layout->addWidget(filterBar);
	}

	// Splitter for results + preview
	QSplitter* splitter = new QSplitter(Qt::Vertical, this);
	splitter->setChildrenCollapsible(false);

	// Results view - minimum height for ~3 rows (header + 3 rows @ ~24px each)
	QWidget* results = createResultsView();
	if (results)
	{
		results->setMinimumHeight(100);  // Header + 3 rows minimum
		splitter->addWidget(results);
	}

	// Preview - expandable, no max height limit
	QWidget* preview = createPreview();
	if (preview)
	{
		preview->setMinimumHeight(60);
		// No max height - allow preview to expand by dragging splitter
		splitter->addWidget(preview);
	}

	// Initial sizes: give more space to results, but preview is resizable
	splitter->setStretchFactor(0, 2);
	splitter->setStretchFactor(1, 1);
	splitter->setSizes({400, 150});  // Initial sizes
	layout->addWidget(splitter, 1);

	// Status bar
	QWidget* statusBar = createStatusBar();
	if (statusBar)
		layout->addWidget(statusBar);
}

void AnalysisTabBase::navigateToAddress(uint64_t address)
{
	emit addressSelected(address);
	if (auto* frame = ViewFrame::viewFrameForWidget(this))
	{
		if (m_data && m_data->GetDefaultArchitecture())
		{
			frame->navigate("Linear:" + QString::fromStdString(
				m_data->GetDefaultArchitecture()->GetName()), address);
		}
	}
}

}  // namespace Armv5UI
