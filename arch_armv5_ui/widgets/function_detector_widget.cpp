/*
 * Advanced Analysis Widget - Implementation
 */

#include "function_detector_widget.h"
#include "binaryninjaapi.h"
#include "theme.h"
#include "fontsettings.h"
#include "viewframe.h"
#include "analysis/function_detector.h"
#include "analysis/string_detector.h"
#include "analysis/structure_detector.h"
#include "analysis/crypto_detector.h"
#include "analysis/entropy_analyzer.h"

#include <QtWidgets/QHeaderView>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QApplication>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QStyle>
#include <QtGui/QTextCursor>

using namespace BinaryNinja;

namespace Armv5UI
{

// LabeledDial removed - using CockpitKnob from analysis_widgets.h instead

// ============================================================================
// CollapsibleGroup
// ============================================================================

CollapsibleGroup::CollapsibleGroup(const QString& title, QWidget* parent)
	: QWidget(parent), m_content(nullptr), m_collapsed(false)
{
	QVBoxLayout* lay = new QVBoxLayout(this);
	lay->setContentsMargins(0, 0, 0, 0);
	lay->setSpacing(0);
	
	m_toggleBtn = new QToolButton();
	m_toggleBtn->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
	m_toggleBtn->setArrowType(Qt::DownArrow);
	m_toggleBtn->setText(title);
	m_toggleBtn->setCheckable(true);
	m_toggleBtn->setStyleSheet("QToolButton { border: none; font-weight: bold; }");
	lay->addWidget(m_toggleBtn);
	
	connect(m_toggleBtn, &QToolButton::clicked, this, &CollapsibleGroup::toggleCollapsed);
}

void CollapsibleGroup::setContent(QWidget* content) {
	m_content = content;
	static_cast<QVBoxLayout*>(layout())->addWidget(content);
}

void CollapsibleGroup::setCollapsed(bool collapsed) {
	m_collapsed = collapsed;
	m_toggleBtn->setArrowType(collapsed ? Qt::RightArrow : Qt::DownArrow);
	if (m_content) m_content->setVisible(!collapsed);
}

void CollapsibleGroup::toggleCollapsed() {
	setCollapsed(!m_collapsed);
}

// ============================================================================
// FunctionTableModel
// ============================================================================

FunctionTableModel::FunctionTableModel(QObject* parent) : QAbstractTableModel(parent) {}
int FunctionTableModel::rowCount(const QModelIndex&) const { return static_cast<int>(m_candidates.size()); }
int FunctionTableModel::columnCount(const QModelIndex&) const { return ColCount; }

QVariant FunctionTableModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid() || index.row() >= static_cast<int>(m_candidates.size())) return QVariant();
	const auto& c = m_candidates[index.row()];
	
	if (role == Qt::DisplayRole) {
		switch (index.column()) {
		case ColAddress: return QString("0x%1").arg(c.address, 8, 16, QChar('0'));
		case ColSize: return c.estimatedSize > 0 ? QString::number(c.estimatedSize) : "?";
		case ColScore: return QString::number(c.score, 'f', 2);
		case ColMode: return c.isThumb ? "T" : "A";
		case ColStatus: return c.isNew ? "New" : "Exists";
		case ColCalls: return c.callCount > 0 ? QString::number(c.callCount) : "-";
		case ColCallees: return c.calleeCount > 0 ? QString::number(c.calleeCount) : "-";
		case ColSources: { QStringList s; for (auto& src : c.sources) if (src.contribution > 0) s << src.name.left(8); return s.join(","); }
		default: return QVariant();
		}
	}
	else if (role == Qt::CheckStateRole && index.column() == ColSelect) return c.selected ? Qt::Checked : Qt::Unchecked;
	else if (role == Qt::ForegroundRole) {
		if (index.column() == ColScore) {
			if (c.score >= m_highScore) return getThemeColor(GreenStandardHighlightColor);
			if (c.score >= (m_minScore + m_highScore) / 2) return getThemeColor(YellowStandardHighlightColor);
			return getThemeColor(OrangeStandardHighlightColor);
		}
		if (index.column() == ColStatus) return c.isNew ? getThemeColor(GreenStandardHighlightColor) : getThemeColor(CommentColor);
		if (index.column() == ColCalls && c.callCount == 0) return getThemeColor(RedStandardHighlightColor);
	}
	else if (role == Qt::BackgroundRole && c.selected) return getThemeColor(SelectionColor);
	else if (role == Qt::TextAlignmentRole && (index.column() == ColSize || index.column() == ColScore || index.column() == ColCalls))
		return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
	else if (role == Qt::UserRole) return static_cast<qulonglong>(c.address);
	else if (role == Qt::UserRole + 1) return c.isNew;
	else if (role == Qt::UserRole + 2) return c.isThumb;
	else if (role == Qt::UserRole + 3) return c.score;
	return QVariant();
}

bool FunctionTableModel::setData(const QModelIndex& index, const QVariant& value, int role)
{
	if (!index.isValid() || index.column() != ColSelect || role != Qt::CheckStateRole) return false;
	m_candidates[index.row()].selected = (value.toInt() == Qt::Checked);
	emit dataChanged(index, index, {Qt::CheckStateRole, Qt::BackgroundRole});
	return true;
}

Qt::ItemFlags FunctionTableModel::flags(const QModelIndex& index) const {
	Qt::ItemFlags f = QAbstractTableModel::flags(index);
	if (index.column() == ColSelect) f |= Qt::ItemIsUserCheckable;
	return f;
}

QVariant FunctionTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
	if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return QVariant();
	const char* h[] = {"", "Address", "Size", "Score", "M", "Status", "Refs", "Calls", "Sources"};
	return section < ColCount ? h[section] : QVariant();
}

void FunctionTableModel::setCandidates(const std::vector<FunctionCandidateUI>& c) { beginResetModel(); m_candidates = c; endResetModel(); }
void FunctionTableModel::setThresholds(double min, double high) { m_minScore = min; m_highScore = high; }
std::vector<FunctionCandidateUI> FunctionTableModel::getSelectedCandidates() const { std::vector<FunctionCandidateUI> r; for (auto& c : m_candidates) if (c.selected) r.push_back(c); return r; }
const FunctionCandidateUI* FunctionTableModel::getCandidateAt(int row) const { return row >= 0 && row < static_cast<int>(m_candidates.size()) ? &m_candidates[row] : nullptr; }
void FunctionTableModel::selectAll(bool s) { for (auto& c : m_candidates) c.selected = s; if (!m_candidates.empty()) emit dataChanged(index(0,0), index(m_candidates.size()-1, ColCount-1)); }
void FunctionTableModel::selectNewOnly() { for (auto& c : m_candidates) c.selected = c.isNew; if (!m_candidates.empty()) emit dataChanged(index(0,0), index(m_candidates.size()-1, ColCount-1)); }
void FunctionTableModel::selectByScore(double min) { for (auto& c : m_candidates) c.selected = c.isNew && c.score >= min; if (!m_candidates.empty()) emit dataChanged(index(0,0), index(m_candidates.size()-1, ColCount-1)); }

// ============================================================================
// FunctionFilterProxy
// ============================================================================

FunctionFilterProxy::FunctionFilterProxy(QObject* parent) : QSortFilterProxyModel(parent) {}
void FunctionFilterProxy::setFilters(double minScore, bool newOnly, int mode, const QString& search) {
	m_minScore = minScore; m_newOnly = newOnly; m_modeFilter = mode; m_searchText = search;
	beginResetModel(); endResetModel();
}
bool FunctionFilterProxy::filterAcceptsRow(int row, const QModelIndex& parent) const {
	auto* m = sourceModel();
	double score = m->data(m->index(row, FunctionTableModel::ColScore, parent), Qt::UserRole + 3).toDouble();
	if (score < m_minScore) return false;
	bool isNew = m->data(m->index(row, 0, parent), Qt::UserRole + 1).toBool();
	if (m_newOnly && !isNew) return false;
	bool isThumb = m->data(m->index(row, 0, parent), Qt::UserRole + 2).toBool();
	if (m_modeFilter == 1 && isThumb) return false;
	if (m_modeFilter == 2 && !isThumb) return false;
	if (!m_searchText.isEmpty()) {
		QString addr = m->data(m->index(row, FunctionTableModel::ColAddress, parent)).toString();
		if (!addr.contains(m_searchText, Qt::CaseInsensitive)) return false;
	}
	return true;
}

// ============================================================================
// StringTableModel
// ============================================================================

StringTableModel::StringTableModel(QObject* parent) : QAbstractTableModel(parent) {}
int StringTableModel::rowCount(const QModelIndex&) const { return static_cast<int>(m_candidates.size()); }
int StringTableModel::columnCount(const QModelIndex&) const { return ColCount; }

QVariant StringTableModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid() || index.row() >= static_cast<int>(m_candidates.size())) return QVariant();
	const auto& s = m_candidates[index.row()];
	
	if (role == Qt::DisplayRole) {
		switch (index.column()) {
		case ColAddress: return QString("0x%1").arg(s.address, 8, 16, QChar('0'));
		case ColLength: return QString::number(s.length);
		case ColDefined: return s.isNew ? "-" : QString::number(s.definedLength);
		case ColXrefs: return s.xrefCount > 0 ? QString::number(s.xrefCount) : "-";
		case ColEncoding: return s.encoding;
		case ColCategory: return s.category;
		case ColContent: return s.content.left(60) + (s.content.length() > 60 ? "..." : "");
		default: return QVariant();
		}
	}
	else if (role == Qt::CheckStateRole && index.column() == ColSelect) return s.selected ? Qt::Checked : Qt::Unchecked;
	else if (role == Qt::ForegroundRole) {
		if (index.column() == ColDefined && s.lengthMismatch) return getThemeColor(OrangeStandardHighlightColor);
		if (index.column() == ColCategory) {
			if (s.category == "Error") return getThemeColor(RedStandardHighlightColor);
			if (s.category == "URL" || s.category == "Path") return getThemeColor(CyanStandardHighlightColor);
		}
		if (!s.isNew) return getThemeColor(CommentColor);
	}
	else if (role == Qt::BackgroundRole && s.selected) return getThemeColor(SelectionColor);
	else if (role == Qt::UserRole) return static_cast<qulonglong>(s.address);
	else if (role == Qt::UserRole + 1) return s.isNew;
	else if (role == Qt::UserRole + 2) return s.category;
	else if (role == Qt::UserRole + 3) return s.lengthMismatch;
	else if (role == Qt::UserRole + 4) return s.content;
	return QVariant();
}

bool StringTableModel::setData(const QModelIndex& index, const QVariant& value, int role) {
	if (!index.isValid() || index.column() != ColSelect || role != Qt::CheckStateRole) return false;
	m_candidates[index.row()].selected = (value.toInt() == Qt::Checked);
	emit dataChanged(index, index, {Qt::CheckStateRole, Qt::BackgroundRole});
	return true;
}

Qt::ItemFlags StringTableModel::flags(const QModelIndex& index) const {
	Qt::ItemFlags f = QAbstractTableModel::flags(index);
	if (index.column() == ColSelect) f |= Qt::ItemIsUserCheckable;
	return f;
}

QVariant StringTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
	if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return QVariant();
	const char* h[] = {"", "Address", "Len", "Def", "Xrefs", "Enc", "Cat", "Content"};
	return section < ColCount ? h[section] : QVariant();
}

void StringTableModel::setCandidates(const std::vector<StringCandidateUI>& c) { beginResetModel(); m_candidates = c; endResetModel(); }
std::vector<StringCandidateUI> StringTableModel::getSelectedCandidates() const { std::vector<StringCandidateUI> r; for (auto& c : m_candidates) if (c.selected) r.push_back(c); return r; }
const StringCandidateUI* StringTableModel::getCandidateAt(int row) const { return row >= 0 && row < static_cast<int>(m_candidates.size()) ? &m_candidates[row] : nullptr; }
void StringTableModel::selectAll(bool s) { for (auto& c : m_candidates) c.selected = s; if (!m_candidates.empty()) emit dataChanged(index(0,0), index(m_candidates.size()-1, ColCount-1)); }

// ============================================================================
// StringFilterProxy
// ============================================================================

StringFilterProxy::StringFilterProxy(QObject* parent) : QSortFilterProxyModel(parent) {}
void StringFilterProxy::setFilters(const QString& search, const QString& category, int status, bool mismatch) {
	m_search = search; m_category = category; m_statusFilter = status; m_lengthMismatchOnly = mismatch;
	beginResetModel(); endResetModel();
}
bool StringFilterProxy::filterAcceptsRow(int row, const QModelIndex& parent) const {
	auto* m = sourceModel();
	bool isNew = m->data(m->index(row, 0, parent), Qt::UserRole + 1).toBool();
	if (m_statusFilter == 1 && !isNew) return false;
	if (m_statusFilter == 2 && isNew) return false;
	bool mismatch = m->data(m->index(row, 0, parent), Qt::UserRole + 3).toBool();
	if (m_lengthMismatchOnly && !mismatch) return false;
	if (!m_category.isEmpty() && m_category != "All") {
		QString cat = m->data(m->index(row, 0, parent), Qt::UserRole + 2).toString();
		if (cat != m_category) return false;
	}
	if (!m_search.isEmpty()) {
		QString content = m->data(m->index(row, 0, parent), Qt::UserRole + 4).toString();
		QString addr = m->data(m->index(row, StringTableModel::ColAddress, parent)).toString();
		if (!content.contains(m_search, Qt::CaseInsensitive) && !addr.contains(m_search, Qt::CaseInsensitive)) return false;
	}
	return true;
}

// ============================================================================
// StructureTableModel
// ============================================================================

StructureTableModel::StructureTableModel(QObject* parent) : QAbstractTableModel(parent) {}
int StructureTableModel::rowCount(const QModelIndex&) const { return static_cast<int>(m_candidates.size()); }
int StructureTableModel::columnCount(const QModelIndex&) const { return ColCount; }

QVariant StructureTableModel::data(const QModelIndex& index, int role) const {
	if (!index.isValid() || index.row() >= static_cast<int>(m_candidates.size())) return QVariant();
	const auto& s = m_candidates[index.row()];
	if (role == Qt::DisplayRole) {
		switch (index.column()) {
		case ColAddress: return QString("0x%1").arg(s.address, 8, 16, QChar('0'));
		case ColType: return s.type;
		case ColElements: return QString::number(s.elementCount);
		case ColSize: return QString::number(s.size);
		case ColFuncs: return s.functionsDiscovered > 0 ? QString::number(s.functionsDiscovered) : "-";
		case ColDescription: return s.description;
		default: return QVariant();
		}
	}
	else if (role == Qt::CheckStateRole && index.column() == ColSelect) return s.selected ? Qt::Checked : Qt::Unchecked;
	else if (role == Qt::ForegroundRole && index.column() == ColType) {
		if (s.type == "VTable") return getThemeColor(CyanStandardHighlightColor);
		if (s.type == "Jump Table") return getThemeColor(OrangeStandardHighlightColor);
	}
	else if (role == Qt::BackgroundRole && s.selected) return getThemeColor(SelectionColor);
	else if (role == Qt::UserRole) return static_cast<qulonglong>(s.address);
	return QVariant();
}

bool StructureTableModel::setData(const QModelIndex& index, const QVariant& value, int role) {
	if (!index.isValid() || index.column() != ColSelect || role != Qt::CheckStateRole) return false;
	m_candidates[index.row()].selected = (value.toInt() == Qt::Checked);
	emit dataChanged(index, index, {Qt::CheckStateRole, Qt::BackgroundRole});
	return true;
}

Qt::ItemFlags StructureTableModel::flags(const QModelIndex& index) const {
	Qt::ItemFlags f = QAbstractTableModel::flags(index);
	if (index.column() == ColSelect) f |= Qt::ItemIsUserCheckable;
	return f;
}

QVariant StructureTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
	if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return QVariant();
	const char* h[] = {"", "Address", "Type", "#", "Size", "Funcs", "Description"};
	return section < ColCount ? h[section] : QVariant();
}

void StructureTableModel::setCandidates(const std::vector<StructureCandidateUI>& c) { beginResetModel(); m_candidates = c; endResetModel(); }
std::vector<StructureCandidateUI> StructureTableModel::getSelectedCandidates() const { std::vector<StructureCandidateUI> r; for (auto& c : m_candidates) if (c.selected) r.push_back(c); return r; }
const StructureCandidateUI* StructureTableModel::getCandidateAt(int row) const { return row >= 0 && row < static_cast<int>(m_candidates.size()) ? &m_candidates[row] : nullptr; }
void StructureTableModel::selectAll(bool s) { for (auto& c : m_candidates) c.selected = s; if (!m_candidates.empty()) emit dataChanged(index(0,0), index(m_candidates.size()-1, ColCount-1)); }

// ============================================================================
// CryptoTableModel
// ============================================================================

CryptoTableModel::CryptoTableModel(QObject* parent) : QAbstractTableModel(parent) {}
int CryptoTableModel::rowCount(const QModelIndex&) const { return static_cast<int>(m_candidates.size()); }
int CryptoTableModel::columnCount(const QModelIndex&) const { return ColCount; }

QVariant CryptoTableModel::data(const QModelIndex& index, int role) const {
	if (!index.isValid() || index.row() >= static_cast<int>(m_candidates.size())) return QVariant();
	const auto& c = m_candidates[index.row()];
	if (role == Qt::DisplayRole) {
		switch (index.column()) {
		case ColAddress: return QString("0x%1").arg(c.address, 8, 16, QChar('0'));
		case ColAlgorithm: return c.algorithm;
		case ColType: return c.constType;
		case ColSize: return QString::number(c.size);
		case ColConf: return QString::number(c.confidence, 'f', 2);
		case ColXrefs: return c.xrefCount > 0 ? QString::number(c.xrefCount) : "-";
		case ColDescription: return c.description;
		default: return QVariant();
		}
	}
	else if (role == Qt::CheckStateRole && index.column() == ColSelect) return c.selected ? Qt::Checked : Qt::Unchecked;
	else if (role == Qt::ForegroundRole && index.column() == ColAlgorithm) {
		if (c.algorithm == "AES") return getThemeColor(GreenStandardHighlightColor);
		if (c.algorithm == "DES") return getThemeColor(OrangeStandardHighlightColor);
		if (c.algorithm.contains("SHA")) return getThemeColor(CyanStandardHighlightColor);
	}
	else if (role == Qt::UserRole) return static_cast<qulonglong>(c.address);
	else if (role == Qt::UserRole + 1) return static_cast<qulonglong>(c.size);
	else if (role == Qt::UserRole + 2) return c.algorithm;
	return QVariant();
}

bool CryptoTableModel::setData(const QModelIndex& index, const QVariant& value, int role) {
	if (!index.isValid() || index.column() != ColSelect || role != Qt::CheckStateRole) return false;
	m_candidates[index.row()].selected = (value.toInt() == Qt::Checked);
	emit dataChanged(index, index, {Qt::CheckStateRole});
	return true;
}

Qt::ItemFlags CryptoTableModel::flags(const QModelIndex& index) const {
	Qt::ItemFlags f = QAbstractTableModel::flags(index);
	if (index.column() == ColSelect) f |= Qt::ItemIsUserCheckable;
	return f;
}

QVariant CryptoTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
	if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return QVariant();
	const char* h[] = {"", "Address", "Algorithm", "Type", "Size", "Conf", "Xrefs", "Description"};
	return section < ColCount ? h[section] : QVariant();
}

void CryptoTableModel::setCandidates(const std::vector<CryptoCandidateUI>& c) { beginResetModel(); m_candidates = c; endResetModel(); }
const CryptoCandidateUI* CryptoTableModel::getCandidateAt(int row) const { return row >= 0 && row < static_cast<int>(m_candidates.size()) ? &m_candidates[row] : nullptr; }

// ============================================================================
// EntropyTableModel
// ============================================================================

EntropyTableModel::EntropyTableModel(QObject* parent) : QAbstractTableModel(parent) {}
int EntropyTableModel::rowCount(const QModelIndex&) const { return static_cast<int>(m_regions.size()); }
int EntropyTableModel::columnCount(const QModelIndex&) const { return ColCount; }

QVariant EntropyTableModel::data(const QModelIndex& index, int role) const {
	if (!index.isValid() || index.row() >= static_cast<int>(m_regions.size())) return QVariant();
	const auto& r = m_regions[index.row()];
	if (role == Qt::DisplayRole) {
		switch (index.column()) {
		case ColAddress: return QString("0x%1").arg(r.address, 8, 16, QChar('0'));
		case ColSize: return QString::number(r.size);
		case ColEntropy: return QString::number(r.entropy, 'f', 2);
		case ColType: return r.type;
		case ColDescription: return r.description;
		default: return QVariant();
		}
	}
	else if (role == Qt::ForegroundRole && index.column() == ColEntropy) {
		if (r.entropy >= 7.5) return getThemeColor(RedStandardHighlightColor);
		if (r.entropy >= 6.0) return getThemeColor(OrangeStandardHighlightColor);
		return getThemeColor(GreenStandardHighlightColor);
	}
	else if (role == Qt::ForegroundRole && index.column() == ColType) {
		if (r.type == "Encrypted") return getThemeColor(RedStandardHighlightColor);
		if (r.type == "Compressed") return getThemeColor(OrangeStandardHighlightColor);
	}
	else if (role == Qt::UserRole) return static_cast<qulonglong>(r.address);
	else if (role == Qt::UserRole + 1) return static_cast<qulonglong>(r.size);
	else if (role == Qt::UserRole + 2) return r.entropy;
	return QVariant();
}

QVariant EntropyTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
	if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return QVariant();
	const char* h[] = {"Address", "Size", "Entropy", "Type", "Description"};
	return section < ColCount ? h[section] : QVariant();
}

void EntropyTableModel::setRegions(const std::vector<EntropyRegionUI>& r) { beginResetModel(); m_regions = r; endResetModel(); }
const EntropyRegionUI* EntropyTableModel::getRegionAt(int row) const { return row >= 0 && row < static_cast<int>(m_regions.size()) ? &m_regions[row] : nullptr; }

// ============================================================================
// DisassemblyPreviewWidget
// ============================================================================

DisassemblyPreviewWidget::DisassemblyPreviewWidget(QWidget* parent) : QWidget(parent) {
	QVBoxLayout* lay = new QVBoxLayout(this);
	lay->setContentsMargins(0, 0, 0, 0);
	lay->setSpacing(2);
	m_headerLabel = new QLabel("Preview");
	lay->addWidget(m_headerLabel);
	m_textEdit = new QTextEdit();
	m_textEdit->setReadOnly(true);
	m_textEdit->setFont(getMonospaceFont(this));
	lay->addWidget(m_textEdit);
}

void DisassemblyPreviewWidget::setBinaryView(BinaryViewRef data) { m_data = data; }
QColor DisassemblyPreviewWidget::tokenColor(BNInstructionTextTokenType type) const { return getTokenColor(const_cast<DisassemblyPreviewWidget*>(this), type); }

void DisassemblyPreviewWidget::showAddress(uint64_t address, bool isThumb, int lineCount) {
	if (!m_data) return;
	m_headerLabel->setText(QString("Disassembly 0x%1 (%2)").arg(address, 8, 16, QChar('0')).arg(isThumb ? "Thumb" : "ARM"));
	Ref<Architecture> arch = m_data->GetDefaultArchitecture();
	if (!arch) return;
	if (isThumb) { uint64_t ta = address | 1; auto t = arch->GetAssociatedArchitectureByAddress(ta); if (t) arch = t; }
	m_textEdit->clear();
	QTextCursor cursor = m_textEdit->textCursor();
	uint64_t addr = address;
	for (int i = 0; i < lineCount; i++) {
		DataBuffer buf = m_data->ReadBuffer(addr, 4);
		if (buf.GetLength() < 2) break;
		InstructionInfo info;
		if (!arch->GetInstructionInfo(static_cast<const uint8_t*>(buf.GetData()), addr, buf.GetLength(), info)) break;
		std::vector<InstructionTextToken> tokens;
		if (!arch->GetInstructionText(static_cast<const uint8_t*>(buf.GetData()), addr, info.length, tokens)) break;
		QTextCharFormat af; af.setForeground(tokenColor(AddressDisplayToken));
		cursor.insertText(QString("0x%1  ").arg(addr, 8, 16, QChar('0')), af);
		for (const auto& tok : tokens) {
			QTextCharFormat tf; tf.setForeground(tokenColor(tok.type));
			cursor.insertText(QString::fromStdString(tok.text), tf);
		}
		cursor.insertText("\n");
		addr += info.length;
	}
}

void DisassemblyPreviewWidget::showString(uint64_t address, size_t length) {
	if (!m_data) return;
	m_headerLabel->setText(QString("String 0x%1 (%2 bytes)").arg(address, 8, 16, QChar('0')).arg(length));
	DataBuffer buf = m_data->ReadBuffer(address, std::min(length + 1, size_t(512)));
	QString content;
	for (size_t i = 0; i < buf.GetLength(); i++) {
		uint8_t c = static_cast<const uint8_t*>(buf.GetData())[i];
		if (c == 0) break;
		if (c >= 0x20 && c < 0x7F) content += QChar(c);
		else content += QString("\\x%1").arg(c, 2, 16, QChar('0'));
	}
	m_textEdit->setPlainText(content);
}

void DisassemblyPreviewWidget::showStructure(uint64_t address, size_t size) {
	if (!m_data) return;
	m_headerLabel->setText(QString("Structure 0x%1 (%2 bytes)").arg(address, 8, 16, QChar('0')).arg(size));
	m_textEdit->clear();
	QTextCursor cursor = m_textEdit->textCursor();
	for (size_t i = 0; i < std::min(size, size_t(64)); i += 4) {
		DataBuffer buf = m_data->ReadBuffer(address + i, 4);
		if (buf.GetLength() < 4) break;
		uint32_t val = *reinterpret_cast<const uint32_t*>(buf.GetData());
		QTextCharFormat af; af.setForeground(tokenColor(AddressDisplayToken));
		cursor.insertText(QString("[%1] ").arg(i, 3), af);
		QTextCharFormat vf; vf.setForeground(tokenColor(IntegerToken));
		cursor.insertText(QString("0x%1").arg(val, 8, 16, QChar('0')), vf);
		Ref<Symbol> sym = m_data->GetSymbolByAddress(val);
		if (sym) { QTextCharFormat sf; sf.setForeground(tokenColor(CodeSymbolToken)); cursor.insertText("  " + QString::fromStdString(sym->GetShortName()), sf); }
		cursor.insertText("\n");
	}
}

void DisassemblyPreviewWidget::showCryptoConstant(uint64_t address, size_t size, const QString& algorithm) {
	if (!m_data) return;
	m_headerLabel->setText(QString("%1 constant 0x%2").arg(algorithm).arg(address, 8, 16, QChar('0')));
	DataBuffer buf = m_data->ReadBuffer(address, std::min(size, size_t(128)));
	QString hex;
	for (size_t i = 0; i < buf.GetLength(); i++) {
		if (i > 0 && i % 16 == 0) hex += "\n";
		else if (i > 0 && i % 4 == 0) hex += " ";
		hex += QString("%1").arg(static_cast<const uint8_t*>(buf.GetData())[i], 2, 16, QChar('0'));
	}
	m_textEdit->setPlainText(hex);
}

void DisassemblyPreviewWidget::showEntropyRegion(uint64_t address, size_t size, double entropy) {
	m_headerLabel->setText(QString("Entropy %.2f at 0x%1 (%2 bytes)").arg(address, 8, 16, QChar('0')).arg(size).arg(entropy));
	showStructure(address, size);
}

void DisassemblyPreviewWidget::clear() { m_textEdit->clear(); m_headerLabel->setText("Preview"); }

// ============================================================================
// FunctionDetectorWidget - Main Widget
// ============================================================================

FunctionDetectorWidget::FunctionDetectorWidget(QWidget* parent) : QWidget(parent), m_data(nullptr) { setupUI(); }

void FunctionDetectorWidget::setupUI() {
	QVBoxLayout* main = new QVBoxLayout(this);
	main->setContentsMargins(2, 2, 2, 2);
	main->setSpacing(2);
	
	m_toolbar = createToolbar();
	main->addWidget(m_toolbar);
	
	QSplitter* splitter = new QSplitter(Qt::Vertical);
	m_mainTabs = new QTabWidget();
	m_mainTabs->addTab(createFunctionsTab(), "Functions");
	m_mainTabs->addTab(createStringsTab(), "Strings");
	m_mainTabs->addTab(createStructuresTab(), "Structures");
	m_mainTabs->addTab(createCryptoTab(), "Crypto");
	m_mainTabs->addTab(createEntropyTab(), "Entropy");
	splitter->addWidget(m_mainTabs);
	
	m_preview = new DisassemblyPreviewWidget();
	m_preview->setMinimumHeight(80);
	m_preview->setMaximumHeight(140);
	splitter->addWidget(m_preview);
	splitter->setStretchFactor(0, 3);
	splitter->setStretchFactor(1, 1);
	main->addWidget(splitter);
}

QToolBar* FunctionDetectorWidget::createToolbar() {
	QToolBar* tb = new QToolBar();
	tb->setIconSize(QSize(16, 16));
	
	auto* runAll = tb->addAction(style()->standardIcon(QStyle::SP_MediaPlay), "");
	runAll->setToolTip("Run All Detection");
	connect(runAll, &QAction::triggered, this, &FunctionDetectorWidget::onRunAll);
	
	tb->addSeparator();
	
	auto* exp = tb->addAction(style()->standardIcon(QStyle::SP_DialogSaveButton), "");
	exp->setToolTip("Export Results");
	connect(exp, &QAction::triggered, this, &FunctionDetectorWidget::onExportResults);
	
	return tb;
}

QWidget* FunctionDetectorWidget::createFunctionsTab() {
	QWidget* tab = new QWidget();
	QVBoxLayout* lay = new QVBoxLayout(tab);
	lay->setSpacing(4);
	
	// Options row with dials
	QHBoxLayout* opts = new QHBoxLayout();
	m_presetCombo = new QComboBox();
	m_presetCombo->addItems({"Default", "Aggressive", "Conservative"});
	m_presetCombo->setMaximumWidth(100);
	opts->addWidget(m_presetCombo);
	
	m_minScoreDial = new CockpitKnob("Min", 0.0, 1.0, 0.4, "Minimum score threshold");
	m_highScoreDial = new CockpitKnob("High", 0.0, 1.0, 0.8, "High confidence threshold");
	opts->addWidget(m_minScoreDial);
	opts->addWidget(m_highScoreDial);
	
	m_detectArm = new QCheckBox("ARM"); m_detectArm->setChecked(true);
	m_detectArm->setToolTip("Detect 32-bit ARM mode functions (4-byte aligned)");
	m_detectThumb = new QCheckBox("Thumb"); m_detectThumb->setChecked(true);
	m_detectThumb->setToolTip("Detect 16-bit Thumb mode functions (2-byte aligned)");
	opts->addWidget(m_detectArm);
	opts->addWidget(m_detectThumb);
	opts->addStretch();
	
	m_detectFuncBtn = new QPushButton("Detect");
	m_detectFuncBtn->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
	opts->addWidget(m_detectFuncBtn);
	lay->addLayout(opts);
	
	// Stats
	m_funcStats = new QLabel("Ready");
	lay->addWidget(m_funcStats);
	
	// Filter row
	QHBoxLayout* filt = new QHBoxLayout();
	m_funcSearch = new QLineEdit();
	m_funcSearch->setPlaceholderText("Search...");
	m_funcSearch->setMaximumWidth(120);
	filt->addWidget(m_funcSearch);
	
	m_funcFilterScore = new QDoubleSpinBox();
	m_funcFilterScore->setRange(0, 1);
	m_funcFilterScore->setSingleStep(0.1);
	m_funcFilterScore->setPrefix(">= ");
	m_funcFilterScore->setMaximumWidth(70);
	filt->addWidget(m_funcFilterScore);
	
	m_funcFilterNew = new QCheckBox("New");
	m_funcFilterNew->setToolTip("Show only newly detected functions (not already defined)");
	filt->addWidget(m_funcFilterNew);
	
	m_funcFilterMode = new QComboBox();
	m_funcFilterMode->addItems({"All", "ARM", "Thumb"});
	m_funcFilterMode->setMaximumWidth(60);
	filt->addWidget(m_funcFilterMode);
	filt->addStretch();
	
	m_applyFuncBtn = new QPushButton("Apply");
	m_applyFuncBtn->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
	m_applyFuncBtn->setEnabled(false);
	filt->addWidget(m_applyFuncBtn);
	lay->addLayout(filt);
	
	// Table
	m_funcTable = new QTableView();
	m_funcTable->setAlternatingRowColors(true);
	m_funcTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_funcTable->setSortingEnabled(true);
	m_funcTable->verticalHeader()->hide();
	m_funcTable->verticalHeader()->setDefaultSectionSize(20);
	m_funcModel = new FunctionTableModel(this);
	m_funcProxy = new FunctionFilterProxy(this);
	m_funcProxy->setSourceModel(m_funcModel);
	m_funcTable->setModel(m_funcProxy);
	m_funcTable->setColumnWidth(0, 24);
	m_funcTable->setColumnWidth(1, 75);
	m_funcTable->horizontalHeader()->setStretchLastSection(true);
	lay->addWidget(m_funcTable, 1);
	
	connect(m_detectFuncBtn, &QPushButton::clicked, this, &FunctionDetectorWidget::onDetectFunctions);
	connect(m_applyFuncBtn, &QPushButton::clicked, this, &FunctionDetectorWidget::onApplyFunctions);
	connect(m_funcTable, &QTableView::clicked, this, &FunctionDetectorWidget::onFunctionClicked);
	connect(m_funcTable, &QTableView::doubleClicked, this, &FunctionDetectorWidget::onFunctionDoubleClicked);
	connect(m_funcSearch, &QLineEdit::textChanged, this, &FunctionDetectorWidget::onFunctionFilterChanged);
	connect(m_funcFilterScore, QOverload<double>::of(&QDoubleSpinBox::valueChanged), this, &FunctionDetectorWidget::onFunctionFilterChanged);
	connect(m_funcFilterNew, &QCheckBox::toggled, this, &FunctionDetectorWidget::onFunctionFilterChanged);
	connect(m_funcFilterMode, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &FunctionDetectorWidget::onFunctionFilterChanged);
	
	return tab;
}

QWidget* FunctionDetectorWidget::createStringsTab() {
	QWidget* tab = new QWidget();
	QVBoxLayout* lay = new QVBoxLayout(tab);
	lay->setSpacing(4);
	
	// Options
	QHBoxLayout* opts = new QHBoxLayout();
	m_strAscii = new QCheckBox("ASCII"); m_strAscii->setChecked(true);
	m_strAscii->setToolTip("Detect ASCII (single-byte) strings");
	m_strUtf16 = new QCheckBox("UTF-16"); m_strUtf16->setChecked(true);
	m_strUtf16->setToolTip("Detect UTF-16 (wide character) strings");
	m_strUnreferenced = new QCheckBox("Unreferenced"); m_strUnreferenced->setChecked(true);
	m_strUnreferenced->setToolTip("Find strings without cross-references");
	opts->addWidget(m_strAscii);
	opts->addWidget(m_strUtf16);
	opts->addWidget(m_strUnreferenced);
	opts->addWidget(new QLabel("Min:"));
	m_strMinLen = new QSpinBox(); m_strMinLen->setRange(2, 100); m_strMinLen->setValue(4); m_strMinLen->setMaximumWidth(50);
	opts->addWidget(m_strMinLen);
	opts->addStretch();
	m_detectStrBtn = new QPushButton("Detect");
	m_detectStrBtn->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
	opts->addWidget(m_detectStrBtn);
	lay->addLayout(opts);
	
	m_strStats = new QLabel("Ready");
	lay->addWidget(m_strStats);
	
	// Filter row
	QHBoxLayout* filt = new QHBoxLayout();
	m_strSearch = new QLineEdit();
	m_strSearch->setPlaceholderText("Search...");
	m_strSearch->setMaximumWidth(120);
	filt->addWidget(m_strSearch);
	
	m_strFilterCategory = new QComboBox();
	m_strFilterCategory->addItems({"All", "Error", "Debug", "Path", "URL", "Version", "Format", "Crypto", "Hardware", "RTOS"});
	m_strFilterCategory->setMaximumWidth(80);
	filt->addWidget(m_strFilterCategory);
	
	m_strFilterStatus = new QComboBox();
	m_strFilterStatus->addItems({"All", "New", "Existing"});
	m_strFilterStatus->setMaximumWidth(70);
	m_strFilterStatus->setToolTip("Filter by new/existing status");
	filt->addWidget(m_strFilterStatus);
	
	m_strFilterMismatch = new QCheckBox("Length Mismatch");
	m_strFilterMismatch->setToolTip("Show only strings where detected length differs from defined length");
	filt->addWidget(m_strFilterMismatch);
	filt->addStretch();
	
	m_applyStrBtn = new QPushButton("Apply");
	m_applyStrBtn->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
	m_applyStrBtn->setEnabled(false);
	filt->addWidget(m_applyStrBtn);
	lay->addLayout(filt);
	
	// Table
	m_strTable = new QTableView();
	m_strTable->setAlternatingRowColors(true);
	m_strTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_strTable->setSortingEnabled(true);
	m_strTable->verticalHeader()->hide();
	m_strTable->verticalHeader()->setDefaultSectionSize(20);
	m_strModel = new StringTableModel(this);
	m_strProxy = new StringFilterProxy(this);
	m_strProxy->setSourceModel(m_strModel);
	m_strTable->setModel(m_strProxy);
	m_strTable->setColumnWidth(0, 24);
	m_strTable->setColumnWidth(1, 75);
	m_strTable->horizontalHeader()->setStretchLastSection(true);
	lay->addWidget(m_strTable, 1);
	
	connect(m_detectStrBtn, &QPushButton::clicked, this, &FunctionDetectorWidget::onDetectStrings);
	connect(m_applyStrBtn, &QPushButton::clicked, this, &FunctionDetectorWidget::onApplyStrings);
	connect(m_strTable, &QTableView::clicked, this, &FunctionDetectorWidget::onStringClicked);
	connect(m_strTable, &QTableView::doubleClicked, this, &FunctionDetectorWidget::onStringDoubleClicked);
	connect(m_strSearch, &QLineEdit::textChanged, this, &FunctionDetectorWidget::onStringFilterChanged);
	connect(m_strFilterCategory, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &FunctionDetectorWidget::onStringFilterChanged);
	connect(m_strFilterStatus, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &FunctionDetectorWidget::onStringFilterChanged);
	connect(m_strFilterMismatch, &QCheckBox::toggled, this, &FunctionDetectorWidget::onStringFilterChanged);
	
	return tab;
}

QWidget* FunctionDetectorWidget::createStructuresTab() {
	QWidget* tab = new QWidget();
	QVBoxLayout* lay = new QVBoxLayout(tab);
	lay->setSpacing(4);
	
	QHBoxLayout* opts = new QHBoxLayout();
	m_structVtables = new QCheckBox("VTables"); m_structVtables->setChecked(true);
	m_structVtables->setToolTip("Detect C++ virtual function tables");
	m_structJumpTables = new QCheckBox("Jump"); m_structJumpTables->setChecked(true);
	m_structJumpTables->setToolTip("Detect switch statement jump tables");
	m_structFuncTables = new QCheckBox("Func Ptrs"); m_structFuncTables->setChecked(true);
	m_structFuncTables->setToolTip("Detect arrays of function pointers");
	m_structPtrArrays = new QCheckBox("Arrays"); m_structPtrArrays->setChecked(true);
	m_structPtrArrays->setToolTip("Detect generic pointer arrays");
	opts->addWidget(m_structVtables);
	opts->addWidget(m_structJumpTables);
	opts->addWidget(m_structFuncTables);
	opts->addWidget(m_structPtrArrays);
	opts->addWidget(new QLabel("Min:"));
	m_structMinElems = new QSpinBox(); m_structMinElems->setRange(2, 50); m_structMinElems->setValue(3); m_structMinElems->setMaximumWidth(45);
	opts->addWidget(m_structMinElems);
	opts->addStretch();
	m_detectStructBtn = new QPushButton("Detect");
	m_detectStructBtn->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
	opts->addWidget(m_detectStructBtn);
	lay->addLayout(opts);
	
	m_structStats = new QLabel("Ready");
	lay->addWidget(m_structStats);
	
	QHBoxLayout* filt = new QHBoxLayout();
	filt->addStretch();
	m_applyStructBtn = new QPushButton("Apply");
	m_applyStructBtn->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
	m_applyStructBtn->setEnabled(false);
	filt->addWidget(m_applyStructBtn);
	lay->addLayout(filt);
	
	m_structTable = new QTableView();
	m_structTable->setAlternatingRowColors(true);
	m_structTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_structTable->setSortingEnabled(true);
	m_structTable->verticalHeader()->hide();
	m_structTable->verticalHeader()->setDefaultSectionSize(20);
	m_structModel = new StructureTableModel(this);
	m_structTable->setModel(m_structModel);
	m_structTable->setColumnWidth(0, 24);
	m_structTable->setColumnWidth(1, 75);
	m_structTable->horizontalHeader()->setStretchLastSection(true);
	lay->addWidget(m_structTable, 1);
	
	connect(m_detectStructBtn, &QPushButton::clicked, this, &FunctionDetectorWidget::onDetectStructures);
	connect(m_applyStructBtn, &QPushButton::clicked, this, &FunctionDetectorWidget::onApplyStructures);
	connect(m_structTable, &QTableView::clicked, this, &FunctionDetectorWidget::onStructureClicked);
	connect(m_structTable, &QTableView::doubleClicked, this, &FunctionDetectorWidget::onStructureDoubleClicked);
	
	return tab;
}

QWidget* FunctionDetectorWidget::createCryptoTab() {
	QWidget* tab = new QWidget();
	QVBoxLayout* lay = new QVBoxLayout(tab);
	lay->setSpacing(4);
	
	QHBoxLayout* opts = new QHBoxLayout();
	m_cryptoAES = new QCheckBox("AES"); m_cryptoAES->setChecked(true);
	m_cryptoAES->setToolTip("Detect AES S-boxes and key schedule constants");
	m_cryptoDES = new QCheckBox("DES"); m_cryptoDES->setChecked(true);
	m_cryptoDES->setToolTip("Detect DES S-boxes and permutation tables");
	m_cryptoSHA = new QCheckBox("SHA"); m_cryptoSHA->setChecked(true);
	m_cryptoSHA->setToolTip("Detect SHA-1/SHA-256 initialization constants");
	m_cryptoMD5 = new QCheckBox("MD5"); m_cryptoMD5->setChecked(true);
	m_cryptoMD5->setToolTip("Detect MD5 sine table constants");
	m_cryptoCRC = new QCheckBox("CRC"); m_cryptoCRC->setChecked(true);
	m_cryptoCRC->setToolTip("Detect CRC-16/CRC-32 lookup tables");
	m_cryptoOther = new QCheckBox("Other"); m_cryptoOther->setChecked(true);
	m_cryptoOther->setToolTip("Detect other crypto constants (RSA, Base64, etc.)");
	opts->addWidget(m_cryptoAES);
	opts->addWidget(m_cryptoDES);
	opts->addWidget(m_cryptoSHA);
	opts->addWidget(m_cryptoMD5);
	opts->addWidget(m_cryptoCRC);
	opts->addWidget(m_cryptoOther);
	opts->addStretch();
	m_detectCryptoBtn = new QPushButton("Detect");
	m_detectCryptoBtn->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
	opts->addWidget(m_detectCryptoBtn);
	lay->addLayout(opts);
	
	m_cryptoStats = new QLabel("Ready");
	lay->addWidget(m_cryptoStats);
	
	m_cryptoTable = new QTableView();
	m_cryptoTable->setAlternatingRowColors(true);
	m_cryptoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_cryptoTable->setSortingEnabled(true);
	m_cryptoTable->verticalHeader()->hide();
	m_cryptoTable->verticalHeader()->setDefaultSectionSize(20);
	m_cryptoModel = new CryptoTableModel(this);
	m_cryptoTable->setModel(m_cryptoModel);
	m_cryptoTable->setColumnWidth(0, 24);
	m_cryptoTable->setColumnWidth(1, 75);
	m_cryptoTable->horizontalHeader()->setStretchLastSection(true);
	lay->addWidget(m_cryptoTable, 1);
	
	connect(m_detectCryptoBtn, &QPushButton::clicked, this, &FunctionDetectorWidget::onDetectCrypto);
	connect(m_cryptoTable, &QTableView::clicked, this, &FunctionDetectorWidget::onCryptoClicked);
	connect(m_cryptoTable, &QTableView::doubleClicked, this, &FunctionDetectorWidget::onCryptoDoubleClicked);
	
	return tab;
}

QWidget* FunctionDetectorWidget::createEntropyTab() {
	QWidget* tab = new QWidget();
	QVBoxLayout* lay = new QVBoxLayout(tab);
	lay->setSpacing(4);
	
	QHBoxLayout* opts = new QHBoxLayout();
	m_entropyThreshold = new CockpitKnob("Thresh", 5.0, 8.0, 7.0, "Entropy threshold for high-entropy regions");
	opts->addWidget(m_entropyThreshold);
	opts->addWidget(new QLabel("Block:"));
	m_entropyBlockSize = new QSpinBox(); m_entropyBlockSize->setRange(64, 4096); m_entropyBlockSize->setValue(256); m_entropyBlockSize->setMaximumWidth(60);
	m_entropyBlockSize->setToolTip("Analysis block size in bytes");
	opts->addWidget(m_entropyBlockSize);
	m_entropySkipCode = new QCheckBox("Skip Code");
	m_entropySkipCode->setToolTip("Skip executable sections");
	opts->addWidget(m_entropySkipCode);
	opts->addStretch();
	m_detectEntropyBtn = new QPushButton("Analyze");
	m_detectEntropyBtn->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
	opts->addWidget(m_detectEntropyBtn);
	lay->addLayout(opts);
	
	m_entropyStats = new QLabel("Ready");
	lay->addWidget(m_entropyStats);
	
	m_entropyTable = new QTableView();
	m_entropyTable->setAlternatingRowColors(true);
	m_entropyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_entropyTable->setSortingEnabled(true);
	m_entropyTable->verticalHeader()->hide();
	m_entropyTable->verticalHeader()->setDefaultSectionSize(20);
	m_entropyModel = new EntropyTableModel(this);
	m_entropyTable->setModel(m_entropyModel);
	m_entropyTable->setColumnWidth(0, 75);
	m_entropyTable->horizontalHeader()->setStretchLastSection(true);
	lay->addWidget(m_entropyTable, 1);
	
	connect(m_detectEntropyBtn, &QPushButton::clicked, this, &FunctionDetectorWidget::onDetectEntropy);
	connect(m_entropyTable, &QTableView::clicked, this, &FunctionDetectorWidget::onEntropyClicked);
	connect(m_entropyTable, &QTableView::doubleClicked, this, &FunctionDetectorWidget::onEntropyDoubleClicked);
	
	return tab;
}

void FunctionDetectorWidget::setBinaryView(BinaryViewRef data) { m_data = data; m_preview->setBinaryView(data); }
void FunctionDetectorWidget::refresh() { m_funcStats->setText(m_data ? "Ready" : "No binary"); }

void FunctionDetectorWidget::navigateToAddress(uint64_t address) {
	emit addressSelected(address);
	// Also try to navigate in the current view frame
	if (auto* frame = ViewFrame::viewFrameForWidget(this)) {
		frame->navigate("Linear:" + QString::fromStdString(m_data->GetDefaultArchitecture()->GetName()), address);
	}
}

void FunctionDetectorWidget::onRunAll() {
	onDetectFunctions();
	onDetectStrings();
	onDetectStructures();
	onDetectCrypto();
	onDetectEntropy();
}

void FunctionDetectorWidget::onDetectFunctions() {
	if (!m_data) return;
	m_funcStats->setText("Scanning..."); QApplication::processEvents();
	Armv5Analysis::FunctionDetectionSettings s;
	s.minimumScore = m_minScoreDial->value();
	s.highConfidenceScore = m_highScoreDial->value();
	s.detectArmFunctions = m_detectArm->isChecked();
	s.detectThumbFunctions = m_detectThumb->isChecked();
	Armv5Analysis::FunctionDetector det(m_data);
	auto res = det.Detect(s);
	std::set<uint64_t> existing;
	std::map<uint64_t, Ref<Function>> fmap;
	for (auto& f : m_data->GetAnalysisFunctionList()) { existing.insert(f->GetStart()); fmap[f->GetStart()] = f; }
	std::vector<FunctionCandidateUI> ui;
	for (auto& r : res) {
		FunctionCandidateUI c;
		c.address = r.address; c.isThumb = r.isThumb; c.score = r.score;
		c.isNew = existing.find(r.address) == existing.end();
		c.selected = c.isNew && c.score >= s.highConfidenceScore;
		c.estimatedSize = 0; c.callCount = 0; c.calleeCount = 0;
		auto it = fmap.find(r.address);
		if (it != fmap.end()) {
			auto rng = it->second->GetAddressRanges();
			if (!rng.empty()) c.estimatedSize = rng.back().end - c.address;
			c.callCount = static_cast<int>(m_data->GetCodeReferences(r.address).size());
			c.calleeCount = static_cast<int>(it->second->GetCallSites().size());
		} else {
			c.callCount = static_cast<int>(m_data->GetCodeReferences(r.address).size());
		}
		for (auto& ss : r.sourceScores) {
			QString name = QString::fromUtf8(Armv5Analysis::DetectionSourceToString(ss.first));
			DetectionCategory cat = DetectionCategory::Advanced;
			if (name.contains("prologue", Qt::CaseInsensitive)) cat = DetectionCategory::Prologue;
			else if (name.contains("BL") || name.contains("target")) cat = DetectionCategory::CallTarget;
			c.sources.push_back({name, ss.second, cat});
		}
		ui.push_back(c);
	}
	m_funcModel->setThresholds(s.minimumScore, s.highConfidenceScore);
	m_funcModel->setCandidates(ui);
	auto stats = det.GetStats();
	m_funcStats->setText(QString("Found %1 | New: %2 | High: %3").arg(stats.totalCandidates).arg(stats.newFunctions).arg(stats.highConfidence));
	m_applyFuncBtn->setEnabled(!ui.empty());
}

void FunctionDetectorWidget::onApplyFunctions() {
	if (!m_data) return;
	auto sel = m_funcModel->getSelectedCandidates();
	if (sel.empty()) return;
	size_t n = 0;
	auto plat = m_data->GetDefaultPlatform();
	for (auto& c : sel) if (c.isNew) { m_data->CreateUserFunction(plat, c.address); n++; }
	QMessageBox::information(this, "Apply", QString("Created %1 function(s).").arg(n));
	emit analysisApplied(n);
	onDetectFunctions();
}

void FunctionDetectorWidget::onDetectStrings() {
	if (!m_data) return;
	m_strStats->setText("Scanning..."); QApplication::processEvents();
	Armv5Analysis::StringDetectionSettings s;
	s.findUnreferenced = m_strUnreferenced->isChecked();
	s.minLength = m_strMinLen->value();
	s.detectAscii = m_strAscii->isChecked();
	s.detectUtf8 = m_strAscii->isChecked();
	s.detectUtf16 = m_strUtf16->isChecked();
	s.skipExisting = false;  // Don't skip - we want to show them
	Armv5Analysis::StringDetector det(m_data);
	auto res = det.Detect(s);
	
	// Get existing strings for comparison
	std::map<uint64_t, size_t> existingStrs;
	for (auto& str : m_data->GetStrings()) existingStrs[str.start] = str.length;
	
	std::vector<StringCandidateUI> ui;
	for (auto& r : res) {
		StringCandidateUI c;
		c.address = r.address;
		c.length = r.length;
		c.content = QString::fromStdString(r.content);
		c.encoding = QString::fromUtf8(Armv5Analysis::StringDetector::EncodingToString(r.encoding));
		c.category = QString::fromUtf8(Armv5Analysis::StringDetector::CategoryToString(r.category));
		c.confidence = r.confidence;
		c.hasXrefs = r.hasXrefs;
		c.xrefCount = static_cast<int>(r.xrefAddresses.size());
		auto it = existingStrs.find(r.address);
		c.isNew = (it == existingStrs.end());
		c.definedLength = c.isNew ? 0 : it->second;
		c.lengthMismatch = !c.isNew && (c.definedLength != c.length);
		c.selected = c.isNew && c.category != "Generic";
		ui.push_back(c);
	}
	m_strModel->setCandidates(ui);
	auto stats = det.GetStats();
	m_strStats->setText(QString("Found %1 | New: %2 | Mismatch: %3").arg(stats.totalFound).arg(stats.newStrings)
		.arg(std::count_if(ui.begin(), ui.end(), [](auto& x) { return x.lengthMismatch; })));
	m_applyStrBtn->setEnabled(!ui.empty());
}

void FunctionDetectorWidget::onApplyStrings() {
	if (!m_data) return;
	auto sel = m_strModel->getSelectedCandidates();
	if (sel.empty()) return;
	size_t n = 0;
	for (auto& s : sel) {
		m_data->DefineUserDataVariable(s.address, Type::ArrayType(Type::IntegerType(1, false), s.length + 1));
		n++;
	}
	QMessageBox::information(this, "Apply", QString("Defined %1 string(s).").arg(n));
	emit analysisApplied(n);
}

void FunctionDetectorWidget::onDetectStructures() {
	if (!m_data) return;
	m_structStats->setText("Scanning..."); QApplication::processEvents();
	Armv5Analysis::StructureDetectionSettings s;
	s.detectVtables = m_structVtables->isChecked();
	s.detectJumpTables = m_structJumpTables->isChecked();
	s.detectFunctionTables = m_structFuncTables->isChecked();
	s.detectPointerArrays = m_structPtrArrays->isChecked();
	s.minElements = m_structMinElems->value();
	Armv5Analysis::StructureDetector det(m_data);
	auto res = det.Detect(s);
	std::vector<StructureCandidateUI> ui;
	for (auto& r : res) {
		StructureCandidateUI c;
		c.address = r.address;
		c.type = QString::fromUtf8(Armv5Analysis::StructureDetector::TypeToString(r.type));
		c.size = r.size; c.elementCount = r.elementCount; c.confidence = r.confidence;
		c.description = QString::fromStdString(r.description);
		c.isNew = r.isNew; c.selected = r.confidence >= 0.7;
		c.functionsDiscovered = static_cast<int>(r.functionTargets.size());
		for (auto& e : r.elementNames) c.elements << QString::fromStdString(e);
		ui.push_back(c);
	}
	m_structModel->setCandidates(ui);
	auto stats = det.GetStats();
	m_structStats->setText(QString("Found %1 | VTables: %2 | Funcs: %3").arg(stats.totalFound).arg(stats.vtables).arg(stats.totalFunctionsDiscovered));
	m_applyStructBtn->setEnabled(!ui.empty());
}

void FunctionDetectorWidget::onApplyStructures() {
	QMessageBox::information(this, "Apply", "Structure application coming soon");
}

void FunctionDetectorWidget::onDetectCrypto() {
	if (!m_data) return;
	m_cryptoStats->setText("Scanning..."); QApplication::processEvents();
	Armv5Analysis::CryptoDetectionSettings s;
	s.detectAES = m_cryptoAES->isChecked();
	s.detectDES = m_cryptoDES->isChecked();
	s.detectSHA = m_cryptoSHA->isChecked();
	s.detectMD5 = m_cryptoMD5->isChecked();
	s.detectCRC = m_cryptoCRC->isChecked();
	Armv5Analysis::CryptoDetector det(m_data);
	auto res = det.Detect(s);
	std::vector<CryptoCandidateUI> ui;
	for (auto& r : res) {
		CryptoCandidateUI c;
		c.address = r.address;
		c.algorithm = QString::fromUtf8(Armv5Analysis::CryptoDetector::AlgorithmToString(r.algorithm));
		c.constType = QString::fromUtf8(Armv5Analysis::CryptoDetector::ConstTypeToString(r.constType));
		c.size = r.size; c.confidence = r.confidence;
		c.description = QString::fromStdString(r.description);
		c.xrefCount = static_cast<int>(r.xrefAddresses.size());
		c.selected = true;
		ui.push_back(c);
	}
	m_cryptoModel->setCandidates(ui);
	auto stats = det.GetStats();
	m_cryptoStats->setText(QString("Found %1 | AES: %2 | SHA: %3 | CRC: %4").arg(stats.totalFound).arg(stats.aesFound).arg(stats.shaFound).arg(stats.crcFound));
}

void FunctionDetectorWidget::onDetectEntropy() {
	if (!m_data) return;
	m_entropyStats->setText("Analyzing..."); QApplication::processEvents();
	Armv5Analysis::EntropyAnalysisSettings s;
	s.highEntropyThreshold = m_entropyThreshold->value();
	s.blockSize = m_entropyBlockSize->value();
	s.skipCodeSections = m_entropySkipCode->isChecked();
	Armv5Analysis::EntropyAnalyzer det(m_data);
	auto res = det.Analyze(s);
	std::vector<EntropyRegionUI> ui;
	for (auto& r : res) {
		EntropyRegionUI e;
		e.address = r.address; e.size = r.size; e.entropy = r.entropy;
		e.type = QString::fromUtf8(Armv5Analysis::EntropyAnalyzer::RegionTypeToString(r.type));
		e.description = QString::fromStdString(r.description);
		ui.push_back(e);
	}
	m_entropyModel->setRegions(ui);
	auto stats = det.GetStats();
	m_entropyStats->setText(QString("Blocks: %1 | Avg: %2 | Encrypted: %3 | Compressed: %4")
		.arg(stats.totalBlocks).arg(stats.averageEntropy, 0, 'f', 2).arg(stats.encryptedRegions).arg(stats.compressedRegions));
}

void FunctionDetectorWidget::onFunctionClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	auto src = m_funcProxy->mapToSource(idx);
	if (auto* c = m_funcModel->getCandidateAt(src.row())) m_preview->showAddress(c->address, c->isThumb);
}
void FunctionDetectorWidget::onFunctionDoubleClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	auto src = m_funcProxy->mapToSource(idx);
	if (auto* c = m_funcModel->getCandidateAt(src.row())) navigateToAddress(c->address);
}
void FunctionDetectorWidget::onStringClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	auto src = m_strProxy->mapToSource(idx);
	if (auto* c = m_strModel->getCandidateAt(src.row())) m_preview->showString(c->address, c->length);
}
void FunctionDetectorWidget::onStringDoubleClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	auto src = m_strProxy->mapToSource(idx);
	if (auto* c = m_strModel->getCandidateAt(src.row())) navigateToAddress(c->address);
}
void FunctionDetectorWidget::onStructureClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	if (auto* c = m_structModel->getCandidateAt(idx.row())) m_preview->showStructure(c->address, c->size);
}
void FunctionDetectorWidget::onStructureDoubleClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	if (auto* c = m_structModel->getCandidateAt(idx.row())) navigateToAddress(c->address);
}
void FunctionDetectorWidget::onCryptoClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	if (auto* c = m_cryptoModel->getCandidateAt(idx.row())) m_preview->showCryptoConstant(c->address, c->size, c->algorithm);
}
void FunctionDetectorWidget::onCryptoDoubleClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	if (auto* c = m_cryptoModel->getCandidateAt(idx.row())) navigateToAddress(c->address);
}
void FunctionDetectorWidget::onEntropyClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	if (auto* r = m_entropyModel->getRegionAt(idx.row())) m_preview->showEntropyRegion(r->address, r->size, r->entropy);
}
void FunctionDetectorWidget::onEntropyDoubleClicked(const QModelIndex& idx) {
	if (!idx.isValid()) return;
	if (auto* r = m_entropyModel->getRegionAt(idx.row())) navigateToAddress(r->address);
}
void FunctionDetectorWidget::onFunctionFilterChanged() {
	m_funcProxy->setFilters(m_funcFilterScore->value(), m_funcFilterNew->isChecked(), m_funcFilterMode->currentIndex(), m_funcSearch->text());
}
void FunctionDetectorWidget::onStringFilterChanged() {
	m_strProxy->setFilters(m_strSearch->text(), m_strFilterCategory->currentText(), m_strFilterStatus->currentIndex(), m_strFilterMismatch->isChecked());
}
void FunctionDetectorWidget::onExportResults() {
	QMessageBox::information(this, "Export", "Export coming soon");
}

}
