/*
 * Function Table Widget
 *
 * Simple table showing existing functions in the binary.
 */

#pragma once

#include "uitypes.h"

#include <QtWidgets/QWidget>
#include <QtWidgets/QTableView>
#include <QtWidgets/QLineEdit>
#include <QtCore/QAbstractTableModel>
#include <QtCore/QSortFilterProxyModel>

namespace Armv5UI
{

class ExistingFunctionModel : public QAbstractTableModel
{
	Q_OBJECT
public:
	enum Column { ColAddress, ColName, ColSize, ColCalls, ColCount };
	
	explicit ExistingFunctionModel(QObject* parent = nullptr);
	
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	
	void refresh(BinaryViewRef data);
	uint64_t getAddressAt(int row) const;

private:
	struct FunctionInfo {
		uint64_t address;
		QString name;
		size_t size;
		int callCount;
	};
	std::vector<FunctionInfo> m_functions;
};

class ExistingFunctionFilterProxy : public QSortFilterProxyModel
{
	Q_OBJECT
public:
	explicit ExistingFunctionFilterProxy(QObject* parent = nullptr);
	void setSearchText(const QString& text);
protected:
	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
private:
	QString m_search;
};

class FunctionTableWidget : public QWidget
{
	Q_OBJECT

public:
	explicit FunctionTableWidget(QWidget* parent = nullptr);
	
	void refresh(BinaryViewRef data);
	void highlightAddress(uint64_t address);

Q_SIGNALS:
	void functionSelected(uint64_t address);

private Q_SLOTS:
	void onRowDoubleClicked(const QModelIndex& index);
	void onSearchChanged(const QString& text);

private:
	QTableView* m_table;
	ExistingFunctionModel* m_model;
	ExistingFunctionFilterProxy* m_proxy;
	QLineEdit* m_search;
	BinaryViewRef m_data;
};

}
