//
// Created by tjp on 3/10/23.
//

#ifndef NPS_MAINWIDGET_H
#define NPS_MAINWIDGET_H

#include <QVBoxLayout>
#include <QLineEdit>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTreeView>
#include <QWidget>

#include <iostream>
#include <sstream>
#include "Protocol.h"

#include "DataPkg.h"

class MainWidget : public QWidget{

Q_OBJECT
public:
    MainWidget(DataPkg*);

    QTableWidget* table;
    QTreeWidget* tree;
    int idx = 0;
    DataPkg* dataPkg;

public slots:
        void displayPacket();
};


#endif //NPS_MAINWIDGET_H
