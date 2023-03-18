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
#include <QTextEdit>
#include "Protocol.h"

#include "DataPkg.h"
#include "Analysiser.h"

class MainWidget : public QWidget{

Q_OBJECT
public:
    MainWidget(DataPkg*);

    QTableWidget* table;
    QTreeWidget* tree;
    QTextEdit* button;

    int idx = 0;
    DataPkg* dataPkg;
private:
    void showEthernet(const EthernetStr& ethernetStr);
    void showIpv4(const IPStr& ipStr);
    void showIpv6(const IPv6Str& iPv6Str);
    void showTCP(const TCPStr& tcpStr);
    void showUDP(const UDPStr& udpStr);
public:
    void update(int selected_row);
    void clearTable();

public slots:
        void displayPacket();

};


#endif //NPS_MAINWIDGET_H
