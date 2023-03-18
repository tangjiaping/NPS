//
// Created by tjp on 3/10/23.
//

#ifndef NPS_MAINWINDOW_H
#define NPS_MAINWINDOW_H


#include <QMainWindow>
#include "DataPkg.h"

class MainWidget;
class QLineEdit;
class Sniffer;

class MainWindow : public QMainWindow{
Q_OBJECT
public:
    MainWindow();
    DataPkg* dataPkg;
    Sniffer* sniffer;
    MainWidget* mainWidget;
    QLineEdit* filter_line;
    signals:
        void loadPacket();

private:
    void InitData();



};


#endif //NPS_MAINWINDOW_H
