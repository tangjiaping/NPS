//
// Created by tjp on 3/10/23.
//

#include <QPushButton>
#include <QToolBar>
#include <QIcon>
#include <QComboBox>
#include <QMenuBar>
#include <QLineEdit>
#include <iostream>
#include <QDebug>
#include "../include/Sniffer.h"
#include "../include/MainWindow.h"
#include "../include/MainWidget.h"

void MainWindow::InitData() {
    dataPkg = new DataPkg;
    sniffer = new Sniffer();
    sniffer->initDataPkg(dataPkg);
    sniffer->serachDevice();
    sniffer->window = this;
}

MainWindow::MainWindow() {

    InitData();

    QString start_active_icon = "/home/tjp/CLionProjects/NPS/icon/start_active.png";
    QString start_no_active_icon = "/home/tjp/CLionProjects/NPS/icon/start_no_active.png";
    QString stop_active_icon = "/home/tjp/CLionProjects/NPS/icon/stop_active.png";
    QString stop_no_active_icon = "/home/tjp/CLionProjects/NPS/icon/stop_no_active.png";

    auto menuBar = new QMenuBar();
    menuBar->addAction("file");
//    setMenuBar(menuBar);

    auto toolBar = new QToolBar();
    auto start_btn = new QAction(QIcon(start_active_icon),"start");
    auto stop_btn = new QAction(QIcon(stop_no_active_icon),"stop");
    toolBar->addAction(start_btn);
    toolBar->addAction(stop_btn);
    stop_btn->setEnabled(false);

    connect(start_btn,&QAction::triggered,this,[=](){
        qDebug() << "click start button";
        start_btn->setIcon(QIcon(start_no_active_icon));
        stop_btn->setIcon(QIcon(stop_active_icon));
        mainWidget->clearTable();
        start_btn->setEnabled(false);
        stop_btn->setEnabled(true);
        sniffer->startCapture();
    });
    connect(stop_btn,&QAction::triggered,this,[=](){
        qDebug( "click stop button");
        start_btn->setIcon(QIcon(start_active_icon));
        stop_btn->setIcon(QIcon(stop_no_active_icon));
        stop_btn->setEnabled(false);
        start_btn->setEnabled(true);
        sniffer->closeCaptrue();
    });


    auto network_card = new QComboBox();
    for(auto dev : dataPkg->network_cards){
        std::string dev_str = dev->name;
        network_card->addItem(QString::fromStdString(dev_str));
    }
    network_card->setFixedWidth(200);
    network_card->setFixedHeight(30);
    network_card->setStyleSheet("QComboBox{combobox-popup:0;}");
    toolBar->addWidget(network_card);
    connect(network_card,(void (QComboBox::*)(int))&QComboBox::currentIndex,this,[&](int index){
        qDebug() << "new_index: " << network_card->currentIndex();

    });

    auto filter_line = new QLineEdit();
    filter_line->setPlaceholderText("please write filter regular");
    filter_line->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    toolBar->addWidget(filter_line);

    toolBar->setFloatable(false);
    addToolBar(Qt::TopToolBarArea,toolBar);


    mainWidget = new MainWidget(dataPkg);
    setCentralWidget(mainWidget);


    connect(this, &MainWindow::loadPacket,mainWidget,&MainWidget::displayPacket);
    resize(800,400);
}