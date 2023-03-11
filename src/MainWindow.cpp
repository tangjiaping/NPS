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

#include "../include/MainWindow.h"
#include "../include/MainWidget.h"

MainWindow::MainWindow() {

    QString start_active_icon = "/home/tjp/CLionProjects/NPS/icon/start_active.png";
    QString start_no_active_icon = "/home/tjp/CLionProjects/NPS/icon/start_no_active.png";
    QString stop_active_icon = "/home/tjp/CLionProjects/NPS/icon/stop_active.png";
    QString stop_no_active_icon = "/home/tjp/CLionProjects/NPS/icon/stop_no_active.png";

    auto menuBar = new QMenuBar();
    menuBar->addAction("file");
    setMenuBar(menuBar);

    auto toolBar = new QToolBar();
    auto start_btn = new QAction(QIcon(start_active_icon),"start");
    auto stop_btn = new QAction(QIcon(stop_no_active_icon),"stop");
    toolBar->addAction(start_btn);
    toolBar->addAction(stop_btn);


    connect(start_btn,&QAction::triggered,this,[=](){
        qDebug() << "click start button";
        start_btn->setIcon(QIcon(start_no_active_icon));
        stop_btn->setIcon(QIcon(stop_active_icon));
    });
    connect(stop_btn,&QAction::triggered,this,[=](){
        qDebug( "click stop button");
        start_btn->setIcon(QIcon(start_active_icon));
        stop_btn->setIcon(QIcon(stop_no_active_icon));
    });


    auto network_card = new QComboBox();
    network_card->addItem("enp2s0");
    network_card->addItem("lo");
    network_card->addItem("wlp3s0");
    network_card->setFixedWidth(200);
    network_card->setFixedHeight(30);
    network_card->setStyleSheet("QComboBox{combobox-popup:0;}");
    toolBar->addWidget(network_card);

    auto filter_line = new QLineEdit();
    filter_line->setPlaceholderText("please write filter regular");
    filter_line->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    toolBar->addWidget(filter_line);

    toolBar->setFloatable(false);
    addToolBar(Qt::TopToolBarArea,toolBar);


    auto mainWidget = new MainWidget();
    setCentralWidget(mainWidget);


    resize(800,400);
}