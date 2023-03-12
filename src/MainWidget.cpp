//
// Created by tjp on 3/10/23.
//




#include "../include/MainWidget.h"


void MainWidget::displayPacket() {
    std::cout << "display packet\n";

    if (idx++ < dataPkg->packets.size()){
        auto packet = dataPkg->packets[idx];
        if (packet.data == nullptr){
            return;
        }
        Ethernet* ethernet_header;
        ethernet_header = (Ethernet*) packet.data;
        std::stringstream ss;

        /// for Ip
        if (ethernet_header->type[0] == 0x08 && ethernet_header->type[1] == 0x00){
            IP* ip_header = (IP*)((packet.data + sizeof(Ethernet)));
            ss.str("");
            ss << "version: " << DEC(ip_header->version) << "\n"
               << "header length: " << DEC(ip_header->header_length) << "\n"
               << "service: " << HEX(ip_header->service) << "\n"
               << "total length: " << DEC(ip_header->total_length) << "\n"
               << "protocol: " << DEC(ip_header->protocol) << "\n"
               << "src IP: " << DEC(ip_header->srcIp[0]) << "." << DEC(ip_header->srcIp[1]) << "." << DEC(ip_header->srcIp[2]) << "." << DEC(ip_header->srcIp[3]) << "\n"
               << "des IP: " << DEC(ip_header->desIp[0]) << "." << DEC(ip_header->desIp[1]) << "." << DEC(ip_header->desIp[2]) << "." << DEC(ip_header->desIp[3]) << "\n";
            std::cout << ss.str() << "\n";

            table->insertRow(table->rowCount());
            ss.str("");
            ss << DEC(ip_header->srcIp[0]) << "."
                << DEC(ip_header->srcIp[1]) << "."
                << DEC(ip_header->srcIp[2]) << "."
                << DEC(ip_header->srcIp[3]);
            table->setItem(table->rowCount()-1,2,
                           new QTableWidgetItem(QString::fromStdString(ss.str())));
            ss.str("");
            ss << DEC(ip_header->desIp[0]) << "."
               << DEC(ip_header->desIp[1]) << "."
               << DEC(ip_header->desIp[2]) << "."
               << DEC(ip_header->desIp[3]);
            table->setItem(table->rowCount()-1,3,
                           new QTableWidgetItem(QString::fromStdString(ss.str())));

            ss.str("");
            if (protocolToStr.find(ip_header->protocol) != protocolToStr.end()){
                ss << protocolToStr[ip_header->protocol] << "v" << DEC(ip_header->version);
            }
            table->setItem(table->rowCount()-1,4,
                           new QTableWidgetItem(QString::fromStdString(ss.str())));

            ss.str("");
            ss << DEC(packet.len);
            table->setItem(table->rowCount()-1,5,
                           new QTableWidgetItem(QString::fromStdString(ss.str())));

        }else if (ethernet_header->type[0] == 0x08 && ethernet_header->type[1] == 0x06){    /// for ARP

        }else{
            std::cout << "Unknown Type" << std::endl;
        }

    }

}

MainWidget::MainWidget(DataPkg* dataPkg) : dataPkg(dataPkg) {
    setLayout(new QVBoxLayout());
    table = new QTableWidget(1,6);
    QStringList header;
    header << "No" << "Time" << "Source" << "Destination" << "Protocol" << "Length";
    table->setHorizontalHeaderLabels(header);
    table->verticalHeader()->setHidden(true);
    table->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table->verticalHeader()->setDefaultSectionSize(10);
    table->horizontalHeader()->setStretchLastSection(true);
    table->setShowGrid(false);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    layout()->addWidget(table);


    tree = new QTreeWidget();
    QTreeWidgetItem* item1 = new QTreeWidgetItem(tree,QStringList(QString("item1")));
    QTreeWidgetItem* item2 = new QTreeWidgetItem(tree,QStringList(QString("item1")));
    QTreeWidgetItem* item3 = new QTreeWidgetItem(tree,QStringList(QString("item1")));
    QTreeWidgetItem* item1_1 = new QTreeWidgetItem(item1,QStringList(QString("item1")));


    layout()->addWidget(tree);


}