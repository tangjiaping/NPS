//
// Created by tjp on 3/10/23.
//




#include <netinet/tcp.h>
#include "../include/MainWidget.h"
#include "../include/Analysiser.h"


void MainWidget::displayPacket() {
//    std::cout << "display packet\n";


        Packet packet = dataPkg->getPacket(idx++);
        if (packet.data == nullptr){
            return;
        }
        Ethernet* ethernet_header = nullptr;
        ethernet_header = (Ethernet*) packet.data;
        EthernetStr ethernetStr = Analysiser::parserEthernet(ethernet_header);

        std::stringstream ss;

        std::vector<std::string> items;
        table->insertRow(table->rowCount());
        items.resize(table->columnCount());

        items[0] = std::to_string(packet.id);
        items[1] = ctime((const time_t*)&packet.ts.tv_sec);
        items[2] = ethernetStr.srcMac;
        items[3] = ethernetStr.desMac;
        items[7] = std::to_string(packet.len);

        if (ethernetStr.type == "IP"){         /// for Ipv4
            IP* ip_header = (IP*)((packet.data + sizeof(ether_header)));
            IPStr ipStr = Analysiser::parserIp(ip_header);

            items[4] = ipStr.srcIp;
            items[5] = ipStr.desIp;
            items[6] = ipStr.protocol;

        }else if (ethernetStr.type == "ARP"){    /// for ARP
            ARP* arp_header = (ARP*)(packet.data + sizeof(ether_header));
            ARPStr arpStr = Analysiser::parserARP(arp_header);
            items[4] = arpStr.srcIp;
            items[5] = arpStr.desIp;
            items[6] = arpStr.protocol;
        }else if (ethernetStr.type == "IPv6"){    /// for Ipv6
            IPv6* iPv6_header = (IPv6*)(packet.data + sizeof(ether_header));
            IPv6Str iPv6Str = Analysiser::parserIpv6(iPv6_header);
            items[4] = iPv6Str.srcIp;
            items[5] = iPv6Str.desIp;
            items[6] = iPv6Str.protocol;
        }else{
            ss.str("");
            ss << "0x" << HEX(ethernet_header->type[0]) << HEX(ethernet_header->type[1]);
            std::cout << "Unknown Type " << ss.str() << std::endl;
        }

        int row = table->rowCount()-1;
        for(int i=0; i<table->columnCount(); i++){
            table->setItem(row,i,
                           new QTableWidgetItem(QString::fromStdString(items[i])));
        }


}

void MainWidget::clearTable() {
    table->clearContents();
    table->setRowCount(0);
    tree->clear();
    idx = 0;
    button->clear();
    dataPkg->clear();
}

void MainWidget::update(int selected_row) {
    int packet_id = table->item(selected_row,0)->text().toInt();
    Packet packet = dataPkg->getPacket(selected_row);
    tree->clear();
    if (packet.data == nullptr){
        return;
    }
    std::stringstream ss;
    for(int i=0; i<packet.len; i++){
        ss << HEX(packet.data[i]) << " ";
        if ((i + 1) % 16 == 0){
            ss << "\n";
        }
    }


    button->setText(QString::fromStdString(ss.str()));

    std::string frame_str = "Frame " + std::to_string(packet_id);
    QTreeWidgetItem* frame = new QTreeWidgetItem(tree,QStringList(QString::fromStdString(frame_str)));
//    frame->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString(packet.interface))));
    frame->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString(
            "Arrive Time: " + std::string(ctime((const time_t*)&packet.ts.tv_sec))
    ))));
    frame->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString(
            "Packet len: " + std::to_string(packet.len)
    ))));

//    Ethernet* ethernet_header = nullptr;
//    ethernet_header = (Ethernet*) packet.data;
//    EthernetStr ethernetStr = Analysiser::parserMacAddress(ethernet_header);

    Ethernet* etherHeader = (Ethernet*)(packet.data);
    EthernetStr ethernetStr = Analysiser::parserEthernet(etherHeader);
    showEthernet(ethernetStr);


    if (ethernetStr.type == "IP"){         /// for Ipv4
        IP* ip_header = (IP*)((packet.data + sizeof(Ethernet)));
        IPStr ipStr = Analysiser::parserIp(ip_header);
        showIpv4(ipStr);

        if (ipStr.protocol == "TCP"){
            TCP* tcp = (TCP*)(packet.data + sizeof(Ethernet) + ipStr.header_len);
            TCPStr tcpStr = Analysiser::parserTCP(tcp);

            showTCP(tcpStr);
        }else if (ipStr.protocol == "UDP"){
            UDP* udp = (UDP*)(packet.data + sizeof(Ethernet) + ipStr.header_len);
            UDPStr udpStr = Analysiser::parserUDP(udp);

            showUDP(udpStr);
        }else if (ipStr.protocol == "ICMP") {
            ICMP* icmp = (ICMP*)(packet.data + sizeof(Ethernet) + ipStr.header_len);
            ICMPStr icmpStr = Analysiser::parserICMP(icmp);
            showICMP(icmpStr);
        }else{
//                assert(false);
        }
    }else if (ethernetStr.type == "ARP"){    /// for ARP
        ARP* arp_header = (ARP*)(packet.data + sizeof(Ethernet));
        ARPStr arpStr = Analysiser::parserARP(arp_header);
        showARP(arpStr);
    }else if (ethernetStr.type == "IPv6"){    /// for Ipv6
        IPv6* iPv6_header = (IPv6*)(packet.data + sizeof(Ethernet));
        IPv6Str iPv6Str = Analysiser::parserIpv6(iPv6_header);
        showIpv6(iPv6Str);
    }else{
        assert(true);
    }



}

MainWidget::MainWidget(DataPkg* dataPkg) : dataPkg(dataPkg) {
    setLayout(new QVBoxLayout());
    table = new QTableWidget(0,8);
    QStringList header;
    header << "No" << "Time" << "srcMac" << "desMac" << "srcIp" << "desIp" << "Protocol" << "Packet size";
    table->setHorizontalHeaderLabels(header);
    table->verticalHeader()->setHidden(true);
    table->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table->verticalHeader()->setDefaultSectionSize(10);
    table->horizontalHeader()->setStretchLastSection(true);
    table->setShowGrid(false);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    layout()->addWidget(table);


    tree = new QTreeWidget();

    layout()->addWidget(tree);

    button = new QTextEdit();
    button->setReadOnly(true);
    layout()->addWidget(button);


    connect(table, &QTableWidget::cellClicked,this,[&](int row,int col){
        std::cout << "seleted row is " << row << std::endl;
        update(row);
    });

}

void MainWidget::showEthernet(const EthernetStr &ethernetStr) {

    QTreeWidgetItem* ethernet = new QTreeWidgetItem(tree,QStringList(QString::fromStdString("Ethernet")));
    ethernet->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString(
            "Source: " + ethernetStr.srcMac
    ))));
    ethernet->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString(
            "Destination: " + ethernetStr.desMac
    ))));
    ethernet->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString(
            "Type: " + ethernetStr.type
    ))));
}

void MainWidget::showIpv4(const IPStr &ipStr) {
    QTreeWidgetItem* IP = new QTreeWidgetItem(tree,QStringList(QString::fromStdString("Internet Protocol Version 4")));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Version: " + std::to_string(ipStr.version)))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Header len: " + std::to_string(ipStr.header_len)))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Total len: " + std::to_string(ipStr.total_len)))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Identification: " + ipStr.identify))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Flags: " + ipStr.flag))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Fragment offset: " + std::to_string(ipStr.offset)))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Time to live: " + std::to_string(ipStr.ttl)))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Protocol: " + ipStr.protocol))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("CheckSum: " + (ipStr.check_sum)))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Source: " + ipStr.srcIp))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Destination: " + ipStr.desIp))));
}

void MainWidget::showIpv6(const IPv6Str &iPv6Str) {
    QTreeWidgetItem* IP = new QTreeWidgetItem(tree,QStringList(QString::fromStdString("Internet Protocol Version 6")));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Version: " + std::to_string(iPv6Str.version)))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Traffic class: " + iPv6Str.communication))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Flow table: " + iPv6Str.flow_label))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Payload Length: " + std::to_string(iPv6Str.playload)))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Hop Limit: " + std::to_string(iPv6Str.ttl)))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Source: " + iPv6Str.srcIp))));
    IP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Destination: " + iPv6Str.desIp))));
}

void MainWidget::showTCP(const TCPStr &tcpStr) {
    QTreeWidgetItem* TCP = new QTreeWidgetItem(tree,QStringList(QString::fromStdString("Transmission Control Protocol")));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Source Port: " + std::to_string(tcpStr.srcPort)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Destination Port: " + std::to_string(tcpStr.desPort)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Header len: " + std::to_string(tcpStr.header_len)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Sequence number: " + std::to_string(tcpStr.seq)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Acknowledgement number: " + std::to_string(tcpStr.ack)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("NS: " + std::to_string(tcpStr.NS)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("CWR: " + std::to_string(tcpStr.CWR)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("ECE: " + std::to_string(tcpStr.ECE)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("URG: " + std::to_string(tcpStr.URG)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("ACK: " + std::to_string(tcpStr.ACK)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("PSH: " + std::to_string(tcpStr.PSH)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("RST: " + std::to_string(tcpStr.RST)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("SYN: " + std::to_string(tcpStr.SYN)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("FIN: " + std::to_string(tcpStr.FIN)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Window size: " + std::to_string(tcpStr.window_size)))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Check sum: " + tcpStr.check_sum))));
    TCP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Urgent pointer: " + tcpStr.urgent_point))));
}

void MainWidget::showUDP(const UDPStr &udpStr) {
    QTreeWidgetItem* UDP = new QTreeWidgetItem(tree,QStringList(QString::fromStdString("User Datagram Protocol")));
    UDP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Source Port: " + std::to_string(udpStr.srcPort)))));
    UDP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Destination Port: " + std::to_string(udpStr.desPort)))));
    UDP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Header len: " + std::to_string(udpStr.total_len)))));
    UDP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Check sum: " + udpStr.check_sum))));
}

void MainWidget::showICMP(const ICMPStr &icmpStr) {
    QTreeWidgetItem* ICMP = new QTreeWidgetItem(tree,QStringList(QString::fromStdString("Internet Control Message Protocol")));
    ICMP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Type: " + std::to_string(icmpStr.type)))));
    ICMP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Code: " + std::to_string(icmpStr.code)))));
    ICMP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Check sum: " + icmpStr.check_sum))));
    ICMP->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Message: " + Analysiser::icmpMessage(icmpStr.type,icmpStr.code)))));
}

void MainWidget::showARP(const ARPStr &arpStr) {
    QTreeWidgetItem* arp = new QTreeWidgetItem(tree,QStringList(QString::fromStdString("Request Resolution Protocol")));
    arp->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Opcode: " + arpStr.op_code))));
    arp->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Sender MAC: " + arpStr.srcMac))));
    arp->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Sender IP: " + arpStr.srcIp))));
    arp->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Target MAC: " + arpStr.desMac))));
    arp->addChild(new QTreeWidgetItem(QStringList(QString::fromStdString("Target IP: " + arpStr.desIp))));
}