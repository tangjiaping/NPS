//
// Created by tjp on 3/11/23.
//

#include <cstring>
#include "../include/Sniffer.h"

DataPkg* Sniffer::dataPkg = nullptr;
MainWindow* Sniffer::window = nullptr;

void Sniffer::packetHandler(u_char *arg, const struct pcap_pkthdr *packet_info, const u_char *packet_data) {
    std::cout << "====================== Capture a packet ===================\n";
    int* id = (int*)arg;
    *id = *id + 1;
    Ethernet* ethernet_header;
    ethernet_header = (Ethernet*) packet_data;
    std::stringstream ss;
    ss << "Packet size: " << packet_info->len;
    std::cout << ss.str() << "\n";

//    ss.str("");
//    ss << HEX(ethernet_header->desMac[0]) << "-"
//              << HEX(ethernet_header->desMac[1]) << "-"
//              << HEX(ethernet_header->desMac[2]) << "-"
//              << HEX(ethernet_header->desMac[3]) << "-"
//              << HEX(ethernet_header->desMac[4]) << "-"
//              << HEX(ethernet_header->desMac[5]);
//    std::cout << "Des MAC: " << ss.str() << "\n";
//
//    ss.str("");
//    ss << HEX(ethernet_header->srcMac[0]) << "-"
//       << HEX(ethernet_header->srcMac[1]) << "-"
//       << HEX(ethernet_header->srcMac[2]) << "-"
//       << HEX(ethernet_header->srcMac[3]) << "-"
//       << HEX(ethernet_header->srcMac[4]) << "-"
//       << HEX(ethernet_header->srcMac[5]);
//    std::cout << "Src MAC: " << ss.str() << "\n";
//
    ss.str("");
    ss << "0x" << HEX(ethernet_header->type[0])
       << HEX(ethernet_header->type[1]);


    /// for Ip
    if (ethernet_header->type[0] == 0x08 && ethernet_header->type[1] == 0x00){
        std::cout << "This is IPv4 packet (" << ss.str() << ")" << std::endl;
    }else if (ethernet_header->type[0] == 0x08 && ethernet_header->type[1] == 0x06){    /// for ARP
        std::cout << "This is ARP packet (" << ss.str() << ")" << std::endl;
    }else if (ethernet_header->type[0] == 0x08 && ethernet_header->type[1] == 0x35){    /// for RARP
        std::cout << "This is ARP packet (" << ss.str() << ")" << std::endl;
    }else if (ethernet_header->type[0] == 0x86 && ethernet_header->type[1] == 0xdd){    /// for ARP
        std::cout << "This is IPv6 packet (" << ss.str() << ")" << std::endl;
    }else {
        std::cout << "This is Unkown packet (" << ss.str() << ")" << std::endl;
    }

    dataPkg->addPacket(*id,packet_data,(int)packet_info->len,packet_info->ts);

    emit window->loadPacket();

//    for(int i=0;i<packet_info->len;i++){
//        printf(" %02x", packet_data[i]);
//        if ((i + 1) % 16 == 0){
//            std::cout << std::endl;
//        }
//    }
//    std::cout << std::endl;

}

void Sniffer::serachDevice() {
    pcap_if* dev_list;
    if (pcap_findalldevs(&dev_list,err) != -1){
        dataPkg->parserDevice(dev_list);
        changeDevice(0);
    }else{
        std::cout << err << std::endl;
        exit(1);
    }
}

void Sniffer::changeDevice(int index) {
    closeCaptrue();
    current_deivce = dataPkg->network_cards[index];
}

void Sniffer::loopCapture() {
    std::thread loop([this](){
        int id = 0;
        pcap_loop(this->current_handler, -1, packetHandler, (u_char*)&id);
    });
    loop.detach();
}

bool Sniffer::startCapture(const std::string& expr) {
    if ((current_handler = pcap_open_live(current_deivce->name,1024,1,0,err))){
        if (expr.empty() || setFilter(expr)){
            loopCapture();
            return true;
        }
    }else{
        std::cout << err << std::endl;
        exit(1);
    }
    return false;
}

void Sniffer::closeCaptrue() {
    if (current_handler){
        pcap_breakloop(current_handler);
        pcap_close(current_handler);
        current_handler = nullptr;
    }
}

bool Sniffer::setFilter(const std::string& expr) {
    std::cout << "filer expression: " << expr << std::endl;
    if (pcap_compile(current_handler,&filter,expr.data(),1,PCAP_NETMASK_UNKNOWN) == -1){
        pcap_perror(current_handler,err);
        std::cout << "compile error: " << err << std::endl;
        return false;
    }
    pcap_setfilter(current_handler,&filter);
    return true;
}