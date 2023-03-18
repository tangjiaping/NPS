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

    ss.str("");
    ss << HEX(ethernet_header->desMac[0]) << "-"
              << HEX(ethernet_header->desMac[1]) << "-"
              << HEX(ethernet_header->desMac[2]) << "-"
              << HEX(ethernet_header->desMac[3]) << "-"
              << HEX(ethernet_header->desMac[4]) << "-"
              << HEX(ethernet_header->desMac[5]);
    std::cout << "Des MAC: " << ss.str() << "\n";

    ss.str("");
    ss << HEX(ethernet_header->srcMac[0]) << "-"
       << HEX(ethernet_header->srcMac[1]) << "-"
       << HEX(ethernet_header->srcMac[2]) << "-"
       << HEX(ethernet_header->srcMac[3]) << "-"
       << HEX(ethernet_header->srcMac[4]) << "-"
       << HEX(ethernet_header->srcMac[5]);
    std::cout << "Src MAC: " << ss.str() << "\n";

    ss.str("");
    ss << HEX(ethernet_header->type[0])
       << HEX(ethernet_header->type[1]);
    std::cout << "Type   : " << ss.str() << "\n";

    /// for Ip
    if (ethernet_header->type[0] == 0x08 && ethernet_header->type[1] == 0x00){
        IP* ip_header = (IP*)((packet_data + sizeof(Ethernet)));

        ss.str("");
        ss << "version: " << DEC(ip_header->version) << "\n"
           << "header length: " << DEC(ip_header->header_length) << "\n"
           << "service: " << HEX(ip_header->service) << "\n"
           << "total length: " << (ip_header->total_length) << "\n"
           << "protocol: " << DEC(ip_header->protocol) << protocolToStr[ip_header->protocol] << "\n"
           << "src IP: " << DEC(ip_header->srcIp[0]) << "." << DEC(ip_header->srcIp[1]) << "." << DEC(ip_header->srcIp[2]) << "." << DEC(ip_header->srcIp[3]) << "\n"
           << "des IP: " << DEC(ip_header->desIp[0]) << "." << DEC(ip_header->desIp[1]) << "." << DEC(ip_header->desIp[2]) << "." << DEC(ip_header->desIp[3]) << "\n";
        std::cout << ss.str() << "\n";

    }else if (ethernet_header->type[0] == 0x08 && ethernet_header->type[1] == 0x06){    /// for ARP
        assert(true);
    }else{
        assert(true);
        std::cout << "Unknown Type" << std::endl;
    }

    dataPkg->addPacket(*id,packet_data,(int)packet_info->len,packet_info->ts);

    emit window->loadPacket();


    for(int i=0;i<packet_info->len;i++){
        printf(" %02x", packet_data[i]);
        if ((i + 1) % 16 == 0){
            std::cout << std::endl;
        }
    }
    std::cout << std::endl;
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

void Sniffer::startCapture() {

    if ((current_handler = pcap_open_live(current_deivce->name,20,1,0,err))){
        loopCapture();
    }else{
        std::cout << err << std::endl;
        exit(1);
    }

}

void Sniffer::closeCaptrue() {
    if (current_handler){
        pcap_breakloop(current_handler);
        pcap_close(current_handler);
        current_handler = nullptr;
    }
}