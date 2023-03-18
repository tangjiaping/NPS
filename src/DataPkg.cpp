//
// Created by tjp on 3/11/23.
//

#include <cstring>
#include "../include/DataPkg.h"


void DataPkg::parserDevice(pcap_if *interface_list) {
    while (interface_list != nullptr){
        network_cards.push_back(interface_list);
        auto next = interface_list->next;
        interface_list->next = nullptr;
        interface_list = next;
    }
}

void DataPkg::addPacket(int id,const u_char *from, int len, timeval ts) {
    auto* data = (u_char*)new u_char[len];
    std::memcpy(data,from,len);
    mtx.lock();
    Packet packet(data,len,ts,"");
    packet.id = id;
    packets.push_back(packet);
    mtx.unlock();
}

void DataPkg::clear() {
    mtx.lock();
    for(int i=0;i<packets.size();i++){
        delete packets[i].data;
        packets[i].data = nullptr;
    }
    packets.clear();
    mtx.unlock();


}