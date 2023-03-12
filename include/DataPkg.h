//
// Created by tjp on 3/11/23.
//

#ifndef NPS_DATAPKG_H
#define NPS_DATAPKG_H


#include <vector>
#include <string>
#include <pcap.h>


struct Packet{
    u_char* data = nullptr;
    int len = 0;
    struct timeval ts;

    Packet(u_char* data_,int len_,struct timeval ts_):data(data_),len(len_),ts(ts_){

    }
};
class DataPkg {

public:
    std::vector<pcap_if*> network_cards;

    std::vector<Packet> packets;

    void parserDevice(pcap_if* interface_list);

    void addPacket(const u_char* data,int len,timeval ts);
};


#endif //NPS_DATAPKG_H
