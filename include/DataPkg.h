//
// Created by tjp on 3/11/23.
//

#ifndef NPS_DATAPKG_H
#define NPS_DATAPKG_H


#include <vector>
#include <string>
#include <pcap.h>
#include <mutex>


struct Packet{
    u_char* data = nullptr;
    int len = 0;
    struct timeval ts;
    int id = 0;
    std::string interface;
    Packet(u_char* data) : data(data){ }

    Packet(u_char* data_,int len_,struct timeval ts_,const std::string& interface)
            :data(data_),
            len(len_),
            ts(ts_),
            interface(interface){

    }
};
class DataPkg {

public:
    std::vector<pcap_if*> network_cards;

    std::vector<Packet> packets;

    std::mutex mtx;

    void clear();

    void parserDevice(pcap_if* interface_list);

    void addPacket(int id,const u_char* data,int len,timeval ts);

    Packet getPacket(int idx){
        if (idx >= packets.size()){
          return {nullptr};
        }
        return packets[idx];
    }
};


#endif //NPS_DATAPKG_H
