//
// Created by tjp on 3/11/23.
//

#ifndef NPS_SNIFFER_H
#define NPS_SNIFFER_H

#include <pcap.h>
#include <iostream>
#include <thread>
#include <sstream>
#include <iomanip>


#include "DataPkg.h"
#include "MainWindow.h"
#include "Protocol.h"




class Sniffer {
public:
    char err[PCAP_ERRBUF_SIZE];
    static DataPkg* dataPkg;
    static MainWindow* window;

    pcap_if* current_deivce = nullptr;
    pcap_t* current_handler = nullptr;
    struct bpf_program filter;


private:
    static void packetHandler(u_char* arg,const struct pcap_pkthdr* packet_info,const u_char* packet_data);

public:
    Sniffer(){}

    void initDataPkg(DataPkg* dataPkg){
        Sniffer::dataPkg = dataPkg;
    }

    void serachDevice();

    void changeDevice(int index);

    bool startCapture(const std::string& expr);

    void loopCapture();

    void closeCaptrue();

    bool setFilter(const std::string& expr);
};


#endif //NPS_SNIFFER_H
