//
// Created by tjp on 3/12/23.
//

#ifndef NPS_PROTOCOL_H
#define NPS_PROTOCOL_H

#include <cstdlib>
#include <iostream>
#include <thread>
#include <sstream>
#include <iomanip>

#define HEX( x ) \
    std::setw(2) << std::setfill('0') << std::hex << (int)(x)

#define DEC( x ) \
    std::dec << (int)(x)

struct Ethernet{

    u_char desMac[6];
    u_char srcMac[6];
    u_char type[2]; // {0x0800:IP; 0x0806: ARP}
};

struct IP{
    int version:4;
    int header_length:4;
    u_char service;
    int total_length:16;

    int identify:16;
    int flags:3;
    int seg_offset:13;

    int ttl:8;
    int protocol:8; // {1:ICMP; 2:IGMP; 6:TCP; 17:UDP}
    int check_sum:16;

    u_char srcIp[4];
    u_char desIp[4];
};

struct ARP{
    u_char hardwareAddrType[2];
    u_char protocolType[2];
    u_char hardwareAddrLength[1];
    u_char protocolAddrLength[1];
    u_char opCode[1];
    u_char srcMac[4];
    u_char srcIp[4];
    u_char desMac[4];
    u_char desIp[4];
};

static std::map<int,std::string> protocolToStr{
        {1,"ICMP"},
        {2,"IGMP"},
        {6,"TCP"},
        {17,"UDP"}
};
#endif //NPS_PROTOCOL_H
