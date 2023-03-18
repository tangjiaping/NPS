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
    u_char header_length:4;
    u_char version:4;

    u_char service;
    u_char total_length[2];

    u_char identify[2];

    u_char flags_segOffset[2];


    u_char ttl;
    u_char protocol; // {1:ICMP; 2:IGMP; 6:TCP; 17:UDP}

    u_char check_sum[2];

    u_char srcIp[4];
    u_char desIp[4];
};

struct IPv6{

    u_char version_trafficClass_flowLabel[4];

    u_char playload[2];
    u_char next_header;
    u_char ttl;

    u_char srcIp[16];
    u_char desIp[16];
};


struct TCP{
    u_char srcPort[2];
    u_char desPort[2];
    u_char seq[4];
    u_char ack[4];

    u_char header_len:4;
    u_char reserved:3;
    u_char NS:1;

    u_char CWR:1;
    u_char ECE:1;
    u_char URG:1;
    u_char ACK:1;
    u_char PSH:1;
    u_char RST:1;
    u_char SYN:1;
    u_char FIN:1;

    u_char window_size[2];
    u_char checksum[2];
    u_char ugenr_pointer[2];


};

struct UDP{
    u_char srcPort[2];
    u_char desPort[2];
    u_char total_len[2];
    u_char check_sum[2];
};

struct ICMP{
    u_char type;
    u_char code;
    u_char check_sum[2];
    u_char other[4];

};
struct ARP{
    u_char hardwareAddrType[2];
    u_char protocolType[2];
    u_char hardwareAddrLength;
    u_char protocolAddrLength;
    u_char opCode[2];
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
