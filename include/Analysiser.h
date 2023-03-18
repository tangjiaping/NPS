//
// Created by tjp on 3/17/23.
//

#ifndef NPS_ANALYSISER_H
#define NPS_ANALYSISER_H


#include <string>
#include "Sniffer.h"

struct EthernetStr{
    std::string srcMac;
    std::string desMac;
    std::string type;
};

struct IPStr{
    unsigned int version;
    unsigned int header_len;
    std::string tos;
    unsigned int total_len;
    std::string identify;
    std::string flag;
    unsigned int offset;
    unsigned int ttl;
    std::string protocol;
    std::string check_sum;
    std::string srcIp;
    std::string desIp;

};

struct IPv6Str{
    unsigned int version;
    std::string communication;
    std::string flow_label;

    unsigned int playload;

    unsigned int ttl;
    std::string protocol;

    std::string srcIp;
    std::string desIp;

};

struct TCPStr{
    unsigned int srcPort;
    unsigned int desPort;
    unsigned int seq;
    unsigned int ack;
    unsigned int header_len;
    unsigned int reserved;
    unsigned int NS;
    unsigned int CWR;
    unsigned int ECE;
    unsigned int URG;
    unsigned int ACK;
    unsigned int PSH;
    unsigned int RST;
    unsigned int SYN;
    unsigned int FIN;
    unsigned int window_size;
    std::string check_sum;
    std::string urgent_point;

};

struct UDPStr{
    unsigned int srcPort;
    unsigned int desPort;
    unsigned int total_len;
    std::string check_sum;
};

struct ARPStr{
    unsigned int hard_address_type;
    unsigned int protocol_type;
    unsigned int hard_address_len;
    unsigned int protocol_address_len;
    std::string op_code;
    std::string srcMac;
    std::string srcIp;
    std::string desMac;
    std::string desIp;
    std::string protocol;
};

class Analysiser {
public:
    static EthernetStr parserMacAddress(Ethernet* ethernet);
    static IPStr parserIp(IP* ip_header);
    static ARPStr parserARP(ARP* arp_header);
    static IPv6Str parserIpv6(IPv6* iPv6);

    static TCPStr parserTCP(TCP* tcp);
    static UDPStr parserUDP(UDP* tcp);

    static unsigned int hexToInt(u_char uChar);
};


#endif //NPS_ANALYSISER_H
