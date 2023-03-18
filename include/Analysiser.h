//
// Created by tjp on 3/17/23.
//

#ifndef NPS_ANALYSISER_H
#define NPS_ANALYSISER_H


#include <string>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <net/if_arp.h>

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

struct ICMPStr{
    uint8_t type;
    uint8_t code;
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
    static EthernetStr parserEthernet(Ethernet* ethernet);
    static IPStr parserIp(IP* ip_header);
    static ARPStr parserARP(ARP* arp_header);
    static IPv6Str parserIpv6(IPv6* iPv6);

    static TCPStr parserTCP(TCP* tcp);
    static UDPStr parserUDP(UDP* tcp);

    static ICMPStr parserICMP(ICMP* icmp);

    static std::string icmpMessage(uint8_t type,uint8_t code);



    static EthernetStr parserEther_header(ether_header* etherHeader);
    static IPStr parserIpv4(ip* ip);

    static std::string toHex(uint8_t num){
        std::stringstream ss;
        ss << HEX(num);
        return ss.str();
    }





};


#endif //NPS_ANALYSISER_H
