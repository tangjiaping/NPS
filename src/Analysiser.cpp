//
// Created by tjp on 3/17/23.
//

#include "../include/Analysiser.h"

EthernetStr Analysiser::parserMacAddress(Ethernet *ethernet_header) {
    EthernetStr ethernetStr;
    std::stringstream ss;
    ss.str("");

    ss << HEX(ethernet_header->desMac[0]) << "-"
       << HEX(ethernet_header->desMac[1]) << "-"
       << HEX(ethernet_header->desMac[2]) << "-"
       << HEX(ethernet_header->desMac[3]) << "-"
       << HEX(ethernet_header->desMac[4]) << "-"
       << HEX(ethernet_header->desMac[5]);
    ethernetStr.desMac = ss.str();

    ss.str("");
    ss << HEX(ethernet_header->srcMac[0]) << "-"
       << HEX(ethernet_header->srcMac[1]) << "-"
       << HEX(ethernet_header->srcMac[2]) << "-"
       << HEX(ethernet_header->srcMac[3]) << "-"
       << HEX(ethernet_header->srcMac[4]) << "-"
       << HEX(ethernet_header->srcMac[5]);
    ethernetStr.srcMac = ss.str();


    if (ethernet_header->type[0] == 0x08 && ethernet_header->type[1] == 0x00){
        ethernetStr.type = "IP";
    }else if (ethernet_header->type[0] == 0x08 && ethernet_header->type[1] == 0x06){
        ethernetStr.type = "ARP";
    }else{
        ethernetStr.type = "UNKNOW";
        std::cout << "Unknown Type" << std::endl;
    }
    return ethernetStr;
}

IPStr Analysiser::parserIp(IP *ip_header) {
    std::stringstream ss;
    IPStr ipStr;

    ipStr.version = ip_header->version;
    ipStr.header_len = ip_header->header_length * 4;
    ipStr.tos = ip_header->service;

    ss << "0x" << HEX(ip_header->identify[0]) << HEX(ip_header->identify[1]);
    ipStr.identify = ss.str();

    unsigned int len = ip_header->total_length[0];
    len = (len << 8) + ip_header->total_length[1];
    ipStr.total_len = len;

    unsigned int flags = (ip_header->flags_segOffset[0]);

    flags = flags >> 5;
    for(int i=0;i<3;i++){
        if (flags & 1){
            ipStr.flag.push_back('1');
        }else{
            ipStr.flag.push_back('0');
        }
        flags >> 1;
    }

    unsigned int offset = ip_header->flags_segOffset[0];
    offset = offset & 0b11111;
    offset = (offset << 8) + ip_header->flags_segOffset[1];

    ipStr.offset = offset;

    ipStr.ttl = ip_header->ttl;

    if (ip_header->protocol == 1){
        ipStr.protocol = "ICMP";
    } else if (ip_header->protocol == 2){
        ipStr.protocol = "IGMP";
    } else if (ip_header->protocol == 6){
        ipStr.protocol = "TCP";
    } else if (ip_header->protocol == 17){
        ipStr.protocol = "UDP";
    }else{
        ipStr.protocol = "UNKNOW";
    }

    ss.str("");
    ss << "0x" << HEX(ip_header->check_sum[0]) << HEX(ip_header->check_sum[1]);
    ipStr.check_sum = ss.str();

    ss.str("");
    ss  << DEC(ip_header->srcIp[0]) << "."
        << DEC(ip_header->srcIp[1]) << "."
        << DEC(ip_header->srcIp[2]) << "."
        << DEC(ip_header->srcIp[3]);
    ipStr.srcIp = ss.str();

    ss.str("");
    ss  << DEC(ip_header->desIp[0]) << "."
        << DEC(ip_header->desIp[1]) << "."
        << DEC(ip_header->desIp[2]) << "."
        << DEC(ip_header->desIp[3]);
    ipStr.desIp = ss.str();
    return ipStr;
}


ARPStr Analysiser::parserARP(ARP *arp_header) {
    ARPStr arpStr;
    std::stringstream ss;

    arpStr.hard_address_type = arp_header->hardwareAddrType;
    arpStr.protocol_type = arp_header->hardwareAddrType;
    arpStr.hard_address_len = arp_header->hardwareAddrLength;
    arpStr.protocol_address_len = arp_header->protocolAddrLength;

    switch (arp_header->opCode) {
        case 1:
            arpStr.op_code = "ARP Request";
            arpStr.protocol = "ARP";
            break;
        case 2:
            arpStr.op_code = "ARP Reply";
            arpStr.protocol = "ARP";
            break;
        case 3:
            arpStr.op_code = "RARP Request";
            arpStr.protocol = "RARP";
            break;
        case 4:
            arpStr.op_code = "RARP Reply";
            arpStr.protocol = "RARP";
            break;
        default:
            arpStr.op_code = "Unknow";
            arpStr.protocol = "--";
            break;
    }

    ss  << DEC(arp_header->srcMac[0]) << "."
        << DEC(arp_header->srcMac[1]) << "."
        << DEC(arp_header->srcMac[2]) << "."
        << DEC(arp_header->srcMac[3]) ;
    arpStr.srcMac = ss.str();

    ss.str("");
    ss  << DEC(arp_header->srcIp[0]) << "."
        << DEC(arp_header->srcIp[1]) << "."
        << DEC(arp_header->srcIp[2]) << "."
        << DEC(arp_header->srcIp[3]) ;
    arpStr.srcIp = ss.str();

    ss.str("");
    ss  << DEC(arp_header->desMac[0]) << "."
        << DEC(arp_header->desMac[1]) << "."
        << DEC(arp_header->desMac[2]) << "."
        << DEC(arp_header->desMac[3]) ;
    arpStr.desMac = ss.str();

    ss.str("");
    ss  << DEC(arp_header->desIp[0]) << "."
        << DEC(arp_header->desIp[1]) << "."
        << DEC(arp_header->desIp[2]) << "."
        << DEC(arp_header->desIp[3]) ;
    arpStr.desIp = ss.str();

    return arpStr;
}

IPv6Str Analysiser::parserIpv6(IPv6 *iPv6) {
    IPv6Str iPv6Str;
    std::stringstream ss;

    unsigned int version = iPv6->version_trafficClass_flowLabel[0];
    iPv6Str.version = (version >> 4);

    iPv6Str.ttl = iPv6->ttl;

    ss.str("");
    unsigned int traffic_class = iPv6->version_trafficClass_flowLabel[0];
    traffic_class = ((traffic_class & 0xf) << 4) + (iPv6->version_trafficClass_flowLabel[1] & 0xf0);
    ss << HEX((traffic_class) << 4);
    iPv6Str.communication = ss.str();

    ss.str("");
    unsigned int flow_table = (iPv6->version_trafficClass_flowLabel[1] & 0xf);
    ss << HEX(flow_table) << HEX(iPv6->version_trafficClass_flowLabel[2]) << HEX(iPv6->version_trafficClass_flowLabel[3]);
    iPv6Str.flow_label = ss.str();

    unsigned int payload = iPv6->playload[0];
    payload = (payload << 8) + iPv6->playload[1];
    iPv6Str.playload = payload;

    ss.str("");
    ss  << HEX(iPv6->srcIp[0]) << HEX(iPv6->srcIp[1]) << ":"
        << HEX(iPv6->srcIp[2]) << HEX(iPv6->srcIp[3]) << ":"
        << HEX(iPv6->srcIp[4]) << HEX(iPv6->srcIp[5]) << ":"
        << HEX(iPv6->srcIp[6]) << HEX(iPv6->srcIp[7]) << ":"
        << HEX(iPv6->srcIp[8]) << HEX(iPv6->srcIp[9]) << ":"
        << HEX(iPv6->srcIp[10]) << HEX(iPv6->srcIp[11]) << ":"
        << HEX(iPv6->srcIp[12]) << HEX(iPv6->srcIp[13]) << ":"
        << HEX(iPv6->srcIp[14]) << HEX(iPv6->srcIp[15]) ;
    iPv6Str.srcIp = ss.str();

    ss.str("");
    ss  << HEX(iPv6->desIp[0]) << HEX(iPv6->desIp[1]) << ":"
        << HEX(iPv6->desIp[2]) << HEX(iPv6->desIp[3]) << ":"
        << HEX(iPv6->desIp[4]) << HEX(iPv6->desIp[5]) << ":"
        << HEX(iPv6->desIp[6]) << HEX(iPv6->desIp[7]) << ":"
        << HEX(iPv6->desIp[8]) << HEX(iPv6->desIp[9]) << ":"
        << HEX(iPv6->desIp[10]) << HEX(iPv6->desIp[11]) << ":"
        << HEX(iPv6->desIp[12]) << HEX(iPv6->desIp[13]) << ":"
        << HEX(iPv6->desIp[14]) << HEX(iPv6->desIp[15]) ;
    iPv6Str.desIp = ss.str();

    iPv6Str.protocol = "IPv6";

    return iPv6Str;
}

unsigned int Analysiser::hexToInt(u_char uChar) {
    if (uChar >= '0' && uChar <= '9'){
        return uChar  - '0';
    }
    if (uChar >= 'A' && uChar <= 'F'){
        return uChar  - 'A' + 10;
    }
    if (uChar >= 'a' && uChar <= 'f'){
        return uChar  - 'a' + 10;
    }
    return 0;
}

TCPStr Analysiser::parserTCP(TCP *tcp) {
    TCPStr tcpStr;
    std::stringstream ss;

//    tcp->srcPort[0] = 0x1;
//    tcp->srcPort[1] = 0xbb;
    unsigned int number = (tcp->srcPort[0]);
    number = (number << 8) + (tcp->srcPort[1]);
    tcpStr.srcPort = number;

//    tcp->desPort[0] = 0xbc;
//    tcp->desPort[1] = 0xf6;
    number = tcp->desPort[0];
    number = (number << 8) + tcp->desPort[1];
    tcpStr.desPort = number;

    number = 0;
    for(int i=0; i<4; i++){
        number = (number << (i * 8)) + tcp->seq[i];
    }
    tcpStr.seq = number;

    number = 0;
    for(int i=0; i<4; i++){
        number = (number << (i * 8)) + tcp->ack[i];
    }
    tcpStr.ack = number;

    tcpStr.header_len = tcp->header_len;
    tcpStr.reserved = tcp->reserved;
    tcpStr.NS = tcp->NS;
    tcpStr.CWR = tcp->CWR;
    tcpStr.ECE = tcp->ECE;
    tcpStr.URG = tcp->URG;
    tcpStr.ACK = tcp->ACK;
    tcpStr.PSH = tcp->PSH;
    tcpStr.RST = tcp->RST;
    tcpStr.SYN = tcp->SYN;
    tcpStr.FIN = tcp->FIN;

    number = tcp->window_size[0];
    number = (number << 8) + tcp->window_size[1];
    tcpStr.window_size = number;

    ss << "0x" << HEX(tcp->checksum[0]) << HEX(tcp->checksum[1]);
    tcpStr.check_sum = ss.str();

    ss.str("");
    ss << HEX(tcp->ugenr_pointer[0]) << HEX(tcp->ugenr_pointer[1]);
    tcpStr.urgent_point = ss.str();

    ss.str("");

    return tcpStr;
}

UDPStr Analysiser::parserUDP(UDP *udp) {
    UDPStr udpStr;
    unsigned int number = (udp->srcPort[0]);
    number = (number << 8) + (udp->srcPort[1]);
    udpStr.srcPort = number;

    number = (udp->desPort[0]);
    number = (number << 8) + (udp->desPort[1]);
    udpStr.desPort = number;

    number = (udp->total_len[0]);
    number = (number << 8) + (udp->total_len[1]);
    udpStr.total_len = number;

    std::stringstream ss;
    ss << "0x" << HEX(udp->check_sum[0]) << HEX(udp->check_sum[1]);
    udpStr.check_sum = ss.str();
    return udpStr;
}