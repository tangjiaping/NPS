//
// Created by tjp on 3/11/23.
//

#include "gtest/gtest.h"
#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//链路层数据包格式 以太网雷系
typedef struct {
    //目的mac地址
    u_char DestMac[6];
    //源mac地址
    u_char SrcMac[6];
    //协议类型 0x0800为IPV4
    u_char Etype[2];
}ETHHEADER;
//IP层数据包格式
typedef struct {
    //头长度
    int header_len:4;
    //版本
    int version:4;
    u_char tos:8;
    //总长度
    int total_len:16;
    int ident:16;
    int flags:16;
    //生存时间ttl
    u_char ttl:8;
    u_char proto:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}IPHEADER;
//协议映射表
char *Proto[]={
        "Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};


void writeToFile(u_char*user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    pcap_dump((u_char *)user, header, pkt_data);
}

//回调函数
void pcap_handle(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{

    writeToFile(user,header,pkt_data);

    ETHHEADER *eth_header=(ETHHEADER*)pkt_data;
    printf("---------------Begin Analysis-----------------\n");
    printf("----------------------------------------------\n");
    printf("Packet length: %d \n",header->len);
    //解析数据包IP头部
    if(header->len>=14){
        IPHEADER *ip_header=(IPHEADER*)(pkt_data+14);
        //解析协议类型
        char strType[100];
        if(ip_header->proto>7)
            strcpy(strType,"IP/UNKNWN");
        else
            strcpy(strType,Proto[ip_header->proto]);
        printf("Source MAC : %02X-%02X-%02X-%02X-%02X-%02X==>",eth_header->SrcMac[0],eth_header->SrcMac[1],eth_header->SrcMac[2],eth_header->SrcMac[3],eth_header->SrcMac[4],eth_header->SrcMac[5]);
        printf("Dest   MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",eth_header->DestMac[0],eth_header->DestMac[1],eth_header->DestMac[2],eth_header->DestMac[3],eth_header->DestMac[4],eth_header->DestMac[5]);
        printf("Source IP : %d.%d.%d.%d==>",ip_header->sourceIP[0],ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);
        printf("Dest   IP : %d.%d.%d.%d\n",ip_header->destIP[0],ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);
        printf("Protocol : %s\n",strType);

        //显示数据帧内容
        int i;
        for(i=0; i<(int)header->len; ++i)  {
            printf("%02X ", pkt_data[i]);
            if( (i + 1) % 16 == 0 )
                printf("\n");
        }
        printf("\n\n");
        printf("-------------ASCII------------------");
        u_char * data = (u_char *)malloc((header->len- 14 - sizeof(IPHEADER))*sizeof(u_char* ));
        strncpy(reinterpret_cast<char *>(data), (char*)(pkt_data + 14 + sizeof(IPHEADER)), header->len - 14 - sizeof(IPHEADER));
        printf("%s",data);

    }
}

int test(int argc, char **argv)
{
    char *device="eth0";
    char errbuf[1024];
    pcap_t *phandle;

    bpf_u_int32 ipaddress,ipmask;
    struct bpf_program fcode;
    int datalink;

    if((device=pcap_lookupdev(errbuf))==NULL){
        perror(errbuf);
        return 1;
    }
    else
        printf("device: %s\n",device);

    phandle=pcap_open_live(device,200,0,0,errbuf);
    if(phandle==NULL){
        perror(errbuf);
        return 1;
    }

    if(pcap_lookupnet(device,&ipaddress,&ipmask,errbuf)==-1){
        perror(errbuf);
        return 1;
    }
    else{
        char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];
        if(inet_ntop(AF_INET,&ipaddress,ip,sizeof(ip))==NULL)
            perror("inet_ntop error");
        else if(inet_ntop(AF_INET,&ipmask,mask,sizeof(mask))==NULL)
            perror("inet_ntop error");
        printf("IP address: %s, Network Mask: %s\n",ip,mask);
    }

    int flag=1;
//    while(flag){
//        //input the design filter
//        printf("Input packet Filter: ");
//        char filterString[1024];
//        scanf("%s",filterString);
//
//        if(pcap_compile(phandle,&fcode,filterString,0,ipmask)==-1)
//            fprintf(stderr,"pcap_compile: %s,please input again....\n",pcap_geterr(phandle));
//        else
//            flag=0;
//    }
//
//    if(pcap_setfilter(phandle,&fcode)==-1){
//        fprintf(stderr,"pcap_setfilter: %s\n",pcap_geterr(phandle));
//        return 1;
//    }

    if((datalink=pcap_datalink(phandle))==-1){
        fprintf(stderr,"pcap_datalink: %s\n",pcap_geterr(phandle));
        return 1;
    }

    printf("datalink= %d\n",datalink);


    pcap_dumper_t *t = pcap_dump_open(phandle, "./test.pcap");

    if (NULL == t){
        fprintf(stderr, "pcap_dump_open failed.\n");
        return 1;
    }

    pcap_loop(phandle,-1,pcap_handle,( u_char * )t);
    pcap_dump_close(t);

    return 0;
}


TEST(TestLibcap, loopupDev){

    char* dev = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];


    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr){
        std::cout << errbuf << std::endl;
    }else{
        std::cout << "Find: " << dev << std::endl;
    }
}

TEST(TestLibpcap, openPcap){
    /**
     * parameter:
     *      device: the name of network interface
     *      snaplen: the length of package you want to capture
     *      promise: 1 representative mix mode
     *      to_ms: waiting time
     *      ebuf: store error information
     */

    char ebuf[PCAP_ERRBUF_SIZE];
    std::string device = "wlp3s0";
    pcap_t* network_interface = pcap_open_live(device.data(),1024,0,0,ebuf);

    if (!network_interface){
        std::cout << ebuf << std::endl;
        exit(1);
    }

    pcap_pkthdr packet_info;
    /**
     * function: capture one package
     * paramter:
     *      1. libpcap
     *      2. package header
     */
    const u_char * packet_data = pcap_next(network_interface,&packet_info);

    std::cout << "Packet length: " << packet_info.len << "\n"
              << "Number of bytes: " << packet_info.caplen << "\n"
              << "Recived time: " << ctime((const time_t*)&packet_info.ts.tv_sec) << "\n"
              << "Data: " << packet_data << std::endl;
    pcap_close(network_interface);
}



struct Ethernet{
    u_char desMac[6];
    u_char srcMac[6];
    u_char type[2];
};

struct Ip{
    int version:4;
    int header_length:4;
    int service:8;
    int total_length:16;

    int identify:16;
    int flags:3;
    int offset:13;

    int ttl:8;
    // ICMP: 1; TCP:6; UDP:17
    int protocol:8;
    int checksum:16;

    u_char srcIp[4];
    u_char desIp[4];

};


void packetHandler(u_char* arg,const struct pcap_pkthdr* packet_info,const u_char* packet_data){
    int* id = (int*)arg;
    std::cout << "id: " << ++(*id) << "\n"
              << "Packet length: " << packet_info->len << "\n"
              << "Number of bytes: " << packet_info->caplen << "\n"
              << "Recived time: " << ctime((const time_t*)&packet_info->ts.tv_sec) << std::endl;

    Ethernet* ethernet_header;
    ethernet_header = (Ethernet*)packet_data;
    printf("Source MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",
           ethernet_header->srcMac[0],ethernet_header->srcMac[1],
           ethernet_header->srcMac[2],ethernet_header->srcMac[3],
           ethernet_header->srcMac[4],ethernet_header->srcMac[5]);
    printf("Dest   MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",
           ethernet_header->desMac[0],ethernet_header->desMac[1],
           ethernet_header->desMac[2],ethernet_header->desMac[3],
           ethernet_header->desMac[4],ethernet_header->desMac[5]);

    Ip* ip_header = (Ip*)(packet_data+14);
    printf("Source IP : %d.%d.%d.%d\n",
           ip_header->srcIp[0],
           ip_header->srcIp[1],
           ip_header->srcIp[2],
           ip_header->srcIp[3]);
    printf("Des    IP : %d.%d.%d.%d\n",
           ip_header->desIp[0],
           ip_header->desIp[1],
           ip_header->desIp[2],
           ip_header->desIp[3]);


    for(int i=0;i<packet_info->len;i++){
        printf(" %02x", packet_data[i]);
        if ((i + 1) % 16 == 0){
            std::cout << std::endl;
        }
    }
    std::cout << std::endl;
}


TEST(TestLibpcap, pcapLoop){
    /**
     * parameter:
     *      device: the name of network interface
     *      snaplen: the length of package you want to capture
     *      promise: 1 representative mix mode
     *      to_ms: waiting time
     *      ebuf: store error information
     */

    char ebuf[PCAP_ERRBUF_SIZE];
    std::string device = "wlp3s0";
    pcap_t* network_interface = pcap_open_live(device.data(),1024,0,0,ebuf);

    if (!network_interface){
        std::cout << ebuf << std::endl;
        exit(1);
    }

    int id = 0;
    /**
     * function: capture packet until error or satify exit condition
     * principle: it invokes callback function for any capture packet, so we can parser packet in callback function.
     *
     * parameter:
     *  1. libpcap
     *  2. packet numbers you want to capture. -1 representative always no return.
     *  3. callback function
     *  4. arg of callback function.
     */
    pcap_loop(network_interface,-1,packetHandler,(u_char*)&id);

    pcap_close(network_interface);
}


/**
 * in order to finish packet filter, we should accomplish three steps:
 *      1. construct a filter expression
 *      2. compile the filter expression
 *      3. apply the filter
 *
 *      int pcap_compile(pcap_t* p, struct bpf_program *fp, char* expression, int optimize, bpf_u_int32 netmask);
 *          parameter:
 *              p: network_interface
 *              fp: bpf filter regular
 *              expression: the string formal of filter regular
 *              optimize:
 *              mask:
 *
 *      int pcap_setfilter(pcap_t* p, struct bpf_program* fp)
 *          parameter:
 *              p: network_interface
 *              fp: bpf filter regular
 */
TEST(TestLibpcap, pcapFilter){
    /**
     * parameter:
     *      device: the name of network interface
     *      snaplen: the length of package you want to capture
     *      promise: 1 representative mix mode
     *      to_ms: waiting time
     *      ebuf: store error information
     */

    char ebuf[PCAP_ERRBUF_SIZE];
    std::string device = "wlp3s0";
    pcap_t* network_interface = pcap_open_live(device.data(),1024,0,0,ebuf);

    if (!network_interface){
        std::cout << ebuf << std::endl;
        exit(1);
    }

    struct bpf_program filter;
    if (pcap_compile(network_interface,&filter,"dst host 159.226.8.7",1,PCAP_NETMASK_UNKNOWN) == -1){
        pcap_perror(network_interface,ebuf);
        std::cout << "compile error: " << ebuf;
        exit(1);
    }
    pcap_setfilter(network_interface,&filter);

    int id = 0;
    /**
     * function: capture packet until error or satify exit condition
     * principle: it invokes callback function for any capture packet, so we can parser packet in callback function.
     *
     * parameter:
     *  1. libpcap
     *  2. packet numbers you want to capture. -1 representative always no return.
     *  3. callback function
     *  4. arg of callback function.
     */
    pcap_loop(network_interface,-1,packetHandler,(u_char*)&id);

    pcap_close(network_interface);
}

TEST(test,test){
    u_char c1 = 0x01;
    u_char c2 = 0xbb;
    std::cout << (c1 << 8) + c2 << std::endl;
    std::cout << (80 << 8) + 16 << std::endl;
    std::cout << ((unsigned int)c1 << 8) + (unsigned  int)c2 << std::endl;
}