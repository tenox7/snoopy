//                                                       &oo{
//            _____ _____ _____ _____ ____ __   __    /~~~~~~~~\
//           |  ___|   | |  _  |  _  | __ |\ \ / /   /__________\
//           |___  | | | | |_| | |_| |  __| \   /      |______|
//        ---|_____|_|___|_____|_____|_|-----|_|-------|______|----
//      -------------------------------------------------------------
// Basic TCP/IP Sniffer for Windows, v1.0 by Antoni Sawicki <as@tenoware.com>   
// Copyright (c) 2015 by Antoni Sawicki - Lincensed under BSD
//
// Note that this application can only snoop unicast TCP, UDP and ICMP traffic              
// You cannot listen to layer 2, multicasts, broadcasts, etc.
//                                                                                        
// todo:                                                                                  
// validate bind to ip address, currently you can bind to /? ;)
// find best route ip address using GetBestInterface(inet_addr("0.0.0.0"), &bestidx);     
// add basic filtering options, for now use | findstr                                     
// add some more protocol analysis, include /etc/services and /etc/protocols as .h                                              
//                                                                                        
#define WIN32_LEAN_AND_MEAN                                                               
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma comment(lib, "ws2_32.lib") 
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

typedef struct _IP_HEADER_ {
   BYTE  ip_hl:4, ip_v:4;
   BYTE  tos_dscp:6, tos_ecn:2;  
   WORD  len;
   WORD  id;
   WORD  flags;
   BYTE  ttl;
   BYTE  protocol;
   WORD  chksum;
   DWORD src_ip; 
   DWORD dst_ip;
} IPHEADER;

typedef struct _TCP_HEADER_ {
   WORD  source_port;
   WORD  destination_port;
   DWORD seq_number;
   DWORD ack_number;
   WORD  info_ctrl;
   WORD  window;
   WORD  checksum;   
   WORD  urgent_pointer;
} TCPHEADER;

typedef struct _UDP_HEADER_ {
    WORD source_port;
    WORD destination_port;
    WORD len;
    WORD checksum;
} UDPHEADER; 

typedef struct _ICMP_HEADER_ {
   BYTE type;
   BYTE code;
   WORD checksum;
} ICMPHEADER;

void errpt(char *msg, ...) {
    va_list valist;
    char vaBuff[1024], errBuff[1024];
    DWORD err;

    va_start(valist, msg); 
    _vsnprintf(vaBuff, sizeof(vaBuff), msg, valist); 
    va_end(valist);
    printf("ERROR: %s\n", vaBuff);
    err=WSAGetLastError();
    if(err) {
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errBuff, sizeof(errBuff), NULL);
        printf("%d [%08X] %s\n\n", err, err, errBuff);
    }    
    printf("\n\n");
    WSACleanup();
    ExitProcess(1);
}

int main(int argc, char **argv) {                //                   .o. 
    struct     sockaddr_in snoop_addr;           //                   |  |    _   ,
    SOCKET     snoop_sock = -1;                  //                 .',  L.-'` `\ ||
    WSADATA    sa_data;                          //               __\___,|__--,__`_|__
    IPHEADER   *ip_header;                       //              |    %     `=`       |
    TCPHEADER  *tcp_header;                      //              | ___%_______________|
    UDPHEADER  *udp_header;                      //              |    `               |
    ICMPHEADER *icmp_header;                     //              | -------------------|
    BYTE       flags;                            //              |____________________|
    DWORD      optval=1, dwLen=0, verbose=0;     //                |~~~~~~~~~~~~~~~~|
    char       packet[65535];                    //            jgs | ---------------|  ,
    char       *argaddr;                         //            \|  | _______________| / /
    struct     in_addr in;                       //         \. \,\\|, .   .   /,  / |///, /
    char       src_ip[20], dst_ip[20];
    SYSTEMTIME lt;

    if(argc<2)
        errpt("\rUsage:\n\n%s [-v] <ipaddr>\n\nipaddr : local IP address on the NIC you want to attach to\n"
              "    -v : verbose mode, print more detailed protocol info\n\nv1.0 written by Antoni Sawicki <as@tenoware.com>\n", argv[0]);
    
    argaddr=argv[1];
    if((argv[1][0]=='-' || argv[1][0]=='/') && argv[1][1]=='v') {
        verbose=1;
        if(argc>2 && argv[2] && strlen(argv[2]))
            argaddr=argv[2];
    }
    
    WSAStartup(MAKEWORD(2,2), &sa_data);
	snoop_sock=socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if(snoop_sock==SOCKET_ERROR) 
        errpt("Opening Socket");
    
    snoop_addr.sin_family = AF_INET;
	snoop_addr.sin_port = htons(0);
	snoop_addr.sin_addr.s_addr = inet_addr(argaddr);
    printf("Binding to %s\n", argaddr);

    if(bind(snoop_sock, (struct sockaddr *)&snoop_addr, sizeof(snoop_addr))==SOCKET_ERROR) 
        errpt("Bind to %s", argaddr);
    
    if(WSAIoctl(snoop_sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwLen, NULL, NULL)==SOCKET_ERROR)
        errpt("SIO_RCVALL");
    
    while(1) {
        memset(packet, 0, sizeof(packet));
        memset(src_ip, 0, sizeof(src_ip));
        memset(dst_ip, 0, sizeof(dst_ip));
        ip_header=NULL;
        tcp_header=NULL;
        udp_header=NULL;
        icmp_header=NULL;

        if(recv(snoop_sock, packet, sizeof(packet), 0) < sizeof(IPHEADER))
            continue;
        
        ip_header=(IPHEADER*)packet;
        
        if(ip_header->ip_v!=4) 
            continue;
        
        in.S_un.S_addr=ip_header->src_ip;
        strcpy(src_ip, inet_ntoa(in));
        in.S_un.S_addr=ip_header->dst_ip;
        strcpy(dst_ip, inet_ntoa(in));
        
        GetLocalTime(&lt);
        
        // TCP
        if(ip_header->protocol==6) {
            tcp_header=(TCPHEADER*) &packet[ip_header->ip_hl*sizeof(DWORD)];
            flags=(ntohs(tcp_header->info_ctrl) & 0x003F); 
            printf("%02d:%02d:%02d.%03d TCP ", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
            printf("%s:%ld -> %s:%ld ", src_ip, htons(tcp_header->source_port), dst_ip, htons(tcp_header->destination_port));
            if(flags & 0x01) printf("FIN ");
            if(flags & 0x02) printf("SYN ");
            if(flags & 0x04) printf("RST ");
            if(flags & 0x08) printf("PSH ");
            if(flags & 0x10) printf("ACK ");
            if(flags & 0x20) printf("URG ");
            if(verbose) printf("seq %lu ", ntohl(tcp_header->seq_number));
            if(verbose) printf("ack %lu ", ntohl(tcp_header->ack_number));
            if(verbose) printf("win %u ", ntohs(tcp_header->window));
        }
        
        // UDP
        else if(ip_header->protocol==17) {
            udp_header=(UDPHEADER*) &packet[ip_header->ip_hl*sizeof(DWORD)];
            printf("%02d:%02d:%02d.%03d UDP ", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
            printf("%s:%ld -> %s:%ld ", src_ip, htons(udp_header->source_port), dst_ip, htons(udp_header->destination_port));
        }
        
        // ICMP
        else if(ip_header->protocol==1) {
            icmp_header=(ICMPHEADER*) &packet[ip_header->ip_hl*sizeof(DWORD)];
            printf("%02d:%02d:%02d.%03d ICMP ", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
            printf("%s -> %s ", src_ip, dst_ip);
            printf("type %d code %d ", icmp_header->type, icmp_header->code);
                 if(icmp_header->type==0) printf("[echo reply] ");
            else if(icmp_header->type==8) printf("[echo request] ");
            else if(icmp_header->type==3) printf("[dst unreachable] ");
            else if(icmp_header->type==5) printf("[redirect] ");
            else if(icmp_header->type==1) printf("[time exceeded] ");
        }
        
        else {
            printf("%02d:%02d:%02d.%03d >>> Unknown protocol=0x%x ", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds, ip_header->protocol);
            printf("%s -> %s ", src_ip, dst_ip);
        }

        if(verbose) printf("dscp %u ecn %u ttl %u ", ip_header->tos_dscp, ip_header->tos_ecn, ip_header->ttl);
        if(ntohs(ip_header->flags) & 0x4000) printf("DF ");
        putchar('\n');
        fflush(stdout); // helps findstr
    } 
   return 0;
}
