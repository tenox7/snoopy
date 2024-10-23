//                                                       &oo{
//            _____ _____ _____ _____ ____ __   __    /~~~~~~~~\
//           |  ___|   | |  _  |  _  | __ |\ \ / /   /__________\
//           |___  | | | | |_| | |_| |  __| \   /      |______|
//        ---|_____|_|___|_____|_____|_|-----|_|-------|______|----
//      -------------------------------------------------------------
// Basic TCP/IP Sniffer for Windows, v1.5 by Antoni Sawicki <as@tenoware.com>
// Copyright (c) 2015-2024 by Antoni Sawicki
// Lincensed under BSD
//
// Note that this application can only snoop unicast TCP, UDP and ICMP traffic
// You cannot listen to layer 2, multicasts, broadcasts, etc. Also IPv4 only.
//
// todo:
// basic filtering options, for now use | findstr
// name resolution
// ipv6
//
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define BUFFER_SIZE 65536
#define USAGE "\rUsage:\n\nsnoopy [-v] <ipaddr>\n\nipaddr : local IP address on the NIC you want to attach to\n" \
"    -v : verbose mode, print more detailed protocol info\n\nv1.4 written by Antoni Sawicki <as@tenoware.com>\n"

const char tcp_flags[8][4] = {"CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"};

typedef struct _IP_HEADER_ {
    BYTE  ip_hl : 4, ip_v : 4;
    BYTE  tos_ecn : 2, tos_dscp : 6;
    WORD  len;
    WORD  id;
    WORD  fragmentoffset : 13, rsrvd : 1, DF : 1, MF : 1;
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
    BYTE  data_offset : 4, rsrvd : 4;
    BYTE  flags;
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

void errpt(char* msg, ...) {
    va_list valist;
    char errBuff[1024] = { 0 };
    DWORD err;

    printf("ERROR: ");
    va_start(valist, msg);
    vprintf(msg, valist);
    va_end(valist);
    err = WSAGetLastError();
    if (err) {
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errBuff, sizeof(errBuff), NULL);
        printf("%d [%08X] %s\n", err, err, errBuff);
    }
    printf("\n");
    WSACleanup();
    ExitProcess(1);
}

IN_ADDR getIpAddr() {
    DWORD idx, status, size=0, i;
    PMIB_IPADDRTABLE iptbl;
    IN_ADDR ip;

    status=GetBestInterface(inet_addr("0.0.0.0"), &idx);
    if (status != NO_ERROR)
        errpt("GetBestInterface(): %d", status);

    iptbl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MIB_IPADDRTABLE));
    if (iptbl == NULL)
        errpt("Unable to allocate memory for iptbl size");

    GetIpAddrTable(iptbl, &size, 0);
    HeapFree(GetProcessHeap(), 0, iptbl);
    iptbl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (iptbl == NULL)
        errpt("Unable to allocate memory for IP Table");

    status = GetIpAddrTable(iptbl, &size, 0);
    if (status != NO_ERROR)
        errpt("GetIpAddrTable Err=%d", status);

    ip.S_un.S_addr = INADDR_NONE;
    for (i = 0; i < iptbl->dwNumEntries; i++) {
        if (iptbl->table[i].dwIndex == idx) {
            ip.S_un.S_addr = iptbl->table[i].dwAddr;
            HeapFree(GetProcessHeap(), 0, iptbl);
            return ip;
        }
    }
    errpt("No ip address specified and no suitable interface found");
    return ip;
}

int main(int argc, char** argv) {                       //                   .o.
    struct      sockaddr_in snoop_addr;                 //                   |  |    _   ,
    SOCKET      snoop_sock = -1;                        //                 .',  L.-'` `\ ||
    WSADATA     sa_data;                                //               __\___,|__--,__`_|__
    IPHEADER*   ip_header;                              //              |    %     `=`       |
    TCPHEADER*  tcp_header;                             //              | ___%_______________|
    UDPHEADER*  udp_header;                             //              |    `               |
    ICMPHEADER* icmp_header;                            //              | -------------------|
    BYTE        flags;                                  //              |____________________|
    DWORD       optval = 1, dwLen = 0;                  //                |~~~~~~~~~~~~~~~~|
    char*       packet;                                 //            jgs | ---------------|  ,
    IN_ADDR     bindIP = { 0 };                         //            \|  | _______________| / /
    IN_ADDR     pktIP = { 0 };                          //         \. \,\\|, .   .   /,  / |///, /
    char        src_ip[20], dst_ip[20];
    SYSTEMTIME  lt;
    int         argn=0, verbose=0, gotIP=0;

    bindIP.S_un.S_addr = INADDR_NONE;
    for (argn = 1; argn < argc; argn++) {
        wprintf(L">>> argv[%d]=%S\n", argn, argv[argn]);
        if ((argv[argn][0] == '-' || argv[argn][0] == '/') && argv[argn][1] == 'v') {
            verbose = 1;
        }
        else if (isdigit(argv[argn][0])) {
            gotIP = 1;
            bindIP.S_un.S_addr = inet_addr(argv[argn]);
        }
        else {
            errpt(USAGE);
        }
    }

    if (!gotIP)
        bindIP = getIpAddr();

    if (WSAStartup(MAKEWORD(2, 2), &sa_data)!=0)
        errpt("Starting WSA");

    snoop_sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, 0);
    if (snoop_sock == SOCKET_ERROR)
        errpt("Opening Socket");

    snoop_addr.sin_family = AF_INET;
    snoop_addr.sin_port = htons(0);
    snoop_addr.sin_addr = bindIP;
    if (snoop_addr.sin_addr.s_addr == INADDR_NONE)
        errpt("Incorrect IP address");

    printf("Binding to %s\n", inet_ntoa(snoop_addr.sin_addr));

    if (bind(snoop_sock, (struct sockaddr*)&snoop_addr, sizeof(snoop_addr)) == SOCKET_ERROR)
        errpt("Bind to %s", inet_ntoa(snoop_addr.sin_addr));

    if (WSAIoctl(snoop_sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwLen, NULL, NULL) == SOCKET_ERROR)
        errpt("SIO_RCVALL");

    packet = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE);
    if (packet == NULL)
        errpt("Unable to allocate memory");

    while (1) {
        ZeroMemory(packet, BUFFER_SIZE);
        ZeroMemory(src_ip, sizeof(src_ip));
        ZeroMemory(dst_ip, sizeof(dst_ip));
        ip_header = NULL;
        tcp_header = NULL;
        udp_header = NULL;
        icmp_header = NULL;

        if (recv(snoop_sock, packet, BUFFER_SIZE, 0) < sizeof(IPHEADER))
            continue;

        ip_header = (IPHEADER*)packet;

        if (ip_header->ip_v != 4)
            continue;

        pktIP.S_un.S_addr = ip_header->src_ip;
        strcpy(src_ip, inet_ntoa(pktIP));
        pktIP.S_un.S_addr = ip_header->dst_ip;
        strcpy(dst_ip, inet_ntoa(pktIP));

        GetLocalTime(&lt);

        // TCP
        if (ip_header->protocol == 6) {
            printf("%02d:%02d:%02d.%03d %s ", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds, proto[ip_header->protocol]);
            tcp_header = (TCPHEADER*)&packet[ip_header->ip_hl * sizeof(DWORD)];
            printf("%s:%ld -> %s:%ld ", src_ip, htons(tcp_header->source_port), dst_ip, htons(tcp_header->destination_port));

            for (flags = 0; flags < sizeof(tcp_flags) / sizeof(*tcp_flags); flags++) {
                if (tcp_header->flags & (0x80 >> flags)) {
                    printf("%s ", tcp_flags[flags]);
                }
            }

            if (verbose) printf("seq %lu ", ntohl(tcp_header->seq_number));
            if (verbose) printf("ack %lu ", ntohl(tcp_header->ack_number));
            if (verbose) printf("win %u ", ntohs(tcp_header->window));
        }

        // UDP
        else if (ip_header->protocol == 17) {
            printf("%02d:%02d:%02d.%03d %s ", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds, proto[ip_header->protocol]);
            udp_header = (UDPHEADER*)&packet[ip_header->ip_hl * sizeof(DWORD)];
            printf("%s:%ld -> %s:%ld ", src_ip, htons(udp_header->source_port), dst_ip, htons(udp_header->destination_port));
        }

        // ICMP
        else if (ip_header->protocol == 1) {
            printf("%02d:%02d:%02d.%03d %s ", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds, proto[ip_header->protocol]);
            icmp_header = (ICMPHEADER*)&packet[ip_header->ip_hl * sizeof(DWORD)];
            printf("%s -> %s ", src_ip, dst_ip);
            printf("type %d code %d ", icmp_header->type, icmp_header->code);
            if (icmp_header->type == 0) printf("[echo reply] ");
            else if (icmp_header->type == 8) printf("[echo request] ");
            else if (icmp_header->type == 3) printf("[dst unreachable] ");
            else if (icmp_header->type == 5) printf("[redirect] ");
            else if (icmp_header->type == 1) printf("[time exceeded] ");
        }

        else {
            printf("%02d:%02d:%02d.%03d %s ", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds, proto[ip_header->protocol]);
            printf("%s -> %s ", src_ip, dst_ip);
        }

        if (verbose) printf("dscp %u ecn %u ttl %u ", ip_header->tos_dscp, ip_header->tos_ecn, ip_header->ttl);
        if (ip_header->DF) printf("DF ");

        putchar('\n');
        fflush(stdout); // helps findstr
    }
    return 0;
}
