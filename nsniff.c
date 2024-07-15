/*
 * nsniff.c
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <signal.h>

#pragma comment(lib, "ws2_32.lib")

// Define IP header
struct ip_header {
    unsigned char  ip_header_len:4; // 4-bit header length
    unsigned char  ip_version:4;    // 4-bit IPv4 version
    unsigned char  ip_tos;          // IP type of service
    unsigned short ip_total_length; // Total length
    unsigned short ip_id;           // Unique identifier
    unsigned short ip_frag_offset;  // Fragment offset field
    unsigned char  ip_ttl;          // Time to live
    unsigned char  ip_protocol;     // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;     // IP checksum
    struct in_addr ip_src, ip_dst;  // Source and destination address
};

// Define TCP header
struct tcp_header {
    unsigned short source_port;     // Source port
    unsigned short dest_port;       // Destination port
    unsigned int   sequence;        // Sequence number
    unsigned int   acknowledge;     // Acknowledgement number
    unsigned char  ns:1;            // Nonce Sum Flag Added in RFC 3540.
    unsigned char  reserved_part1:3;// According to RFC
    unsigned char  data_offset:4;   /* The number of 32-bit words in the TCP header.
                                     * This indicates where the data begins.
                                     * The length of the TCP header is always a multiple
                                     * of 32 bits. */
    unsigned char  fin:1;           // Finish Flag
    unsigned char  syn:1;           // Synchronise Flag
    unsigned char  rst:1;           // Reset Flag
    unsigned char  psh:1;           // Push Flag
    unsigned char  ack:1;           // Acknowledgement Flag
    unsigned char  urg:1;           // Urgent Flag
    unsigned char  ecn:1;           // ECN-Echo Flag
    unsigned char  cwr:1;           // Congestion Window Reduced Flag
    unsigned short window;          // Window
    unsigned short checksum;        // Checksum
    unsigned short urgent_pointer;  // Urgent pointer
};

// Define UDP header
struct udp_header {
    unsigned short source_port;     // Source port
    unsigned short dest_port;       // Destination port
    unsigned short udp_length;      // UDP packet length
    unsigned short udp_checksum;    // UDP checksum
};

// Define ICMP header
struct icmp_header {
    unsigned char  type;            // ICMP message type
    unsigned char  code;            // Error code
    unsigned short checksum;        // Checksum
    unsigned short id;              // Identification
    unsigned short sequence;        // Sequence number
};

// Define ARP header
struct arp_header {
    unsigned short hw_type;         // Hardware type
    unsigned short proto_type;      // Protocol type
    unsigned char  hw_addr_len;     // Hardware address length
    unsigned char  proto_addr_len;  // Protocol address length
    unsigned short operation;       // Operation (request/reply)
    unsigned char  sender_hw_addr[6]; // Sender hardware address
    unsigned char  sender_proto_addr[4]; // Sender protocol address
    unsigned char  target_hw_addr[6]; // Target hardware address
    unsigned char  target_proto_addr[4]; // Target protocol address
};

// Define IGMP header
struct igmp_header {
    unsigned char type;             // IGMP message type
    unsigned char max_resp_time;    // Maximum response time
    unsigned short checksum;        // IGMP checksum
    struct in_addr group_address;   // Group address (multicast)
};

// Define GRE header
struct gre_header {
    unsigned short flags_version;   // Flags and Version
    unsigned short protocol_type;   // Protocol Type
};

// Define OSPF header
struct ospf_header {
    unsigned char version;          // OSPF version
    unsigned char type;             // OSPF type
    unsigned short packet_length;   // Packet length
    unsigned int router_id;         // Router ID
    unsigned int area_id;           // Area ID
    unsigned short checksum;        // Checksum
    unsigned short autype;          // Authentication type
    unsigned long authentication[2]; // Authentication
};

int link_hdr_length = 0;
pcap_t *capdev;

void resolve_ip(const char *ip_str, char *host, size_t host_len) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &sa.sin_addr);

    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, host_len, NULL, 0, 0) != 0) {
        strncpy(host, "Unknown", host_len);
    }
}

void process_ip_packet(const u_char *packetd_ptr) {
    struct ip_header *ip_hdr = (struct ip_header *)packetd_ptr;

    char packet_srcip[INET_ADDRSTRLEN]; 
    char packet_dstip[INET_ADDRSTRLEN];  
    char src_host[NI_MAXHOST];
    char dst_host[NI_MAXHOST];

    strcpy(packet_srcip, inet_ntoa(ip_hdr->ip_src));
    strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst));
    
    resolve_ip(packet_srcip, src_host, sizeof(src_host));
    resolve_ip(packet_dstip, dst_host, sizeof(dst_host));
    
    int packet_id = ntohs(ip_hdr->ip_id),
        packet_ttl = ip_hdr->ip_ttl,
        packet_tos = ip_hdr->ip_tos,
        packet_len = ntohs(ip_hdr->ip_total_length),
        packet_hlen = ip_hdr->ip_header_len;

    printf("************************************"
           "**************************************\n");
    printf("ID: %d | SRC: %s (%s) | DST: %s (%s) | TOS: 0x%x | TTL: %d\n", packet_id,
           packet_srcip, src_host, packet_dstip, dst_host, packet_tos, packet_ttl);

    packetd_ptr += (4 * packet_hlen);
    int protocol_type = ip_hdr->ip_protocol;

    struct tcp_header *tcp_hdr;
    struct udp_header *udp_hdr;
    struct icmp_header *icmp_hdr;
    int src_port, dst_port;

    switch (protocol_type) {
        case IPPROTO_TCP:
            tcp_hdr = (struct tcp_header *)packetd_ptr;
            src_port = ntohs(tcp_hdr->source_port);
            dst_port = ntohs(tcp_hdr->dest_port);
            printf("PROTO: TCP | FLAGS: %c/%c/%c | SPORT: %d | DPORT: %d |\n",
                   (tcp_hdr->syn ? 'S' : '-'),
                   (tcp_hdr->ack ? 'A' : '-'),
                   (tcp_hdr->urg ? 'U' : '-'), src_port, dst_port);
            break;
        case IPPROTO_UDP:
            udp_hdr = (struct udp_header *)packetd_ptr;
            src_port = ntohs(udp_hdr->source_port);
            dst_port = ntohs(udp_hdr->dest_port);
            printf("PROTO: UDP | SPORT: %d | DPORT: %d |\n", src_port, dst_port);
            break;
        case IPPROTO_ICMP:
            icmp_hdr = (struct icmp_header *)packetd_ptr;
            int icmp_type = icmp_hdr->type;
            int icmp_type_code = icmp_hdr->code;
            printf("PROTO: ICMP | TYPE: %d | CODE: %d |\n", icmp_type, icmp_type_code);
            break;
        default:
            printf("Unknown IP protocol: %d\n", protocol_type);
    }
}

void process_arp_packet(const u_char *packetd_ptr) {
    struct arp_header *arp_hdr = (struct arp_header *)packetd_ptr;

    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];

    snprintf(sender_ip, INET_ADDRSTRLEN, "%d.%d.%d.%d",
             arp_hdr->sender_proto_addr[0],
             arp_hdr->sender_proto_addr[1],
             arp_hdr->sender_proto_addr[2],
             arp_hdr->sender_proto_addr[3]);

    snprintf(target_ip, INET_ADDRSTRLEN, "%d.%d.%d.%d",
             arp_hdr->target_proto_addr[0],
             arp_hdr->target_proto_addr[1],
             arp_hdr->target_proto_addr[2],
             arp_hdr->target_proto_addr[3]);

    printf("************************************"
           "**************************************\n");
    printf("ARP Packet: \n");
    printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_hdr->sender_hw_addr[0], arp_hdr->sender_hw_addr[1], arp_hdr->sender_hw_addr[2],
           arp_hdr->sender_hw_addr[3], arp_hdr->sender_hw_addr[4], arp_hdr->sender_hw_addr[5]);
    printf("Sender IP: %s\n", sender_ip);
    printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_hdr->target_hw_addr[0], arp_hdr->target_hw_addr[1], arp_hdr->target_hw_addr[2],
           arp_hdr->target_hw_addr[3], arp_hdr->target_hw_addr[4], arp_hdr->target_hw_addr[5]);
    printf("Target IP: %s\n", target_ip);
}

void process_igmp_packet(const u_char *packetd_ptr) {
    struct igmp_header *igmp_hdr = (struct igmp_header *)packetd_ptr;

    printf("************************************"
           "**************************************\n");
    printf("IGMP Packet: \n");
    printf("Type: %d | Max Response Time: %d | Checksum: 0x%x | Group Address: %s\n",
           igmp_hdr->type, igmp_hdr->max_resp_time, ntohs(igmp_hdr->checksum),
           inet_ntoa(igmp_hdr->group_address));
}

void process_gre_packet(const u_char *packetd_ptr) {
    struct gre_header *gre_hdr = (struct gre_header *)packetd_ptr;

    printf("************************************"
           "**************************************\n");
    printf("GRE Packet: \n");
    printf("Flags and Version: 0x%x | Protocol Type: 0x%x\n",
           ntohs(gre_hdr->flags_version), ntohs(gre_hdr->protocol_type));
}

void process_ospf_packet(const u_char *packetd_ptr) {
    struct ospf_header *ospf_hdr = (struct ospf_header *)packetd_ptr;

    printf("************************************"
           "**************************************\n");
    printf("OSPF Packet: \n");
    printf("Version: %d | Type: %d | Packet Length: %d | Router ID: %u | Area ID: %u | Checksum: 0x%x\n",
           ospf_hdr->version, ospf_hdr->type, ntohs(ospf_hdr->packet_length), 
           ntohl(ospf_hdr->router_id), ntohl(ospf_hdr->area_id), ntohs(ospf_hdr->checksum));
}

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr) {
    packetd_ptr += link_hdr_length;
    struct ip_header *ip_hdr = (struct ip_header *)packetd_ptr;

    switch (ip_hdr->ip_protocol) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMP:
            process_ip_packet(packetd_ptr);
            break;
        case 2: // IGMP
            process_igmp_packet(packetd_ptr);
            break;
        case 47: // GRE
            process_gre_packet(packetd_ptr);
            break;
        case 89: // OSPF
            process_ospf_packet(packetd_ptr);
            break;
        case 0x0806: // ARP
            process_arp_packet(packetd_ptr);
            break;
        default:
            printf("Unknown packet type: %d\n", ip_hdr->ip_protocol);
    }
}

void handle_signal(int signal) {
    if (signal == SIGINT) {
        pcap_breakloop(capdev);
        pcap_close(capdev);
        printf("\nPacket capture stopped.\n");
        exit(0);
    }
}

int main(int argc, char const *argv[]) {
    char *device = "\\Device\\NPF_{080AB94D-6338-43EE-A4CD-16FD009E6F79}"; // Intel(R) Wi-Fi 6 AX200 160MHz
    char error_buffer[PCAP_ERRBUF_SIZE];

    printf("Starting packet capture on device: %s\n", device);

    capdev = pcap_open_live(device, BUFSIZ, 1, -1, error_buffer); // Set promiscuous mode to 1

    if (capdev == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device, error_buffer);
        exit(EXIT_FAILURE);
    }

    int link_hdr_type = pcap_datalink(capdev);

    switch (link_hdr_type) {
        case DLT_NULL:
            link_hdr_length = 4;
            break;
        case DLT_EN10MB:
            link_hdr_length = 14;
            break;
        default:
            fprintf(stderr, "Unsupported link layer type: %d\n", link_hdr_type);
            exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_signal);

    while (1) {
        if (pcap_dispatch(capdev, 0, call_me, (u_char *)NULL) < 0) {
            fprintf(stderr, "Error in pcap_dispatch: %s\n", pcap_geterr(capdev));
            pcap_close(capdev);
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
