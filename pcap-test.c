#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>

void print_hex(const u_char* data, int length) {
    for (int i = 0; i < length && i < 10; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(argv[1], errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) return null - %s\n", argv[1], errbuf);
        return -1;
    }

    struct pcap_pkthdr header;
    const u_char* packet;
    int res;

    struct libnet_ethernet_hdr* eth_header = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr* ip_header = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
    struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr*)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);

    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_header->ether_shost[0], eth_header->ether_shost[1],eth_header->ether_shost[2], eth_header->ether_shost[3],eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_header->ether_dhost[0], eth_header->ether_dhost[1],eth_header->ether_dhost[2], eth_header->ether_dhost[3],eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*)&(ip_header->ip_src)));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&(ip_header->ip_dst)));

    printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));

    printf("Payload (hexadecimal value):\n");
    print_hex(packet + LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H, header.caplen - (LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H));
    printf("\n");

    pcap_close(pcap);
    return 0;
}

