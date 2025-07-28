#include <errno.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>

static void print_help(void) {
    printf("Usage: pcap_reader --jobs 4 --help $INPUT_PCAP\n");
}

#define IP_HDRLEN   20
#define IPV6_HDRLEN   40

static void read_packets(pcap_t *handle) {
    struct pcap_pkthdr *pkt_hdr;
    const unsigned char *pkt_data;
    int datalink;

    datalink = pcap_datalink(handle);
    if (datalink != DLT_EN10MB) {
        printf("Not reading non ethernet PCAP file\n");
        return;
    }

    while (pcap_next_ex(handle, &pkt_hdr, &pkt_data) == 1) {
        struct ether_header *eth_hdr;

        // Check if packet is long enough for Ethernet header
        if (pkt_hdr->len < ETH_HLEN)
            continue;

        eth_hdr = (struct ether_header *)pkt_data;

        // We only care about IPv4 and IPv6 packets
        if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
            struct iphdr *ip_hdr;

            // Check if the remaining length is enough for IPv4 header
            if (pkt_hdr->len < (ETH_HLEN + IP_HDRLEN))
                continue;

            ip_hdr = (struct iphdr *)(pkt_data + ETH_HLEN);
        } else if (eth_hdr->ether_type == htons(ETHERTYPE_IPV6)) {
            struct ipv6hdr *ipv6_hdr;

            // Check if the remaining length is enough for IPv6 header
            if (pkt_hdr->len < (ETH_HLEN + IPV6_HDRLEN))
                continue;

            ipv6_hdr = (struct ipv6hdr *)(pkt_data + ETH_HLEN);
        } else {
            continue;
        }
    }
}

int main (int argc, char **argv) {
    long jobs = 1;
    char *pcap_file = NULL;
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i;

    // We always need at least one argument - input pcap
    if (argc < 2) {
        print_help();
        return -ENOENT;
    }

    // Parse arguments
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--jobs") == 0) {
            char *endptr = NULL;

            // Parse next argument as thread count
            i += 1;
            if (i >= argc) {
                print_help();
                return -EINVAL;
            }

            jobs = strtol(argv[i], &endptr, 10);
            if (endptr[0] != '\0') {
                print_help();
                return -EINVAL;
            }

            // Catch negative numbers
            if (jobs < 0) {
                print_help();
                return -EINVAL;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        } else {
            // This arg is our input PCAP file, we only allow 1 input file
            if (pcap_file != NULL) {
                return -EINVAL;
            }

            pcap_file = argv[i];
        }
    }

    if (pcap_file == NULL) {
        print_help();
        return -EINVAL;
    }

    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        printf("Unable to open PCAP file: %s\n", errbuf);
        return -EINVAL;
    }

    printf("Opened PCAP file: %s\n", pcap_file);

    // Read packets
    read_packets(handle);

    // Cleanup
    pcap_close(handle);

    return 0;
}
