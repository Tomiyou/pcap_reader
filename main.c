#include <errno.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>

#include <pthread.h>

#include "ringbuffer.h"

// The fastest data structure (since it only needs simple synchronization) for
// passing packets between main thread and worker threads is probably a ringbuffer.
// A ringbuffer per IP-tuple also makes it easy to preserve packet ordering for
// that IP-tuple.
// Since the majority of internet packets have a MTU of 1500 bytes, a ringbuffer
// large enough to contain multiple packets + PCAP metadata for each packet would
// probably be ideal. It avoids malloc() for each packet and keeps cache locality.
// Implementation could be:
// - a ringbuffer with multiple memory pages pointing to the same underlying
//   memory (which greatly simplifies memory access since it appears contiguous)
// - copy packet from ringbuffer to a local memory block (making it contiguous)
// - check if memcpy()ing a packet would wrap around ringbuffer and instead place
//   copy the packet to the beginning of ringbuffer avoiding a wrap
//
// If working with mostly jumbo frames (64kB each) then that would definitely
// impact the decision how to tune the ringbuffer.

static void print_help(void) {
    printf("Usage: pcap_reader --threads 4 --help $INPUT_PCAP\n");
}

static int parse_arguments(int argc, char **argv, long *num_threads, char **pcap_file) {
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--threads") == 0) {
            char *endptr = NULL;

            // Parse next argument as thread count
            i += 1;
            if (i >= argc) {
                return -EINVAL;
            }

            *num_threads = strtol(argv[i], &endptr, 10);
            if (endptr[0] != '\0') {
                return -EINVAL;
            }

            // Catch invalid numbers
            if (*num_threads < 1) {
                return -EINVAL;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            print_help();
            exit(0);
        } else {
            // This arg is our input PCAP file, we only allow 1 input file
            if (*pcap_file != NULL) {
                return -EINVAL;
            }

            *pcap_file = argv[i];
        }
    }

    return 0;
}

#define IP_HDRLEN   20
#define IPV6_HDRLEN   40

static int round_robin = 0;

static void read_packets(pcap_t *handle, long num_threads, struct ringbuffer *rings) {
    struct pcap_pkthdr *pkt_hdr;
    const unsigned char *pkt_data;
    int datalink;
    int i;

    datalink = pcap_datalink(handle);
    if (datalink != DLT_EN10MB) {
        printf("Not reading non ethernet PCAP file\n");
        return;
    }

    while (pcap_next_ex(handle, &pkt_hdr, &pkt_data) == 1) {
        struct ether_header *eth_hdr;
        struct ringbuffer *ring;

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

        ring = &rings[round_robin];
        ringbuffer_write(ring, (unsigned char *)pkt_hdr, sizeof(*pkt_hdr));

        // TODO: Use hash instead of round robin
        round_robin = (round_robin + 1) % num_threads;
    }

    // Tell our workers we are done
    for (i = 0; i < num_threads; i++) {
        ringbuffer_close(&rings[i]);
    }
}

void *reader_routine(void *arg) {
    struct ringbuffer *ring = (struct ringbuffer *)arg;
    struct pcap_pkthdr pkt_hdr;

    while (ringbuffer_read(ring, (unsigned char *)&pkt_hdr, sizeof(pkt_hdr)) == 0) {
        printf("received msg %u\n", pkt_hdr.len);
    }

    printf("Worker thread exiting\n");

    // Cleanup
    ringbuffer_destroy(ring);

    return NULL;
}

int main (int argc, char **argv) {
    long num_threads = 1;
    char *pcap_file = NULL;
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pthread_t *threads;
    struct ringbuffer *rings;
    int err;
    int i;

    // We always need at least one argument - input pcap
    if (argc < 2) {
        print_help();
        return -ENOENT;
    }

    // Parse arguments
    err = parse_arguments(argc, argv, &num_threads, &pcap_file);
    if (err) {
        printf("AAAAA\n");
        print_help();
        return err;
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

    rings = malloc(sizeof(*rings) * num_threads);
    if (rings == NULL) {
        return -ENOMEM;
    }

    // Spawn worker threads
    threads = malloc(sizeof(*threads) * num_threads);
    if (threads == NULL) {
        return -ENOMEM;
    }
    for (i = 0; i < num_threads; i++) {
        ringbuffer_init(&rings[i], 1600);

        err = pthread_create(&threads[i], NULL, &reader_routine, (void *)&rings[i]);
        if (err) {
            return err;
        }
    }

    // Read packets
    read_packets(handle, num_threads, rings);

    // Wait for threads
    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    free(threads);

    printf("All threads finished, exiting\n");

    // Cleanup
    pcap_close(handle);
    free(rings);

    return 0;
}
