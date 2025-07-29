#include <errno.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>

#include <pthread.h>

// The fastest data structure (since it only needs simple synchronization) for
// passing packets between main thread and worker threads is probably a ringbuffer.
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
        if (strcmp(argv[i], "--num_threads") == 0) {
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

            // Catch negative numbers
            if (num_threads < 0) {
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

// TODO: Tweak this
#define RING_BUF_SIZE 1504 * 50

struct ringbuffer {
    pthread_spinlock_t lock;
    unsigned char *buffer;
    size_t buffer_size;
    size_t head;
    size_t tail;
    size_t bytes_used;
    unsigned int pkt_count;
};

static inline size_t min(size_t a, size_t b) {
    return (a < b) ? a : b;
}

static struct ringbuffer *ringbuffer_alloc(size_t size) {
    struct ringbuffer *r = calloc(1, sizeof(struct ringbuffer));

    // Initialize default values
    pthread_spin_init(&r->lock, PTHREAD_PROCESS_PRIVATE);
    r->buffer = malloc(size);
    if (r->buffer == NULL) {
        free(r);
        return NULL;
    }
    r->buffer_size = size;

    return r;
}

static int ringbuffer_write(struct ringbuffer *r, unsigned char *data, size_t size) {
    // Check if there is enough space for a write
    if ((r->buffer_size - r->bytes_used) < size)
        return -1;

    // If write does not wrap, second memcpy() does nothing
    size_t wrap = min(size, r->buffer_size - r->tail);
    memcpy(r->buffer + r->tail, data, wrap);
    memcpy(r->buffer, data + wrap, size - wrap);

    // Account for written memory
    r->tail = (r->tail + size) % r->buffer_size;
    r->bytes_used += size;

    return 0;
}

static int ringbuffer_read(struct ringbuffer *r, unsigned char *data, size_t size) {
    // Check if there is enough space for a read
    if (r->bytes_used < size)
        return -1;

    // If read does not wrap, second memcpy() does nothing
    size_t wrap = min(size, r->buffer_size - r->head);
    memcpy(data, r->buffer + r->head, wrap);
    memcpy(data + wrap, r->buffer, size - wrap);

    // Account for read memory
    r->head = (r->head + size) % r->buffer_size;
    r->bytes_used -= size;

    return 0;
}

int main (int argc, char **argv) {
    long num_threads = 1;
    char *pcap_file = NULL;
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int err;

    // We always need at least one argument - input pcap
    if (argc < 2) {
        print_help();
        return -ENOENT;
    }

    // Parse arguments
    err = parse_arguments(argc, argv, &num_threads, &pcap_file);
    if (err) {
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

    // Read packets
    read_packets(handle);

    // Cleanup
    pcap_close(handle);

    return 0;
}
