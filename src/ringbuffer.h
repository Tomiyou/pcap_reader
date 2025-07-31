#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

// TODO: Tweak this
#define RING_BUF_SIZE 2^16

struct ringbuffer {
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    uint8_t *buffer;
    size_t buffer_size;
    size_t head;
    size_t tail;
    size_t bytes_used;
    size_t write_waiting;
    int writer_closed;
};

int ringbuffer_init(struct ringbuffer *r, size_t size);
void ringbuffer_destroy(struct ringbuffer *r);
int ringbuffer_write(struct ringbuffer *r, struct pcap_pkthdr *pkt_hdr, const uint8_t *data);
int ringbuffer_read(struct ringbuffer *r, struct pcap_pkthdr *pkt_hdr, uint8_t *data, size_t bufsize);
void ringbuffer_close(struct ringbuffer *r);