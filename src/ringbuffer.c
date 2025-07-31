#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>

#include "ringbuffer.h"

// This ringbuffer is basically a channel (like the ones in Go lang)
// that allows to store and fetch packets of variable size using
// libpcap's struct pcap_pkthdr. Implementation is based on this
// very simple implementation of channels in C, but I also added the
// ability to notify worker threads when a channel is closed.
// https://github.com/leo-aa88/channels-in-c

// It is possible to implement ringbuffer with contiguous virtual
// pages mapped that point to the same underlying buffer. This makes
// writing and fetching data from ringbuffer extremely simple, but
// I intentionally avoided it since some consider it a hack.
// If that implementation was used, it would be possible to avoid
// copying memory back from ringbuffer to thread, but memcpy()
// should be plenty fast (due to cache locality) and once you copy
// data back to thread, ringbuffer mutex can be released, meaning
// main thread can access ringbuffer while worker thread is
// processing the current packet.

static inline size_t min(size_t a, size_t b) {
    return (a < b) ? a : b;
}

int ringbuffer_init(struct ringbuffer *r, size_t size) {
    memset(r, 0, sizeof(*r));

    r->buffer = malloc(size);
    if (r->buffer == NULL)
        return -ENOMEM;
    r->buffer_size = size;

    pthread_mutex_init(&r->mutex, NULL);
    pthread_cond_init(&r->not_empty, NULL);
    pthread_cond_init(&r->not_full, NULL);

    return 0;
}

void ringbuffer_destroy(struct ringbuffer *r) {
    pthread_mutex_destroy(&r->mutex);
    pthread_cond_destroy(&r->not_empty);
    pthread_cond_destroy(&r->not_full);
    free(r->buffer);
}

static inline void write(struct ringbuffer *r, const uint8_t *data, size_t size) {
    // If write does not wrap, second memcpy() does nothing
    size_t wrap = min(size, r->buffer_size - r->tail);
    memcpy(r->buffer + r->tail, data, wrap);
    memcpy(r->buffer, data + wrap, size - wrap);

    // Account for written memory
    r->tail = (r->tail + size) % r->buffer_size;
    r->bytes_used += size;
}

int ringbuffer_write(struct ringbuffer *r, struct pcap_pkthdr *pkt_hdr, const uint8_t *data) {
    uint32_t size = sizeof(*pkt_hdr) + pkt_hdr->caplen;

    pthread_mutex_lock(&r->mutex);

    // TODO: What if (size > r->buffer_size) ?

    // We indicate to our reader how much we need for next write, this way
    // reader can wake us up when enough space is free in the ringbuffer
    r->write_waiting = size;

    // Wait until there is enough space for a write
    while ((r->buffer_size - r->bytes_used) < size) {
        // pthread_cond_wait() must be called with mutex locked. It unlocks
        // the mutex and waits for conditional variable, then locks it again
        // and returns.
        pthread_cond_wait(&r->not_full, &r->mutex);
    }

    // Write both pcap_pkthdr and the packet itself
    write(r, (uint8_t *)pkt_hdr, sizeof(*pkt_hdr));
    write(r, data, pkt_hdr->caplen);
    r->write_waiting = 0;

    // TODO: Only send not_empty signal if actually empty
    pthread_cond_signal(&r->not_empty);

    pthread_mutex_unlock(&r->mutex);

    return 0;
}

static inline void read(struct ringbuffer *r, uint8_t *data, size_t size) {
    // If read does not wrap, second memcpy() does nothing
    size_t wrap = min(size, r->buffer_size - r->head);
    memcpy(data, r->buffer + r->head, wrap);
    memcpy(data + wrap, r->buffer, size - wrap);

    // Account for read memory
    r->head = (r->head + size) % r->buffer_size;
    r->bytes_used -= size;
}

int ringbuffer_read(struct ringbuffer *r, struct pcap_pkthdr *pkt_hdr, uint8_t *data, size_t bufsize) {
    pthread_mutex_lock(&r->mutex);

    // Check if there is enough space for a read
    while (r->bytes_used == 0) {
        // If writer closed and all of the bytes have been read, we are done
        if (r->writer_closed) {
            pthread_mutex_unlock(&r->mutex);
            return -1;
        }

        pthread_cond_wait(&r->not_empty, &r->mutex);
    }

    read(r, (uint8_t *)pkt_hdr, sizeof(*pkt_hdr));
    // If the next packet is too large for the given buffer,
    // undo read and let caller know
    if ((sizeof(*pkt_hdr) + pkt_hdr->caplen) > bufsize) {
        r->head = (r->buffer_size + r->head - sizeof(*pkt_hdr)) % r->buffer_size;
        r->bytes_used += sizeof(*pkt_hdr);

        pthread_mutex_unlock(&r->mutex);
        return -ENOMEM;
    }
    read(r, data, pkt_hdr->caplen);

    // Only trigger not_full if enough space has been freed
    if ((r->buffer_size - r->bytes_used) >= r->write_waiting) {
        pthread_cond_signal(&r->not_full);
    }

    pthread_mutex_unlock(&r->mutex);

    return 0;
}

void ringbuffer_close(struct ringbuffer *r) {
    pthread_mutex_lock(&r->mutex);
    r->writer_closed = 1;
    // Wake thread in case it is sleeping
    pthread_cond_signal(&r->not_empty);
    pthread_mutex_unlock(&r->mutex);
}
