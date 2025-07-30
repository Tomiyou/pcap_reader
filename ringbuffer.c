#include <string.h>

#include "ringbuffer.h"

static inline size_t min(size_t a, size_t b) {
    return (a < b) ? a : b;
}

struct ringbuffer *ringbuffer_alloc(size_t size) {
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

int ringbuffer_write(struct ringbuffer *r, unsigned char *data, size_t size) {
    pthread_spin_lock(&r->lock);

    // Check if there is enough space for a write
    if ((r->buffer_size - r->bytes_used) < size) {
        pthread_spin_unlock(&r->lock);
        return -1;
    }

    // If write does not wrap, second memcpy() does nothing
    size_t wrap = min(size, r->buffer_size - r->tail);
    memcpy(r->buffer + r->tail, data, wrap);
    memcpy(r->buffer, data + wrap, size - wrap);

    // Account for written memory
    r->tail = (r->tail + size) % r->buffer_size;
    r->bytes_used += size;

    pthread_spin_unlock(&r->lock);
    return 0;
}

int ringbuffer_read(struct ringbuffer *r, unsigned char *data, size_t size) {
    pthread_spin_lock(&r->lock);

    // Check if there is enough space for a read
    if (r->bytes_used < size) {
        pthread_spin_unlock(&r->lock);
        return -1;
    }

    // If read does not wrap, second memcpy() does nothing
    size_t wrap = min(size, r->buffer_size - r->head);
    memcpy(data, r->buffer + r->head, wrap);
    memcpy(data + wrap, r->buffer, size - wrap);

    // Account for read memory
    r->head = (r->head + size) % r->buffer_size;
    r->bytes_used -= size;

    pthread_spin_unlock(&r->lock);
    return 0;
}
