#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "ringbuffer.h"

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

int ringbuffer_write(struct ringbuffer *r, unsigned char *data, size_t size) {
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

    // If write does not wrap, second memcpy() does nothing
    size_t wrap = min(size, r->buffer_size - r->tail);
    memcpy(r->buffer + r->tail, data, wrap);
    memcpy(r->buffer, data + wrap, size - wrap);

    // Account for written memory
    r->tail = (r->tail + size) % r->buffer_size;
    r->bytes_used += size;
    r->write_waiting = 0;

    // TODO: Only send not_empty signal if actually empty
    pthread_cond_signal(&r->not_empty);

    pthread_mutex_unlock(&r->mutex);

    return 0;
}

int ringbuffer_read(struct ringbuffer *r, unsigned char *data, size_t size) {
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

    // If read does not wrap, second memcpy() does nothing
    size_t wrap = min(size, r->buffer_size - r->head);
    memcpy(data, r->buffer + r->head, wrap);
    memcpy(data + wrap, r->buffer, size - wrap);

    // Account for read memory
    r->head = (r->head + size) % r->buffer_size;
    r->bytes_used -= size;

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
