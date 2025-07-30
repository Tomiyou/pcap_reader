#include <pthread.h>
#include <stdlib.h>

// TODO: Tweak this
#define RING_BUF_SIZE 1504 * 50

struct ringbuffer {
    pthread_spinlock_t lock;
    unsigned char *buffer;
    size_t buffer_size;
    size_t head;
    size_t tail;
    size_t bytes_used;
};

struct ringbuffer *ringbuffer_alloc(size_t size);
int ringbuffer_write(struct ringbuffer *r, unsigned char *data, size_t size);
int ringbuffer_read(struct ringbuffer *r, unsigned char *data, size_t size);