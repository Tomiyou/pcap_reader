CC = gcc

TARGET = pcap_reader
CFLAGS := -Wall -O2 -I./murmurhash
LDFLAGS := -lpcap

# Copied from murmurhash.c Makefile
HASH_CFLAGS := -std=c99 -Wall -I./murmurhash -DMURMURHASH_WANTS_HTOLE32=1
HASH_SRC := ./murmurhash/murmurhash

SOURCES = main.c ringbuffer.c $(HASH_SRC).o

# Default target
all: $(TARGET)

$(HASH_SRC).o:
	$(CC) $(HASH_CFLAGS) -c $(HASH_SRC).c -o $(HASH_SRC).o

# Main build rule
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
