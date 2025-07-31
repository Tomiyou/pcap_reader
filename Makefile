CC = gcc

TARGET = pcap_reader
CFLAGS := -Wall -Wextra -O2 -I./murmurhash
LDFLAGS := -lpcap

# Copied from murmurhash.c Makefile
HASH_CFLAGS := -std=c99 -Wall -I./murmurhash -DMURMURHASH_WANTS_HTOLE32=1
HASH_PATH := ./murmurhash/murmurhash

SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:.c=.o) $(HASH_PATH).o

# TODO: Check if dependencies are installed via pkgconfig

# Default target
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(HASH_PATH).o: $(HASH_PATH).c
	$(CC) $(HASH_CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)
