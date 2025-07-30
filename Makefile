CC = gcc

TARGET = pcap_reader
SOURCES = main.c ringbuffer.c
CFLAGS := -Wall -O2
LDFLAGS := -lpcap

# Default target
all: $(TARGET)

# Main build rule
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
