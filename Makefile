CC = gcc

TARGET = pcap_reader
SOURCES = main.c
CFLAGS := -Wall -O2

# Default target
all: $(TARGET)

# Main build rule
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
