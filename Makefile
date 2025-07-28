CC = gcc

TARGET = pcap_reader
SOURCES = main.c
CFLAGS :=

# Default target
all: $(TARGET)

# Main build rule
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
