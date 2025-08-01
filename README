# PCAP reader

This is a C program that will parse an input .pcap file and output the total sum of IPv4/6 payloads of all packets in that .pcap file.

## Requirements
* Docker (with non-superuser permissions)

## Usage
After cloning murmurhash submodule must be initialized for pcap_reader to compile:
```
git submodule update --remote --init
```

#### Create and run the development container

This container is also used to compile release binary and all dependencies come preinstalled
```
./run.sh dev
# Inside container
make
./pcap_reader --help
```

#### Create release Docker image
```
# Release image contains pcap_reader as entrypoint
./run.sh release
```

#### Test the release binary Docker image
```
# This will run pcap_reader with 16 threads and all.pcap as input, then check that the output is correct
./run.sh test
```

## Implementation
I chose a buffered channel (with an internal ringbuffer) as the primary data structure to pass packets between main thread and worker threads. The synchronization is simple and since the memory is all contiguous, cache hits rate should be very high - which means that even though we copy each packet 2x (once from libpcap internal buffer to channel and then back from channel to worker thread local buffer), performance should be great. Copying memory back to worker thread's local buffer also means that channel (ringbuffer) mutex can be unlocked immediately after, while worker is still processing the packet. Since this application only needs a single-producer, single-consumer the ringbuffer implementation is simple. As each IP-tuple always goes to the same ringbuffer (thanks to the hash function), packet ordering is preserved for that IP-tuple.

I assumed that main thread should copy entire packets to the worker threads through the ringbuffer. If we only packet headers were needed for processing, then this would make the whole implementation a lot simpler, since payloads can vary in sizes between a couple of bytes to kilobytes (jumbo frames). Since the majority of internet packets have a MTU of 1500 bytes, a ringbuffer large enough to contain multiple packets + PCAP metadata for each packet would
probably be ideal. It avoids malloc() for each packet and keeps cache locality. Implementation could be:
* a ringbuffer with multiple memory pages pointing to the same underlying memory (which greatly simplifies memory access since it appears contiguous) and process data directly from ringbuffer
* copy packet from ringbuffer to a local memory block (making it contiguous)
* check if memcpy()ing a packet would wrap around ringbuffer and instead place copy the packet to the beginning of ringbuffer avoiding a wrap
* This channel with ringbuffer should be very fast as is, but it might be a good idea to try and use a lockless ringbuffer for this task, for example like the ones used in Linux kernel which use memory pages in a linked list to achieve as little locking as possible.

If working with mostly jumbo frames (64KB each) then that would definitely impact the decision how to tune the ringbuffer.

## Extras

#### Possible improvements
* Currently, if a worker thread's ringbuffer fills up, main thread will also block, even though other threads might have plenty of space. Perhaps a backlog of some sorts would help with this issue.
* If we only needed packet headers without paylods for processing, this would make the whole implementation much simpler.
* Better error handling (while cleaning up) is probably a good next step. Currently when pcap_reader hits an unexpected error (like malloc returning NULL), it will simply exit the program and let kernel handle the cleanup.
* Replacing mutex with spinlock might be worth it (since mutex can put thread to sleep).

#### Logging
* Implementing logging in a performance critical application would probably be implemented using asynchronous logging, meaning that rather than waiting for access to file/socket, it is far more efficient to write log requests to a queue and have a completely separate thread write to file/socket. This would reduce the amount of system calls greatly (no fighting for file/socket access) and allow low latency (much less locking).

#### Collections

