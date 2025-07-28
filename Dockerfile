# Since instructions mention Docker both for build environment and as a deploy
# target, I assumed 2 docker containers. One for building and one for
# distribution, since images used to distribute binaries are usually minimized
# as much as possible.

# Build environment
FROM debian:bookworm AS dev

RUN apt-get update -y
RUN apt-get install gcc make libpcap-dev -y

WORKDIR /mnt/pcap_reader

ENTRYPOINT [ "/bin/bash" ]

# Runtime environment
FROM debian:bookworm AS release

RUN apt install libpcap

COPY build/pcap_reader /app/pcap_reader
RUN chmod +x /app/pcap_reader

ENTRYPOINT ["/app/pcap_reader"]
