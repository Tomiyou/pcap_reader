#!/bin/bash

DEV_IMAGE="pcap_reader_builder"

case "$1" in
  dev)
    # Build dev image if needed
    if ! docker image inspect "$DEV_IMAGE" > /dev/null 2>&1; then
        docker build --target dev -t "$DEV_IMAGE" .
    fi
    # Run dev image and mount current directory
    docker run -it --rm -v "$PWD":/mnt/pcap_reader "$DEV_IMAGE"
    ;;
  release)
    # TODO
    ;;
  *)
    echo "Unknown argument: $1"
    echo "Usage: $0 {dev|release}"
    exit 1
    ;;
esac
