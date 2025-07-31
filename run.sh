#!/bin/bash

DEV_IMAGE="pcap_reader_builder"
RELEASE_IMAGE="pcap_reader"

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
    # Build release image
    docker build --target release -t "$RELEASE_IMAGE" .
    ;;
  test)
    # Test docker image
    if [ -z "$2" ]; then
      echo "Please provide a test file: $0 $1 test.pcap"
      exit 1
    fi
    # Make path absolute if needed
    TEST_FILE="$(basename $2)"
    HOST_PATH="$2"
    if [[ $HOST_PATH != /* ]]; then
      HOST_PATH="$PWD/$HOST_PATH"
    fi
    docker run --rm -v "$HOST_PATH:/app/$TEST_FILE" pcap_reader "$TEST_FILE"
    ;;
  *)
    echo "Unknown argument: $1"
    echo "Usage: $0 {dev|release|test}"
    exit 1
    ;;
esac
