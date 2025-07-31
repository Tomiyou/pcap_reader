#!/bin/bash

DEV_IMAGE="pcap_reader_builder"
RELEASE_IMAGE="pcap_reader"

dev() {
    # Build dev image if needed
    if ! docker image inspect "$DEV_IMAGE" > /dev/null 2>&1; then
        docker build --target dev -t "$DEV_IMAGE" .
    fi

    # Run dev image and mount current directory
    if [ -n "$1" ]; then
        BASH_CMD="$1"
    else
        BASH_CMD="/bin/bash"
    fi
    docker run -it --rm -v "$PWD":/mnt/pcap_reader "$DEV_IMAGE" -c "$BASH_CMD"
}

release () {
    echo "Building release image..."
    dev "make clean && make"
    docker build --target release -t "$RELEASE_IMAGE" .
}

test () {
    if [ -z "$2" ]; then
        echo "Please provide a test file: $0 $1 test.pcap"
        exit 1
    fi

    # If we don't have a release build Docker image, we need to build it first
    if ! docker image inspect "$RELEASE_IMAGE" > /dev/null 2>&1; then
        release
    fi

    echo "Testing ..."
    # Make path absolute if needed
    TEST_FILE="$(basename $2)"
    HOST_PATH="$2"
    if [[ $HOST_PATH != /* ]]; then
        HOST_PATH="$PWD/$HOST_PATH"
    fi
    docker run --rm -v "$HOST_PATH:/app/$TEST_FILE" pcap_reader --threads 16 "$TEST_FILE"
}

case "$1" in
    dev)
        dev
        ;;
    release)
        # Build release image
        release
        ;;
    test)
        # Test docker image
        test "$@"
        ;;
    *)
        echo "Unknown argument: $1"
        echo "Usage: $0 {dev|release|test}"
        exit 1
        ;;
esac
