#!/bin/bash

DEV_IMAGE="pcap_reader_devel"
RELEASE_IMAGE="pcap_reader"

dev() {
    # Build dev image if needed
    if ! docker image inspect "$DEV_IMAGE" > /dev/null 2>&1; then
        echo "Building development image"
        docker build --target dev -t "$DEV_IMAGE" .
    fi

    # Run dev image and mount current directory
    if [ -n "$1" ]; then
        local BASH_CMD="$1"
    else
        local BASH_CMD="/bin/bash"
    fi
    docker run -it --rm -v "$PWD":/mnt/pcap_reader "$DEV_IMAGE" -c "$BASH_CMD"
    return $?
}

release () {
    dev "make clean && make"
    if [ ! "$?" -eq 0 ]; then
        echo "Compilation failed"
        exit 1
    else
        echo "Compilation succeeded"
    fi

    # Remove previous image, if it exists
    if docker image inspect "$RELEASE_IMAGE:latest" > /dev/null 2>&1; then
        echo "Removing previous $RELEASE_IMAGE:latest"
        docker rmi "$RELEASE_IMAGE:latest"
    fi

    echo "Building release image..."
    docker build --target release -t "$RELEASE_IMAGE" .
}

test () {
    # If we don't have a release build Docker image, we need to build it first
    if ! docker image inspect "$RELEASE_IMAGE" > /dev/null 2>&1; then
        release
    fi

    local TEST_FILE="all.pcap"
    local TEST_THREADS="16"
    echo "Testing with $TEST_THREADS threads and $TEST_FILE"
    # Make path absolute if needed
    local OUTPUT=$(docker run --rm -v "$PWD/$TEST_FILE:/app/$TEST_FILE" pcap_reader --threads "$TEST_THREADS" "$TEST_FILE")
    if echo "$OUTPUT" | grep -q "payload bytes: 292252"; then
        echo "Test passed, pcap_reader successfully parsed 292252 bytes of payload"
    else
        local PARSED_BYTES="$(echo "$OUTPUT" | grep "payload bytes" | awk '{ print $6 }')"
        echo "Test did NOT pass, pcap_reader incorrectly parsed $PARSED_BYTES bytes of payload (correct is 292252)"
        exit 1
    fi
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
