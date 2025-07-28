#include <asm-generic/errno-base.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_help(void) {
    printf("Usage: pcap_reader --jobs 4 --help $INPUT_PCAP\n");
}

int main (int argc, char **argv) {
    long jobs = 1;
    char *pcap = NULL;
    int i;

    // We always need at least one argument - input pcap
    if (argc < 2) {
        print_help();
        return -ENOENT;
    }

    // Parse arguments
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--jobs") == 0) {
            char *endptr = NULL;

            // Parse next argument as thread count
            i += 1;
            if (i >= argc) {
                print_help();
                return -EINVAL;
            }

            jobs = strtol(argv[i], &endptr, 10);
            if (endptr[0] != '\0') {
                print_help();
                return -EINVAL;
            }

            // Catch negative numbers
            if (jobs < 0) {
                print_help();
                return -EINVAL;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        } else {
            // This arg is our input PCAP file, we only allow 1 input file
            if (pcap != NULL) {
                return -EINVAL;
            }

            pcap = argv[i];
        }
    }

    if (pcap == NULL) {
        print_help();
        return -EINVAL;
    }
    printf("Input PCAP file is %s\n", pcap);

    return 0;
}
