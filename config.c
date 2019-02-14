//
// Created by hx1997 on 2018/8/17.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

DisassemblerConfig cf = {0};

static void usage(const char *executable) {
    printf("Usage: %s -s SIZE [-a ADDR] [-b BASE] [-h] FILE\n", executable);
    printf("-s SIZE\t\tdisassemble SIZE bytes (in decimal) starting from ADDR\n");
    printf("-a ADDR\t\tstart disassembling from file offset ADDR (in hex)\n");
    printf("-b BASE\t\tspecify the image base in hex (i.e. the address an executable is loaded to in memory); "
           "the disassember will add BASE to file offsets to form virtual addresses (VA). "
           "Note: this BASE is calculated automatically if FILE is a PE; you don't need to specify it manually.\n");
    printf("-h\t\tdisplay this help message\n");
}

void conf_parse_args(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        exit(-1);
    }

    // loop through argv
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m16") == 0) {
            cf.mode_bitwidth = BIT_WIDTH_16;
        } else if (strcmp(argv[i], "-m32") == 0) {
            cf.mode_bitwidth = BIT_WIDTH_32;
        } else if (strcmp(argv[i], "-m64") == 0) {
            cf.mode_bitwidth = BIT_WIDTH_64;
        } else if (strcmp(argv[i], "-s") == 0) {
            cf.size_to_disasm = (unsigned int)strtol(argv[i+1], 0, 10);
            i++;
        } else if (strcmp(argv[i], "-a") == 0) {
            cf.start_address = strtoul(argv[i+1], 0, 16);
            i++;
        } else if (strcmp(argv[i], "-b") == 0) {
            cf.image_base = strtoul(argv[i+1], 0, 16);
            i++;
        } else if (strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            exit(0);
        } else if (*argv[i] == '-') {
            fprintf(stderr, "conf_parse_args(): ignoring invalid argument '%s'!\n", argv[i]);
            usage(argv[0]);
        } else {
            if (cf.size_to_disasm == 0) {
                fprintf(stderr, "conf_parse_args(): disassembly of PE files requires the '-s' option! "
                                "Either you did not specify it, or the argument specified is invalid!\n");
                usage(argv[0]);
                exit(-1);
            }
            cf.disasm_file = argv[i];
        }
    }
}
