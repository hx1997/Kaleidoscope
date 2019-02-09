//
// Created by hx1997 on 2018/8/17.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

DisassemblerConfig cf = {0};

void conf_parse_args(int argc, char **argv) {
    // default value for start_address. -1 means to set the PE entry point as the start_address.
    cf.start_address = -1;
    // loop through argv
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-m16") == 0) {
            cf.mode_bitwidth = BIT_WIDTH_16;
        } else if (strcmp(argv[i], "-m32") == 0) {
            cf.mode_bitwidth = BIT_WIDTH_32;
        } else if (strcmp(argv[i], "-m64") == 0) {
            cf.mode_bitwidth = BIT_WIDTH_64;
        } else if (strcmp(argv[i], "-s") == 0) {
            cf.size_to_disasm = (unsigned int)strtol(argv[i+1], 0, 10);
        } else if (strcmp(argv[i], "-a") == 0) {
            cf.start_address = strtol(argv[i+1], 0, 16);
        } else if (*argv[i] == '-') {
            fprintf(stderr, "conf_parse_args(): ignoring invalid argument '%s'!\n", argv[i]);
        } else {
            if (cf.size_to_disasm == 0) {
                fprintf(stderr, "conf_parse_args(): disassembly of PE files requires the '-s' option! "
                                "Either you did not specify it, or the argument specified is invalid!");
                exit(-1);
            }
            cf.disasm_file = argv[i];
        }
    }
}
