//
// Created by hx1997 on 2018/8/17.
//

#include <stdio.h>
#include <string.h>
#include "config.h"

DisassemblerConfig cf;

void conf_parse_args(int argc, char **argv) {
    // loop through argv
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-m16") == 0) {
            cf.mode_bitwidth = BIT_WIDTH_16;
        }
        else if (strcmp(argv[i], "-m32") == 0) {
            cf.mode_bitwidth = BIT_WIDTH_32;
        }
        else if (strcmp(argv[i], "-m64") == 0) {
            cf.mode_bitwidth = BIT_WIDTH_64;
        } else {
            fprintf(stderr, "conf_parse_args(): Invalid argument '%s'!\n", argv[i]);
        }
    }
}
