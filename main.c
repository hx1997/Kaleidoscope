#include <stdio.h>
#include "disassemble.h"
#include "config.h"

int main(int argc, char **argv) {
    cf.mode_bitwidth = BIT_WIDTH_32;

    if (argc > 1) {
        conf_parse_args(argc-1, argv+1);    /* skip the executable name */
    }

    disasm_pe_file(cf.disasm_file, cf.size_to_disasm, cf.start_address);
    return 0;
}