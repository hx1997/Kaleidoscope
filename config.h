//
// Created by hx1997 on 2018/8/17.
//

#ifndef KALEIDOSCOPE_CONFIG_H
#define KALEIDOSCOPE_CONFIG_H

/* supported ISAs (Instruction Set Architectures) */
typedef enum {
    ISA_INTEL_X86,
} ISA;

/* disassembly modes, 16-bit or 32-bit or 64-bit */
typedef enum { BIT_WIDTH_16 = 0x1, BIT_WIDTH_32 = 0x2, BIT_WIDTH_64 = 0x4, BIT_WIDTH_UNSPECIFIED = 0xff, } BitWidth;

/* disassembler config, working mode, etc. */
typedef struct {
    ISA mode_isa;
    BitWidth mode_bitwidth;
    const char *disasm_file;
    unsigned int size_to_disasm;
    long int start_address;
} DisassemblerConfig;
extern DisassemblerConfig cf;

/* parse command-line arguments and config accordingly */
void conf_parse_args(int argc, char **argv);

#endif //KALEIDOSCOPE_CONFIG_H
