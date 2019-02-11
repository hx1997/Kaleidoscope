//
// Created by hx1997 on 2018/9/22.
//

#ifndef KALEIDOSCOPE_DISASSEMBLE_H
#define KALEIDOSCOPE_DISASSEMBLE_H

#include <stdint.h>
#include <windows.h>
#include "instruction.h"

#define ASM_BUFSIZE 128

typedef enum {
    ASM_ADDR_INVALID,
    ASM_ADDR_1,         // for instructions like "rol bx, 1" where 1 is a fixed number
    ASM_ADDR_IMM,
    ASM_ADDR_REG,
    ASM_ADDR_MEM_DIRECT,
    ASM_ADDR_JMP_RELATIVE,
    ASM_ADDR_REG_INDIRECT,
    ASM_ADDR_INDEX_SCALE,
    ASM_ADDR_BASE_INDEX_SCALE,
    ASM_ADDR_REG_RELATIVE,
    ASM_ADDR_RELATIVE_BASE_INDEX,

} AsmAddrMethod;

typedef struct {
    AsmAddrMethod addr_method;
    OperandType optype;
    uint8_t reg;
    uint8_t index_reg;
    uint8_t real_scale;
} CurrentOperand;

typedef struct {
    uint8_t prefixes[4];
    uint8_t opcode1, opcode2;
    const char *mnemonic;
    uint8_t opcount;
    CurrentOperand operand[4];
    uint8_t effective_opsize;
    uint8_t effective_addrsize;
    uint8_t modrm;
    uint8_t is_modrm_decoded;
    uint8_t sib;
    uint8_t is_sib_decoded;
    struct {
        uint8_t size;
        union {
            int8_t disp8;
            int16_t disp16;
            int32_t disp32;
        };
    } displacement;
    uint32_t imm;
    struct {
        uint8_t size;
        union {
            int8_t offset8;
            int16_t offset16;
            int32_t offset32;
        };
    } relative_offset;
} CurrentInst;

typedef struct {
    char asm_buf[ASM_BUFSIZE];
    uint8_t asm_buf_size;
    uint32_t curr_inst_offset;
} Disassembly;

int disasm_byte_buf(unsigned char buf[], unsigned int bufsize, unsigned long int start_address);
int disasm_pe_file(const char *file, unsigned int size, DWORD start_address);

#endif //KALEIDOSCOPE_DISASSEMBLE_H
