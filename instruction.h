//
// Created by hx1997 on 2018/8/19.
//

#ifndef KALEIDOSCOPE_INSTRUCTION_H
#define KALEIDOSCOPE_INSTRUCTION_H

#include <stdint.h>
#include "config.h"

// operand addressing methods, the MSB indicates ModR/M
// http://sparksandflames.com/files/x86InstructionChart.html
typedef enum {
    ADDR_1,         // for instructions like "rol bx, 1" where 1 is a fixed number
    ADDR_DIRECT_ADDRESS,
    ADDR_CONTROL_REG,
    ADDR_DEBUG_REG,
    ADDR_EFLAGS,
    ADDR_IMM,
    ADDR_RELATIVE,
    ADDR_DIRECT_OFFSET,
    ADDR_MEM_DS,
    ADDR_MEM_ES,
    ADDR_AL,
    ADDR_CL,
    ADDR_DL,
    ADDR_BL,
    ADDR_AH,
    ADDR_CH,
    ADDR_DH,
    ADDR_BH,
    ADDR_AX,
    ADDR_CX,
    ADDR_DX,
    ADDR_BX,
    ADDR_SP,
    ADDR_BP,
    ADDR_SI,
    ADDR_DI,
    ADDR_EAX,
    ADDR_ECX,
    ADDR_EDX,
    ADDR_EBX,
    ADDR_ESP,
    ADDR_EBP,
    ADDR_ESI,
    ADDR_EDI,
    ADDR_DS,
    ADDR_ES,
    ADDR_FS,
    ADDR_GS,
    ADDR_SS,
    ADDR_CS,
    ADDR_MODRM_GPREG_MEM = 0x80,
    ADDR_MODRM_GREG,
    ADDR_MODRM_MEM,
    ADDR_MODRM_MMXREG,
    ADDR_MODRM_MMXREG_MEM,
    ADDR_MODRM_MOD_GREG_ONLY,
    ADDR_MODRM_SREG,
    ADDR_MODRM_TREG,
    ADDR_MODRM_FPREG,
    ADDR_MODRM_FPREG_MEM,
} AddressingMethod;

#define ADDR_16BIT_REGSITER (ADDR_AX)

// operand type
// http://sparksandflames.com/files/x86InstructionChart.html
typedef enum {
    OPR_UNSPECIFIED,
    OPR_BOUND,
    OPR_BYTE,
    OPR_BYTE_WORD,
    OPR_DWORD,
    OPR_DQWORD,
    OPR_32_48_PTR,
    OPR_QWORD_MMXREG,
    OPR_PS_FP,
    OPR_SS_FP,
    OPR_QWORD,
    OPR_PSEUDO_DESCRIPTOR,
    OPR_DWORD_REG,
    OPR_WORD_DWORD,
    OPR_WORD,
} OperandType;

typedef struct {
    AddressingMethod addr_method;
    OperandType optype;
} OperandInfo;

typedef struct {
    const char *mnemonic;
    uint8_t opcount;
    uint8_t opsize;
    OperandInfo opinfo[4];
} InstInfo;

typedef struct {
    uint8_t opcode;
    InstInfo info;
} Inst;

typedef struct {
    uint8_t opcode;
    InstInfo info;
    uint8_t opcode_ex;
} ExtendedGroupInst;

#endif //KALEIDOSCOPE_INSTRUCTION_H
