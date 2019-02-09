//
// Created by hx1997 on 2018/8/19.
//

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "peparser.h"
#include <winnt.h>
#include "disassemble.h"
#include "instruction.h"
#include "config.h"

#define MODRM_MOD(modrm) (((modrm) & 0b11000000u) >> 6u)
#define MODRM_REGOPCODE(modrm) (((modrm) & 0b00111000u) >> 3u)
#define MODRM_RM(modrm) ((modrm) & 0b00000111u)

#define SIB_SCALE(sib) (((sib) & 0b11000000u) >> 6u)
#define SIB_INDEX(sib) (((sib) & 0b00111000u) >> 3u)
#define SIB_BASE(sib) ((sib) & 0b00000111u)

#define SIGN(num) ((num) >= 0 ? '+' : '-')
#define MAGNITUDE(num) ((num) >= 0 ? (num) : -(num))

static inline uint8_t u8(unsigned const char buf[]) {
    return buf[0];
}

static inline uint16_t u16(unsigned const char buf[]) {
    return (buf[0] | (uint16_t)(buf[1] << 8u));
}

static inline uint32_t u32(unsigned const char buf[]) {
    return (buf[0] | (uint32_t)(buf[1] << 8u) | (uint32_t)(buf[2] << 16u) | (uint32_t)(buf[3] << 24u));
}

int is_prefix(unsigned const char byte) {
    return (byte == 0x26 || byte == 0x2e || byte == 0x36 || byte == 0x3e
            || byte == 0x64 || byte == 0x65 || byte == 0x66 || byte == 0x67
            || byte == 0xf0 || byte == 0xf2 || byte == 0xf3);
}

int is_opcode_extended(unsigned const char opcode1) {
    return ((opcode1 == 0x0f) ||            // two-byte opcodes
            (opcode1 >= 0x80 && opcode1 <= 0x83) || (opcode1 >= 0xc0 && opcode1 <= 0xc1) ||
            (opcode1 >= 0xd0 && opcode1 <= 0xd3) || (opcode1 >= 0xd8 && opcode1 <= 0xdf) ||
            (opcode1 >= 0xf6 && opcode1 <= 0xf7) || (opcode1 >= 0xfe && opcode1 <= 0xff));
}

void decode_prefixes(unsigned const char buf[], Disassembly *dis, CurrentInst *curr_inst) {
    assert(buf != NULL);

    unsigned const char *ptr_prefix = buf + dis->curr_inst_offset;
    while (is_prefix(*ptr_prefix)) {
        switch (*ptr_prefix) {
            case 0xf0:
            case 0xf2:
            case 0xf3:
                curr_inst->prefixes[0] = *ptr_prefix;
                break;
            case 0x2e:
            case 0x36:
            case 0x3e:
            case 0x26:
            case 0x64:
            case 0x65:
                curr_inst->prefixes[1] = *ptr_prefix;
                break;
            case 0x66:
                curr_inst->prefixes[2] = *ptr_prefix;
                curr_inst->effective_opsize = (cf.mode_bitwidth == BIT_WIDTH_32 ? BIT_WIDTH_16 : BIT_WIDTH_32);
                break;
            case 0x67:
                curr_inst->prefixes[3] = *ptr_prefix;
                curr_inst->effective_addrsize = (cf.mode_bitwidth == BIT_WIDTH_32 ? BIT_WIDTH_16 : BIT_WIDTH_32);
                break;
            default:
                return;
        }
        dis->curr_inst_offset++;
        ptr_prefix++;
    }
}

InstInfo decode_opcodes(unsigned const char buf[], Disassembly *dis, CurrentInst *curr_inst) {
    assert(buf != NULL);
    int i = 0;

    unsigned const char *ptr_opcode = buf + dis->curr_inst_offset;
    curr_inst->opcode1 = *ptr_opcode;
    int is_extended = is_opcode_extended(*ptr_opcode);

    // FIXME: ugly copy-and-paste programming!
    if (!is_extended) {
        for (i = 0; standard_insts[i].info.opsize != 0 && standard_insts[i].opcode <= curr_inst->opcode1; i++) {
            if (standard_insts[i].opcode == curr_inst->opcode1) {
                if (curr_inst->effective_opsize & standard_insts[i].info.opsize) {
                    curr_inst->mnemonic = standard_insts[i].info.mnemonic;
                    curr_inst->opcount = standard_insts[i].info.opcount;
                    break;
                }
            }
        }
        return standard_insts[i].info;
    } else {
        if (*ptr_opcode == 0x0f) {
            curr_inst->opcode2 = *(ptr_opcode + 1);
            for (i = 0; extended_insts[i].info.opsize != 0 && extended_insts[i].opcode <= curr_inst->opcode2; i++) {
                if (extended_insts[i].opcode == curr_inst->opcode2) {
                    if (curr_inst->effective_opsize & extended_insts[i].info.opsize) {
                        curr_inst->mnemonic = extended_insts[i].info.mnemonic;
                        curr_inst->opcount = extended_insts[i].info.opcount;
                        dis->curr_inst_offset++;
                        break;
                    }
                }
            }
            return extended_insts[i].info;
        } else {
            curr_inst->modrm = *(ptr_opcode + 1);
            for (i = 0; extended_group_insts[i].info.opsize != 0 && extended_group_insts[i].opcode <= curr_inst->opcode1; i++) {
                if (extended_group_insts[i].opcode == curr_inst->opcode1 &&
                    extended_group_insts[i].opcode_ex == MODRM_REGOPCODE(curr_inst->modrm)) {
                    if (curr_inst->effective_opsize & extended_group_insts[i].info.opsize) {
                        curr_inst->mnemonic = extended_group_insts[i].info.mnemonic;
                        curr_inst->opcount = extended_group_insts[i].info.opcount;
                        break;
                    }
                }
            }
            return extended_group_insts[i].info;
        }
    }
}

void decode_imm(unsigned const char *ptr_imm, Disassembly *dis, CurrentInst *curr_inst, OperandInfo opinfo) {
    switch (opinfo.optype) {
        case OPR_BYTE:
            curr_inst->imm = u8(ptr_imm);
            dis->curr_inst_offset += 1;
            break;
        case OPR_WORD:
            curr_inst->imm = u16(ptr_imm);
            dis->curr_inst_offset += 2;
            break;
        case OPR_DWORD:
            curr_inst->imm = u32(ptr_imm);
            dis->curr_inst_offset += 4;
            break;
        case OPR_WORD_DWORD:
            if (curr_inst->effective_opsize == BIT_WIDTH_16) {
                curr_inst->imm = u16(ptr_imm);
                dis->curr_inst_offset += 2;
                break;
            } else if (curr_inst->effective_opsize == BIT_WIDTH_32) {
                curr_inst->imm = u32(ptr_imm);
                dis->curr_inst_offset += 4;
                break;
            }
        default:
            return;
    }
}

void decode_sib(int op_ordinal, CurrentInst *curr_inst) {
    int scale = SIB_SCALE(curr_inst->sib);
    int index = SIB_INDEX(curr_inst->sib);
    int base = SIB_BASE(curr_inst->sib);

    // https://css.csail.mit.edu/6.858/2014/readings/i386/s17_02.htm
    if (base == 0b101 && MODRM_MOD(curr_inst->modrm) == 0b00) {
        // no base, operand is of the form [index*scale+disp]
        curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_INDEX_SCALE;
    } else {
        curr_inst->operand[op_ordinal].reg = (uint8_t) (base + ADDR_EAX);
    }

    if (index != 0b100) {
        // operand is of the form [base+index*scale+disp]
        curr_inst->operand[op_ordinal].index_reg = (uint8_t)(index + ADDR_EAX);
        switch (scale) {
            case 0b00:
                curr_inst->operand[op_ordinal].real_scale = 1;
                break;
            case 0b01:
                curr_inst->operand[op_ordinal].real_scale = 2;
                break;
            case 0b10:
                curr_inst->operand[op_ordinal].real_scale = 4;
                break;
            case 0b11:
                curr_inst->operand[op_ordinal].real_scale = 8;
                break;
            default:
                return;
        }
    } else {
        if (curr_inst->operand[op_ordinal].addr_method != ASM_ADDR_INDEX_SCALE) {
            // no index/scale, operand is of the form [base+disp]
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG_RELATIVE;
        } else {
            // no base/index/scale, operand is of the form [disp]
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_MEM_DIRECT;
        }
        curr_inst->operand[op_ordinal].real_scale = 0;
    }
}

void decode_modrm_greg(int op_ordinal, CurrentInst *curr_inst, OperandInfo opinfo) {
    int regopcode = MODRM_REGOPCODE(curr_inst->modrm);

    curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG;

    // is it DWORD type operand? if so, set the base to ADDR_AX (see next comment)
    if ((opinfo.optype == OPR_WORD_DWORD && curr_inst->effective_opsize == BIT_WIDTH_32) || (opinfo.optype == OPR_DWORD)) {
        curr_inst->operand[op_ordinal].reg = ADDR_AX;
    } else {
        curr_inst->operand[op_ordinal].reg = ADDR_AL;
    }

    // add an offset to the base to arrive at the correct register.
    // Offset is, BYTE operand: regopcode, WORD or DWORD operand: regopcode + (ADDR_AX - ADDR_AL)
    curr_inst->operand[op_ordinal].reg += (opinfo.optype == OPR_BYTE ? regopcode : regopcode + (ADDR_AX - ADDR_AL));
}

void decode_modrm_mem(unsigned const char buf[], int op_ordinal, Disassembly *dis, CurrentInst *curr_inst) {
    int rm = MODRM_RM(curr_inst->modrm);
    int mod = MODRM_MOD(curr_inst->modrm);

    if (mod == 0b00) {
        if (rm == 0b101) {
            // operand is of the form [disp32]
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_MEM_DIRECT;
            curr_inst->displacement.size = 32;
            curr_inst->displacement.disp32 = u32(buf + dis->curr_inst_offset);
            dis->curr_inst_offset += sizeof(uint32_t);
        } else if (rm == 0b100) {
            // operand is of the form [base+index*scale]
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_BASE_INDEX_SCALE;

            if (!curr_inst->is_sib_decoded) {
                curr_inst->sib = *(buf + dis->curr_inst_offset);
                curr_inst->is_sib_decoded = 1;
                dis->curr_inst_offset++;
                decode_sib(op_ordinal, curr_inst);
            } else {
                decode_sib(op_ordinal, curr_inst);
            }
        } else {
            // operand is of the form [reg]
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG_INDIRECT;
            curr_inst->operand[op_ordinal].reg = (uint8_t)(rm + ADDR_EAX);
        }
    } else if (mod == 0b01) {
        if (rm == 0b100) {
            // operand is of the form [base+index*scale+disp8]
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_RELATIVE_BASE_INDEX;

            if (!curr_inst->is_sib_decoded) {
                curr_inst->sib = *(buf + dis->curr_inst_offset);
                curr_inst->is_sib_decoded = 1;
                dis->curr_inst_offset++;
                decode_sib(op_ordinal, curr_inst);
            } else {
                decode_sib(op_ordinal, curr_inst);
            }

            curr_inst->displacement.size = 8;
            curr_inst->displacement.disp8 = u8(buf + dis->curr_inst_offset);
            dis->curr_inst_offset += sizeof(uint8_t);
        } else {
            // operand is of the form [reg+disp8]
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG_RELATIVE;
            curr_inst->operand[op_ordinal].reg = (uint8_t)(rm + ADDR_EAX);

            curr_inst->displacement.size = 8;
            curr_inst->displacement.disp8 = u8(buf + dis->curr_inst_offset);
            dis->curr_inst_offset += sizeof(uint8_t);
        }
    } else if (mod == 0b10) {
        if (rm == 0b100) {
            // operand is of the form [base+index*scale+disp32]
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_RELATIVE_BASE_INDEX;

            if (!curr_inst->is_sib_decoded) {
                curr_inst->sib = *(buf + dis->curr_inst_offset);
                curr_inst->is_sib_decoded = 1;
                dis->curr_inst_offset++;
                decode_sib(op_ordinal, curr_inst);
            } else {
                decode_sib(op_ordinal, curr_inst);
            }

            curr_inst->displacement.size = 32;
            curr_inst->displacement.disp32 = u32(buf + dis->curr_inst_offset);
            dis->curr_inst_offset += sizeof(uint32_t);
        } else {
            // operand is of the form [reg+disp32]
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG_RELATIVE;
            curr_inst->operand[op_ordinal].reg = (uint8_t)(rm + ADDR_EAX);

            curr_inst->displacement.size = 32;
            curr_inst->displacement.disp32 = u32(buf + dis->curr_inst_offset);
            dis->curr_inst_offset += sizeof(uint32_t);
        }
    }
}

void decode_modrm_gpreg_mem(unsigned const char buf[], int op_ordinal, Disassembly *dis, CurrentInst *curr_inst, OperandInfo opinfo) {
    int rm = MODRM_RM(curr_inst->modrm);
    int mod = MODRM_MOD(curr_inst->modrm);

    if (mod == 0b11) {
        // operand is a register
        curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG;

        // is it DWORD type operand? if so, set the base to ADDR_AX (see next comment)
        if ((opinfo.optype == OPR_WORD_DWORD && curr_inst->effective_opsize == BIT_WIDTH_32) || (opinfo.optype == OPR_DWORD)) {
            curr_inst->operand[op_ordinal].reg = ADDR_AX;
        } else {
            curr_inst->operand[op_ordinal].reg = ADDR_AL;
        }

        // add an offset to the base to arrive at the correct register.
        // Offset is, BYTE operand: rm, WORD or DWORD operand: rm + (ADDR_AX - ADDR_AL)
        curr_inst->operand[op_ordinal].reg += (opinfo.optype == OPR_BYTE ? rm : rm + (ADDR_AX - ADDR_AL));
    } else {
        // operand is a memory location
        decode_modrm_mem(buf, op_ordinal, dis, curr_inst);
    }
}

void decode_modrm_cdstreg(int op_ordinal, CurrentInst *curr_inst, AddressingMethod base_reg) {
    int regopcode = MODRM_REGOPCODE(curr_inst->modrm);
    curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG;
    curr_inst->operand[op_ordinal].reg = base_reg + regopcode;
}

void decode_modrm_greg_only(int op_ordinal, CurrentInst *curr_inst) {
    int rm = MODRM_RM(curr_inst->modrm);
    curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG;
    curr_inst->operand[op_ordinal].reg = ADDR_EAX + rm;
}

void decode_modrm(unsigned const char buf[], int op_ordinal, Disassembly *dis, CurrentInst *curr_inst, OperandInfo opinfo) {
    switch (opinfo.addr_method) {
        case ADDR_MODRM_GREG:
            decode_modrm_greg(op_ordinal, curr_inst, opinfo);
            break;
        case ADDR_MODRM_MEM:
            decode_modrm_mem(buf, op_ordinal, dis, curr_inst);
            break;
        case ADDR_MODRM_GPREG_MEM:
            decode_modrm_gpreg_mem(buf, op_ordinal, dis,curr_inst, opinfo);
            break;
        case ADDR_MODRM_MOD_GREG_ONLY:
            decode_modrm_greg_only(op_ordinal, curr_inst);
            break;
        case ADDR_CONTROL_REG:
            decode_modrm_cdstreg(op_ordinal, curr_inst, ADDR_CR0);
            break;
        case ADDR_DEBUG_REG:
            decode_modrm_cdstreg(op_ordinal, curr_inst, ADDR_DR0);
            break;
        case ADDR_MODRM_TREG:
            decode_modrm_cdstreg(op_ordinal, curr_inst, ADDR_TR0);
            break;
        case ADDR_MODRM_SREG:
            decode_modrm_cdstreg(op_ordinal, curr_inst, ADDR_ES);
            break;
        default:
            return;
    }
}

int decode_operand(unsigned const char buf[], int op_ordinal, Disassembly *dis, CurrentInst *curr_inst, OperandInfo opinfo) {
    // point to the operand
    unsigned const char *ptr_operand = buf + dis->curr_inst_offset;
    curr_inst->operand[op_ordinal].optype = opinfo.optype;

    switch (opinfo.addr_method) {
        // register addressing
        case ADDR_AL:
        case ADDR_BL:
        case ADDR_CL:
        case ADDR_DL:
        case ADDR_AH:
        case ADDR_BH:
        case ADDR_CH:
        case ADDR_DH:
        case ADDR_CS:
        case ADDR_DS:
        case ADDR_ES:
        case ADDR_FS:
        case ADDR_GS:
        case ADDR_SS:
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG;
            curr_inst->operand[op_ordinal].reg = opinfo.addr_method;
            break;
        // register addressing, those that have a 32-bit counterpart need special handling
        case ADDR_AX:
        case ADDR_CX:
        case ADDR_DX:
        case ADDR_BX:
        case ADDR_SP:
        case ADDR_BP:
        case ADDR_SI:
        case ADDR_DI:
            // setting the operand info struct according to decode results
            // reg should contain a symbolic constant indicating which register this operand refers to
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_REG;
            curr_inst->operand[op_ordinal].reg = opinfo.addr_method;

            // is it DWORD type operand? if so, change reg field to its 32-bit counterpart by adding a offset
            if (opinfo.optype == OPR_WORD_DWORD && curr_inst->effective_opsize == BIT_WIDTH_32) {
                curr_inst->operand[op_ordinal].reg += (ADDR_EAX - ADDR_AX);
            }
            break;
        // immediate addressing
        case ADDR_IMM:
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_IMM;
            decode_imm(ptr_operand, dis, curr_inst, opinfo);
            break;
        case ADDR_MODRM_GREG:
        case ADDR_MODRM_MEM:
        case ADDR_MODRM_GPREG_MEM:
        case ADDR_MODRM_MOD_GREG_ONLY:
        case ADDR_MODRM_SREG:
        case ADDR_CONTROL_REG:
        case ADDR_DEBUG_REG:
        case ADDR_MODRM_TREG:
            // Make sure we increment dis->curr_inst_offset only once,
            // because ModR/M occupies 1 byte at most
            if (!curr_inst->is_modrm_decoded) {
                curr_inst->modrm = *ptr_operand;
                curr_inst->is_modrm_decoded = 1;
                dis->curr_inst_offset++;
                decode_modrm(buf, op_ordinal, dis, curr_inst, opinfo);
            } else {
                decode_modrm(buf, op_ordinal, dis, curr_inst, opinfo);
            }
            break;
        case ADDR_DIRECT_OFFSET:
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_MEM_DIRECT;
            if (opinfo.optype == OPR_BYTE) {
                curr_inst->displacement.size = 8;
                curr_inst->displacement.disp8 = u8(ptr_operand);
                dis->curr_inst_offset += sizeof(uint8_t);
            } else {
                if (curr_inst->effective_opsize == BIT_WIDTH_32) {
                    curr_inst->displacement.size = 32;
                    curr_inst->displacement.disp32 = u32(ptr_operand);
                    dis->curr_inst_offset += sizeof(uint32_t);
                } else if (curr_inst->effective_opsize == BIT_WIDTH_16) {
                    curr_inst->displacement.size = 16;
                    curr_inst->displacement.disp16 = u16(ptr_operand);
                    dis->curr_inst_offset += sizeof(uint16_t);
                }
            }
            break;
        case ADDR_RELATIVE:
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_JMP_RELATIVE;
            if (opinfo.optype == OPR_BYTE) {
                curr_inst->relative_offset.size = 8;
                curr_inst->relative_offset.offset8 = u8(ptr_operand);
                dis->curr_inst_offset += sizeof(uint8_t);
            } else if (opinfo.optype == OPR_WORD_DWORD) {
                if (curr_inst->effective_opsize == BIT_WIDTH_32) {
                    curr_inst->relative_offset.size = 32;
                    curr_inst->relative_offset.offset32 = u32(ptr_operand);
                    dis->curr_inst_offset += sizeof(uint32_t);
                } else if (curr_inst->effective_opsize == BIT_WIDTH_16) {
                    curr_inst->relative_offset.size = 16;
                    curr_inst->relative_offset.offset16 = u16(ptr_operand);
                    dis->curr_inst_offset += sizeof(uint16_t);
                }
            }
            break;
        case ADDR_1:
            curr_inst->operand[op_ordinal].addr_method = ASM_ADDR_1;
            break;
        default:
            break;
    }

    return 0;
}

int disasm_one_inst_x86(unsigned const char buf[], Disassembly *dis, CurrentInst *curr_inst) {
    int delta = dis->curr_inst_offset;  // number of bytes of current instruction
    int i;
    InstInfo inst_info;

    // prefixes
    curr_inst->effective_opsize = cf.mode_bitwidth;
    curr_inst->effective_addrsize = cf.mode_bitwidth;
    decode_prefixes(buf, dis, curr_inst);

    // opcode
    inst_info = decode_opcodes(buf, dis, curr_inst);

    // operands
    dis->curr_inst_offset++;
    if (curr_inst->mnemonic) {
        for (i = 0; i < curr_inst->opcount; i++) {
            decode_operand(buf, i, dis, curr_inst, inst_info.opinfo[i]);
        }
    }

    delta = dis->curr_inst_offset - delta;
    return delta;
}

int translate_inst_into_intel(CurrentInst curr_inst, char buf[], size_t bufsize, int start_address, int delta) {
    int i = 0;

    memset(buf, 0, bufsize);

    // translate prefixes
    for (i = 0; i < 4; i++) {
        switch (curr_inst.prefixes[i]) {
            case 0x26:
                strcpy(buf, "es: ");
                continue;
            case 0x2e:
                strcpy(buf, "cs: ");
                continue;
            case 0x36:
                strcpy(buf, "ss: ");
                continue;
            case 0x3e:
                strcpy(buf, "ds: ");
                continue;
            case 0x64:
                strcpy(buf, "fs: ");
                continue;
            case 0x65:
                strcpy(buf, "gs: ");
                continue;
            case 0xf0:
                strcpy(buf, "lock ");
                continue;
            case 0xf2:
                strcpy(buf, "repne ");
                continue;
            case 0xf3:
                strcpy(buf, "rep ");
                continue;
            default:
                continue;
        }
    }

    // copy mnemonic directly to buf, since we already decoded that in disasm_one_inst
    if (curr_inst.mnemonic) {
        sprintf(buf, "%s%s ", buf, curr_inst.mnemonic);
    } else {
        sprintf(buf, "%sdb 0x%x ", buf, curr_inst.opcode1);
    }

    // translate operands
    for (i = 0; i < curr_inst.opcount; i++) {
        switch (curr_inst.operand[i].addr_method) {
            case ASM_ADDR_INVALID:
                sprintf(buf, "%s(none)", buf);
                break;
            case ASM_ADDR_1:
                sprintf(buf, "%s1", buf);
                break;
            case ASM_ADDR_IMM:
                sprintf(buf, "%s0x%x", buf, curr_inst.imm);
                break;
            case ASM_ADDR_REG:
                sprintf(buf, "%s%s", buf, regname[curr_inst.operand[i].reg - ADDR_AL]);
                break;
            case ASM_ADDR_MEM_DIRECT:
                if (curr_inst.operand[i].optype == OPR_BYTE) {
                    sprintf(buf, "%sbyte ptr ", buf);
                } else if (curr_inst.operand[i].optype == OPR_WORD_DWORD) {
                    if (curr_inst.effective_opsize == BIT_WIDTH_16) {
                        sprintf(buf, "%sword ptr ", buf);
                    } else if (curr_inst.effective_opsize == BIT_WIDTH_32) {
                        sprintf(buf, "%sdword ptr ", buf);
                    }
                } else if (curr_inst.operand[i].optype == OPR_WORD) {
                    sprintf(buf, "%sword ptr ", buf);
                } else if (curr_inst.operand[i].optype == OPR_DWORD) {
                    sprintf(buf, "%sdword ptr ", buf);
                }

                switch (curr_inst.displacement.size) {
                    case 8:
                        sprintf(buf, "%s[0x%x]", buf, curr_inst.displacement.disp8);
                        break;
                    case 16:
                        sprintf(buf, "%s[0x%x]", buf, curr_inst.displacement.disp16);
                        break;
                    case 32:
                        sprintf(buf, "%s[0x%x]", buf, curr_inst.displacement.disp32);
                        break;
                    default:
                        break;
                }
                break;
            case ASM_ADDR_JMP_RELATIVE:
                switch (curr_inst.relative_offset.size) {
                    case 8:
                        sprintf(buf, "%s0x%x", buf, curr_inst.relative_offset.offset8 + (int8_t)delta + start_address);
                        break;
                    case 16:
                        sprintf(buf, "%s0x%x", buf, curr_inst.relative_offset.offset16 + (int16_t)delta + start_address);
                        break;
                    case 32:
                        sprintf(buf, "%s0x%x", buf, curr_inst.relative_offset.offset32 + (int32_t)delta + start_address);
                        break;
                    default:
                        break;
                }
                break;
            case ASM_ADDR_REG_INDIRECT:
                if (curr_inst.operand[i].optype == OPR_BYTE) {
                    sprintf(buf, "%sbyte ptr ", buf);
                } else if (curr_inst.operand[i].optype == OPR_WORD_DWORD) {
                    if (curr_inst.effective_opsize == BIT_WIDTH_16) {
                        sprintf(buf, "%sword ptr ", buf);
                    } else if (curr_inst.effective_opsize == BIT_WIDTH_32) {
                        sprintf(buf, "%sdword ptr ", buf);
                    }
                }

                sprintf(buf, "%s[%s]", buf, regname[curr_inst.operand[i].reg - ADDR_AL]);
                break;
            case ASM_ADDR_REG_RELATIVE:
                if (curr_inst.operand[i].optype == OPR_BYTE) {
                    sprintf(buf, "%sbyte ptr ", buf);
                } else if (curr_inst.operand[i].optype == OPR_WORD_DWORD) {
                    if (curr_inst.effective_opsize == BIT_WIDTH_16) {
                        sprintf(buf, "%sword ptr ", buf);
                    } else if (curr_inst.effective_opsize == BIT_WIDTH_32) {
                        sprintf(buf, "%sdword ptr ", buf);
                    }
                }

                switch (curr_inst.displacement.size) {
                    case 0:
                        // no displacement
                        sprintf(buf, "%s[%s]", buf, regname[curr_inst.operand[i].reg - ADDR_AL]);
                        break;
                    case 8:
                        sprintf(buf, "%s[%s%c0x%x]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                SIGN(curr_inst.displacement.disp8), MAGNITUDE(curr_inst.displacement.disp8));
                        break;
                    case 16:
                        sprintf(buf, "%s[%s%c0x%x]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                SIGN(curr_inst.displacement.disp16), MAGNITUDE(curr_inst.displacement.disp16));
                        break;
                    case 32:
                        sprintf(buf, "%s[%s%c0x%x]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                SIGN(curr_inst.displacement.disp32), MAGNITUDE(curr_inst.displacement.disp32));
                        break;
                    default:
                        break;
                }
                break;
            case ASM_ADDR_INDEX_SCALE:
                if (curr_inst.operand[i].optype == OPR_BYTE) {
                    sprintf(buf, "%sbyte ptr ", buf);
                } else if (curr_inst.operand[i].optype == OPR_WORD_DWORD) {
                    if (curr_inst.effective_opsize == BIT_WIDTH_16) {
                        sprintf(buf, "%sword ptr ", buf);
                    } else if (curr_inst.effective_opsize == BIT_WIDTH_32) {
                        sprintf(buf, "%sdword ptr ", buf);
                    }
                }

                if (curr_inst.operand[i].real_scale == 1) {
                    sprintf(buf, "%s[%s]", buf, regname[curr_inst.operand[i].index_reg - ADDR_AL]);
                } else {
                    sprintf(buf, "%s[%s*%d]", buf,
                            regname[curr_inst.operand[i].index_reg - ADDR_AL], curr_inst.operand[i].real_scale);
                }
                break;
            case ASM_ADDR_BASE_INDEX_SCALE:
                if (curr_inst.operand[i].optype == OPR_BYTE) {
                    sprintf(buf, "%sbyte ptr ", buf);
                } else if (curr_inst.operand[i].optype == OPR_WORD_DWORD) {
                    if (curr_inst.effective_opsize == BIT_WIDTH_16) {
                        sprintf(buf, "%sword ptr ", buf);
                    } else if (curr_inst.effective_opsize == BIT_WIDTH_32) {
                        sprintf(buf, "%sdword ptr ", buf);
                    }
                }

                if (curr_inst.operand[i].real_scale == 1) {
                    sprintf(buf, "%s[%s+%s]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                            regname[curr_inst.operand[i].index_reg - ADDR_AL]);
                } else {
                    sprintf(buf, "%s[%s+%s*%d]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                            regname[curr_inst.operand[i].index_reg - ADDR_AL], curr_inst.operand[i].real_scale);
                }
                break;
            case ASM_ADDR_RELATIVE_BASE_INDEX:
                if (curr_inst.operand[i].optype == OPR_BYTE) {
                    sprintf(buf, "%sbyte ptr ", buf);
                } else if (curr_inst.operand[i].optype == OPR_WORD_DWORD) {
                    if (curr_inst.effective_opsize == BIT_WIDTH_16) {
                        sprintf(buf, "%sword ptr ", buf);
                    } else if (curr_inst.effective_opsize == BIT_WIDTH_32) {
                        sprintf(buf, "%sdword ptr ", buf);
                    }
                }

                if (curr_inst.operand[i].real_scale == 1) {
                    switch (curr_inst.displacement.size) {
                        case 0:
                            // no displacement
                            sprintf(buf, "%s[%s+%s]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                    regname[curr_inst.operand[i].index_reg - ADDR_AL]);
                            break;
                        case 8:
                            sprintf(buf, "%s[%s+%s%c0x%x]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                    regname[curr_inst.operand[i].index_reg - ADDR_AL],
                                    SIGN(curr_inst.displacement.disp8), MAGNITUDE(curr_inst.displacement.disp8));
                            break;
                        case 16:
                            sprintf(buf, "%s[%s+%s%c0x%x]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                    regname[curr_inst.operand[i].index_reg - ADDR_AL],
                                    SIGN(curr_inst.displacement.disp16), MAGNITUDE(curr_inst.displacement.disp16));
                            break;
                        case 32:
                            sprintf(buf, "%s[%s+%s%c0x%x]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                    regname[curr_inst.operand[i].index_reg - ADDR_AL],
                                    SIGN(curr_inst.displacement.disp32), MAGNITUDE(curr_inst.displacement.disp32));
                            break;
                        default:
                            break;
                    }
                } else {
                    switch (curr_inst.displacement.size) {
                        case 0:
                            // no displacement
                            sprintf(buf, "%s[%s+%s*%d]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                    regname[curr_inst.operand[i].index_reg - ADDR_AL], curr_inst.operand[i].real_scale);
                            break;
                        case 8:
                            sprintf(buf, "%s[%s+%s*%d%c0x%x]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                    regname[curr_inst.operand[i].index_reg - ADDR_AL], curr_inst.operand[i].real_scale,
                                    SIGN(curr_inst.displacement.disp8), MAGNITUDE(curr_inst.displacement.disp8));
                            break;
                        case 16:
                            sprintf(buf, "%s[%s+%s*%d%c0x%x]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                    regname[curr_inst.operand[i].index_reg - ADDR_AL], curr_inst.operand[i].real_scale,
                                    SIGN(curr_inst.displacement.disp16), MAGNITUDE(curr_inst.displacement.disp16));
                            break;
                        case 32:
                            sprintf(buf, "%s[%s+%s*%d%c0x%x]", buf, regname[curr_inst.operand[i].reg - ADDR_AL],
                                    regname[curr_inst.operand[i].index_reg - ADDR_AL], curr_inst.operand[i].real_scale,
                                    SIGN(curr_inst.displacement.disp32), MAGNITUDE(curr_inst.displacement.disp32));
                            break;
                        default:
                            break;
                    }
                }
                break;
        }
        if (i+1 < curr_inst.opcount) strcat(buf, ", ");
    }

    return 0;
}

void init_disasm_struct(Disassembly *dis) {
    memset(dis, 0, sizeof(Disassembly));
    dis->asm_buf_size = ASM_BUFSIZE;
}

int disasm_byte_buf_x86(unsigned char buf[], unsigned int bufsize, int start_address) {
    int delta;
    Disassembly dis;

    init_disasm_struct(&dis);

    // decode each instruction in buf
    for (int i = 0; i < bufsize; i += delta, start_address += delta) {
        CurrentInst curr_inst = {0};
        delta = disasm_one_inst_x86(buf, &dis, &curr_inst);
        printf("%08x: ", start_address);

        // print the opcode. 50 should suffice because the longest possible x86 inst is 15 bytes.
        char opcode_str[50] = "";
        for (int j = 0; j < delta; j++) {
            sprintf(opcode_str, "%s%02x ", opcode_str, buf[i+j]);
        }
        printf("%-20s ", opcode_str);

        char asmbuf[128];
        translate_inst_into_intel(curr_inst, asmbuf, 128, start_address, delta);
        printf("%s\n", asmbuf);
        dis.asm_buf[0] = '\0';
    }
    return 0;
}

int disasm_byte_buf(unsigned char buf[], unsigned int bufsize, int start_address) {
    int ret = 0;

    switch (cf.mode_isa) {
        case ISA_INTEL_X86:
            ret = disasm_byte_buf_x86(buf, bufsize, start_address);
            break;
    }

    return ret;
}

int disasm_pe_file(const char *file, unsigned int size, long int start_address) {
    if (!file || size <= 0) {
        fprintf(stderr, "disasm_pe_file(): invalid arguments!\n");
        return -1;
    }

    FILE *fp = fopen(file, "rb");
    if (!fp) {
        fprintf(stderr, "disasm_pe_file(): error opening file %s!\n", file);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long int file_size = ftell(fp);
    if (file_size < size || file_size < start_address) {
        fprintf(stderr, "disasm_pe_file(): specified file size too big!\n");
        return -1;
    }

    // if start_address is negative, set it to the address of the PE entry point
    if (start_address < 0) {
        long int rva;
        start_address = get_pe_ep_addr(fp, &rva);
        if (start_address <= 0) {
            return -1;
        }
        fseek(fp, start_address, SEEK_SET);
        start_address = rva;
    } else {
        fseek(fp, start_address, SEEK_SET);
    }

    // allocate a buffer of 'size' bytes
    unsigned char *buf = malloc(sizeof(unsigned char) * size);
    // read 'size' bytes from 'file' and disassemble it
    size_t bytes_read = fread(buf, sizeof(unsigned char), size, fp);
    if (bytes_read != size) {
        fprintf(stderr, "disasm_pe_file(): error reading file %s!\n", file);
        return -1;
    }

    return disasm_byte_buf(buf, size, start_address);
}