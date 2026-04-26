// Portable ebpf interpreter
//
// Copyright (C) 2026  Timofey Titovets <nefelim4ag@gmail.com>
//
// This file may be distributed under the terms of the GNU GPLv3 license.

#include <stdio.h>
#include <stdint.h>
#include "tiny_ebpf.h"

// As per https://www.rfc-editor.org/rfc/rfc9669.html
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    opcode     |     regs      |            offset             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              imm                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// opcode:
// +-+-+-+-+-+-+-+-+
// |specific |class|
// +-+-+-+-+-+-+-+-+
// regs:
// +-+-+-+-+-+-+-+-+
// |src_reg|dst_reg|
// +-+-+-+-+-+-+-+-+


void print_ebpf_instruction(const uint64_t *instruction) {
    const struct ebpf_instruct *instruct = (struct ebpf_instruct *) instruction;
    fprintf(stdout, "  0x%02x", instruct->opcode);
    if (instruct->src_reg > 9)
        fprintf(stdout, "    %d", instruct->src_reg);
    else
        fprintf(stdout, "     %d", instruct->src_reg);
    if (instruct->dst_reg > 9)
        fprintf(stdout, "    %d", instruct->dst_reg);
    else
        fprintf(stdout, "     %d", instruct->dst_reg);
    fprintf(stdout, " 0x%04x", (uint16_t) instruct->offset);
    fprintf(stdout, "      0x%08x", (uint32_t) instruct->imm);
    uint8_t class = instruct->opcode & BPF_CS_MASK;
    switch (class) {
        case BPF_LD:    fprintf(stdout, "\tLD    "); break;
        case BPF_LDX:   fprintf(stdout, "\tLDX   "); break;
        case BPF_ST:    fprintf(stdout, "\tST    "); break;
        case BPF_STX:   fprintf(stdout, "\tSTX   "); break;
        case BPF_ALU:   fprintf(stdout, "\tALU   "); break;
        case BPF_JMP:   fprintf(stdout, "\tJMP   "); break;
        case BPF_JMP32: fprintf(stdout, "\tJMP32 "); break;
        case BPF_ALU64: fprintf(stdout, "\tALU64 "); break;
    }
    if (class <= BPF_STX) {
        uint8_t sz = (instruct->opcode >> 3) & 3;
        if (sz == 0)
            sz = 32;
        else if (sz == 1)
            sz = 16;
        else if (sz == 2)
            sz = 8;
        else if (sz == 4)
            sz = 64;
        uint8_t opcode = instruct->opcode & BPF_LD_MASK;

        switch (opcode) {
            case BPF_MEM:
                if (class == BPF_LD)
                    fprintf(stdout, "MEM r%d = *(u%d *) (%d + %d)", instruct->dst_reg, sz, instruct->imm, instruct->offset);
                if (class == BPF_LDX)
                    fprintf(stdout, "MEM r%d = *(u%d *) (r%d + %d)", instruct->dst_reg, sz, instruct->src_reg, instruct->offset);
                if (class == BPF_ST)
                    fprintf(stdout, "MEM *(u%d *) (r%d + %d) = %d", sz, instruct->dst_reg, instruct->offset, instruct->imm);
                if (class == BPF_STX)
                    fprintf(stdout, "MEM *(u%d *) (r%d + %d) = r%d", sz, instruct->dst_reg, instruct->offset, instruct->src_reg);
                break;
            default:
                fprintf(stdout, "opcode %d ? not implemented", opcode);
        }
    } else if (class == BPF_ALU || class == BPF_ALU64) {
        uint8_t s = (instruct->opcode >> 3) & 1;
        uint8_t opcode = instruct->opcode & BPF_ALU_MASK;
        switch (opcode) {
            case BPF_ADD:
                fprintf(stdout, "ADD r%d += ", instruct->dst_reg);
                break;
            case BPF_SUB:
                fprintf(stdout, "SUB r%d -= ", instruct->dst_reg);
                break;
            case BPF_MUL:
                fprintf(stdout, "MUL r%d *= ", instruct->dst_reg);
                break;
            case BPF_DIV:
                fprintf(stdout, "DIV r%d /= ", instruct->dst_reg);
                break;
            case BPF_LSH:
                if (class == BPF_ALU)
                    fprintf(stdout, "LSH r%d <<= ((1 << 32 - 1) & ", instruct->dst_reg);
                else
                    fprintf(stdout, "LSH r%d <<= ((1 << 64 - 1) & ", instruct->dst_reg);
                break;
            case BPF_MOV:
                fprintf(stdout, "MOV r%d = ", instruct->dst_reg);
                break;
            case BPF_ARSH:
                if (class == BPF_ALU)
                    fprintf(stdout, "ARSH r%d >>= ((1 << 32 - 1) & ", instruct->dst_reg);
                else
                    fprintf(stdout, "ARSH r%d >>= ((1 << 64 - 1) & ", instruct->dst_reg);
                break;
            default:
                fprintf(stdout, "opcode %d ? - not implemented", opcode);
        }
        if (s)
            fprintf(stdout, "r%d", instruct->src_reg);
        else
            fprintf(stdout, "%u", instruct->imm);
    } else if (class == BPF_JMP || class == BPF_JMP32) {
        // uint8_t s = (instruct->opcode >> 3) & 1;
        uint8_t opcode = instruct->opcode & BPF_JMP_MASK;
        switch (opcode) {
            case BPF_JA:
                fprintf(stdout, "PC += %i", instruct->offset);
                break;
            case BPF_JEQ:
                fprintf(stdout, "PC += %i if r%d == r%d", instruct->offset, instruct->dst_reg, instruct->src_reg);
                break;
            case BPF_JGT:
                fprintf(stdout, "PC += %i if r%d > r%d", instruct->offset, instruct->dst_reg, instruct->src_reg);
                break;
            case BPF_JGE:
                fprintf(stdout, "PC += %i if r%d >= r%d", instruct->offset, instruct->dst_reg, instruct->src_reg);
                break;
            case BPF_JSET:
                fprintf(stdout, "PC += %i if r%d & r%d", instruct->offset, instruct->dst_reg, instruct->src_reg);
            case BPF_JNE:
                fprintf(stdout, "PC += %i if r%d != r%d", instruct->offset, instruct->dst_reg, instruct->src_reg);
            case BPF_CALL:
                fprintf(stdout, "BPF_CALL %p", instruct->imm);
                break;
            case BPF_EXIT:
                fprintf(stdout, "EXIT");
                break;
            default:
                fprintf(stdout, "opcode %d ? - not implemented", opcode);
        }
    } else {
        fprintf(stdout, "unknown");
    }
    fprintf(stdout, "\n");
}

int ebpf_prog_disasm(uint8_t *prog, uint32_t size) {
    fprintf(stdout, "opcode src_r dst_r offset immediate value\tassembly\n");
    uint32_t i = 0;
    for (; i < size; i += sizeof(uint64_t)) {
        uint64_t *cur_i = (uint64_t *) &prog[i];
        print_ebpf_instruction(cur_i);
    }
    if (i > size)
        return -1;
    return 0;
}

static inline uint64_t read_reg(uint64_t *R, int reg, int is64) {
    if (is64)
        return R[reg];
    return (uint32_t)R[reg];
}

static inline void write_reg(uint64_t *R, int reg, uint64_t val, int is64) {
    if (is64)
        R[reg] = val;
    else
        R[reg] = (uint32_t)val;
}

int ebpf_interpreter(const uint8_t *prog, uint32_t prog_size, int argc, uint64_t **argv) {
    uint8_t stack[128] = {};
    uint64_t R[11] = {};
    for (int i = 1; i < argc; i++)
        R[i] = *argv[i-1];
    // RO end of the stack
    R[10] = (uint64_t) &stack[sizeof(stack)];
    // Program counter
    uint64_t *start = (uint64_t *) prog;
    const uint64_t *end = (uint64_t *) prog + prog_size;
    uint64_t *PC = start;
    const struct ebpf_instruct *instruct;
    while (PC < end) {
        instruct = (struct ebpf_instruct *) PC;
        fprintf(stdout, "%p | ", PC);
        print_ebpf_instruction(PC);
        uint8_t class = instruct->opcode & BPF_CS_MASK;
        if (class <= BPF_STX) {
            const uint8_t opcode = instruct->opcode & (BPF_LD_MASK | BPF_CS_MASK);
            const uint8_t sz = instruct->opcode & BPF_DW;
            uint64_t *dst_reg = &R[instruct->dst_reg];
            uint64_t *src_reg = &R[instruct->src_reg];
            uint64_t addr;
            switch (opcode) {
                case BPF_LD_MEM:
                    addr = *src_reg + instruct->imm;
                    if (sz == BPF_W)
                        *dst_reg = *(const uint32_t *)addr;
                    if (sz == BPF_H)
                        *dst_reg = *(const uint16_t *)addr;
                    if (sz == BPF_B)
                        *dst_reg = *(const uint8_t *)addr;
                    if (sz == BPF_DW)
                        *dst_reg = *(const uint64_t *)addr;
                    break;
                case BPF_LDX_MEM:
                    addr = *src_reg + instruct->offset;
                    if (sz == BPF_W)
                        *dst_reg = *(const uint32_t *)addr;
                    if (sz == BPF_H)
                        *dst_reg = *(const uint16_t *)addr;
                    if (sz == BPF_B)
                        *dst_reg = *(const uint8_t *)addr;
                    if (sz == BPF_DW)
                        *dst_reg = *(const uint64_t *)addr;
                    break;
                case BPF_ST_MEM:
                    addr = *dst_reg + (uint64_t)(int64_t)(int32_t)instruct->offset;
                    if (sz == BPF_W)
                        *(uint32_t *)addr = instruct->imm;
                    if (sz == BPF_H)
                        *(uint16_t *)addr = instruct->imm;
                    if (sz == BPF_B)
                        *(uint8_t *)addr = instruct->imm;
                    if (sz == BPF_DW)
                        *(uint64_t *)addr = instruct->imm;
                    break;
                case BPF_STX_MEM:
                    addr = *dst_reg + (uint64_t)(int64_t)(int32_t)instruct->offset;
                    // fprintf(stdout, "Set to %p\n", addr);
                    if (sz == BPF_W)
                        *(uint32_t *)addr = *src_reg;
                    if (sz == BPF_H)
                        *(uint16_t *)addr = *src_reg;
                    if (sz == BPF_B)
                        *(uint8_t *)addr = *src_reg;
                    if (sz == BPF_DW)
                        *(uint64_t *)addr = *src_reg;
                    break;
                default:
                    // fprintf(stdout, "opcode %d ? - not implemented", opcode);
                    return -1;
            }
        } else if (class == BPF_ALU || class == BPF_ALU64) {
            const uint8_t source = instruct->opcode & BPF_X;
            const uint8_t opcode = instruct->opcode & BPF_ALU_MASK;
            uint8_t is64 = class == BPF_ALU64 ? 1 : 0;
            uint64_t dst = read_reg(R, instruct->dst_reg, is64);
            uint64_t src = read_reg(R, instruct->src_reg, is64);
            uint64_t mask = 0xffffffff;
            if (is64)
                mask = 0xffffffffffffffffLLU;
            if (source == BPF_K)
                src = (uint64_t)(int64_t)(int32_t) instruct->imm;
            switch (opcode) {
                case BPF_ADD: dst += src; break;
                case BPF_SUB: dst -= src; break;
                case BPF_MUL: dst *= src; break;
                case BPF_LSH: dst <<= (src & mask); break;
                case BPF_MOV: dst = src; break;
                case BPF_ARSH: dst = ((int64_t)dst >> (src & mask)); break;
                default:
                    fprintf(stdout, "opcode %d ? - not implemented", opcode);
                    return -1;
            }
            // fprintf(stdout, "dst = %llx, src = %llx\n", dst, src);
            write_reg(R, instruct->dst_reg, dst, is64);

        } else if (class == BPF_JMP || class == BPF_JMP32) {
            const uint8_t source = instruct->opcode & BPF_X;
            const uint8_t opcode = instruct->opcode & BPF_ALU_MASK;
            uint8_t is64 = class == BPF_JMP ? 1 : 0;
            uint64_t dst = read_reg(R, instruct->dst_reg, is64);
            uint64_t src = read_reg(R, instruct->src_reg, is64);
            if (source == BPF_K)
                src = (uint64_t)(int64_t)(int32_t) instruct->imm;
            switch (opcode) {
                case BPF_JA: PC += instruct->offset; break;
                case BPF_JEQ:
                    if (dst == src)
                        PC += instruct->offset;
                    break;
                case BPF_JGT:
                    if (dst > src)
                        PC += instruct->offset;
                    break;
                case BPF_JGE:
                    if (dst >= src)
                        PC += instruct->offset;
                    break;
                case BPF_JSET:
                    if (dst & src)
                        PC += instruct->offset;
                    break;
                case BPF_JNE:
                    if (dst != src)
                        PC += instruct->offset;
                    break;
                case BPF_CALL:
                    uint8_t id = instruct->imm;
                    platform_helper_call(id, &R[0], R[1], R[2], R[3], R[4], R[5]);
                    break;
                case BPF_EXIT: goto exit; break;
                default:
                    fprintf(stdout, "opcode %d ? - not implemented", opcode);
                    return -1;
            }
        } else {
            fprintf(stdout, "class %d ? - not implemented", class);
            return -1;
        }
        PC++;
    }

exit:
    return R[0];
}
