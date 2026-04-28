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

int ebpf_interpreter(struct ebpf_context *ctx) {
    const uint8_t MODE = ctx->mode;
    // R1O end of the stack
    ctx->R[10] = (size_t) &ctx->stack[sizeof(ctx->stack)];
    // Program counter
    uint32_t PC = 0;
    for (;; PC++) {
        const uint8_t *ptr = &ctx->prog_start[PC * 8];
        uint8_t opcode = ptr[0];
        uint8_t dst_reg = ptr[1] & 0xF;
        uint8_t src_reg = ptr[1] >> 4;
        int16_t offset = ptr[2] | (ptr[3] << 8);
        int32_t imm = ptr[4] | (ptr[5] << 8) | (ptr[6] << 16) | (ptr[7] << 24);
        uint8_t class = opcode & BPF_CS_MASK;
        if (MODE)
            fprintf(stdout, "%03d | ", PC);
        if (class == BPF_LD || class == BPF_LDX ||
            class == BPF_ST || class == BPF_STX) {
            if (MODE) {
                char *class_str = "LD   ";
                if (class == BPF_LDX) class_str = "LDX  ";
                if (class == BPF_ST)  class_str = "ST   ";
                if (class == BPF_STX) class_str = "STX  ";
                printf("%s ", class_str);
            }
            const uint8_t sz = opcode & BPF_DW;
            const uint8_t lopcode = (opcode >> 5) << 5;
            const char *sz_str = "u64";
            if (sz == BPF_W) sz_str = "u32";
            if (sz == BPF_H) sz_str = "u16";
            if (sz == BPF_B) sz_str = "u8";
            // uint64_t *dst_reg = &ctx->R[dst_reg];
            // uint64_t *src_reg = &ctx->R[src_reg];
            if (class == BPF_LDX && lopcode == BPF_MEM) {
                if (MODE)
                    printf("MEM r%d = *(%s *) r%d + %d\n", dst_reg, sz_str, src_reg, offset);
                if (MODE == EBPF_MODE_DISASM)
                    continue;
                uint8_t *addr = (uint8_t *) (ctx->R[src_reg] + offset);
                if (sz == BPF_W) ctx->R[dst_reg] = *(const uint32_t *) addr;
                if (sz == BPF_H) ctx->R[dst_reg] = *(const uint16_t *) addr;
                if (sz == BPF_B) ctx->R[dst_reg] = *(const uint8_t *) addr;
                if (sz == BPF_DW) ctx->R[dst_reg] = *(const uint64_t *) addr;
            } else if (class == BPF_ST && lopcode == BPF_MEM) {
                if (MODE)
                    printf("MEM *(%s *) r%d + %d = %d\n", sz_str, dst_reg, offset, imm);
                if (MODE == EBPF_MODE_DISASM)
                    continue;
                uint8_t *addr = (uint8_t *) (ctx->R[dst_reg] + offset);
                if (sz == BPF_W) *(uint32_t *)addr = imm;
                if (sz == BPF_H) *(uint16_t *)addr = imm;
                if (sz == BPF_B) *(uint8_t *) addr = imm;
                if (sz == BPF_DW) *(uint64_t *)addr = imm;
            } else if (class == BPF_STX && lopcode == BPF_MEM) {
                if (MODE)
                    printf("MEM *(%s *) r%d + %d = r%d\n", sz_str, dst_reg, offset, src_reg);
                if (MODE == EBPF_MODE_DISASM)
                    continue;
                uint8_t *addr = (uint8_t *) (ctx->R[dst_reg] + offset);
                if (sz == BPF_W) *(uint32_t *)addr = ctx->R[src_reg];
                if (sz == BPF_H) *(uint16_t *)addr = ctx->R[src_reg];
                if (sz == BPF_B) *(uint8_t *)addr = ctx->R[src_reg];
                if (sz == BPF_DW) *(uint64_t *)addr = ctx->R[src_reg];
            } else {
                if (MODE)
                    printf("lopcode: 0x%02x - not implemented\n", lopcode);
                return -1;
            }
        } else if (class == BPF_ALU || class == BPF_ALU64) {
            if (MODE) {
                char *class_str = "ALU  ";
                if (class == BPF_ALU64) class_str = "ALU64";
                printf("%s ", class_str);
            }
            const uint8_t source = opcode & BPF_X;
            const uint8_t lopcode = opcode & BPF_ALU_MASK;
            size_t dst = ctx->R[dst_reg];
            size_t src = ctx->R[src_reg];
            if (source == BPF_K) {
                src = imm;
                if (imm < 0 && sizeof(size_t) == 8)
                    src = (uint64_t)(int64_t)imm;
            }
            if (sizeof(size_t) == 8) {
                if (class == BPF_ALU)
                    src = src & 0xFFFFFFFF;
                if (class == BPF_ALU64)
                    src = src & 0xFFFFFFFFFFFFFFFFLLU;
            }
            switch (lopcode) {
                case BPF_ADD:
                    if (MODE)
                        printf("ADD r%d += r%d // %lu += %lu\n", dst_reg,src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    dst += src;
                    break;
                case BPF_SUB:
                    if (MODE)
                        printf("SUB r%d -= r%d // (%lu) -= (%lu)\n", dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    dst -= src;
                    break;
                case BPF_MUL:
                    if (MODE)
                        printf("MUL r%d *= r%d // (%lu) *= (%lu)\n", dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    dst *= src;
                    break;
                case BPF_LSH:
                    if (MODE)
                        printf("LSH r%d <<= r%d // (%lu) <<= (%lu)\n", dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    dst <<= src;
                    break;
                case BPF_MOV:
                    if (MODE)
                        printf("MOV r%d = r%d // (%lu) = (%lu)\n", dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    dst = src;
                    break;
                case BPF_ARSH:
                    if (MODE)
                        printf("ARSH r%d >>= r%d // (%lu) >>= (%lu)\n", dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    size_t MSB = 1;
                    MSB = MSB << (8 * sizeof(size_t) - 1);
                    if (dst & MSB) {
                        size_t mask = (0 - 1);
                        mask <<= ((8 * sizeof(size_t) - src));
                        dst = dst >> src;
                        dst |= mask;
                    } else {
                        dst = dst >> src;
                    }
                    break;
                default:
                    if (MODE)
                        printf("lopcode: 0x%02x - not implemented\n", lopcode);
                    return -1;
            }
            ctx->R[dst_reg] = dst;
        } else if (class == BPF_JMP || class == BPF_JMP32) {
            if (MODE) {
                char *class_str = "JMP  ";
                if (class == BPF_JMP32) class_str = "JMP32";
                printf("%s ", class_str);
            }
            const uint8_t source = opcode & BPF_X;
            const uint8_t lopcode = opcode & BPF_ALU_MASK;
            size_t dst = ctx->R[dst_reg];
            size_t src = ctx->R[src_reg];
            if (source == BPF_K) {
                src = imm;
                src_reg = -1;
                if (imm < 0 && sizeof(size_t) == 8)
                    src = (uint64_t)(int64_t)imm;
            }
            switch (lopcode) {
                case BPF_JA:
                    if (MODE)
                        printf("PC (%d) += %d\n", PC, offset);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    PC += offset;
                    break;
                case BPF_JEQ:
                    if (MODE)
                        printf("PC (%d) += %d if r%d == r%d // %lu == %lu\n",
                            PC, offset, dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    if (dst == src)
                        PC += offset;
                    break;
                case BPF_JGT:
                    if (MODE)
                        printf("PC (%d) += %d if r%d > r%d // %lu > %lu\n",
                            PC, offset, dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    if (dst > src)
                        PC += offset;
                    break;
                case BPF_JGE:
                    if (MODE)
                        printf("PC (%d) += %d if r%d >= r%d // %lu >= %lu\n",
                           PC, offset, dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    if (dst >= src)
                        PC += offset;
                    break;
                case BPF_JSET:
                    if (MODE)
                        printf("PC (%d) += %d if r%d & r%d // %lu & %lu\n",
                            PC, offset, dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    if (dst & src)
                        PC += offset;
                    break;
                case BPF_JNE:
                    if (MODE)
                        printf("PC (%d) += %d if r%d != %d // %lu != %lu\n",
                            PC, offset, dst_reg, src_reg, dst, src);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    if (dst != src)
                        PC += offset;
                    break;
                case BPF_CALL:
                    if (MODE)
                        printf("CALL 0x%02x\n", imm);
                    if (MODE == EBPF_MODE_DISASM)
                        continue;
                    uint8_t id = imm;
                    platform_helper_call(id,
                        &ctx->R[0], ctx->R[1], ctx->R[2],
                        ctx->R[3], ctx->R[4], ctx->R[5]);
                    break;
                case BPF_EXIT:
                    if (MODE)
                        printf("EXIT 0x%02x\n", imm);
                    return 0;
                    break;
                default:
                    printf("lopcode: 0x%02x - not implemented\n", lopcode);
                    return -1;
            }
        } else {
            if (MODE)
                printf("class 0x%02x - not implemented\n", class);
            return -1;
        }
    }
}
