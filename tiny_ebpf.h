#ifndef TINY_EBPF_H
#define TINY_EBPF_H
#include <stdint.h>

// Classes
#define BPF_LD      0x00
#define BPF_LDX     0x01
#define BPF_ST      0x02
#define BPF_STX     0x03
#define BPF_ALU     0x04
#define BPF_JMP     0x05
#define BPF_JMP32   0x06
#define BPF_ALU64   0x07
#define BPF_CS_MASK 0x07

// BPF_ALU, BPF_ALU64
#define BPF_ADD      0x00
#define BPF_SUB      0x10
#define BPF_MUL      0x20
#define BPF_DIV      0x30
#define BPF_OR       0x40
#define BPF_AND      0x50
#define BPF_LSH      0x60
#define BPF_RSH      0x70
#define BPF_NEG      0x80
#define BPF_MOD      0x90
#define BPF_XOR      0xa0
#define BPF_MOV      0xb0
#define BPF_ARSH     0xc0
#define BPF_END      0xd0
#define BPF_ALU_MASK 0xf0

#define BPF_K 0x00 // source imm
#define BPF_X 0x08 // source src

// BPF_JMP32, BPF_JMP
#define BPF_JA       0x00
#define BPF_JEQ      0x10
#define BPF_JGT      0x20
#define BPF_JGE      0x30
#define BPF_JSET     0x40
#define BPF_JNE      0x50
#define BPF_JSGT     0x60
#define BPF_JSGE     0x70
#define BPF_CALL     0x80
#define BPF_EXIT     0x90
#define BPF_JLT      0xa0
#define BPF_JLE      0xb0
#define BPF_JSLT     0xc0
#define BPF_JSLE     0xd0
#define BPF_JMP_MASK 0xf0

// BPF_LD, BPF_LDX, BPF_ST, BPF_STX
#define BPF_IMM    0x00
#define BPF_ABS    0x20
#define BPF_IND    0x40
#define BPF_MEM    0x60
#define BPF_ATOMIC 0xc0

#define BPF_W  0x00 // 32 - 4 bytes
#define BPF_H  0x08 // 16 - 2 bytes
#define BPF_B  0x10 // 8 - 1 byte
#define BPF_DW 0x18 // 64 - 8 bytes

struct ebpf_instruct {
    uint8_t opcode;
    uint8_t dst_reg:4;
    uint8_t src_reg:4;
    int16_t offset;
    uint32_t imm;
};

// Runtime
#define EBPF_MODE_INT 0
#define EBPF_MODE_INT_DEBUG 1
#define EBPF_MODE_DISASM 2

struct ebpf_context {
    size_t R[11];
    uint8_t stack[512];
    uint8_t mode;
    uint8_t *prog_start;
    size_t prog_size;
};

int ebpf_interpreter(struct ebpf_context *ctx);

// Platform helpers
void
platform_helper_call(uint32_t id, size_t *r0, size_t r1,
                     size_t r2, size_t r3,  size_t r4, size_t r5);

#endif // TINY_EBPF_H
