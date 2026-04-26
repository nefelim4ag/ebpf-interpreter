#include <stdint.h>

#ifndef TINY_EBPF_H
#define TINY_EBPF_H

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

#define BPF_LD_MASK 0xe0

#define BPF_W  0x00 // 32 - 4 bytes
#define BPF_H  0x08 // 16 - 2 bytes
#define BPF_B  0x10 // 8 - 1 byte
#define BPF_DW 0x18 // 64 - 8 bytes

#define BPF_LD_MEM  (BPF_LD  | BPF_MEM)
#define BPF_LDX_MEM (BPF_LDX | BPF_MEM)
#define BPF_ST_MEM  (BPF_ST  | BPF_MEM)
#define BPF_STX_MEM (BPF_STX | BPF_MEM)

struct ebpf_instruct {
    uint8_t opcode;
    uint8_t dst_reg:4;
    uint8_t src_reg:4;
    int16_t offset;
    uint32_t imm;
};

int ebpf_prog_disasm(uint8_t *prog, uint32_t size);
int ebpf_interpreter(const uint8_t *prog, uint32_t prog_size, int argc, uint64_t **argv);

// Platform helpers
void
platform_helper_call(uint32_t id, uint64_t *r0, uint64_t r1,
                     uint64_t r2, uint64_t r3,  uint64_t r4, uint64_t r5);

// Macro magic
#define BPF_CALL_N(N) \
    ({ register unsigned long long _r  __asm__("r0"); \
    __asm__ volatile ("call %1" : "=r"(_r) : "i"(N)); \
    _r; })
#define BPF_CALL_N1(N, A1) \
    ({ register unsigned long long _r  __asm__("r0"); \
       register unsigned long long _a1 __asm__("r1") = (unsigned long long)(A1); \
       __asm__ volatile ("call %1" : "=r"(_r) : "i"(N), "r"(_a1)); \
       _r; })
#define BPF_CALL_N2(N, A1, A2) \
    ({ register unsigned long long _r  __asm__("r0"); \
        register unsigned long long _a1 __asm__("r1") = (unsigned long long)(A1); \
        register unsigned long long _a2 __asm__("r2") = (unsigned long long)(A2); \
        __asm__ volatile ("call %1" : "=r"(_r) : "i"(N), "r"(_a1), "r"(_a2)); \
        _r; })
#define BPF_CALL_N3(N, A1, A2, A3) \
    ({ register unsigned long long _r  __asm__("r0"); \
        register unsigned long long _a1 __asm__("r1") = (unsigned long long)(A1); \
        register unsigned long long _a2 __asm__("r2") = (unsigned long long)(A2); \
        register unsigned long long _a3 __asm__("r3") = (unsigned long long)(A3); \
        __asm__ volatile ("call %1" : "=r"(_r) : "i"(N), "r"(_a1), "r"(_a2), "r"(_a3)); \
        _r; })
#define BPF_CALL_N4(N, A1, A2, A3, A4) \
    ({ register unsigned long long _r  __asm__("r0"); \
        register unsigned long long _a1 __asm__("r1") = (unsigned long long)(A1); \
        register unsigned long long _a2 __asm__("r2") = (unsigned long long)(A2); \
        register unsigned long long _a3 __asm__("r3") = (unsigned long long)(A3); \
        register unsigned long long _a4 __asm__("r4") = (unsigned long long)(A4); \
        __asm__ volatile ("call %1" : "=r"(_r) : "i"(N), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4)); \
        _r; })
#define BPF_CALL_N5(N, A1, A2, A3, A4, A5) \
    ({ register unsigned long long _r  __asm__("r0"); \
        register unsigned long long _a1 __asm__("r1") = (unsigned long long)(A1); \
        register unsigned long long _a2 __asm__("r2") = (unsigned long long)(A2); \
        register unsigned long long _a3 __asm__("r3") = (unsigned long long)(A3); \
        register unsigned long long _a4 __asm__("r4") = (unsigned long long)(A4); \
        register unsigned long long _a5 __asm__("r5") = (unsigned long long)(A5); \
        __asm__ volatile ("call %1" : "=r"(_r) : "i"(N), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)); \
        _r; })


#ifndef __section
# define __section(NAME)                  \
__attribute__((section(NAME), used))
#endif

#endif // TINY_EBPF_H
