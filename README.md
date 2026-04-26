# ebpf-interpreter
My attempt to implement embeddable eBPF

# bpf.c

Example ebpf programm

# main.c

For interpreter debbugging development

# tiny_ebpf.c tiny_ebpf.h

supposed to be library functions in the end

# Example run

```
make
./main ebpf.o
...
// Disassembly
File: bpf.o  (1128 bytes)
opcode src_r dst_r offset immediate value       assembly
  0x63     1    10 0xfffc      0x00000000       STX   MEM *(u32 *) (r10 + -4) = r1
  0x63     2    10 0xfff8      0x00000000       STX   MEM *(u32 *) (r10 + -8) = r2
  0x61    10     1 0xfffc      0x00000000       LDX   MEM r1 = *(u32 *) (r10 + -4)
  0x61    10     3 0xfff8      0x00000000       LDX   MEM r3 = *(u32 *) (r10 + -8)
  0xbc     1     2 0x0000      0x00000000       ALU   MOV r2 = r1
  0x0c     3     2 0x0000      0x00000000       ALU   ADD r2 += r3
  0x04     0     2 0x0000      0x00000001       ALU   ADD r2 += 1
  0x04     0     1 0x0000      0xffffffff       ALU   ADD r1 += 4294967295
  0xbc     1     4 0x0000      0x00000000       ALU   MOV r4 = r1
  0x67     0     4 0x0000      0x00000020       ALU64 LSH r4 <<= ((1 << 64 - 1) & 32
  0xc7     0     4 0x0000      0x00000020       ALU64 ARSH r4 >>= ((1 << 64 - 1) & 32
  0xbf    10     1 0x0000      0x00000000       ALU64 MOV r1 = r10
...
  0x7b     2    10 0xffa8      0x00000000       STX   MEM *(u3 *) (r10 + -88) = r2
  0x79    10     1 0xffa8      0x00000000       LDX   MEM r1 = *(u3 *) (r10 + -88)
  0x85     0     0 0x0000      0x00000002       JMP   BPF_CALL 0x2
  0x7b     0    10 0xffc8      0x00000000       STX   MEM *(u3 *) (r10 + -56) = r0
  0x79    10     1 0xffc8      0x00000000       LDX   MEM r1 = *(u3 *) (r10 + -56)
  0x7b     1    10 0xffb0      0x00000000       STX   MEM *(u3 *) (r10 + -80) = r1
  0x79    10     1 0xffb0      0x00000000       LDX   MEM r1 = *(u3 *) (r10 + -80)
  0x63     1    10 0xffe8      0x00000000       STX   MEM *(u32 *) (r10 + -24) = r1
  0x61    10     0 0xffe8      0x00000000       LDX   MEM r0 = *(u32 *) (r10 + -24)
  0x95     0     0 0x0000      0x00000000       JMP   EXIT
...
// Interpreter execution
Test interpreter
0x7f81e06a0040 |   0x63     1    10 0xfffc      0x00000000      STX   MEM *(u32 *) (r10 + -4) = r1
0x7f81e06a0048 |   0x63     2    10 0xfff8      0x00000000      STX   MEM *(u32 *) (r10 + -8) = r2
0x7f81e06a0050 |   0x61    10     1 0xfffc      0x00000000      LDX   MEM r1 = *(u32 *) (r10 + -4)
0x7f81e06a0058 |   0x61    10     3 0xfff8      0x00000000      LDX   MEM r3 = *(u32 *) (r10 + -8)
0x7f81e06a0060 |   0xbc     1     2 0x0000      0x00000000      ALU   MOV r2 = r1
0x7f81e06a0068 |   0x0c     3     2 0x0000      0x00000000      ALU   ADD r2 += r3
0x7f81e06a0070 |   0x04     0     2 0x0000      0x00000001      ALU   ADD r2 += 1
0x7f81e06a0078 |   0x04     0     1 0x0000      0xffffffff      ALU   ADD r1 += 4294967295
0x7f81e06a0080 |   0xbc     1     4 0x0000      0x00000000      ALU   MOV r4 = r1
0x7f81e06a0088 |   0x67     0     4 0x0000      0x00000020      ALU64 LSH r4 <<= ((1 << 64 - 1) & 32
0x7f81e06a0090 |   0xc7     0     4 0x0000      0x00000020      ALU64 ARSH r4 >>= ((1 << 64 - 1) & 32
0x7f81e06a0098 |   0xbf    10     1 0x0000      0x00000000      ALU64 MOV r1 = r10
...
0x7fe208f29208 |   0x79    10     1 0xffc0      0x00000000      LDX   MEM r1 = *(u3 *) (r10 + -64)
0x7fe208f29210 |   0x79    10     2 0xffb8      0x00000000      LDX   MEM r2 = *(u3 *) (r10 + -72)
0x7fe208f29218 |   0x85     0     0 0x0000      0x00000002      JMP   BPF_CALL 0x2
0x7fe208f29220 |   0x7b     0    10 0xffc8      0x00000000      STX   MEM *(u3 *) (r10 + -56) = r0
0x7fe208f29228 |   0x79    10     1 0xffc8      0x00000000      LDX   MEM r1 = *(u3 *) (r10 + -56)
0x7fe208f29230 |   0x7b     1    10 0xffb0      0x00000000      STX   MEM *(u3 *) (r10 + -80) = r1
0x7fe208f29238 |   0x79    10     1 0xffb0      0x00000000      LDX   MEM r1 = *(u3 *) (r10 + -80)
0x7fe208f29240 |   0x63     1    10 0xffe8      0x00000000      STX   MEM *(u32 *) (r10 + -24) = r1
0x7fe208f29248 |   0x61    10     0 0xffe8      0x00000000      LDX   MEM r0 = *(u32 *) (r10 + -24)
0x7fe208f29250 |   0x95     0     0 0x0000      0x00000000      JMP   EXIT
Execution result: 4
...
// Temporary ELF output, because I'm puzzled with ELF
#### ELF HEADER
  Class:       ELF64
  Data:        little-endian (2's complement)
  Version:     1
  OS/ABI:      0
  Type:        REL (relocatable)
  Machine:     eBPF
  PHoff:       0 bytes
  SHoff:       744 bytes
  Flags:       0x0
  EHdr size:   64 bytes
  PHdr size:   0 bytes  ×  0 entries
  SHdr size:   64 bytes  ×  6 entries
  SH strndx:   1

#### SECTION HEADERS
  Idx  Name                 Type         Address            Offset     Size    
  [ 0]                      NULL         0x0000000000000000 0x00000000 0
  [ 1] .strtab              STRTAB       0x0000000000000000 0x000002b1 53
  [ 2] .text                PROGBITS     0x0000000000000000 0x00000040 0
  [ 3] prog                 PROGBITS     0x0000000000000000 0x00000040 552
  [ 4] .llvm_addrsig        other        0x0000000000000000 0x000002b0 1
  [ 5] .symtab              SYMTAB       0x0000000000000000 0x00000268 72

#### SYMTAB (3 entries)
  Num   Value              Size     Type     Bind   Name
  0     0x0000000000000000 0        NOTYPE   LOCAL  
  1     0x0000000000000000 0        FILE     LOCAL  bpf.c
  2     0x0000000000000000 552      FUNC     GLOBAL task
```
