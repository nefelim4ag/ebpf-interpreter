# ebpf-interpreter
My attempt to implement embeddable eBPF

# bpf.c

Example ebpf programm

# main.c

For interpreter debbugging development

# tiny_ebpf.c tiny_ebpf.h

supposed to be library functions in the end

# ebpf.h

supposed to be eBPF program headers

# Example run

Interpreter support 3 modes:
- Execution
- Execution + Debug
- Disassembler

```
make
./main ebpf.o
...
// Disassembly output
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
Test interpreter
000 | STX MEM *(u32 *) r10 + -4 = r1
001 | STX MEM *(u32 *) r10 + -8 = r2
002 | LDX MEM r1 = *(u32 *) r10 + -4
003 | LDX MEM r3 = *(u32 *) r10 + -8
004 | ALU r2 = r1 // (0) = (0)
005 | ALU r2 += r3 // 0 += 0
006 | ALU r2 += r0 // 0 += 1
007 | ALU r1 += r0 // 0 += 4294967295
008 | ALU r4 = r1 // (0) = (4294967295)
009 | ALU64 r4 <<= r0 // (4294967295) <<= (32)
010 | ALU64 r4 >>= r0 // (18446744069414584320) >>= (32)
011 | ALU64 r1 = r10 // (4294967295) = (140735225792888)
012 | ALU64 r1 += r0 // 140735225792888 += 18446744073709551598
013 | ALU64 r3 = r1 // (0) = (140735225792870)
014 | ALU64 r3 += r4 // 140735225792870 += 18446744073709551615
015 | STX MEM *(u8 *) r3 + 0 = r2
016 | LDX MEM r2 = *(u32 *) r10 + -4
017 | ALU r2 += r0 // 0 += 4294967295
018 | ALU r2 = r2 // (4294967295) = (4294967295)
019 | ALU64 r2 <<= r0 // (4294967295) <<= (32)
020 | ALU64 r2 >>= r0 // (18446744069414584320) >>= (32)
021 | ALU64 r1 += r2 // 140735225792870 += 18446744073709551615
022 | LDX MEM r1 = *(u8 *) r1 + 0
023 | ALU r1 += r0 // 1 += 1
024 | STX MEM *(u32 *) r10 + -24 = r1
025 | JMP PC (25) += 0
026 | LDX MEM r1 = *(u32 *) r10 + -24
027 | BPF_JMP32 PC (27) += 5 if r1 == r255 // 2 == 0
...
029 | LDX MEM r1 = *(u32 *) r10 + -24
030 | ALU r1 += r0 // 1 += 4294967295
031 | STX MEM *(u32 *) r10 + -24 = r1
032 | JMP PC (32) += -7
026 | LDX MEM r1 = *(u32 *) r10 + -24
027 | BPF_JMP32 PC (27) += 5 if r1 == r255 // 0 == 0
033 | LDX MEM r1 = *(u32 *) r10 + -24
034 | BPF_JMP32 PC (34) += 5 if r1 != 255 // 0 != 0
035 | JMP PC (35) += 0
036 | LDX MEM r1 = *(u32 *) r10 + -24
037 | ALU r1 += r0 // 0 += 1
038 | STX MEM *(u32 *) r10 + -24 = r1
039 | JMP PC (39) += 0
040 | LDX MEM r1 = *(u32 *) r10 + -24
041 | BPF_JMP32 PC (41) += 5 if r1 > r255 // 1 > 1
042 | JMP PC (42) += 0
043 | LDX MEM r1 = *(u32 *) r10 + -24
044 | ALU r1 += r0 // 1 += 1
045 | STX MEM *(u32 *) r10 + -24 = r1
046 | JMP PC (46) += 0
047 | JMP CALL 0x01
...
066 | JMP EXIT 0x00
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
