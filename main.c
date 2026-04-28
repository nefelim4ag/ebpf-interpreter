// Code to open and test ebpf programs
//
// Copyright (C) 2026  Timofey Titovets <nefelim4ag@gmail.com>
//
// This file may be distributed under the terms of the GNU GPLv3 license.


#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tiny_ebpf.h"

static const char *elf_class_str(uint8_t c) {
    switch (c) {
        case ELFCLASS32: return "ELF32";
        case ELFCLASS64: return "ELF64";
        default:         return "unknown";
    }
}

static const char *elf_data_str(uint8_t d) {
    switch (d) {
        case ELFDATA2LSB: return "little-endian (2's complement)";
        case ELFDATA2MSB: return "big-endian (2's complement)";
        default:          return "unknown";
    }
}

static const char *elf_type_str(uint16_t t) {
    switch (t) {
        case ET_NONE: return "NONE (unknown)";
        case ET_REL:  return "REL (relocatable)";
        case ET_EXEC: return "EXEC (executable)";
        case ET_DYN:  return "DYN (shared object / PIE)";
        case ET_CORE: return "CORE (core dump)";
        default:      return "other";
    }
}

static const char *elf_machine_str(uint16_t m) {
    switch (m) {
        case 0xf7:       return "eBPF";
        default:         return "other";
    }
}

static const char *sec_type_str(uint32_t t) {
    switch (t) {
        case SHT_NULL:     return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB:   return "SYMTAB";
        case SHT_STRTAB:   return "STRTAB";
        case SHT_RELA:     return "RELA";
        case SHT_HASH:     return "HASH";
        case SHT_DYNAMIC:  return "DYNAMIC";
        case SHT_NOTE:     return "NOTE";
        case SHT_NOBITS:   return "NOBITS";
        case SHT_REL:      return "REL";
        case SHT_DYNSYM:   return "DYNSYM";
        default:           return "other";
    }
}

static void print_elf64(const uint8_t *base, size_t size) {
    if (size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "file too small for ELF64 header\n");
        return;
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;

    printf("\n#### ELF HEADER\n");
    printf("  Class:       %s\n",            elf_class_str(eh->e_ident[EI_CLASS]));
    printf("  Data:        %s\n",            elf_data_str(eh->e_ident[EI_DATA]));
    printf("  Version:     %u\n",            eh->e_ident[EI_VERSION]);
    printf("  OS/ABI:      %u\n",            eh->e_ident[EI_OSABI]);
    printf("  Type:        %s\n",            elf_type_str(eh->e_type));
    printf("  Machine:     %s\n",            elf_machine_str(eh->e_machine));
    printf("  PHoff:       %lu bytes\n",     (unsigned long)eh->e_phoff);
    printf("  SHoff:       %lu bytes\n",     (unsigned long)eh->e_shoff);
    printf("  Flags:       0x%x\n",          eh->e_flags);
    printf("  EHdr size:   %u bytes\n",      eh->e_ehsize);
    printf("  PHdr size:   %u bytes  ×  %u entries\n", eh->e_phentsize, eh->e_phnum);
    printf("  SHdr size:   %u bytes  ×  %u entries\n", eh->e_shentsize, eh->e_shnum);
    printf("  SH strndx:   %u\n",            eh->e_shstrndx);

    if (eh->e_shnum == 0 || eh->e_shoff >= size) return;

    const Elf64_Shdr *sh   = (const Elf64_Shdr *)(base + eh->e_shoff);
    const char       *stab = NULL;

    if (eh->e_shstrndx < eh->e_shnum)
        stab = (const char *)(base + sh[eh->e_shstrndx].sh_offset);

    printf("\n#### SECTION HEADERS\n");
    printf("  %-4s %-20s %-12s %-18s %-10s %-8s\n",
           "Idx", "Name", "Type", "Address", "Offset", "Size");

    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const char *name = (stab && sh[i].sh_name) ? stab + sh[i].sh_name : "";
        printf("  [%2u] %-20s %-12s 0x%016lx 0x%08lx %lu\n",
               i,
               name,
               sec_type_str(sh[i].sh_type),
               (unsigned long)sh[i].sh_addr,
               (unsigned long)sh[i].sh_offset,
               (unsigned long)sh[i].sh_size);
    }

    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_SYMTAB && sh[i].sh_type != SHT_DYNSYM)
            continue;

        const char *kind = (sh[i].sh_type == SHT_SYMTAB) ? "SYMTAB" : "DYNSYM";

        const char *sym_stab = NULL;
        uint32_t lnk = sh[i].sh_link;
        if (lnk < eh->e_shnum && sh[lnk].sh_offset < size)
            sym_stab = (const char *)(base + sh[lnk].sh_offset);

        size_t nsyms = sh[i].sh_size / sizeof(Elf64_Sym);
        const Elf64_Sym *syms = (const Elf64_Sym *)(base + sh[i].sh_offset);

        printf("\n#### %s (%zu entries)\n",
               kind, nsyms);
        printf("  %-5s %-18s %-8s %-8s %-6s %s\n",
               "Num", "Value", "Size", "Type", "Bind", "Name");

        for (size_t s = 0; s < nsyms; s++) {
            uint8_t type = ELF64_ST_TYPE(syms[s].st_info);
            uint8_t bind = ELF64_ST_BIND(syms[s].st_info);
            const char *sname = (sym_stab && syms[s].st_name)
                                ? sym_stab + syms[s].st_name : "";

            const char *tname;
            switch (type) {
                case STT_NOTYPE:  tname = "NOTYPE";  break;
                case STT_OBJECT:  tname = "OBJECT";  break;
                case STT_FUNC:    tname = "FUNC";    break;
                case STT_SECTION: tname = "SECTION"; break;
                case STT_FILE:    tname = "FILE";    break;
                default:          tname = "other";   break;
            }
            const char *bname;
            switch (bind) {
                case STB_LOCAL:  bname = "LOCAL";  break;
                case STB_GLOBAL: bname = "GLOBAL"; break;
                case STB_WEAK:   bname = "WEAK";   break;
                default:         bname = "other";  break;
            }

            printf("  %-5zu 0x%016lx %-8lu %-8s %-6s %s\n",
                   s,
                   (unsigned long)syms[s].st_value,
                   (unsigned long)syms[s].st_size,
                   tname, bname, sname);
        }
    }
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <elf-file>\n", prog);
    exit(1);
}

void
platform_helper_call(uint32_t id, size_t *r0, size_t r1,
    size_t r2, size_t r3, size_t r4, size_t r5) {
    switch (id) {
        // dummy()
        case 1: *r0 = 2; break;
        // sum(a, b)
        case 2: *r0 = r1 + r2; break;
        case 3: printf("print %lu\n", r1); break;
        default: printf("unknown id\n"); break;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) usage(argv[0]);

    const char *path = argv[1];

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror(path);
        exit(1);
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        exit(1);
    }

    size_t size = (size_t)st.st_size;
    if (size < EI_NIDENT) {
        fprintf(stderr, "%s: too small to be an ELF file\n", path);
        close(fd);
        exit(1);
    }

    uint8_t *base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    /* verify ELF magic */
    if (memcmp(base, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s: not an ELF file\n", path);
        munmap(base, size);
        exit(1);
    }

    fprintf(stdout, "File: %s  (%zu bytes)\n", path, size);

    uint8_t cls = base[EI_CLASS];
    if (cls != ELFCLASS64) {
        fprintf(stderr, "Not an ELF file\n");
        exit(1);
    }

    if (size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "file too small for ELF64 header\n");
        exit(1);
    }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    if (eh->e_shnum == 0 || eh->e_shoff >= size) {
        fprintf(stderr, "No sections\n");
        exit(1);
    }
    const Elf64_Shdr *sh   = (const Elf64_Shdr *)(base + eh->e_shoff);
    const char       *stab = NULL;

    if (eh->e_shstrndx < eh->e_shnum)
        stab = (const char *)(base + sh[eh->e_shstrndx].sh_offset);

    uint8_t *prog_start = NULL;
    uint32_t prog_size = 0;
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const char *name = stab + sh[i].sh_name;
        if (memcmp(name, "prog", 4) == 0) {
            prog_start = (uint8_t *)(base + sh[i].sh_offset);
            prog_size = sh[i].sh_size;
        }
    }

    if (prog_start == NULL) {
        fprintf(stderr, "No eBPF program section\n");
        exit(1);
    }

    struct ebpf_context prog = {
        .mode = EBPF_MODE_INT_DEBUG,
        .prog_start = prog_start,
        .prog_size = prog_size,
    };

    fprintf(stdout, "Test interpreter\n");
    int ret = ebpf_interpreter(&prog);
    if (ret < 0) {
        printf("ebpf_interpreter failed\n");
    }
    printf("Execution result: %lu\n", prog.R[0]);

    print_elf64(base, size);

    munmap(base, size);
    return 0;
}
