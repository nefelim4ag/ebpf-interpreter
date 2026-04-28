#ifndef EBPF_H
#define EBPF_H
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
#endif // EBPF_H
