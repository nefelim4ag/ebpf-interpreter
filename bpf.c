// Code for ebpf code generation testing
//
// Copyright (C) 2026  Timofey Titovets <nefelim4ag@gmail.com>
//
// This file may be distributed under the terms of the GNU GPLv3 license.

#include <stdint.h>
#include "bpf.h"

#define dummy() (BPF_CALL_N(1))
#define sum(a, b) (BPF_CALL_N2(2, a, b))
#define print(a) (BPF_CALL_N1(3, a))

__section("prog")
int32_t task(int32_t arg, int32_t tskid)
{
    uint8_t array[10];
    array[arg - 1] = arg + 1 + tskid;
    uint32_t a = array[arg - 1] + 1;
    while (a)
        a--;
    if (a == 0)
        a++;
    if (a <= 1)
        a++;
    uint32_t b = dummy();
    // print(5);
    a = sum(a, b);
    return a;
}
