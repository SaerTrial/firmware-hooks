/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Everything a firmware hook may call. Each call behaves the same in the
 * fuzzer and in the concolic executor, so one hook serves both engines.
 */
#ifndef FIRMWARE_HOOKS_HOOK_API_H
#define FIRMWARE_HOOKS_HOOK_API_H

#include "qemu/osdep.h"
#include "hw/core/cpu.h"

typedef void (*hook_fn)(CPUState *cs);

/*
 * Define a hook and register it under its own name, which is the name a
 * configuration uses:  FIRMWARE_HOOK(uart_recv) { ... }  <->  "hook": "uart_recv".
 * Registration runs before main(), so configurations are checked at startup.
 */
#define FIRMWARE_HOOK(name)                                             \
    static void name(CPUState *cs);                                     \
    static void __attribute__((constructor)) name##_register(void)      \
    {                                                                   \
        hook_register(#name, name);                                     \
    }                                                                   \
    static void name(CPUState *cs)

void hook_register(const char *name, hook_fn fn);

/* Calling convention of the hooked function (hooks/<arch>/abi.c). */
uint64_t hook_arg(CPUState *cs, unsigned n);       /* n-th integer argument */
void hook_set_ret(CPUState *cs, uint64_t val);      /* return value */
uint64_t hook_read_reg(CPUState *cs, unsigned reg);
void hook_write_reg(CPUState *cs, unsigned reg, uint64_t val);

/* Guest memory. Reads keep MMIO side effects, as a guest load would. */
void hook_read_mem(CPUState *cs, vaddr addr, void *buf, size_t len);
void hook_write_mem(CPUState *cs, vaddr addr, const void *buf, size_t len);

/*
 * Take the next `len` input bytes and store them at guest `addr`, which must be
 * writable RAM. Input byte k lands in guest memory unchanged in both engines,
 * and the concolic executor also marks it as symbolic byte k of the input
 * file. Running out of input ends the run, as for an MMIO read.
 */
void hook_input_to_guest(CPUState *cs, vaddr addr, size_t len);

/* Write to the engine's log (-d afl_fuzzing_log / -d concolic_replay). */
void hook_log(const char *fmt, ...) G_GNUC_PRINTF(1, 2);

#endif
