/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The contract between the shared hook code and an engine. Hooks never use it.
 *   engine -> hooks: load the configuration, dispatch at each translation block,
 *                    log MMIO input reads.
 *   hooks -> engine: the port, five small calls that each engine implements.
 */
#ifndef FIRMWARE_HOOKS_HOOK_ENGINE_H
#define FIRMWARE_HOOKS_HOOK_ENGINE_H

#include "hooks/hook_api.h"
#include "qapi/qmp/qdict.h"

/* Read "symbols" and "patch" from the configuration; exits on any mistake. */
void hook_load_config(QDict *conf, const char *config_path);
/* If `pc` is patched: run its hook and return to the caller, then answer true. */
bool hook_dispatch(CPUState *cs, vaddr pc);
/* Register number for a name such as "r0" or "PC"; -1 if unknown. */
int hook_reg_index(const char *name);
/*
 * Log one read from the input tape, so the log shows who took which bytes:
 *   input[1664]          hook uart_recv -> 0x2000ffe3
 *   input[1665..1668]    MMIO 0x58023014 = 0xfcfcfcfc
 * Hook reads log themselves; engines call this for each MMIO read. Without
 * a -d option it returns at once.
 */
void hook_log_input(uint64_t offset, size_t len, const char *fmt, ...)
    G_GNUC_PRINTF(3, 4);

/* Architecture ABI used by the shared code (hooks/<arch>/abi.c). */
vaddr hook_arch_entry(uint64_t addr);   /* configured address -> block-entry PC */
void hook_arch_return(CPUState *cs);    /* PC := return address */

/* The port (hw/<engine>/hook_port.c). It knows no architecture: abi.c says
 * where a register lives, as a pointer into the CPU state. */
uint64_t hook_port_take_input(uint8_t *buf, size_t len); /* -> input offset of buf[0]; exits when input runs out */
void hook_port_mem_input(void *host, size_t len, uint64_t offset); /* host[i] holds input byte offset+i */
void hook_port_mem_concrete(void *host, size_t len);     /* host bytes hold plain values now */
void hook_port_reg_concrete(CPUState *cs, void *reg);    /* the register at `reg` holds a plain value now */
void hook_port_log(const char *msg);

#endif
