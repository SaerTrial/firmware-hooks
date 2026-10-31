/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FIRMWARE_HOOKS_ARM_BACKEND_H
#define FIRMWARE_HOOKS_ARM_BACKEND_H

#include "qemu/osdep.h"
#include "target/arm/cpu.h"

/* Supplied by each engine. These reads retain guest MMIO side effects. */
uint32_t hook_read_register(CPUARMState *env, unsigned index);
uint8_t hook_read_memory8(CPUARMState *env, uint32_t addr);
void hook_log_call(const char *name, uint32_t count, const char *suffix);

#endif
