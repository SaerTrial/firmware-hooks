/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FIRMWARE_HOOKS_ARM_FUNCTION_HOOKS_H
#define FIRMWARE_HOOKS_ARM_FUNCTION_HOOKS_H

#include "qemu/osdep.h"
#include "target/arm/cpu.h"

typedef void (*func_hook_t)(CPUARMState *env);

extern GHashTable *func_ptr_htable;

void hook_init(void);
void uart_printf(CPUARMState *env);
void delay_hook(CPUARMState *env);
int return_reg_index_by_name(const char *reg_name);

#endif
