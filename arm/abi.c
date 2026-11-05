/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ARM calling convention (AAPCS) for hooks: arguments in r0-r3 and then on the
 * stack, the return value in r0, the return address in lr.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cpu_ldst.h"
#include "hooks/hook_engine.h"

static const char *const reg_names[] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "pc",
};

int hook_reg_index(const char *name)
{
    for (int i = 0; i < ARRAY_SIZE(reg_names); i++) {
        if (!g_ascii_strcasecmp(name, reg_names[i])) {
            return i;
        }
    }
    return -1;
}

uint64_t hook_read_reg(CPUState *cs, unsigned reg)
{
    g_assert(reg < ARRAY_SIZE(reg_names));
    return cpu_env(cs)->regs[reg];
}

void hook_write_reg(CPUState *cs, unsigned reg, uint64_t val)
{
    g_assert(reg < ARRAY_SIZE(reg_names));
    cpu_env(cs)->regs[reg] = val;
    hook_port_reg_concrete(cs, reg);    /* the old symbolic value is gone */
}

uint64_t hook_arg(CPUState *cs, unsigned n)
{
    if (n < 4) {
        return hook_read_reg(cs, n);
    }
    /* Argument 4 is at [sp], argument 5 at [sp + 4], ... */
    return cpu_ldl_data(cpu_env(cs), hook_read_reg(cs, 13) + 4 * (n - 4));
}

void hook_set_ret(CPUState *cs, uint64_t val)
{
    hook_write_reg(cs, 0, val);
}

vaddr hook_arch_entry(uint64_t addr)
{
    return addr & ~1ULL;        /* Thumb symbols are odd; block-entry PCs are even */
}

void hook_arch_return(CPUState *cs)
{
    uint32_t lr = hook_read_reg(cs, 14);

    hook_write_reg(cs, 15, cpu_env(cs)->thumb ? lr & ~1 : lr);     /* bx lr */
}
