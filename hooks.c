/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The hooks. A configuration patch entry selects one by name; the dispatcher
 * then runs it and returns to the patched function's caller.
 */
#include "hooks/hook_api.h"

#define MAX_MSG_LEN 256

/* Skip a function. Add "ret" to the patch entry when callers need a value. */
FIRMWARE_HOOK(stub)
{
}

/* Skip HAL_Delay's busy wait. The firmware's tick counter does not advance. */
FIRMWARE_HOOK(HAL_Delay)
{
}

/*
 * HAL-style receive: (handle, buffer, length, timeout) -> 0 (HAL_OK).
 * The buffer gets the next `length` bytes of the input.
 */
FIRMWARE_HOOK(uart_recv)
{
    hook_input_to_guest(cs, hook_arg(cs, 1), (uint16_t)hook_arg(cs, 2));
    hook_set_ret(cs, 0);
}

static void print_guest_string(CPUState *cs, vaddr addr)
{
    for (int i = 0; i < 511; i++) {
        char c;

        hook_read_mem(cs, addr + i, &c, 1);
        if (!c) {
            break;
        }
        putchar(c);
    }
}

/*
 * printf-like output on the host: format in argument 0, up to three values in
 * arguments 1-3. Handles %d %x %p %c %s; width digits and 'l' are skipped.
 */
FIRMWARE_HOOK(uart_printf)
{
    char fmt[MAX_MSG_LEN + 1] = "";     /* last byte stays '\0' */
    vaddr ptr = hook_arg(cs, 0);
    unsigned arg = 1;
    char *p = fmt;

    g_assert(ptr);
    hook_read_mem(cs, ptr, fmt, MAX_MSG_LEN);
    while (arg <= 3) {
        char *pct = strchr(p, '%');

        if (!pct) {
            break;
        }
        fwrite(p, 1, pct - p, stdout);                  /* text before '%' */
        p = pct + 1 + strspn(pct + 1, "0123456789");    /* skip width */
        p += strspn(p, "l");                            /* skip length */
        switch (*p) {
        case 's':
            print_guest_string(cs, hook_arg(cs, arg++));
            break;
        case 'd':
            printf("%d", (int)hook_arg(cs, arg++));
            break;
        case 'x':
        case 'p':
            printf("%x", (uint32_t)hook_arg(cs, arg++));
            break;
        case 'c':
            putchar((int)hook_arg(cs, arg++));
            break;
        }
        if (*p) {
            p++;                                        /* skip the specifier */
        }
    }
    fputs(p, stdout);                                   /* the rest */
    fflush(stdout);
}
