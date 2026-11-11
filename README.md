# Firmware hooks

Hooks that replace firmware functions in two QEMU-based engines:
`SaerTrial/triforce-qemu` (the AFL fuzzer) and `SaerTrial/concolic-executor`
(the concolic executor). Both include this repository as their `hooks`
submodule, so a hook is written once and runs in both.

The full design, with examples, is `docs/hook-api.md` in
`SaerTrial/concolic-fuzzing`.

## Files

| File | Who uses it | What it holds |
| --- | --- | --- |
| `hooks.c` | you | The hooks: `stub`, `HAL_Delay`, `uart_recv`, `uart_printf`. |
| `hook_api.h` | hooks | `FIRMWARE_HOOK`, arguments, return value, guest memory, input. |
| `core.c` | engines | Hook registry, `symbols`/`patch` configuration, dispatch, page-by-page copies, the tape log. |
| `arm/abi.c` | core | ARM calling convention: r0-r3 then stack, r0 return, `bx lr`. |
| `hook_engine.h` | engines | What engines call, and the five-call port they implement. |

## Add a hook

```c
/* hooks.c */
FIRMWARE_HOOK(uart_recv)                 /* the name the configuration uses */
{
    hook_input_to_guest(cs, hook_arg(cs, 1), (uint16_t)hook_arg(cs, 2));
    hook_set_ret(cs, 0);
}
```

```json
"patch": [{"addr": "0x08004d50", "hook": "uart_recv"}]
```

Nothing else: no registration table, no engine code. An unknown name in a
configuration stops both engines at startup and lists the registered hooks.

## Engine port

Each engine implements the `hook_port_*` calls in `hook_engine.h`, in
`hw/<engine>/hook_port.c`: take input bytes, mark host bytes as input or as
plain values, mark a register as a plain value, and log. In the fuzzer the
marking calls are empty; in the concolic executor they update symbolic state.

The port has no architecture code. `arm/abi.c` passes a register as a pointer
into the CPU state (`&env->regs[0]`), and the port finds that register's
symbolic value from there. A new architecture needs only `<arch>/abi.c`.

## The tape log

Every read from the input file writes one line to the engine's log
(`-d afl_fuzzing_log` or `-d concolic_replay`), saying which bytes were taken
and by whom:

```text
input[1664]          hook uart_recv -> 0x2000ffe3
input[1665..1668]    MMIO 0x58023014 = 0xfcfcfcfc
```

Hook reads log themselves in `core.c`. Each engine calls `hook_log_input` for
its MMIO reads, so both engines write the same lines.

## Updating consumers

1. Commit and push the hook change here.
2. Point the `hooks` gitlink of both QEMU forks at that same commit.
3. Record both QEMU commits in `concolic-fuzzing`. Its build script refuses to
   build when the two forks pin different hook commits.

## License

GPL-2.0-or-later, as the QEMU sources these hooks were extracted from. See
`COPYING`. Original hook author: Zhanpeng Huang.
