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
| `core.c` | engines | Hook registry, `symbols`/`patch` configuration, dispatch, page-by-page copies. |
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

## Updating consumers

1. Commit and push the hook change here.
2. Point the `hooks` gitlink of both QEMU forks at that same commit.
3. Record both QEMU commits in `concolic-fuzzing`. Its build script refuses to
   build when the two forks pin different hook commits.

## License

GPL-2.0-or-later, as the QEMU sources these hooks were extracted from. See
`COPYING`. Original hook author: Zhanpeng Huang.
