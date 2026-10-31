# Firmware hooks

Shared ARM hook sources compiled into `SaerTrial/triforce-qemu` and
`SaerTrial/concolic-executor`. Each engine includes this repository as its
`hooks` Git submodule and builds `arm/function_hooks.c` alongside its own
`hw/.../arm/hook_backend.c` adapter.

The current registry contains `HAL_Delay` and `uart_printf`. Register-name
parsing for firmware configuration is shared too. The extraction preserves
the existing callback behavior, registration names, output and memory reads.
In particular, `printf` is not an alias for `uart_printf`.

## Engine adapter

Implement the declarations in `arm/hook_backend.h`:

- `hook_read_register`: read the concrete ARM register value.
- `hook_read_memory8`: use the engine's guest byte-load operation, including
  MMIO side effects. Reading ordinary guest RAM does not consume fuzz input.
- `hook_log_call`: emit the hook prefix through the engine's logging category,
  preserving the supplied suffix.

These are source interfaces compiled against each engine's QEMU headers, not
a stable binary ABI. ARM-specific code stays in `arm/`; another architecture
can provide its own directory and callback conventions later.

Neither current hook writes guest state or injects fuzz input into a guest
buffer. A future receive hook must use an engine adapter that consumes the
engine's existing input cursor and, for concolic execution, updates symbolic
memory as well as concrete bytes. Plain C copies do not provide that behavior.

## Updating consumers

1. Commit and push the hook change here.
2. Update and commit the `hooks` gitlink in both QEMU forks to the same commit.
3. Update both QEMU gitlinks in `concolic-fuzzing` and run its shared-hook check.
4. Build both engines and compare each one's hook output and firmware execution
   against its previous revision.

Do not make builds follow the latest branch automatically. Every consumer pins
an exact hook commit. Hook logic is maintained here; engine adapters remain in
their respective QEMU repositories.

## Provenance and license

Extracted from `SaerTrial/triforce-qemu` commit
`abbe183b7a5723243aa8d3b9177c9f51cef47085`,
`hw/rehosting/arm/function_hooks.{c,h}`. The corresponding implementation in
`SaerTrial/concolic-executor` commit
`b793b1601e032652a4afd4cf00c4c6047a4a7c96` differed only in logging category
and whitespace. Original hook author: Zhanpeng Huang.

The original files had no individual license notice; both source repositories'
`LICENSE` places such QEMU source files under GPL version 2 or, at your option,
any later version. These extracted sources retain `GPL-2.0-or-later`. See
`COPYING` for the GPL version 2 text.
