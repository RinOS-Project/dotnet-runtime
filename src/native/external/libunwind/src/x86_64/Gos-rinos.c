/*
 * RinOS-specific remote-unwind OS hook.
 *
 * RinOS intentionally does not reuse Linux's signal/syscall-frame rules.
 * Until the RinOS unwind ABI is published, DWARF and frame-chain unwinding
 * remain the only connected paths and this hook must fail closed.
 */

#include "libunwind_i.h"
#include "unwind_i.h"

HIDDEN int
x86_64_os_step(struct cursor *c)
{
  (void)c;
  return 0;
}
