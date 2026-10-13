/*
 * libunwind - RinOS x86-64 signal-frame support.
 *
 * RinOS uses a Linux-shaped rt_sigreturn syscall, but its signal frame is
 * owned by the RinOS kernel/libc pair. Keep the implementation here
 * explicitly tied to that contract instead of selecting Gos-linux.c merely
 * because the target has a Unix-shaped C ABI.
 *
 * The kernel publishes, at the signal-handler CFA, a 128-byte siginfo_t
 * followed by the 256-byte RinOS ucontext_t. public-base/libs/libc/ucontext.h
 * and src/kernel/sched.h assert the register offsets used below.
 */

#include "libunwind_i.h"
#include "unwind_i.h"
#include "ucontext_i.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#ifndef __linux__
#include <unistd.h>
#endif

#define RINOS_SIGINFO_SIZE UINT64_C(128)
#define RINOS_RT_SIGRETURN_MOV UINT64_C(0x0f000000adc0c748)
#define RINOS_RT_SIGRETURN_TAIL UINT64_C(0x00000000000b0f05)

/* The x86-64 libunwind headers select these hooks when the host compiler
 * defines __linux__. Crossgen builds a Linux host JIT from this RinOS source
 * too, so provide the cursor-cache hooks used by Gparser.c in that build.
 * RinOS target builds intentionally compile the no-op macro variants from
 * libunwind_i.h because they do not define __linux__. */
#ifdef __linux__
HIDDEN void
tdep_fetch_frame(struct dwarf_cursor *dw, unw_word_t ip UNUSED,
                 int need_unwind_info UNUSED)
{
  struct cursor *c = (struct cursor *)dw;

  assert(!need_unwind_info || dw->pi_valid);
  assert(!need_unwind_info || dw->pi.unwind_info);
  if (dw->pi_valid && dw->pi.unwind_info &&
      ((struct dwarf_cie_info *)dw->pi.unwind_info)->signal_frame)
    c->sigcontext_format = X86_64_SCF_LINUX_RT_SIGFRAME;
  else
    c->sigcontext_format = X86_64_SCF_NONE;
}

HIDDEN int
tdep_cache_frame(struct dwarf_cursor *dw)
{
  struct cursor *c = (struct cursor *)dw;
  return c->sigcontext_format;
}

HIDDEN void
tdep_reuse_frame(struct dwarf_cursor *dw, int frame)
{
  struct cursor *c = (struct cursor *)dw;

  c->sigcontext_format = frame;
  if (c->sigcontext_format == X86_64_SCF_LINUX_RT_SIGFRAME) {
    c->frame_info.frame_type = UNW_X86_64_FRAME_SIGRETURN;
    c->frame_info.cfa_reg_offset = 0;
    c->sigcontext_addr = dw->cfa;
  }
}
#endif

int
tdep_get_elf_image(struct elf_image *ei, pid_t pid, unw_word_t ip,
                   unsigned long *segbase, unsigned long *mapoff,
                   char *path, size_t pathlen)
{
  /* A failed image lookup must not leave caller-visible metadata from an
   * earlier frame.  The RinOS process-image ABI currently exposes only the
   * authenticated executable path, not an IP-to-image map, so fail closed
   * after clearing every optional output. */
  if (segbase != NULL)
    *segbase = 0;
  if (mapoff != NULL)
    *mapoff = 0;
  if (path != NULL && pathlen != 0)
    path[0] = '\0';

  /* RinOS does not expose process memory maps to libunwind. The generic ELF
   * helpers are shared with other targets, so provide the platform hook and
   * report that process-image lookup is unavailable. */
  (void)ei;
  (void)pid;
  (void)ip;
  (void)segbase;
  (void)mapoff;
  (void)path;
  (void)pathlen;
  return -UNW_ENOINFO;
}

#ifndef UNW_REMOTE_ONLY
void
tdep_get_exe_image_path(char *path)
{
#ifdef __linux__
  /* Crossgen's host JIT is built from this RinOS platform source, but runs
   * on Linux and needs the host executable image for .eh_frame lookup. */
  strcpy(path, "/proc/self/exe");
#else
  RinProcessImagePathResponseV1 response = { 0 };
  if (rin_process_image_path_get(&response) != 0 ||
      response.struct_size != sizeof(response) ||
      response.version != RIN_PROCESS_IMAGE_PATH_ABI_VERSION ||
      (response.flags & ~RIN_PROCESS_IMAGE_PATH_FLAG_AUTHENTICATED) != 0u ||
      (response.flags & RIN_PROCESS_IMAGE_PATH_FLAG_AUTHENTICATED) == 0u ||
      response.reserved0 != 0u || response.length == 0u ||
      response.length >= RIN_PROCESS_IMAGE_PATH_MAX ||
      response.path[response.length] != '\0' ||
      memchr(response.path, '\0', response.length) != NULL)
    path[0] = '\0';
  else
    memcpy(path, response.path, (size_t)response.length + 1u);
#endif
}
#endif /* !UNW_REMOTE_ONLY */

static int
rinos_amd64_canonical(unw_word_t value)
{
  const unw_word_t upper = value >> 48;
  return upper == 0u || upper == UINT64_C(0xffff);
}

static int
rinos_signal_trampoline(struct cursor *c)
{
  unw_word_t first;
  unw_word_t tail;
  unw_accessors_t *accessors;
  int ret;

  if (c == NULL || c->dwarf.as == NULL || c->dwarf.ip == 0u ||
      !rinos_amd64_canonical(c->dwarf.ip) ||
      c->dwarf.ip > UINTPTR_MAX - UINT64_C(16) ||
      !rinos_amd64_canonical(c->dwarf.ip + UINT64_C(8)))
    return 0;

  accessors = unw_get_accessors_int(c->dwarf.as);
  if (accessors == NULL || accessors->access_mem == NULL)
    return 0;

  ret = (*accessors->access_mem)(c->dwarf.as, c->dwarf.ip, &first, 0,
                                 c->dwarf.as_arg);
  if (ret < 0 || first != RINOS_RT_SIGRETURN_MOV)
    return 0;

  ret = (*accessors->access_mem)(c->dwarf.as, c->dwarf.ip + 8u, &tail, 0,
                                 c->dwarf.as_arg);
  return ret >= 0 && (tail & UINT64_C(0x0000000000ffffff)) ==
                         RINOS_RT_SIGRETURN_TAIL;
}

int
unw_is_signal_frame(unw_cursor_t *cursor)
{
  struct cursor *c = (struct cursor *)cursor;

  if (!rinos_signal_trampoline(c)) {
    if (c != NULL)
      c->sigcontext_format = X86_64_SCF_NONE;
    return 0;
  }
  c->sigcontext_format = X86_64_SCF_LINUX_RT_SIGFRAME;
  return 1;
}

HIDDEN int
x86_64_handle_signal_frame(unw_cursor_t *cursor)
{
  struct cursor *c = (struct cursor *)cursor;
  unw_word_t ucontext;
  unw_word_t restored_rsp;
  unw_word_t restored_rip;
  int ret;
  int i;

  if (c == NULL || c->sigcontext_format != X86_64_SCF_LINUX_RT_SIGFRAME ||
      c->dwarf.cfa == 0u || !rinos_amd64_canonical(c->dwarf.cfa) ||
      c->dwarf.cfa > UINTPTR_MAX - RINOS_SIGINFO_SIZE - UINT64_C(256))
    return -UNW_EBADFRAME;

  ucontext = c->dwarf.cfa + RINOS_SIGINFO_SIZE;
  if (!rinos_amd64_canonical(ucontext))
    return -UNW_EBADFRAME;

  /* cfa points at the kernel-written siginfo_t. sigreturn needs the
   * ucontext itself, unlike the Linux helper whose local sigcontext alias
   * starts at the same address as its platform frame. */
  c->sigcontext_addr = ucontext;
  ret = dwarf_get(&c->dwarf,
                  DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RSP, 0),
                  &restored_rsp);
  if (ret < 0 || restored_rsp == 0u || (restored_rsp & 7u) != 0u ||
      !rinos_amd64_canonical(restored_rsp))
    return -UNW_EBADFRAME;
  ret = dwarf_get(&c->dwarf,
                  DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RIP, 0),
                  &restored_rip);
  if (ret < 0 || restored_rip == 0u || !rinos_amd64_canonical(restored_rip))
    return -UNW_EBADFRAME;

  for (i = 0; i < DWARF_NUM_PRESERVED_REGS; ++i)
    c->dwarf.loc[i] = DWARF_NULL_LOC;

  c->dwarf.loc[RAX] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RAX, 0);
  c->dwarf.loc[RDX] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RDX, 0);
  c->dwarf.loc[RCX] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RCX, 0);
  c->dwarf.loc[RBX] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RBX, 0);
  c->dwarf.loc[RSI] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RSI, 0);
  c->dwarf.loc[RDI] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RDI, 0);
  c->dwarf.loc[RBP] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RBP, 0);
  c->dwarf.loc[RSP] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RSP, 0);
  c->dwarf.loc[R8] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_R8, 0);
  c->dwarf.loc[R9] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_R9, 0);
  c->dwarf.loc[R10] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_R10, 0);
  c->dwarf.loc[R11] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_R11, 0);
  c->dwarf.loc[R12] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_R12, 0);
  c->dwarf.loc[R13] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_R13, 0);
  c->dwarf.loc[R14] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_R14, 0);
  c->dwarf.loc[R15] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_R15, 0);
  c->dwarf.loc[RIP] = DWARF_LOC(ucontext + UC_MCONTEXT_GREGS_RIP, 0);
  c->dwarf.cfa = restored_rsp;
  c->dwarf.ip = restored_rip;
  c->dwarf.use_prev_instr = 1;
  return 0;
}

#ifndef UNW_REMOTE_ONLY
HIDDEN void *
x86_64_r_uc_addr(ucontext_t *uc, int reg)
{
  void *addr;

  if (uc == NULL)
    return NULL;
  switch (reg) {
    case UNW_X86_64_R8: addr = &uc->uc_mcontext.gregs[REG_R8]; break;
    case UNW_X86_64_R9: addr = &uc->uc_mcontext.gregs[REG_R9]; break;
    case UNW_X86_64_R10: addr = &uc->uc_mcontext.gregs[REG_R10]; break;
    case UNW_X86_64_R11: addr = &uc->uc_mcontext.gregs[REG_R11]; break;
    case UNW_X86_64_R12: addr = &uc->uc_mcontext.gregs[REG_R12]; break;
    case UNW_X86_64_R13: addr = &uc->uc_mcontext.gregs[REG_R13]; break;
    case UNW_X86_64_R14: addr = &uc->uc_mcontext.gregs[REG_R14]; break;
    case UNW_X86_64_R15: addr = &uc->uc_mcontext.gregs[REG_R15]; break;
    case UNW_X86_64_RDI: addr = &uc->uc_mcontext.gregs[REG_RDI]; break;
    case UNW_X86_64_RSI: addr = &uc->uc_mcontext.gregs[REG_RSI]; break;
    case UNW_X86_64_RBP: addr = &uc->uc_mcontext.gregs[REG_RBP]; break;
    case UNW_X86_64_RBX: addr = &uc->uc_mcontext.gregs[REG_RBX]; break;
    case UNW_X86_64_RDX: addr = &uc->uc_mcontext.gregs[REG_RDX]; break;
    case UNW_X86_64_RAX: addr = &uc->uc_mcontext.gregs[REG_RAX]; break;
    case UNW_X86_64_RCX: addr = &uc->uc_mcontext.gregs[REG_RCX]; break;
    case UNW_X86_64_RSP: addr = &uc->uc_mcontext.gregs[REG_RSP]; break;
    case UNW_X86_64_RIP: addr = &uc->uc_mcontext.gregs[REG_RIP]; break;
    default: addr = NULL; break;
  }
  return addr;
}

HIDDEN NORETURN void
x86_64_sigreturn(unw_cursor_t *cursor)
{
  struct cursor *c = (struct cursor *)cursor;
  mcontext_t *mcontext;
  ucontext_t *uc;

  if (c == NULL || c->sigcontext_addr == 0u)
    abort();
  uc = (ucontext_t *)(uintptr_t)c->sigcontext_addr;
  mcontext = &uc->uc_mcontext;

  /* RinOS rt_sigreturn consumes the kernel-owned frame associated with the
   * restorer. Update only the register image changed by libunwind; the
   * kernel restores the saved signal mask and xstate. */
  memcpy(mcontext->gregs, &dwarf_get_uc(&c->dwarf)->uc_mcontext.gregs[0],
         DWARF_NUM_PRESERVED_REGS * sizeof(unw_word_t));
  __asm__ __volatile__("mov %0, %%rsp; mov %1, %%rax; syscall"
                       :: "r"((uint64_t)c->sigcontext_addr),
                          "i"(SYS_rt_sigreturn)
                       : "memory");
  abort();
}
#endif

HIDDEN int
x86_64_os_step(struct cursor *c)
{
  /* RinOS has no Linux vDSO/vsyscall page. Signal trampolines are detected
   * by the exact libc restorer sequence above; ordinary syscall returns use
   * the compiler's DWARF/frame-chain path and need no synthetic step. */
  return c == NULL ? -UNW_EBADREG : 0;
}
