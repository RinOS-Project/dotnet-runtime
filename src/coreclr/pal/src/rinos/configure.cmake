# RinOS CoreCLR PAL target contract.
#
# Do not derive these values from the build host.  RinOS libc exposes a
# freestanding POSIX-shaped ABI through its own headers and syscalls; it does
# not provide Linux libpthread/libdl/librt link objects or Linux procfs.

if(NOT CLR_CMAKE_TARGET_RINOS)
  message(FATAL_ERROR "RinOS PAL configuration included for a non-RinOS target")
endif()

if(NOT CLR_CMAKE_TARGET_ARCH_AMD64)
  message(FATAL_ERROR "The initial RinOS CoreCLR PAL supports x86_64 only")
endif()

set(CLR_CMAKE_RINOS_PAL 1)
set(CMAKE_RT_LIBS "")
set(PTHREAD_LIBRARY "")

# RinOS libc supplies these entry points as target ABI wrappers.  Do not ask
# CMake to link Linux libraries merely because the API names are POSIX-shaped.
set(HAVE_PTHREAD_IN_LIBC 1)
set(HAVE_PTHREAD_ATTR_GET_NP 0)
set(HAVE_PTHREAD_GETATTR_NP 1)
set(HAVE_PTHREAD_GETCPUCLOCKID 0)
set(HAVE_PTHREAD_GETAFFINITY_NP 0)
set(HAVE_PTHREAD_CONDATTR_SETCLOCK 1)
set(HAVE_CLOCK_THREAD_CPUTIME 0)

set(HAVE_SYSCONF 1)
set(HAVE__SC_PHYS_PAGES 1)
set(HAVE__SC_AVPHYS_PAGES 1)
set(HAVE_GMTIME_R 1)
set(HAVE_POLL 1)
set(HAVE_STATVFS 1)
set(HAVE_FSYNC 1)
set(HAVE_FUTIMES 0)
set(HAVE_PIPE2 1)
set(HAVE_SIGALTSTACK 1)
set(HAVE_UCONTEXT_H 1)
set(HAVE_UCONTEXT_T 1)
set(HAVE_SYS_UCONTEXT_H 1)

# RinOS scheduler exposes a bounded fixed-size cpuset ABI.  The generic PAL
# affinity implementation requires CPU_ALLOC/CPU_COUNT_S, which is a
# host-libc extension and cannot be enabled by a target-only symbol probe.
# Keep affinity on the safe sysconf CPU-count path until the PAL gets a
# dedicated bounded cpuset adapter.
set(HAVE_SCHED_GETAFFINITY 0)
set(HAVE_SCHED_SETAFFINITY 0)
set(HAVE_SCHED_GET_PRIORITY 0)
set(HAVE_SCHED_OTHER_ASSIGNABLE 0)

# The RinOS ucontext contract uses gregset_t/FXSAVE storage, but its register
# state is not a Linux pt_regs or glibc __gregs structure.
set(HAVE_PT_REGS 0)
set(HAVE_BSD_REGS_T 0)
set(HAVE_GREGSET_T 0)
set(HAVE___GREGSET_T 0)
set(HAVE_FPREGS_WITH_CW 0)
set(HAVE_PUBLIC_XSTATE_STRUCT 0)
set(HAVE__FPX_SW_BYTES_WITH_XSTATE_BV 0)
set(HAVE_SYS_PTRACE_H 0)
set(HAVE_PRCTL_H 0)
set(HAVE_PR_SET_PTRACER 0)
set(HAVE_PROCFS_CTL 0)
set(HAVE_PROCFS_STAT 0)
set(HAVE_SYSCTL 0)
set(HAVE_SYSCTLBYNAME 0)
set(HAVE_KQUEUE 0)
set(HAVE_MACH_EXCEPTIONS 0)
set(HAVE_VM_ALLOCATE 0)
set(HAVE_VM_READ 0)
set(HAS_SYSV_SEMAPHORES 0)
set(HAS_PTHREAD_MUTEXES 1)
set(HAVE_WORKING_GETTIMEOFDAY 1)
set(HAVE_WORKING_CLOCK_GETTIME 1)
set(REALPATH_SUPPORTS_NONEXISTENT_FILES 0)
set(MMAP_ANON_IGNORES_PROTECTION 0)
set(ONE_SHARED_MAPPING_PER_FILEREGION_PER_PROCESS 0)
set(PAL_PTRACE "")

# Keep the generic PAL's suspension signalling policy explicit for RinOS.
set(SYNCHMGR_SUSPENSION_SAFE_CONDITION_SIGNALING 1)
set(ERROR_FUNC_FOR_GLOB_HAS_FIXED_PARAMS 1)
