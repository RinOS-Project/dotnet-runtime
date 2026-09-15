include(CheckSymbolExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)

if(CLR_CMAKE_TARGET_RINOS)
  # EventPipe is a target component. Do not run host header/symbol probes for
  # a Windows-hosted RinOS cross-build; the product libc contract is the
  # source of truth and Linux user-events/memfd are not target capabilities.
  set(HAVE_SYS_SOCKET_H 1)
  set(HAVE_ACCEPT4 0)
  set(HAVE_LINUX_USER_EVENTS_H 0)
  set(HAVE_SYS_IOCTL_H 1)
  set(HAVE_SYS_SYSCALL_H 1)
  set(HAVE_UNISTD_H 1)
  set(HAVE_SYS_UIO_H 1)
  set(HAVE_ERRNO_H 1)
  set(HAVE_SYS_MMAN_H 1)
  set(HAVE_MEMFD_CREATE 0)
else()
  check_include_file(
      sys/socket.h
      HAVE_SYS_SOCKET_H
  )

  check_symbol_exists(
      accept4
      sys/socket.h
      HAVE_ACCEPT4)
endif()

# Use TCP for EventPipe on mobile platforms
if (CLR_CMAKE_HOST_IOS OR CLR_CMAKE_HOST_TVOS OR CLR_CMAKE_HOST_ANDROID)
  set(FEATURE_PERFTRACING_PAL_TCP 1)
  set(FEATURE_PERFTRACING_DISABLE_DEFAULT_LISTEN_PORT 1)
endif()

if(NOT CLR_CMAKE_TARGET_RINOS)
  check_include_file(
      linux/user_events.h
      HAVE_LINUX_USER_EVENTS_H
  )

  check_include_file(
      sys/ioctl.h
      HAVE_SYS_IOCTL_H
  )

  check_include_file(
      sys/syscall.h
      HAVE_SYS_SYSCALL_H
  )

  check_include_file(
      unistd.h
      HAVE_UNISTD_H
  )

  check_include_file(
      "sys/uio.h"
      HAVE_SYS_UIO_H
  )

  check_include_file(
      errno.h
      HAVE_ERRNO_H
  )

  check_include_file(
      sys/mman.h
      HAVE_SYS_MMAN_H
  )

  check_symbol_exists(
      __NR_memfd_create
      sys/syscall.h
      HAVE_MEMFD_CREATE
  )
endif()

if (NOT DEFINED EP_GENERATED_HEADER_PATH)
    message(FATAL_ERROR "Required configuration EP_GENERATED_HEADER_PATH not set.")
endif (NOT DEFINED EP_GENERATED_HEADER_PATH)

configure_file(${CLR_SRC_NATIVE_DIR}/eventpipe/ep-shared-config.h.in ${EP_GENERATED_HEADER_PATH}/ep-shared-config.h)

set (SHARED_EVENTPIPE_CONFIG_HEADER_PATH "${EP_GENERATED_HEADER_PATH}")
