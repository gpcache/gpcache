#pragma once

#include <spdlog/spdlog.h>

#include "wrappers/json.h"
#include "wrappers/filesystem.h"
#include "wrappers/ptrace/SyscallWrappers.h"
#include "wrappers/ptrace.h"
#include "state.h"

namespace gpcache
{
  struct CachedSyscall_Open
  {
    static constexpr char name[] = "open";

    struct Parameters
    {
      int dirfd;
      std::string filename;
      int flags;
      mode_t mode;

      CONVENIENCE(Parameters, dirfd, filename, flags, mode)
    } parameters;

    struct Result
    {
      int fd;
      int errno_code;

      CONVENIENCE(Result, fd, errno_code)
    } result;

    CONVENIENCE(CachedSyscall_Open, parameters, result)
  };

  auto execute_cached_syscall(State &, CachedSyscall_Open::Parameters const &cached_syscall) -> CachedSyscall_Open::Result;
  auto covert_to_cachable_syscall(State &state, Syscall_openat const &syscall) -> std::optional<CachedSyscall_Open>;
}
