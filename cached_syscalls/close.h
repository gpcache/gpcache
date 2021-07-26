#pragma once

#include <spdlog/spdlog.h>

#include "wrappers/json.h"
#include "wrappers/filesystem.h"
#include "wrappers/ptrace/SyscallWrappers.h"
#include "wrappers/ptrace.h"
#include "state.h"

namespace gpcache
{
  struct CachedSyscall_Close
  {
    static constexpr char name[] = "close";

    struct Parameters
    {
      int fd;

      BOILERPLATE(Parameters, fd)
    } parameters;

    struct Result
    {
      int errno_code;

      BOILERPLATE(Result, errno_code)
    } result;

    BOILERPLATE(CachedSyscall_Close, parameters, result)
  };

  auto execute_cached_syscall(State &, CachedSyscall_Close::Parameters const &cached_syscall) -> CachedSyscall_Close::Result;
  auto covert_to_cachable_syscall(State &state, Syscall_close const &syscall) -> CachedSyscall_Close;
}
