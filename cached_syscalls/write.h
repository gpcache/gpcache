#pragma once

#include <spdlog/spdlog.h>

#include "wrappers/json.h"
#include "wrappers/filesystem.h"
#include "wrappers/ptrace/SyscallWrappers.h"
#include "wrappers/ptrace.h"
#include "state.h"

namespace gpcache
{
  struct CachedSyscall_Write
  {
    static constexpr char name[] = "write";

    struct Parameters
    {
      int fd;
      std::string data; // ToDo: string vs vector

      CONVENIENCE(Parameters, fd, data);
    } action;

    struct Result
    {
      int return_value;
      int errno_value;

      CONVENIENCE(Result, return_value, errno_value)
    } result;

    CONVENIENCE(CachedSyscall_Write, action, result)
  };

  /// execute_cached_syscall
  auto execute_cached_syscall(CachedSyscall_Write::Parameters const &) -> CachedSyscall_Write::Result;

  /// cache_syscall
  /// covert_to_cachable_syscall
  auto covert_to_cachable_syscall(State &, Syscall_write const &) -> CachedSyscall_Write;
}
