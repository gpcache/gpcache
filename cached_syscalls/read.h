#pragma once

#include <spdlog/spdlog.h>

#include "wrappers/json.h"
#include "wrappers/filesystem.h"
#include "wrappers/ptrace/SyscallWrappers.h"
#include "wrappers/ptrace.h"
#include "state.h"

namespace gpcache
{
  struct CachedSyscall_Read
  {
    static constexpr char name[] = "write";

    struct Parameters
    {
      int fd;
      std::string data; // ToDo: string vs vector

      CONVENIENCE(Parameters, fd, data);
    } parameters;

    struct Result
    {
      int return_value;
      int errno_value;

      CONVENIENCE(Result, return_value, errno_value)
    } result;

    CONVENIENCE(CachedSyscall_Read, parameters, result)
  };

  /// execute_cached_syscall
  auto execute_cached_syscall(CachedSyscall_Read::Parameters const &) -> CachedSyscall_Read::Result;

  /// cache_syscall
  /// covert_to_cachable_syscall
  auto covert_to_cachable_syscall(State &, Syscall_read const &) -> CachedSyscall_Read;
}
