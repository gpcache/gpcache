#pragma once

#include <spdlog/spdlog.h>

#include "wrappers/json.h"
#include "wrappers/filesystem.h"
#include "wrappers/ptrace/SyscallWrappers.h"
#include "wrappers/ptrace.h"
#include "state.h"

namespace gpcache
{
  struct CachedSyscall_Access
  {
    static constexpr char name[] = "access";

    struct Parameters
    {
      std::string filename;
      int mode;

      CONVENIENCE(Parameters, filename, mode);
    } action; // FIXME -> parameters

    struct Result
    {
      int return_value;
      int errno_value;

      CONVENIENCE(Result, return_value, errno_value)
    } result;

    CONVENIENCE(CachedSyscall_Access, action, result)
  };

  auto execute_cached_syscall(CachedSyscall_Access::Parameters const &) -> CachedSyscall_Access::Result;
  auto covert_to_cachable_syscall(State &, Syscall_access const &) -> CachedSyscall_Access;
}
