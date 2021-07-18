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

    struct Action
    {
      std::string filename;
      int mode;

      CONVENIENCE(Action, filename, mode);
    } action;

    struct Result
    {
      int return_value;
      int errno_value;

      CONVENIENCE(Result, return_value, errno_value)
    } result;

    CONVENIENCE(CachedSyscall_Access, action, result)
  };

  /// execute_cached_syscall
  auto execute_action(CachedSyscall_Access::Action const &) -> CachedSyscall_Access::Result;

  /// cache_syscall
  /// covert_to_cachable_syscall
  auto from_syscall(State &, Syscall_access const &) -> CachedSyscall_Access;
}
