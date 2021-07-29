#pragma once

#include "main/state.h"

#include "wrappers/filesystem.h"
#include "wrappers/json.h"
#include "wrappers/ptrace.h"
#include "wrappers/ptrace/SyscallWrappers.h"

#include <spdlog/spdlog.h>

namespace gpcache {
struct CachedSyscall_Access {
  static constexpr char name[] = "access";

  struct Parameters {
    std::string filename;
    int mode;

    BOILERPLATE(Parameters, filename, mode);
  } parameters; // FIXME -> parameters

  struct Result {
    int return_value;
    int errno_value;

    BOILERPLATE(Result, return_value, errno_value)
  } result;

  BOILERPLATE(CachedSyscall_Access, parameters, result)
};

auto execute_cached_syscall(State &, CachedSyscall_Access::Parameters const &)
    -> CachedSyscall_Access::Result;
auto covert_to_cachable_syscall(State &, Syscall_access const &)
    -> CachedSyscall_Access;
} // namespace gpcache
