#pragma once

#include "main/state.h"

#include "wrappers/filesystem.h"
#include "wrappers/json.h"
#include "wrappers/ptrace.h"
#include "wrappers/ptrace/SyscallWrappers.h"

#include <spdlog/spdlog.h>

namespace gpcache {
struct CachedSyscall_Write {
  static constexpr char name[] = "write";

  struct Parameters {
    int fd;
    std::string data; // ToDo: string vs vector

    BOILERPLATE(Parameters, fd, data);
  } parameters;

  struct Result {
    int return_value;
    int errno_value;

    BOILERPLATE(Result, return_value, errno_value)
  } result;

  BOILERPLATE(CachedSyscall_Write, parameters, result)
};

/// execute_cached_syscall
auto execute_cached_syscall(State &, CachedSyscall_Write::Parameters const &)
    -> CachedSyscall_Write::Result;

/// cache_syscall
/// covert_real_to_cachable_syscall
auto covert_real_to_cachable_syscall(State &, Syscall_write const &)
    -> CachedSyscall_Write;
} // namespace gpcache
