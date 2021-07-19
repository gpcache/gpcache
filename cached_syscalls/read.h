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
    static constexpr char name[] = "read";

    struct Parameters
    {
      int fd;
      size_t count;
      bool is_pread64; // This is quite stupid, but it avoids some boilerplate code here for now.
      off_t pread64_offset;

      CONVENIENCE(Parameters, fd, count, is_pread64, pread64_offset);
    } parameters;

    struct Result
    {
      std::string data; // external file? hashsum?
      ssize_t return_value;
      int errno_value;

      CONVENIENCE(Result, data, return_value, errno_value);
    } result;

    CONVENIENCE(CachedSyscall_Read, parameters, result)
  };

  auto execute_cached_syscall(State &, CachedSyscall_Read::Parameters const &) -> CachedSyscall_Read::Result;
  auto covert_to_cachable_syscall(State &, Syscall_read const &) -> CachedSyscall_Read;
  auto covert_to_cachable_syscall(State &, Syscall_pread64 const &) -> CachedSyscall_Read;
}
