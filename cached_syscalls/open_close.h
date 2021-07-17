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

    struct Action
    {
      int dirfd;
      std::string filename;
      int flags;
      mode_t mode;

      CONVENIENCE(Action, dirfd, filename, flags, mode)
    } action;

    struct Result
    {
      int fd;
      int errno_code;

      CONVENIENCE(Result, fd, errno_code)
    } result;

    CONVENIENCE(CachedSyscall_Open, action, result)
  };

  auto execute_action(CachedSyscall_Open::Action const &cached_syscall) -> CachedSyscall_Open::Result;

  auto from_syscall(State &state, SyscallEx<Syscall_openat> const &syscall) -> std::optional<CachedSyscall_Open>;
}
