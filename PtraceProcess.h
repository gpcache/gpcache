#pragma once

#ifndef __PTRACEPROCESS_H__
#define __PTRACEPROCESS_H__

#include "syscall_decoder.h"
#include "logging.h"

#include <sys/user.h> // user_regs_struct
#include <string>
#include <vector>
#include <optional>

namespace gpcache
{
  struct SysCall
  {
    const SyscallDataType syscall_id;
    const SyscallInfo syscall_info;
    const std::optional<SyscallDataType> return_value;
    const std::vector<SyscallDataType> syscall_arguments;
  };

  // useless abstraction?!
  class PtraceProcess
  {
  public:
    PtraceProcess(pid_t pidForPtrace)
        : pid(pidForPtrace)
    {
    }

    auto get_pid() const { return pid; }

    auto restart_child_and_wait_for_next_syscall() -> SysCall;

  private:
    pid_t pid;

    enum class EnterExit
    {
      enter,
      exit
    };
    EnterExit next_call = EnterExit::enter;
  };

  auto createChildProcess(const std::string program, const std::vector<std::string> arguments) -> int;

} // namespace

#endif // __PTRACEPROCESS_H__
