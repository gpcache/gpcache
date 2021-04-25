#pragma once

#ifndef __PTRACEPROCESS_H__
#define __PTRACEPROCESS_H__

#include "wrapper/Strace.h"

#include <sys/user.h> // user_regs_struct
#include <string>
#include <vector>
#include <optional>

namespace gpcache
{
  struct SysCall
  {
    const int syscall_id;
    const Strace::StraceSyscall syscall_info;
    const std::optional<int> return_value;
    //const auto syscall_arguments = Strace::get_syscall_args(regs);
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
