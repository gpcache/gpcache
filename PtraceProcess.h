#pragma once

#ifndef __PTRACEPROCESS_H__
#define __PTRACEPROCESS_H__

#include "utils/enumerate.h"

#include "syscall_decoder.h"
#include "SyscallMap.h"
#include "wrapper/Posix.h"
#include "fmt/format.h"

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

  inline auto syscall_to_string(pid_t const p, SysCall const &syscall)
  {
    const std::string params = [&]() {
      std::string params = "";
      for (auto [pos, param] : enumerate(syscall.syscall_info.params))
      {
        if (!params.empty())
          params += ", ";
        SyscallDataType const value = syscall.syscall_arguments[pos];
        if (param.type == std::string("const char *") || param.type == std::string("char *"))
        {
          std::string str = Posix::Ptrace::PEEKTEXT_string(p, reinterpret_cast<char const *>(value));
          params += fmt::format("{} {} = {}", param.type, param.name, str);
        }
        else
        {
          params += fmt::format("{} {} = {}", param.type, param.name, value);
        }
      }
      return params;
    }();

    return fmt::format("{} ({}) with ({}) --> {} = {}\n",
                       syscall.syscall_info.name, syscall.syscall_info.syscall_id,
                       params, syscall.return_value.value(),
                       static_cast<int64_t>(syscall.return_value.value()));
  }

  class PtraceProcess
  {
  public:
    PtraceProcess(pid_t pidForPtrace)
        : pid(pidForPtrace)
    {
    }

    auto get_pid() const { return pid; }

    /// @return empty if process has existed
    auto restart_child_and_wait_for_next_syscall() -> std::optional<SysCall>;

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
