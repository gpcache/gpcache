#pragma once

#include <optional>
#include <string>
#include <array>
#include <vector>
#include <map>
#include <sys/user.h> // user_regs_struct

#include <fmt/format.h>      // good dependency?
#include "utils/enumerate.h" // good dependency?
#include "utils/flag_to_string.h"

// ptrace is more than a simple function, each possible parameter has a separate wrapper.
namespace Ptrace
{
  using SyscallDataType = decltype(user_regs_struct{}.rax);
  using Syscall_Args = std::array<SyscallDataType, 6>;

  struct SyscallInfo
  {
    SyscallDataType syscall_id;
    char const *name;

    struct SyscallParam
    {
      char const *type;
      char const *name;
    };
    std::vector<SyscallParam> params;
  };

  struct SysCall
  {
    const pid_t pid;
    const SyscallInfo info;
    const Syscall_Args arguments;
    const std::optional<SyscallDataType> return_value;

    // only makes sense if all other parameters are const (or if this is a complex class)
    mutable std::string _cached_string_representation;
  };

  namespace Raw
  {
    auto CONT(int pid) -> void;
    auto PEEKTEXT(int pid, const uint8_t *const begin) -> long;
    auto GETREGS(int pid) -> user_regs_struct;
    auto TRACEME() -> void;
    auto SETOPTIONS(int pid, int options) -> void;

    /// Restart the stopped tracee and arrange for the tracee to be stopped at the next entry to or exit from a system call.
    auto SYSCALL(int pid, int signal = 0) -> void;
  }

  auto PEEKTEXT(int pid, const uint8_t *const begin, size_t count) -> std::string;
  auto PEEKTEXT_string(int pid, char const *begin) -> std::string;

  // This is an explicit function because in addition to the SysCall it also needs pid_t.

  // sounds like this could be a co_routine, but let's see what else we need here
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
  };

  auto createChildProcess(const std::string program, const std::vector<std::string> arguments) -> int;

  auto get_syscall_number_from_registers(const user_regs_struct &regs) -> SyscallDataType;
  auto get_syscall_return_value_from_registers(const user_regs_struct &regs) -> SyscallDataType;

  auto get_syscall_args(const user_regs_struct &regs) -> std::array<SyscallDataType, 6>;

  auto create_syscall_map() -> std::map<SyscallDataType, SyscallInfo> const;

} // namespace ptrace

auto get_readable_param_value(auto pid, auto param_type, auto param_value)
{
  if (param_type == std::string("const char *") || param_type == std::string("char *"))
  {
    std::string str = Ptrace::PEEKTEXT_string(pid, reinterpret_cast<char const *>(param_value));
    if (auto pos = str.find('\n'); pos != std::string::npos)
      str = str.substr(0, pos) + "...";
    if (str.length() > 50)
      str = str.substr(0, 50) + "...";
    return str;
  }
  else
  {
    // need to return same type, since fmt doesn't really work with any or variant :-/
    return std::to_string(param_value);
  }
}

template <>
struct fmt::formatter<Ptrace::SysCall>
{
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(Ptrace::SysCall const &syscall, auto &ctx)
  {
    if (syscall._cached_string_representation.empty())
    {
      const std::string params = [&]()
      {
        std::string params = "";
        for (auto [pos, param] : enumerate(syscall.info.params))
        {
          if (!params.empty())
            params += ", ";

          auto param_value = get_readable_param_value(syscall.pid, param.type, syscall.arguments[pos]);
          params += fmt::format("{} {} = {}", param.type, param.name, param_value);
        }
        return params;
      }();

      syscall._cached_string_representation =
          fmt::format("{}({}) --> {}",
                      syscall.info.name,
                      params,
                      gpcache::return_code_to_string(syscall.return_value.value()));
    }
    // There is probably a better direct function for this.
    return fmt::format_to(ctx.out(), "{}", syscall._cached_string_representation);
  }
};
