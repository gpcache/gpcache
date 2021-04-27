#include "SyscallDelegator.h"
#include "syscall_decoder.h"
#include "wrapper/Posix.h"
#include <fmt/format.h>
#include <optional>
#include <string>

namespace gpcache
{

  SyscallDelegator::SyscallDelegator(const pid_t pid, SyscallListener &new_listener)
      : pid(pid), listener(new_listener)
  {
  }

  auto SyscallDelegator::delegate_syscall(const user_regs_struct &regs) -> void
  {
#if 0
    const int syscall_id = static_cast<int>(Strace::get_syscall_number_from_registers(regs));
    const Strace::StraceSyscall syscall_info = Strace::get_syscall_info_from_strace_syscallent(syscall_id);
    const std::optional<int> return_value = (next_call == EnterExit::exit) ? std::nullopt : std::make_optional<int>(Strace::get_syscall_return_value_from_registers(regs));
    const auto syscall_arguments = Strace::get_syscall_args(regs);

    using namespace std::literals::string_literals;
    if (syscall_info.name == "read"s)
    {
      const std::string text = Posix::Ptrace::PEEKTEXT(pid, reinterpret_cast<uint8_t *>(syscall_arguments[1]), syscall_arguments[2]);
      listener.read(syscall_arguments[0], text, text.size(), return_value);
    }
#endif
  }

}
