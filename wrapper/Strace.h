#pragma once

#include <sys/user.h> // user_regs_struct
#include <vector>

namespace gpcache
{
  /// Other than language change (e.g. using return values), this is unmodified strace as far as possible.
  namespace Strace
  {
    auto get_syscall_number_from_registers(const user_regs_struct &regs) -> decltype(regs.rax);
    auto get_syscall_return_value_from_registers(const user_regs_struct &regs) -> decltype(regs.rax);

    struct StraceSyscall
    {
      unsigned number_of_arguments;
      int flags;
      int (*function)();
      const char *name;
    };
    auto get_syscall_info_from_strace_syscallent(int syscall_id) -> StraceSyscall;

    auto get_syscall_args(const user_regs_struct &regs) -> std::vector<decltype(regs.rdi)>;
  }
}
