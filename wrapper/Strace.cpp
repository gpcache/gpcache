#include "Strace.h"

#include <fmt/format.h>

// Supporting all the architectures strace supports is theoretically possible here.
// However for the moment this project focuses on a single architecture to make that work first.
// Otherwise it would compile fine on any possible architecture but do nothing.
// Maybe a better source than strace will be discovered at some point.

namespace gpcache
{
      namespace Strace
      {
            auto get_syscall_info_from_strace_syscallent(int syscall_id) -> StraceSyscall
            {
#define SEN(x) 0
#include "strace/sysent.h"
#include "strace/sysent_shorthand_defs.h"
                  static const StraceSyscall strace_system_calls[] = {
#if __x86_64__
#include "strace/linux_64_syscallent.h"
#else
#error "Unsupported CPU architecture"
#endif
                  };

                  if (syscall_id > sizeof(strace_system_calls) || strace_system_calls[syscall_id].name[0] == '\0')
                        throw fmt::format("Unknown syscall_id {}", syscall_id);

                  return strace_system_calls[syscall_id];
            }

            // Return type is system dependent.
            auto get_syscall_number_from_registers(const user_regs_struct &regs) -> decltype(regs.rax)
            {
#if __x86_64__
                  return regs.orig_rax;
#else
#error "Unsupported CPU architecture"
#endif
            }

            auto get_syscall_return_value_from_registers(const user_regs_struct &regs) -> decltype(regs.rax)
            {
#if __x86_64__
                  return regs.rax;
#else
#error "Unsupported CPU architecture"
#endif
            }

            auto get_syscall_args(const user_regs_struct &regs) -> std::vector<decltype(regs.rdi)>
            {
#if __x86_64__
                  return {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};
#else
#error "Unsupported CPU architecture"
#endif
            }
      }
}
