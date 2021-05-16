#include "syscall_decoder.h"

// Supporting all architectures is theoretically possible here.
// Registers defined at https://man7.org/linux/man-pages/man2/syscall.2.html

namespace gpcache
{
  // Return type is system dependent.
  auto get_syscall_number_from_registers(const user_regs_struct &regs) -> SyscallDataType
  {
#if __x86_64__
    return regs.orig_rax;
#else
#error "Unsupported CPU architecture"
#endif
  }

  auto get_syscall_return_value_from_registers(const user_regs_struct &regs) -> SyscallDataType
  {
#if __x86_64__
    return regs.rax;
#else
#error "Unsupported CPU architecture"
#endif
  }

  auto get_syscall_args(const user_regs_struct &regs) -> std::vector<SyscallDataType>
  {
#if __x86_64__
    return {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};
#else
#error "Unsupported CPU architecture"
#endif
  }

}
