#pragma once

#include <sys/user.h> // user_regs_struct
#include <vector>
#include <map>

using SyscallDataType = decltype(user_regs_struct{}.rax);

namespace gpcache
{
  auto get_syscall_number_from_registers(const user_regs_struct &regs) -> SyscallDataType;
  auto get_syscall_return_value_from_registers(const user_regs_struct &regs) -> SyscallDataType;

  struct SyscallInfo
  {
    const char *name;

    struct SyscallParam
    {
      const char *type;
      const char *name;
    };
    std::vector<SyscallParam> params;
  };
  auto get_syscall_map() -> std::map<SyscallDataType, SyscallInfo>;

  auto get_syscall_args(const user_regs_struct &regs) -> std::vector<SyscallDataType>;
}
