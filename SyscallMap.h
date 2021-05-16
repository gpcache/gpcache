#pragma once

#include <sys/user.h>

#include <map>
#include <vector>

namespace gpcache
{
  using SyscallDataType = decltype(user_regs_struct{}.rax);

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

  auto create_syscall_map() -> std::map<SyscallDataType, SyscallInfo> const;
}
