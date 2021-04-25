#pragma once

#include <map>
#include <vector>

struct SyscallInfo
{
  const char *syscall_name;

  struct SyscallParam
  {
    const char *type;
    const char *name;
  };
  std::vector<SyscallParam> params;
};

auto get_syscall_map() -> std::map<int, SyscallInfo>;
