#pragma once

#include "syscall_params.h"

auto get_syscall_map() -> std::map<int, SyscallInfo>
{
  std::map<int, SyscallInfo> syscall_params;
#include "syscall_params_generated.inc.h"
  return syscall_params;
}
