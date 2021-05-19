#pragma once

#include "../ptrace.h"
#include <map>

namespace gpcache
{
  auto create_syscall_map() -> std::map<ptrace::SyscallDataType, ptrace::SyscallInfo> const;
}
