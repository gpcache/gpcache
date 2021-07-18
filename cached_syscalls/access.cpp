#include "cached_syscalls/access.h"

#include <fcntl.h> // O_RDONLY

#include "wrappers/ptrace.h"
#include "wrappers/json.h"
#include "wrappers/filesystem.h"

#include "utils/flag_to_string.h"
#include "utils/Utils.h"

namespace gpcache
{
  auto execute_action(CachedSyscall_Access::Parameters const &cached_syscall) -> CachedSyscall_Access::Result
  {
    // ToDo: execute syscall directly instead of libc wrapper?
    // This would allow full reuse of from_syscall.
    // On the other hand: why bother? This is trivial enough.
    CachedSyscall_Access::Result result;
    result.return_value = access(cached_syscall.filename.c_str(), cached_syscall.mode);
    result.errno_value = result.return_value == 0 ? 0 : errno;
    return result;
  }

  auto from_syscall(State &, Syscall_access const &syscall) -> CachedSyscall_Access
  {
    std::string const filename = Ptrace::PEEKTEXT_string(syscall.pid, syscall.filename());
    CachedSyscall_Access::Parameters const action{filename, syscall.mode()};
    CachedSyscall_Access::Result const result{(int)syscall.return_value(), syscall.errno_value()};
    return {action, result};
  }
}
