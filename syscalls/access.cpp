#include "syscalls/access.h"

#include "wrappers/filesystem.h"
#include "wrappers/json.h"
#include "wrappers/ptrace.h"

#include "utils/Utils.h"
#include "utils/flag_to_string.h"

#include <fcntl.h> // O_RDONLY

namespace gpcache {
auto execute_cached_syscall(
    State &, CachedSyscall_Access::Parameters const &cached_syscall)
    -> CachedSyscall_Access::Result {
  // ToDo: execute syscall directly instead of libc wrapper?
  // This would allow full reuse of covert_to_cachable_syscall.
  // On the other hand: why bother? This is trivial enough.
  CachedSyscall_Access::Result result;
  result.return_value =
      access(cached_syscall.filename.c_str(), cached_syscall.mode);
  result.errno_value = result.return_value == 0 ? 0 : errno;
  return result;
}

auto covert_to_cachable_syscall(State &, Syscall_access const &syscall)
    -> CachedSyscall_Access {
  std::string const filename =
      Ptrace::PEEKTEXT_string(syscall.pid, syscall.filename());
  CachedSyscall_Access::Parameters const parameters{filename, syscall.mode()};
  CachedSyscall_Access::Result const result{(int)syscall.return_value(),
                                            syscall.errno_value()};
  return {parameters, result};
}
} // namespace gpcache
