#include "cached_syscalls/write.h"

#include <fcntl.h> // O_RDONLY

#include "wrappers/ptrace.h"
#include "wrappers/json.h"
#include "wrappers/filesystem.h"

#include "utils/flag_to_string.h"
#include "utils/Utils.h"

namespace gpcache
{
  auto execute_action(CachedSyscall_Write::Action const &cached_syscall) -> CachedSyscall_Write::Result
  {
    // ToDo: execute syscall directly instead of libc wrapper?
    // This would allow full reuse of from_syscall.
    // On the other hand: why bother? This is trivial enough.
    CachedSyscall_Write::Result result;
    result.return_value = write(cached_syscall.fd, cached_syscall.data.data(), cached_syscall.data.size());
    // Apparently there is some clever logic in libc...
    // "If count is zero and fd refers to a regular file, then write() may return a failure status"
    result.errno_value = result.return_value > 0 ? 0 : errno;
    return result;
  }

  auto from_syscall(State &state, Syscall_write const &syscall) -> CachedSyscall_Write
  {
    std::string const data = Ptrace::PEEKTEXT(syscall.pid, syscall.buf(), syscall.count());
    CachedSyscall_Write::Action const action{syscall.fd(), data}; // ToDo: binary data... store as separate file?
    CachedSyscall_Write::Result const result{(int)syscall.return_value(), syscall.errno_value()};
    return {action, result};
  }
}
