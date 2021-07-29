#include "syscalls/close.h"

#include "wrappers/filesystem.h"
#include "wrappers/json.h"
#include "wrappers/ptrace.h"

#include "utils/Utils.h"
#include "utils/flag_to_string.h"

#include <fcntl.h> // O_RDONLY

namespace gpcache {

auto execute_cached_syscall(
    State &state, CachedSyscall_Close::Parameters const &cached_syscall)
    -> CachedSyscall_Close::Result {
  errno = 0;
  (void)close(cached_syscall.fd);
  state.fds.close(cached_syscall.fd, json(cached_syscall).dump());
  return CachedSyscall_Close::Result{errno};
}

auto covert_to_cachable_syscall(State &state, Syscall_close const &syscall)
    -> CachedSyscall_Close {
  state.fds.close(syscall.fd(), json(syscall).dump());
  return CachedSyscall_Close{{(int)syscall.fd()}, {syscall.errno_value()}};
}
} // namespace gpcache
