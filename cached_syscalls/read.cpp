#include "cached_syscalls/read.h"

#include <fcntl.h> // O_RDONLY

#include "wrappers/ptrace.h"
#include "wrappers/json.h"
#include "wrappers/filesystem.h"

#include "utils/flag_to_string.h"
#include "utils/Utils.h"

namespace gpcache
{
  auto execute_cached_syscall(CachedSyscall_Read::Parameters const &cached_syscall) -> CachedSyscall_Read::Result
  {
    // ToDo: execute syscall directly instead of libc wrapper?
    // This would allow full reuse of covert_to_cachable_syscall.
    // On the other hand: why bother? This is trivial enough.
    CachedSyscall_Read::Result result;
    result.return_value = write(cached_syscall.fd, cached_syscall.data.data(), cached_syscall.data.size());
    result.errno_value = result.return_value > 0 ? 0 : errno;
    return result;
  }

  auto covert_to_cachable_syscall(State &, Syscall_read const &syscall) -> CachedSyscall_Read
  {
    std::string const data = Ptrace::PEEKTEXT(syscall.pid, syscall.buf(), syscall.count());
    CachedSyscall_Read::Parameters const parameters{(int)syscall.fd(), data}; // ToDo: binary data... store as separate file?
    CachedSyscall_Read::Result const result{(int)syscall.return_value(), syscall.errno_value()};
    return {parameters, result};
  }
}
