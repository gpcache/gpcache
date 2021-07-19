#include "cached_syscalls/read.h"

#include <fcntl.h> // O_RDONLY

#include "wrappers/ptrace.h"
#include "wrappers/json.h"
#include "wrappers/filesystem.h"

#include "utils/flag_to_string.h"
#include "utils/Utils.h"

namespace gpcache
{
  auto execute_cached_syscall(State &, CachedSyscall_Read::Parameters const &cached_syscall) -> CachedSyscall_Read::Result
  {
    CachedSyscall_Read::Result result;
    result.data.resize(cached_syscall.count);

    if (cached_syscall.is_pread64)
    {
      result.return_value = pread64(cached_syscall.fd, result.data.data(), cached_syscall.count, cached_syscall.pread64_offset);
    }
    else
    {
      result.return_value = read(cached_syscall.fd, result.data.data(), cached_syscall.count);
    }
    result.errno_value = result.return_value > 0 ? 0 : errno;
    return result;
  }

  auto covert_to_cachable_syscall(State &, Syscall_read const &syscall) -> CachedSyscall_Read
  {
    std::string const data = Ptrace::PEEKTEXT(syscall.pid, syscall.buf(), syscall.count());
    CachedSyscall_Read::Parameters const parameters{(int)syscall.fd(), syscall.count(), false, 0}; // ToDo: binary data... store as separate file? store only hashsum?
    CachedSyscall_Read::Result const result{data, (int)syscall.return_value(), syscall.errno_value()};
    return {parameters, result};
  }

  auto covert_to_cachable_syscall(State &, Syscall_pread64 const &syscall) -> CachedSyscall_Read
  {
    std::string const data = Ptrace::PEEKTEXT(syscall.pid, syscall.buf(), syscall.count());
    CachedSyscall_Read::Parameters const parameters{(int)syscall.fd(), syscall.count(), true, syscall.pos()}; // ToDo: binary data... store as separate file? store only hashsum?
    CachedSyscall_Read::Result const result{data, (int)syscall.return_value(), syscall.errno_value()};
    return {parameters, result};
  }
}
