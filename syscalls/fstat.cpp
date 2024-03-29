#include "syscalls/fstat.h"

#include "wrappers/filesystem.h"
#include "wrappers/json.h"
#include "wrappers/ptrace.h"

#include "utils/Utils.h"
#include "utils/flag_to_string.h"

#include <fcntl.h> // O_RDONLY

namespace gpcache
{

auto execute_cached_syscall(State &, CachedSyscall_Fstat::Parameters const &cached_syscall)
    -> CachedSyscall_Fstat::Result
{
    CachedSyscall_Fstat::Result result;
    result.return_value = fstat(cached_syscall.fd, &result.stats);
    result.errno_value = errno;
    return result;
}

auto covert_real_to_cachable_syscall(State &, Syscall_fstat const &syscall) -> CachedSyscall_Fstat
{
    struct stat const s = Ptrace::PEEKTEXT<struct stat>(syscall.pid, syscall.statbuf());
    // auto const path = state.fds.get_open(syscall.fd()).filename;

    // assert fd is actually known?
    CachedSyscall_Fstat::Parameters const parameters{static_cast<int>(syscall.fd())};
    CachedSyscall_Fstat::Result const result{s, (int)syscall.return_value(), syscall.errno_value()};
    return CachedSyscall_Fstat{parameters, result};
}
} // namespace gpcache
