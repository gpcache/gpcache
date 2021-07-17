#include "cached_syscalls/fstat.h"

#include <fcntl.h> // O_RDONLY

#include "wrappers/ptrace.h"
#include "wrappers/json.h"
#include "wrappers/filesystem.h"

#include "utils/flag_to_string.h"
#include "utils/Utils.h"

namespace gpcache
{

  auto execute_action(CachedSyscall_Fstat::Action const &cached_syscall) -> CachedSyscall_Fstat::Result
  {
    return {};
  }

  auto from_syscall(State &state, SyscallEx<Syscall_fstat> const &syscall) -> std::optional<CachedSyscall_Fstat>
  {
    struct stat const s = Ptrace::PEEKTEXT<struct stat>(syscall.process.get_pid(),
                                                        reinterpret_cast<char *>(syscall.statbuf()));
    auto const path = state.fds.get_open(syscall.fd()).filename;

    CachedSyscall_Fstat::Action const action{path};
    CachedSyscall_Fstat::Result const result{s, syscall.return_value, syscall.errno_value};
    return CachedSyscall_Fstat{action, result};
  }
}
