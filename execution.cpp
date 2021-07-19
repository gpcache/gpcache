#include "execution.h"

#include <string>
#include <vector>
#include <optional>

#include <spdlog/spdlog.h>
#include <sys/mman.h> // mmap PROT_READ

#include "wrappers/hash.h"
#include "wrappers/posix.h"
#include "wrappers/ptrace.h"
#include "wrappers/ptrace/SyscallWrappers.h"

namespace gpcache
{
  // bool true = ignore
  // bool false = unsupported
  // ToDo: consider adding CachedSyscall_Unsupported with bool flag or CachedSyscall_Unsupported and CachedSyscall_Ignore
  using SyscallResult = std::variant<CachedSyscall, bool>;

  auto handle_syscall(Ptrace::PtraceProcess const p, Ptrace::SysCall const &ptrace_syscall, State &state) -> SyscallResult
  {
    Syscall_Base syscall{
        .pid = p.get_pid(),
        .args = ptrace_syscall.arguments,
        .real_return_value = ptrace_syscall.return_value.value()};

    // Design problem:
    // * variant with all possible syscall types takes minutes to compile
    // * creating hundreds of virtual methods is kind of pointless when most of them are not supported
    // So the only solution is this huge switch statement.
    switch (ptrace_syscall.info.syscall_id)
    {
    case Syscall_brk::syscall_id:
    case Syscall_arch_prctl::syscall_id:
    case Syscall_mprotect::syscall_id: // maybe interesting with ignoring more mmap calls... ignore for now
      return SyscallResult{true};
    case Syscall_access::syscall_id:
    {
      return covert_to_cachable_syscall(state, static_cast<Syscall_access>(syscall));
    }
    case Syscall_openat::syscall_id:
    {
      auto const cached_syscall = covert_to_cachable_syscall(state, static_cast<Syscall_openat>(syscall));

      if (cached_syscall)
        return CachedSyscall{cached_syscall.value()};
      else
        return false;
      break; // unreachable, but g++ complains otherwise
    }
    case Syscall_close::syscall_id:
    {
      auto const syscall_close = static_cast<Syscall_close>(syscall);
      state.fds.close(syscall_close.fd(), fmt::format("close via {}", json(syscall).dump()));
      return true;
    }
    case Syscall_fstat::syscall_id:
    {
      return covert_to_cachable_syscall(state, static_cast<Syscall_fstat>(syscall));
    }
    case Syscall_read::syscall_id:
    {
      return covert_to_cachable_syscall(state, static_cast<Syscall_read>(syscall));
    }
    case Syscall_pread64::syscall_id:
    {
      return covert_to_cachable_syscall(state, static_cast<Syscall_pread64>(syscall));
    }
    case Syscall_write::syscall_id:
    {
      return covert_to_cachable_syscall(state, static_cast<Syscall_write>(syscall));
    }
    case Syscall_mmap::syscall_id:
    {
      // Wow.. C++... In caes of a return a, in case of b return b.
      auto result = covert_to_cachable_syscall(state, static_cast<Syscall_mmap>(syscall));
      if (bool const *b = std::get_if<bool>(&result))
        return *b;
      else
        return std::get<CachedSyscall_Mmap>(result);
    }
    case Syscall_munmap::syscall_id:
    {
      auto const syscall_munmap = static_cast<Syscall_munmap>(syscall);
      auto const addr = reinterpret_cast<void *>(syscall_munmap.addr());

      // Who cares...?
      state.mmaps.munmap(addr);
      return true;
    }
    } // switch
    return false;
  }

  auto execute_program(std::vector<char *> const &prog_and_arguments) -> std::vector<CachedSyscall>
  {
    Ptrace::PtraceProcess p = Ptrace::createChildProcess(prog_and_arguments);
    spdlog::debug("after createChildProcess");

    std::vector<CachedSyscall> execution_cache;
    State state;

    while (true)
    {
      auto syscall = p.restart_child_and_wait_for_next_syscall();
      if (!syscall)
      {
        spdlog::debug("child has exited (ToDo: exit code)");
        break;
      }

      // Since gpcache does not modify syscalls, just monitoring the exists is sufficient
      if (!syscall->return_value)
      {
        continue;
      }

      // add p to SysCall!
      auto result = handle_syscall(p, *syscall, state);

      if (const CachedSyscall *const cached_syscall = std::get_if<CachedSyscall>(&result))
      {
        execution_cache.push_back(*cached_syscall);
      }
      else if (bool const supported = std::get<bool>(result); !supported)
      {
        spdlog::warn("Unsupported syscall {}", *syscall);
      }
    }

    return execution_cache;
  }
}
