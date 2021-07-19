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

  class MmapState
  {
  private:
    struct MmapData
    {
      void *addr;
      int prot;
      int flags;
      std::optional<int> fd;
    };
    std::vector<MmapData> mmaps;

  public:
    //auto mmap(void *addr, int prot, int flags, std::filesystem::path path) {}
    auto mmap(void *, int, int, std::filesystem::path) {}
    //auto munmap(void *addr) {}
    auto munmap(void *) {}
  };

  // bool true = ignore
  // bool false = unsupported
  // ToDo: consider adding CachedSyscall_Unsupported with bool flag or CachedSyscall_Unsupported and CachedSyscall_Ignore
  using SyscallResult = std::variant<CachedSyscall, bool>;

  auto handle_syscall(Ptrace::PtraceProcess const p, Ptrace::SysCall const &ptrace_syscall, State &state, MmapState &mmaps) -> SyscallResult
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
      auto const syscall_mmap = static_cast<Syscall_mmap>(syscall);
      auto const addr = reinterpret_cast<void *>(syscall_mmap.addr());

      // Yes this will truncate! and wrap around 4294967295 to -1!
      int const fd = static_cast<int>(syscall_mmap.fd());

      auto file_data = state.fds.get_open_opt(fd);

      if (file_data.has_value() && (syscall_mmap.prot() == PROT_READ || syscall_mmap.prot() == (PROT_READ | PROT_EXEC)))
      {
        FileHash hash{file_data->filename, "ToDo"};
        mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(), file_data->filename);
        return CachedSyscall{hash};
      }
      else if (file_data.has_value() && (syscall_mmap.prot() == (PROT_READ | PROT_WRITE)) && ((file_data->flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_RDONLY))
      {
        // Well this should not work... but it seems to work... let's assume it's read only?!
        FileHash hash{file_data->filename, "ToDo"};
        mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(), file_data->filename);
        return CachedSyscall{hash};
      }
      else if (!file_data.has_value())
      {
        // Shared memory without a file is just memory until the process forks.
        return true;
      }
      else
      {
        spdlog::warn("flags {} = {}", syscall_mmap.flags(), mmap_flag_to_string(syscall_mmap.flags()));
        spdlog::warn("prot {} = {}", syscall_mmap.prot(), mmap_prot_to_string(syscall_mmap.prot()));
        if (file_data.has_value())
        {
          spdlog::warn("fd.path {}", file_data->filename.string());
          spdlog::warn("fd.flags {}", openat_flag_to_string(file_data->flags));
        }

        // ToDo: handle length correctly
        mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(), {});

        return false;
      }
      break; // unreachable, but g++ complains otherwise
    }
    case Syscall_munmap::syscall_id:
    {
      auto const syscall_munmap = static_cast<Syscall_munmap>(syscall);
      auto const addr = reinterpret_cast<void *>(syscall_munmap.addr());

      // Who cares...?
      mmaps.munmap(addr);
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
    MmapState mmaps;

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
      auto result = handle_syscall(p, *syscall, state, mmaps);

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
