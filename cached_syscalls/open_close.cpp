#include "cached_syscalls/open_close.h"

#include <fcntl.h> // O_RDONLY

#include "wrappers/ptrace.h"
#include "wrappers/json.h"
#include "wrappers/filesystem.h"

#include "utils/flag_to_string.h"
#include "utils/Utils.h"

namespace gpcache
{

  static const std::vector<int> mode_allowlist = {
      O_RDONLY,
      O_RDONLY | O_CLOEXEC | O_LARGEFILE,
      O_RDONLY | O_LARGEFILE,
      O_RDONLY | O_CLOEXEC,
  };

  auto execute_cached_syscall(State & state, CachedSyscall_Open::Parameters const &cached_syscall) -> CachedSyscall_Open::Result
  {
    if (!gpcache::contains(mode_allowlist, cached_syscall.mode))
    {
      spdlog::warn("Cannot execute {} from cache at the moment (not yet implemented)", json(cached_syscall).dump());
      return {};
    }

    // ToDo: dirfd => full tracking of open files

    CachedSyscall_Open::Result result;
    int const fd = openat(0, cached_syscall.filename.c_str(), cached_syscall.flags, cached_syscall.mode);
    result.fd = fd; // todo: fd is dynamic
    result.errno_code = errno;

    if(fd >= 0)
      state.fds.open(fd, cached_syscall.filename, cached_syscall.flags, "cached syscall");
    return result;
  }

  auto covert_to_cachable_syscall(State &state, Syscall_openat const &syscall) -> std::optional<CachedSyscall_Open>
  {
    {
      const std::filesystem::path path = Ptrace::PEEKTEXT_string(syscall.pid, syscall.filename());
      if (path.is_absolute() && (syscall.flags() == O_CLOEXEC || syscall.flags() == (O_RDONLY | O_CLOEXEC) || syscall.flags() == (O_RDONLY | O_LARGEFILE)))
      {
        CachedSyscall_Open const cached_syscall{{0, path, syscall.flags(), syscall.mode()}, {(int)syscall.return_value(), syscall.errno_value()}};
        if (syscall.errno_value() == 0)
          state.fds.open(syscall.return_value(), path, syscall.flags(), json(cached_syscall).dump());
        return cached_syscall;
      }
      else
      {
        auto const dirfd = syscall.dfd();
        if (dirfd == AT_FDCWD)
        {
          // open relative to CWD
        }
        else
        {
          // open relative to dirfd
        }
        spdlog::warn("flags {} = {}", syscall.flags(), openat_flag_to_string(syscall.flags()));
        return {};
      }
    }
  }
}
