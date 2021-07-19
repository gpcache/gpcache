#include "cached_syscalls/mmap_munmap.h"

#include <fcntl.h>    // O_RDONLY
#include <sys/mman.h> // mmap PROT_READ

#include "wrappers/ptrace.h"
#include "wrappers/json.h"
#include "wrappers/filesystem.h"

#include "utils/flag_to_string.h"
#include "utils/Utils.h"

namespace gpcache
{

  static const std::vector<int> prot_readonly_list = {
      PROT_READ,            // e.g. regular files
      PROT_READ | PROT_EXEC // dynamic libraries
  };

  auto execute_cached_syscall(CachedSyscall_Mmap::Parameters const &cached_syscall) -> CachedSyscall_Mmap::Result
  {
    CachedSyscall_Mmap::Result result;
    return result;
  }

  auto covert_to_cachable_syscall(State &state, Syscall_mmap const &syscall_mmap) -> std::variant<bool, CachedSyscall_Mmap>
  {
    auto const addr = reinterpret_cast<void *>(syscall_mmap.addr());
    int const fd = static_cast<int>(syscall_mmap.fd());

    auto file_data = state.fds.get_open_opt(fd);

    bool is_readonly = gpcache::contains(prot_readonly_list, syscall_mmap.prot());

    // PROT_WRITE on O_RDONLY file seems ok contradicting documentation
    bool const file_readonly = file_data.has_value() && ((file_data->flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_RDONLY);
    if (file_readonly && gpcache::contains(prot_readonly_list, syscall_mmap.prot() & ~PROT_WRITE))
      is_readonly = true;

    if (is_readonly)
    {
      CachedSyscall_Mmap::Parameters parameters{
          addr == nullptr,
          syscall_mmap.len(),
          static_cast<int>(syscall_mmap.prot()),
          static_cast<int>(syscall_mmap.flags()),
          static_cast<int>(syscall_mmap.fd()),
          syscall_mmap.pgoff()};
      CachedSyscall_Mmap::Result result{syscall_mmap.return_value() == 0, syscall_mmap.errno_value()};
      state.mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(), file_data->filename);
      return CachedSyscall_Mmap{parameters, result};
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
      state.mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(), {});

      return false;
    }
  }
}
