#include "syscalls/mmap_munmap.h"

#include "wrappers/filesystem.h"
#include "wrappers/hash.h"
#include "wrappers/json.h"
#include "wrappers/ptrace.h"

#include "utils/Utils.h"
#include "utils/flag_to_string.h"

#include <fcntl.h>    // O_RDONLY
#include <sys/mman.h> // mmap PROT_READ

namespace gpcache {

static const std::vector<int> prot_readonly_list = {
    PROT_READ,            // e.g. regular files
    PROT_READ | PROT_EXEC // dynamic libraries
};

auto execute_cached_syscall(
    State &state, CachedSyscall_Mmap::Parameters const &cached_syscall)
    -> CachedSyscall_Mmap::Result {
  CachedSyscall_Mmap::Result result{};
  errno = 0;
  void *addr =
      mmap(nullptr, cached_syscall.length, cached_syscall.prot,
           cached_syscall.flags, cached_syscall.fd, cached_syscall.offset);
  result.is_addr_nullptr = addr == nullptr;
  result.errno_code = errno;
  auto file_data = state.fds.get_open_opt(cached_syscall.fd);
  if (!file_data) {
    spdlog::warn("Unknown fd {}", cached_syscall.fd);
  }
  result.file_hash = calculate_hash_of_file(
      file_data.value().filename); // maybe a little overkill...
  state.mmaps.mmap(addr, cached_syscall.prot, cached_syscall.flags,
                   file_data.value().filename);
  return result;
}

auto covert_to_cachable_syscall(State &state, Syscall_mmap const &syscall_mmap)
    -> std::variant<bool, CachedSyscall_Mmap> {
  auto const addr = reinterpret_cast<void *>(syscall_mmap.addr());
  int const fd = static_cast<int>(syscall_mmap.fd());

  auto file_data = state.fds.get_open_opt(fd);

  bool is_readonly = gpcache::contains(prot_readonly_list, syscall_mmap.prot());

  // PROT_WRITE on O_RDONLY file seems ok contradicting documentation
  bool const file_readonly =
      file_data.has_value() &&
      ((file_data->flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_RDONLY);
  if (file_readonly &&
      gpcache::contains(prot_readonly_list, syscall_mmap.prot() & ~PROT_WRITE))
    is_readonly = true;

  if (is_readonly) {
    auto const file_hash = calculate_hash_of_file(
        file_data.value().filename); // maybe a little overkill...
    CachedSyscall_Mmap::Parameters parameters{
        addr == nullptr,
        syscall_mmap.len(),
        static_cast<int>(syscall_mmap.prot()),
        static_cast<int>(syscall_mmap.flags()),
        static_cast<int>(syscall_mmap.fd()),
        syscall_mmap.pgoff()};
    CachedSyscall_Mmap::Result result{syscall_mmap.return_value() == 0,
                                      syscall_mmap.errno_value(), file_hash};
    state.mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(),
                     file_data->filename);
    return CachedSyscall_Mmap{parameters, result};
  } else if (!file_data.has_value()) {
    // Shared memory without a file is just memory until the process forks.
    return true;
  } else {
    spdlog::warn("flags {} = {}", syscall_mmap.flags(),
                 mmap_flag_to_string(syscall_mmap.flags()));
    spdlog::warn("prot {} = {}", syscall_mmap.prot(),
                 mmap_prot_to_string(syscall_mmap.prot()));
    if (file_data.has_value()) {
      spdlog::warn("fd.path {}", file_data->filename.string());
      spdlog::warn("fd.flags {}", openat_flag_to_string(file_data->flags));
    }

    // ToDo: handle length correctly
    state.mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(), {});

    return false;
  }
}
} // namespace gpcache
