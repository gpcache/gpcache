#include "syscalls/read.h"

#include "wrappers/filesystem.h"
#include "wrappers/hash.h"
#include "wrappers/json.h"
#include "wrappers/ptrace.h"

#include "utils/Utils.h"
#include "utils/flag_to_string.h"

#include <fcntl.h> // O_RDONLY

template <class T> static auto limit(const T min, const T value, const T max) {
  if (value < min)
    return min;
  else if (value > max)
    return max;
  else
    return value;
}

static auto hash_of_data(auto data) {
  // Idea: return data itself in case it's printable ASCII only (and short
  // enough).
  // blake2b is limited to 64
  const auto hash_length = limit(10UL, data.size() / 20, 64UL);
  return gpcache::calculate_hash_of_str(data, hash_length);
}

namespace gpcache {
auto execute_cached_syscall(
    State &, CachedSyscall_Read::Parameters const &cached_syscall)
    -> CachedSyscall_Read::Result {
  CachedSyscall_Read::Result result;
  result.data.resize(cached_syscall.count);

  if (cached_syscall.is_pread64) {
    result.return_value =
        pread64(cached_syscall.fd, result.data.data(), cached_syscall.count,
                cached_syscall.pread64_offset);
  } else {
    result.return_value =
        read(cached_syscall.fd, result.data.data(), cached_syscall.count);
  }

  result.data = hash_of_data(result.data);
  result.data.shrink_to_fit();
  result.errno_value = result.return_value > 0 ? 0 : errno;
  return result;
}

auto covert_real_to_cachable_syscall(State &, Syscall_read const &syscall)
    -> CachedSyscall_Read {
  std::string const data =
      Ptrace::PEEKTEXT(syscall.pid, syscall.buf(), syscall.count());
  CachedSyscall_Read::Parameters const parameters{(int)syscall.fd(),
                                                  syscall.count(), false, 0};
  CachedSyscall_Read::Result const result{
      hash_of_data(data), (int)syscall.return_value(), syscall.errno_value()};
  return {parameters, result};
}

auto covert_real_to_cachable_syscall(State &, Syscall_pread64 const &syscall)
    -> CachedSyscall_Read {
  std::string const data =
      Ptrace::PEEKTEXT(syscall.pid, syscall.buf(), syscall.count());
  CachedSyscall_Read::Parameters const parameters{
      (int)syscall.fd(), syscall.count(), true, syscall.pos()};
  CachedSyscall_Read::Result const result{
      hash_of_data(data), (int)syscall.return_value(), syscall.errno_value()};
  return {parameters, result};
}
} // namespace gpcache
