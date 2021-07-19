#pragma once

#include <spdlog/spdlog.h>

#include "wrappers/json.h"
#include "wrappers/filesystem.h"
#include "wrappers/ptrace/SyscallWrappers.h"
#include "wrappers/ptrace.h"
#include "state.h"

// The following is intentionally in global namespace (same as struct stat).

inline std::strong_ordering int_to_strong_order(int i)
{
  switch (i)
  {
  case -1:
    return std::strong_ordering::less;
  case 0:
    return std::strong_ordering::equal;
  case 1:
    return std::strong_ordering::greater;
  }
  __builtin_unreachable();
}

inline auto operator<=>(const struct stat &lhs, const struct stat &rhs)
{
  return int_to_strong_order(std::memcmp(
      reinterpret_cast<const void *>(&lhs),
      reinterpret_cast<const void *>(&rhs),
      sizeof(struct stat)));
}

inline auto operator==(const struct stat &lhs, const struct stat &rhs)
{
  return operator<=>(lhs, rhs) == std::strong_ordering::equal;
}

template <>
struct fmt::formatter<struct stat>
{
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(struct stat const &s, auto &ctx)
  {
    return fmt::format_to(ctx.out(),
                          "(dev {}, ino {}, mode {}, nlink {}, uid {}, gid {}, rdev {}, "
                          "size {}, blksize {}, blocks {}, "
                          "atim {}.{}, mtim {}.{}, ctim {}.{})",
                          s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid, s.st_rdev,
                          s.st_size, s.st_blksize, s.st_blocks,
                          s.st_atim.tv_sec, s.st_atim.tv_nsec,
                          s.st_mtim.tv_sec, s.st_mtim.tv_nsec,
                          s.st_ctim.tv_sec, s.st_ctim.tv_nsec);
  }
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(struct stat,
                                   st_dev, st_ino, st_mode, st_nlink,
                                   st_uid, st_gid, st_rdev,
                                   st_size, st_blksize, st_blocks,
                                   st_atim.tv_sec, st_atim.tv_nsec,
                                   st_mtim.tv_sec, st_mtim.tv_nsec,
                                   st_ctim.tv_sec, st_ctim.tv_nsec)

namespace gpcache
{
  struct CachedSyscall_Fstat
  {
    static constexpr char name[] = "fstat";

    struct Parameters
    {
      FiledescriptorState::file_descriptor_t fd;

      CONVENIENCE(Parameters, fd)
    } parameters;

    struct Result
    {
      struct stat stats;
      int return_value;
      int errno_value;

      CONVENIENCE(Result, stats, return_value, errno_value)
    } result;

    CONVENIENCE(CachedSyscall_Fstat, parameters, result)
  };

  auto execute_cached_syscall(CachedSyscall_Fstat::Parameters const &cached_syscall) -> CachedSyscall_Fstat::Result;

  auto covert_to_cachable_syscall(State &state, Syscall_fstat const &syscall) -> CachedSyscall_Fstat;
}
