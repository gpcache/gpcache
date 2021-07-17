#pragma once

#include "wrappers/json.h"
#include "wrappers/filesystem.h"
#include <boost/pfr/core.hpp>
#include <fmt/format.h>

#include <string>
#include <variant>
#include <vector>
#include <sys/stat.h>

#include "utils/flag_to_string.h"

#include "cached_syscalls/open_close.h"

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
  struct Input_Access
  {
    static constexpr char name[] = "access";

    struct Action
    {
      std::string filename;
      int mode;

      CONVENIENCE(Action, filename, mode);
    } action;

    struct Result
    {
      int result;

      CONVENIENCE(Result, result)
    } result;

    CONVENIENCE(Input_Access, action, result)
  };

  struct FstatAction
  {
    static constexpr char name[] = "fstat";

    struct Action
    {
      std::filesystem::path path;

      CONVENIENCE(Action, path)
    } action;

    struct Result
    {
      struct stat stats;
      bool success;
      int errno_code;

      CONVENIENCE(Result, stats, success, errno_code)
    } result;

    CONVENIENCE(FstatAction, action, result)
  };

  struct FileHash
  {
    static constexpr char name[] = "filehash";

    struct Action
    {
      std::filesystem::path path;
      CONVENIENCE(Action, path)
    } action;

    struct Result
    {
      std::string hash;
      CONVENIENCE(Result, hash)
    } result;

    CONVENIENCE(FileHash, action, result)
  };

  struct ParamsInput
  {
    static constexpr char name[] = "params";

    struct Action
    {
      bool dummy = true;
      CONVENIENCE(Action, dummy)
    } action;

    struct Result
    {
      std::filesystem::path path; // cache this?
      std::vector<std::string> params;
      std::string cwd; // etc... ENV?

      CONVENIENCE(Result, path, params, cwd)
    } result;

    CONVENIENCE(ParamsInput, action, result)
  };

  struct UnsupportedInput
  {
    static constexpr char name[] = "unsupported";

    struct Action
    {
      bool thisIsJustCrazy;
      CONVENIENCE(Action, thisIsJustCrazy)
    } action;

    struct Result
    {
      bool thisIsJustCrazy;
      CONVENIENCE(Result, thisIsJustCrazy)
    } result;

    CONVENIENCE(UnsupportedInput, action, result)
  };

  // ToDo: rename to "Input"
  using Action = std::variant<Input_Access, CachedSyscall_Open, FstatAction, FileHash, ParamsInput, UnsupportedInput>;

  // Holds collection of all inputs which should lead to the same output.
  using Inputs = std::vector<Action>;

} // namespace gpcache
