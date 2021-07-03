#include <nlohmann/json.hpp>
#include <boost/pfr/core.hpp>
#include <fmt/format.h>

#include <string>
#include <variant>
#include <vector>
#include <sys/stat.h>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
error "Missing the <filesystem> header."
#endif

#include "utils/flag_to_string.h"

using json = nlohmann::json;

// Generate this file? C++ is just awful.
#define CPP_SUCKS(STRUCT, ...)                                       \
  friend auto operator<=>(const STRUCT &, const STRUCT &) = default; \
  NLOHMANN_DEFINE_TYPE_INTRUSIVE(STRUCT, __VA_ARGS__)

//  friend auto operator==(const STRUCT &, const STRUCT &) = default;  \

struct Input_Access
{
  static constexpr char name[] = "access";

  struct Action
  {
    std::string filename;
    int mode;

    CPP_SUCKS(Action, filename, mode);
  } action;

  struct Result
  {
    uint64_t result; // int? bool? SyscallDataType?

    CPP_SUCKS(Result, result)
  } result;

  CPP_SUCKS(Input_Access, action, result)
};

struct OpenAction
{
  static constexpr char name[] = "open";

  struct Action
  {
    int dirfd;
    std::string filename;
    int flags;
    mode_t mode;

    CPP_SUCKS(Action, dirfd, filename, flags, mode)
  } action;

  struct Result
  {
    bool success;
    int errno_code;

    CPP_SUCKS(Result, success, errno_code)
  } result;

  CPP_SUCKS(OpenAction, action, result)
};

std::strong_ordering int_to_strong_order(int i)
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

auto operator<=>(const struct stat &lhs, const struct stat &rhs)
{
  return int_to_strong_order(std::memcmp(
      reinterpret_cast<const void *>(&lhs),
      reinterpret_cast<const void *>(&rhs),
      sizeof(struct stat)));
}

auto operator==(const struct stat &lhs, const struct stat &rhs)
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

struct FstatAction
{
  static constexpr char name[] = "fstat";

  struct Action
  {
    std::filesystem::path path;

    CPP_SUCKS(Action, path)
  } action;

  struct Result
  {
    struct stat stats;
    bool success;
    int errno_code;

    CPP_SUCKS(Result, stats, success, errno_code)
  } result;

  CPP_SUCKS(FstatAction, action, result)
};

struct FileHash
{
  static constexpr char name[] = "filehash";

  struct Action
  {
    std::filesystem::path path;
    CPP_SUCKS(Action, path)
  } action;

  struct Result
  {
    std::string hash;
    CPP_SUCKS(Result, hash)
  } result;

  CPP_SUCKS(FileHash, action, result)
};

using Action = std::variant<Input_Access, OpenAction, FstatAction, FileHash>;

// Holds collection of all inputs which should lead to the same output.
struct Inputs
{
  // ToDo:
  // - cwd/pwd
  // - some env variables like SOURCE_DATE_EPOCH
  //   (never ending list... but adding everything would be overkill)
  // - uid, gid ?!

  std::vector<Action> actions;
};
