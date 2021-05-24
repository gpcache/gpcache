#include <string>
#include <variant>
#include <vector>

struct AccessAction
{
  std::string filename;
  int mode;

  uint64_t result; // int? bool? SyscallDataType?
};

template <>
struct fmt::formatter<AccessAction>
{
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(AccessAction const &action, auto &ctx)
  {
    return fmt::format_to(ctx.out(), "access({}, {}) -> {}", action.filename, action.mode, action.result);
  }
};

struct OpenAction
{
  int dirfd;
  std::string filename;
  int flags;
  mode_t mode;

  bool success;
  int errno_code;
};

template <>
struct fmt::formatter<OpenAction>
{
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(OpenAction const &action, auto &ctx)
  {
    return fmt::format_to(ctx.out(), "openat({}, {}, {}, {}) -> {}, {}", action.dirfd, action.filename, action.flags, action.mode, action.success, action.errno_code);
  }
};

struct FstatAction
{
  std::filesystem::path path;
  struct stat stats;

  bool success;
  int errno_code;
};

template <>
struct fmt::formatter<struct stat>
{
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(struct stat const &s, auto &ctx)
  {
    return fmt::format_to(ctx.out(),
                          "(dev {}, ino {}, mode{}, nlink {}, uid {}, gid {}, rdev {}, "
                          "size {}, blksize {}, blocks {}, "
                          "atim {}.{}, mtim {}.{}, ctim {}.{})",
                          s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid, s.st_rdev,
                          s.st_size, s.st_blksize, s.st_blocks,
                          s.st_atim.tv_sec, s.st_atim.tv_nsec,
                          s.st_mtim.tv_sec, s.st_mtim.tv_nsec,
                          s.st_ctim.tv_sec, s.st_ctim.tv_nsec);
  }
};

template <>
struct fmt::formatter<FstatAction>
{
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(FstatAction const &action, auto &ctx)
  {
    return fmt::format_to(ctx.out(), "fstat({}, {}) -> {}, {}",
                          action.path.string(), action.stats, action.success, action.errno_code);
  }
};

struct FileHash
{
  std::filesystem::path path;
  std::string hash;
};

template <>
struct fmt::formatter<FileHash>
{
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(FileHash const &action, auto &ctx)
  {
    return fmt::format_to(ctx.out(), "file hash ({}) -> {}",
                          action.path.string(), action.hash);
  }
};

using Action = std::variant<AccessAction, OpenAction, FstatAction, FileHash>;

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
