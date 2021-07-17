#pragma once

#include <spdlog/spdlog.h>

#include "wrappers/json.h"
#include "wrappers/filesystem.h"
#include "wrappers/ptrace/SyscallWrappers.h"
#include "wrappers/ptrace.h"

// C++ boilerplate :-(
// fmt overloads will not be provided. Then all this overhead would need to be generated by python. For printing use `json(some_struct).dump()`.
#define CONVENIENCE(STRUCT, ...)                                     \
  friend auto operator<=>(const STRUCT &, const STRUCT &) = default; \
  NLOHMANN_DEFINE_TYPE_INTRUSIVE(STRUCT, __VA_ARGS__)

namespace gpcache
{

  class FiledescriptorState
  {
  public:
    // openat returns int: -1 for error, otherwise fd
    using file_descriptor_t = unsigned int;

    enum class State
    {
      open,
      closed
    };
    struct FiledescriptorData
    {
      file_descriptor_t fd;
      std::filesystem::path filename;
      int flags;
      State state;
      std::vector<std::string> source; ///< for debugging only
    };

    FiledescriptorState();

    auto dump(auto const level, file_descriptor_t const fd) const -> void;
    auto dump(spdlog::level::level_enum const level) const -> void;
    auto get_open(file_descriptor_t const fd) const -> const FiledescriptorData &;
    auto get_open_opt(file_descriptor_t const fd) const -> std::optional<FiledescriptorData>;

    auto open(file_descriptor_t fd, std::string file, int flags, std::string source) -> void;
    auto close(file_descriptor_t fd, std::string source) -> void;

  private:
    std::map<file_descriptor_t, FiledescriptorData> fds;

    // Sounds like this should be in fmt
    auto dump_data(auto const level, FiledescriptorData const &data) const -> void;
  };

  struct State
  {
    FiledescriptorState fds;
    //MmapState mmaps;
  };

  struct CachedSyscall_Open
  {
    static constexpr char name[] = "open";

    struct Action
    {
      int dirfd;
      std::string filename;
      int flags;
      mode_t mode;

      CONVENIENCE(Action, dirfd, filename, flags, mode)
    } action;

    struct Result
    {
      int fd;
      int errno_code;

      CONVENIENCE(Result, fd, errno_code)
    } result;

    CONVENIENCE(CachedSyscall_Open, action, result)
  };

  auto execute_action(CachedSyscall_Open::Action const &cached_syscall) -> CachedSyscall_Open::Result;

  auto from_syscall(State &state, SyscallEx<Syscall_openat> const &syscall) -> std::optional<CachedSyscall_Open>;
}
