#pragma once

#include "wrappers/filesystem.h"

#include <map>
#include <vector>
#include <spdlog/spdlog.h>

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
}
