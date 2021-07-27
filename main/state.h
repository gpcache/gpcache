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
    // we need to be able to store -1:
    // openat returns int: -1 for error, otherwise fd
    // fstat returns int: -1 for error, otherwise fd
    using file_descriptor_t = int;

    enum class State
    {
      open,
      closed
    };
    struct FiledescriptorData
    {
      file_descriptor_t fd; // orig_fd and actual_fd for replay?
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


  class MmapState
  {
  private:
    struct MmapData
    {
      void *addr;
      int prot;
      int flags;
      std::optional<int> fd;
    };
    std::vector<MmapData> mmaps;

  public:
    //auto mmap(void *addr, int prot, int flags, std::filesystem::path path) {}
    auto mmap(void *, int, int, std::filesystem::path) {}
    //auto munmap(void *addr) {}
    auto munmap(void *) {}
  };


  // kernel state? application state? Handles?
  struct State
  {
    FiledescriptorState fds;
    MmapState mmaps;
  };
}
