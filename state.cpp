#include "state.h"

#include "utils/flag_to_string.h"

namespace gpcache
{

  // Sounds like this should be in fmt
  auto FiledescriptorState::dump_data(auto const level, FiledescriptorData const &data) const -> void
  {
    spdlog::log(level, "file descriptor fd: {}", data.fd);
    spdlog::log(level, "file descriptor filename: {}", data.filename.string());
    spdlog::log(level, "file descriptor state: {}", data.state);
    spdlog::log(level, "file descriptor flags: {}", openat_flag_to_string(data.flags));
    for (auto const &src : data.source)
      spdlog::log(level, "file descriptor history: {}", src);
  }

  FiledescriptorState::FiledescriptorState()
  {
    fds[0] = {.fd = 0, .filename = "0", .flags = 0, .state = State::open, .source = {"default"}};
    fds[1] = {.fd = 1, .filename = "1", .flags = 0, .state = State::open, .source = {"default"}};
    fds[2] = {.fd = 2, .filename = "2", .flags = 0, .state = State::open, .source = {"default"}};
  }

  auto FiledescriptorState::dump(auto const level, file_descriptor_t const fd) const -> void
  {
    if (auto entry = fds.find(fd); entry != fds.end())
    {
      dump_data(level, entry->second);
    }
    else
    {
      spdlog::log(level, "{} has not been touched", fd);
    }
  }

  auto FiledescriptorState::dump(spdlog::level::level_enum const level) const -> void
  {
    for (auto const &[key, state] : fds)
    {
      spdlog::log(level, "-----------");
      dump_data(level, state);
    }
  }

  auto FiledescriptorState::get_open(file_descriptor_t const fd) const -> const FiledescriptorData &
  {
    if (auto entry = fds.find(fd); entry != fds.end() && entry->second.state == State::open)
    {
      return entry->second;
    }
    else
    {
      // ToDo cache invalid syscall?
      spdlog::warn("get_open of file descriptor {}", fd);
      dump(spdlog::level::warn);
      throw std::runtime_error("invalid get_open");
    }
  }

  auto FiledescriptorState::get_open_opt(file_descriptor_t const fd) const -> std::optional<FiledescriptorData>
  {
    if (auto entry = fds.find(fd); entry != fds.end() && entry->second.state == State::open)
    {
      return std::make_optional(entry->second);
    }
    else
    {
      return std::optional<FiledescriptorData>{};
    }
  }

  auto FiledescriptorState::open(file_descriptor_t fd, std::string file, int flags, std::string source) -> void
  {
    FiledescriptorData new_entry = {
        .fd = fd,
        .filename = file,
        .flags = flags,
        .state = State::open,
        .source = {"open via " + source}};

    if (auto entry = fds.find(fd); entry != fds.end())
    {
      if (entry->second.state == State::open)
      {
        // ToDo
        spdlog::warn("double open of file descriptor {}", fd);
        dump_data(spdlog::level::warn, new_entry);
        dump(spdlog::level::warn, fd);
      }
      else
      {
        entry->second.filename = file;
        entry->second.source.push_back("open via " + source);
        entry->second.state = State::open;
      }
    }
    else
    {
      fds.insert({fd, new_entry});
    }
  }

  auto FiledescriptorState::close(file_descriptor_t fd, std::string source) -> void
  {
    if (auto entry = fds.find(fd); entry != fds.end())
    {
      auto &data = entry->second;
      if (data.state == State::closed)
      {
        throw std::runtime_error(fmt::format("closing closed fd {} from {}", fd, source));
      }
      else
      {
        data.state = State::closed;
        data.source.push_back("closed via " + source);
      }
    }
    else
    {
      throw std::runtime_error(fmt::format("closing unknown fd {} from {}", fd, source));
    }
  }
}
