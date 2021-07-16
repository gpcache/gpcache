#include <string>
#include <vector>
#include <optional>

#include <spdlog/spdlog.h>
#include <sys/mman.h> // mmap PROT_READ

#include "inputs.h"
#include "outputs.h"
#include "wrappers/hash.h"
#include "wrappers/posix.h"
#include "wrappers/ptrace.h"
#include "wrappers/ptrace/SyscallWrappers.h"

namespace gpcache
{

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
    auto mmap(void *addr, int prot, int flags, std::filesystem::path path) {}
    auto munmap(void *addr) {}
  };

  class FiledescriptorState
  {
  public:
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

  private:
    std::map<file_descriptor_t, FiledescriptorData> fds;

    // Sounds like this should be in fmt
    auto dump_data(auto const level, FiledescriptorData const &data) const -> void
    {
      spdlog::log(level, "file descriptor fd: {}", data.fd);
      spdlog::log(level, "file descriptor filename: {}", data.filename.string());
      spdlog::log(level, "file descriptor state: {}", data.state);
      spdlog::log(level, "file descriptor flags: {}", openat_flag_to_string(data.flags));
      for (auto const &src : data.source)
        spdlog::log(level, "file descriptor history: {}", src);
    }

  public:
    FiledescriptorState()
    {
      fds[0] = {.fd = 0, .filename = "0", .flags = 0, .state = State::open, .source = {"default"}};
      fds[1] = {.fd = 1, .filename = "1", .flags = 0, .state = State::open, .source = {"default"}};
      fds[2] = {.fd = 2, .filename = "2", .flags = 0, .state = State::open, .source = {"default"}};
    }

    auto dump(auto const level, file_descriptor_t const fd) const -> void
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

    auto dump(spdlog::level::level_enum const level) const -> void
    {
      for (auto const &[key, state] : fds)
      {
        spdlog::log(level, "-----------");
        dump_data(level, state);
      }
    }

    const auto &get_open(file_descriptor_t const fd) const
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

    auto get_open_opt(file_descriptor_t const fd) const
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

    auto open(file_descriptor_t fd, std::string file, int flags, std::string source) -> void
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

    auto close(file_descriptor_t fd, std::string source) -> void
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
  };

  struct SyscallResult
  {
    bool supported;
    // todo: variant
    std::optional<Action> input;
    std::optional<Output> output;
  };

  auto handle_syscall(Ptrace::PtraceProcess const p, Ptrace::SysCall const &syscall, FiledescriptorState &fds, MmapState &mmaps) -> SyscallResult
  {
    switch (syscall.info.syscall_id)
    {
    case Syscall_brk::syscall_id:
    case Syscall_arch_prctl::syscall_id:
    case Syscall_mprotect::syscall_id: // maybe interesting with ignoring more mmap calls... ignore for now
      return SyscallResult{true};
    case Syscall_access::syscall_id:
    {
      auto syscall_access = static_cast<Syscall_access>(syscall.arguments);
      std::string const filename = Ptrace::PEEKTEXT_string(p.get_pid(), syscall_access.filename());
      return SyscallResult{true, Input_Access{filename, syscall_access.mode(), syscall.return_value.value()}};
    }
    case Syscall_openat::syscall_id:
    {
      auto const syscall_openat = static_cast<Syscall_openat>(syscall.arguments);

      const std::filesystem::path path = Ptrace::PEEKTEXT_string(p.get_pid(), syscall_openat.filename());
      if (path.is_absolute() && (syscall_openat.flags() == O_CLOEXEC || syscall_openat.flags() == (O_RDONLY | O_CLOEXEC) || syscall_openat.flags() == (O_RDONLY | O_LARGEFILE)))
      {
        int fd = syscall.return_value.value();
        fds.open(fd, path, syscall_openat.flags(), fmt::format("open via {}", syscall));
        spdlog::debug("openat flags {} = {}", syscall_openat.flags(), openat_flag_to_string(syscall_openat.flags()));
        return SyscallResult{true, OpenAction{0, path, syscall_openat.flags(), syscall_openat.mode(), fd != -1, 0}};
      }
      else
      {
        auto const dirfd = syscall_openat.dfd();
        if (dirfd == AT_FDCWD)
        {
          // open relative to CWD
        }
        else
        {
          // open relative to dirfd
        }
        spdlog::warn("flags {} = {}", syscall_openat.flags(), openat_flag_to_string(syscall_openat.flags()));
        return SyscallResult{.supported = false};
      }
    }
    case Syscall_close::syscall_id:
    {
      auto const syscall_close = static_cast<Syscall_close>(syscall.arguments);
      fds.close(syscall_close.fd(), fmt::format("close via {}", syscall));
      return SyscallResult{.supported = true};
    }
    case Syscall_fstat::syscall_id:
    {
      auto const syscall_fstat = static_cast<Syscall_fstat>(syscall.arguments);
      struct stat s;
      // ToDo: Ptrace::PEEKTEXT<struct stat>
      auto data = Ptrace::PEEKTEXT(p.get_pid(),
                                   reinterpret_cast<char *>(syscall_fstat.statbuf()),
                                   sizeof(struct stat));
      memcpy(&s, data.c_str(), sizeof(struct stat));

      auto const path = fds.get_open(syscall_fstat.fd()).filename;

      FstatAction fstat{path, s, syscall.return_value.value() == 0, 0};
      return SyscallResult{true, fstat};
    }
    case Syscall_read::syscall_id:
    {
      auto const syscall_read = static_cast<Syscall_close>(syscall.arguments);
      // In theory only the actually read parts of the file...
      FileHash hash{fds.get_open(syscall_read.fd()).filename, "ToDo"};
      return SyscallResult{true, hash};
    }
    case Syscall_pread64::syscall_id:
    {
      auto const syscall_read = static_cast<Syscall_pread64>(syscall.arguments);
      // In theory only the actually read parts of the file...
      FileHash hash{fds.get_open(syscall_read.fd()).filename, "ToDo"};
      return SyscallResult{true, hash};
    }
    case Syscall_write::syscall_id:
    {
      auto const syscall_write = static_cast<Syscall_write>(syscall.arguments);

      auto const filename = fds.get_open(syscall_write.fd()).filename;

      json const ftw{
          {"fd", syscall_write.fd()},
          {"filename", fds.get_open(syscall_write.fd()).filename},
          {"content", Ptrace::PEEKTEXT(p.get_pid(),
                                       syscall_write.buf(),
                                       syscall_write.count())}};

      return SyscallResult{.supported = true, .output = ftw};
    }
    case Syscall_mmap::syscall_id:
    {
      auto const syscall_mmap = static_cast<Syscall_mmap>(syscall.arguments);
      auto const addr = reinterpret_cast<void *>(syscall_mmap.addr());

      // Yes this will truncate! and wrap around 4294967295 to -1!
      int const fd = static_cast<int>(syscall_mmap.fd());

      auto file_data = fds.get_open_opt(fd);

      if (file_data.has_value() && (syscall_mmap.prot() == PROT_READ || syscall_mmap.prot() == (PROT_READ | PROT_EXEC)))
      {
        FileHash hash{file_data->filename, "ToDo"};
        mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(), file_data->filename);
        return SyscallResult{true, hash};
      }
      else if (file_data.has_value() && (syscall_mmap.prot() == (PROT_READ | PROT_WRITE)) && ((file_data->flags & (O_RDONLY | O_WRONLY | O_RDWR)) == O_RDONLY))
      {
        // Well this should not work... but it seems to work... let's assume it's read only?!
        FileHash hash{file_data->filename, "ToDo"};
        mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(), file_data->filename);
        return SyscallResult{true, hash};
      }
      else if (!file_data.has_value())
      {
        // Shared memory without a file is just memory until the process forks.
        return SyscallResult{true};
      }
      else
      {
        spdlog::warn("flags {} = {}", syscall_mmap.flags(), mmap_flag_to_string(syscall_mmap.flags()));
        spdlog::warn("prot {} = {}", syscall_mmap.prot(), mmap_prot_to_string(syscall_mmap.prot()));
        if (file_data.has_value())
        {
          spdlog::warn("fd.path {}", file_data->filename.string());
          spdlog::warn("fd.flags {}", openat_flag_to_string(file_data->flags));
        }

        // ToDo: handle length correctly
        mmaps.mmap(addr, syscall_mmap.prot(), syscall_mmap.flags(), {});

        return SyscallResult{.supported = false};
      }
    }
    case Syscall_munmap::syscall_id:
    {
      auto const syscall_munmap = static_cast<Syscall_munmap>(syscall.arguments);
      auto const addr = reinterpret_cast<void *>(syscall_munmap.addr());

      // Who cares...?
      mmaps.munmap(addr);
      return SyscallResult{.supported = true};
    }
    } // switch
    return SyscallResult{.supported = false};
  }

  struct ExecutionCache
  {
    Inputs inputs;
    Outputs outputs;
  };

  auto cache_execution(std::vector<char *> const &prog_and_arguments) -> ExecutionCache
  {
    Ptrace::PtraceProcess p = Ptrace::createChildProcess(prog_and_arguments);
    spdlog::debug("after createChildProcess");

    Inputs inputs;
    Outputs outputs;
    FiledescriptorState fds;
    MmapState mmaps;

    while (true)
    {
      auto syscall = p.restart_child_and_wait_for_next_syscall();
      if (!syscall)
      {
        // child has exited
        // ToDo: exit code
        spdlog::debug("!syscall");
        break;
      }

      // Since gpcache does not modify syscalls, just monitoring the exists is sufficient
      if (!syscall->return_value)
      {
        continue;
      }

      // Do the conversion only once (move into optional in SysCall ?!) -> Yeah. TODO
      // Simply add p to SysCall!
      auto result = handle_syscall(p, *syscall, fds, mmaps);

      if (result.supported)
      {
        spdlog::debug("Supported syscall {}", *syscall);
        if (result.input)
        {
          auto &new_action = *result.input;

          // Only the most trivial optimization for now
          if (inputs.empty() || inputs.back() != new_action)
            inputs.push_back(new_action);
        }
        else if (result.output)
        {
          auto &new_output = *result.output;
          outputs.push_back(new_output);
        }
      }
      else
        spdlog::warn("Unsupported syscall {}", *syscall);
    }

    return ExecutionCache{inputs, outputs};
  }
}
