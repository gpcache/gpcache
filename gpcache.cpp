// ToDo: cleanup includes
#include <iostream>
#include <fmt/format.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/time/time.h"
#include "utils/enumerate.h"
#include "utils/join.h"
#include <asm/prctl.h>
#include <sys/prctl.h>
#include "spdlog/pattern_formatter.h"
#include "wrappers/hash.h"
#include "wrappers/posix.h"
#include "wrappers/ptrace.h"
#include "wrappers/ptrace/SyscallWrappers.h"
#include <any>
#include <variant>
#include <set>
#include "utils/Utils.h"
#include <spdlog/spdlog.h>
#include "inputs.h"
#include "outputs.h"
#include <sys/mman.h> // mmap PROT_READ

ABSL_FLAG(bool, verbose, false, "Add verbose output");
ABSL_FLAG(std::string, cache_dir, "~/.gpcache", "cache dir");

namespace gpcache
{
  class FiledescriptorManager
  {
  private:
    enum class State
    {
      open,
      closed
    };
    struct FiledescriptorData
    {
      int fd;
      std::string filename;
      State state;
      std::vector<std::string> source;
    };
    std::map<int, FiledescriptorData> fds;

    // Sounds like this should be in fmt
    auto dump_data(auto const level, FiledescriptorData const &data) const -> void
    {
      spdlog::log(level, "file descriptor fd: {}", data.fd);
      spdlog::log(level, "file descriptor filename: {}", data.filename);
      spdlog::log(level, "file descriptor state: {}", data.state);
      for (auto const &src : data.source)
        spdlog::log(level, "file descriptor source: {}", src);
    }

  public:
    FiledescriptorManager()
    {
      fds[0] = {.fd = 0, .filename = "0", .state = State::open, .source = {"default"}};
      fds[1] = {.fd = 1, .filename = "1", .state = State::open, .source = {"default"}};
      fds[2] = {.fd = 2, .filename = "2", .state = State::open, .source = {"default"}};
    }

    auto dump(auto const level, int const fd) const -> void
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

    auto get_path(int const fd) const -> std::filesystem::path
    {
      if (auto entry = fds.find(fd); entry != fds.end() && entry->second.state == State::open)
      {
        return entry->second.filename;
      }
      else
      {
        // ToDo cache invalid syscall?
        spdlog::warn("get_path of file descriptor {}", fd);
        dump(spdlog::level::warn);
        throw std::runtime_error("invalid get_path");
      }
    }

    auto open(int fd, std::string file, std::string source) -> void
    {
      FiledescriptorData new_entry = {
          .fd = fd,
          .filename = file,
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

    auto close(int fd, std::string source) -> void
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

  auto mmap_flag_to_string(int flags)
  {
    std::vector<std::string> s;
#define FLAG(x)      \
  if (flags & x)     \
  {                  \
    s.push_back(#x); \
    flags &= ~x;     \
  }
    FLAG(MAP_SHARED);
    FLAG(MAP_SHARED_VALIDATE);
    FLAG(MAP_PRIVATE);
    FLAG(MAP_32BIT);
    FLAG(MAP_ANONYMOUS);
    FLAG(MAP_DENYWRITE);
    FLAG(MAP_FIXED);
    FLAG(MAP_FIXED_NOREPLACE);
    FLAG(MAP_GROWSDOWN);
    FLAG(MAP_HUGETLB);
    FLAG(MAP_LOCKED);
    FLAG(MAP_NONBLOCK);
    FLAG(MAP_NORESERVE);
    FLAG(MAP_POPULATE);
    FLAG(MAP_STACK);
    FLAG(MAP_SYNC);
    if (flags)
      s.push_back(fmt::format("Remaining flags: {}", flags));

    return join(s, ", ");
  }

  auto cache_execution(std::string const program, std::vector<std::string> const arguments) -> Inputs
  {
    Ptrace::PtraceProcess p = Ptrace::createChildProcess(program, arguments);
    spdlog::debug("after createChildProcess");

    std::set ignore = {Syscall_brk::syscall_id, Syscall_arch_prctl::syscall_id};

    Inputs inputs;
    FiledescriptorManager fds;

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

      auto const syscall_str = syscall_to_string(p.get_pid(), *syscall);

      bool supported = false;

      if (contains(ignore, syscall->info.syscall_id))
      {
        supported = true;
      }
      else if (syscall->info.syscall_id == Syscall_access::syscall_id)
      {
        auto syscall_access = static_cast<Syscall_access>(syscall->arguments);
        std::string filename = Ptrace::PEEKTEXT_string(p.get_pid(), syscall_access.filename());
        inputs.actions.push_back(AccessAction{filename, syscall_access.mode(), syscall->return_value.value()});
        supported = true;
      }
      else if (syscall->info.syscall_id == Syscall_openat::syscall_id)
      {
        auto const syscall_openat = static_cast<Syscall_openat>(syscall->arguments);

        const std::filesystem::path path = Ptrace::PEEKTEXT_string(p.get_pid(), syscall_openat.filename());
        if (path.is_absolute())
        {
          int fd = syscall->return_value.value();
          inputs.actions.push_back(OpenAction{0, path, syscall_openat.flags(), syscall_openat.mode(), fd != -1, 0});
          fds.open(fd, path, syscall_str);
          supported = true;
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
        }
      }
      else if (syscall->info.syscall_id == Syscall_close::syscall_id)
      {
        auto const syscall_close = static_cast<Syscall_close>(syscall->arguments);
        fds.close(syscall_close.fd(), "close via " + syscall_str);
        supported = true;
      }
      else if (syscall->info.syscall_id == Syscall_newfstat::syscall_id)
      {
        // This is fstat, fo rsome reason called newfstat.
        // Using wrong field in parser?!
        auto const syscall_fstat = static_cast<Syscall_newfstat>(syscall->arguments);
        struct stat s;
        // ToDo: Ptrace::PEEKTEXT<struct stat>
        auto data = Ptrace::PEEKTEXT(p.get_pid(),
                                     reinterpret_cast<uint8_t *>(syscall_fstat.statbuf()),
                                     sizeof(struct stat));
        memcpy(&s, data.c_str(), sizeof(struct stat));

        auto path = fds.get_path(syscall_fstat.fd());

        FstatAction fstat{path, s, syscall->return_value.value() == 0, 0};
        inputs.actions.push_back(fstat);
        supported = true;
      }
      else if (syscall->info.syscall_id == Syscall_read::syscall_id)
      {
        auto const syscall_read = static_cast<Syscall_close>(syscall->arguments);
        // In theory only the actually read parts of the file...
        FileHash hash{fds.get_path(syscall_read.fd()), "ToDo"};
        inputs.actions.push_back(hash);
        supported = true;
      }
      else if (syscall->info.syscall_id == Syscall_pread64::syscall_id)
      {
        auto const syscall_read = static_cast<Syscall_pread64>(syscall->arguments);
        // In theory only the actually read parts of the file...
        FileHash hash{fds.get_path(syscall_read.fd()), "ToDo"};
        inputs.actions.push_back(hash);
        supported = true;
      }
      else if (syscall->info.syscall_id == Syscall_mmap::syscall_id)
      {
        auto const syscall_mmap = static_cast<Syscall_mmap>(syscall->arguments);
        if (syscall_mmap.fd() != 0 && syscall_mmap.prot() == PROT_READ)
        {
          FileHash hash{fds.get_path(syscall_mmap.fd()), "ToDo"};
          inputs.actions.push_back(hash);
          supported = true;
        }
        else
        {
          auto str = mmap_flag_to_string(syscall_mmap.flags());
          spdlog::warn("flags {} = {}", syscall_mmap.flags(), str);
        }
      }
      else if (syscall->info.syscall_id == Syscall_munmap::syscall_id)
      {
        auto const syscall_mmap = static_cast<Syscall_munmap>(syscall->arguments);
        // ToDo: keep mmap list...
      }
      if (!supported)
        spdlog::warn("Unsupported syscall {}", syscall_str);
      else
        spdlog::info("Supported syscall {}", syscall_str);
    }

    return inputs;
  }
}

int main(int argc, char **argv)
{
  absl::SetProgramUsageMessage(
      "General Purpose Cache will speed up repetitios retesting, just as ccache speeds up repetitions recompilations.\n"
      "Examplory usage:\n"
      "* gpcache --version\n"
      "* gpcache echo 'This will be cached'\n");

  std::vector<char *> params = absl::ParseCommandLine(argc, argv);
  std::cout << fmt::format("'Hello, World' called with:\n");
  for (auto param : params)
    std::cout << fmt::format("* {}\n", param);

  bool const verbose_flag = absl::GetFlag(FLAGS_verbose);
  if (verbose_flag)
    spdlog::set_level(spdlog::level::debug);
  else
    spdlog::set_level(spdlog::level::info);

  // later from args:
  try
  {
    auto inputs = gpcache::cache_execution("echo", {"huhu"});

    fmt::print("\n");
    for (auto &action : inputs.actions)
    {
      std::visit(
          [](auto &&cached_syscall) {
            fmt::print("Cached syscall: {}\n", cached_syscall);
          },
          action);
    }
  }
  catch (const char *error)
  {
    fmt::print("\nerror: {}\n\n", error);
  }
}
