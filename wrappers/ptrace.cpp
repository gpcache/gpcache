#include "ptrace.h"

#include <unistd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fmt/format.h>
#include <bit>
#include <ranges>

#include <spdlog/spdlog.h>

#include "posix.h"

namespace
{
  // Code from https://stackoverflow.com/questions/58320316/stdbit-cast-with-stdarray
  // Need from https://en.cppreference.com/w/cpp/compiler_support
  // ToDo: move to Utils?
  template <class Dest, class Source>
  Dest bit_cast(Source const &source)
  {
    static_assert(sizeof(Dest) == sizeof(Source));
    static_assert(std::is_trivially_copyable<Dest>::value);
    static_assert(std::is_trivially_copyable<Source>::value);

    Dest dest;
    std::memcpy(&dest, &source, sizeof(dest));
    return dest;
  }

  auto readable_ptrace_request(const enum __ptrace_request request) -> std::string
  {
    switch (request)
    {
    case PTRACE_TRACEME:
      return "PTRACE_TRACEME";
    case PTRACE_SYSCALL:
      return "PTRACE_SYSCALL";
    case PTRACE_SETOPTIONS:
      return "PTRACE_SETOPTIONS";
    default:
      return std::to_string(request);
    }
  }

  auto call_ptrace(const enum __ptrace_request request, const int pid, const auto addr, const auto data)
  {
    /* TODO:
  On success, PTRACE_PEEK* requests return the requested data, while other requests return zero.
  On error, all requests return -1, and errno is set appropriately. Since the value returned by
  a successful PTRACE_PEEK* request may be -1, the caller must clear errno before the call, and
  then check it afterward to determine whether or not an error occurred.
  */
    errno = 0;
    // ToDo: explain_ptrace_or_die
    const auto ret = ptrace(request, pid, addr, data);

    if constexpr (false)
    {
      // wow this is terrible
      if constexpr (std::is_pointer_v<decltype(addr)>)
        if constexpr (std::is_pointer_v<decltype(data)>)
          spdlog::debug("ptrace({}, {}, {}, {}) -> {}, {}", readable_ptrace_request(request), pid, reinterpret_cast<void const *>(addr), reinterpret_cast<void *>(data), ret, ::strerror(errno));
        else
          spdlog::debug("ptrace({}, {}, {}, {}) -> {}, {}", readable_ptrace_request(request), pid, reinterpret_cast<void const *>(addr), data, ret, ::strerror(errno));
      else if constexpr (std::is_pointer_v<decltype(data)>)
        spdlog::debug("ptrace({}, {}, {}, {}) -> {}, {}", readable_ptrace_request(request), pid, addr, reinterpret_cast<void *>(data), ret, ::strerror(errno));
      else
        spdlog::debug("ptrace({}, {}, {}, {}) -> {}, {}", readable_ptrace_request(request), pid, addr, data, ret, ::strerror(errno));
    }

    if (ret == -1 || errno) // ToDo: improve detection. E.g. PEEKTEXT may return -1
    {
      throw fmt::format("ptrace({}, {}, {}, {}) failed: {}, {}", readable_ptrace_request(request), pid, addr, reinterpret_cast<void *>(data), ret, ::strerror(errno));
    }
    return ret;
  }
}

namespace Ptrace
{
  namespace Raw
  {
    void CONT(const int pid)
    {
      call_ptrace(PTRACE_CONT, pid, nullptr, 0);
    }

    auto PEEKTEXT(const int pid, const uint8_t *const begin) -> long
    {
      return call_ptrace(PTRACE_PEEKTEXT, pid, begin, 0);
    }

    auto GETREGS(const int pid) -> user_regs_struct
    {
      user_regs_struct regs;
      call_ptrace(PTRACE_GETREGS, pid, 0, &regs);
      return regs;
    }

    auto TRACEME() -> void
    {
      call_ptrace(PTRACE_TRACEME, 0, nullptr, 0);
    }

    auto SYSCALL(const int pid, const int signal) -> void
    {
      call_ptrace(PTRACE_SYSCALL, pid, nullptr, signal);
    }

    auto SETOPTIONS(const int pid, const int options) -> void
    {
      call_ptrace(PTRACE_SETOPTIONS, pid, nullptr, options);
    }
  }

  auto PEEKTEXT(const int pid, const char *const begin, const size_t count) -> std::string
  {
    std::string result; // vector?
    result.reserve(count);

    for (size_t pos_in_string = 0; pos_in_string < count; pos_in_string += sizeof(intptr_t))
    {
      long const data = Raw::PEEKTEXT(pid, reinterpret_cast<uint8_t const *>(begin) + pos_in_string);
      std::memcpy(result.data() + pos_in_string,
                  &data,
                  std::min(count - pos_in_string, sizeof(intptr_t)));
    }

    return result;
  }

  auto PEEKTEXT_string(int const pid, char const *const begin) -> std::string
  {
    std::string result;

    constexpr auto maximum = 1024 * 1024;
    bool end_of_string = false;
    for (size_t pos_in_string = 0; pos_in_string < maximum && !end_of_string; pos_in_string += sizeof(intptr_t))
    {
      const long data = Raw::PEEKTEXT(pid, reinterpret_cast<uint8_t const *>(begin) + pos_in_string);
      auto chars = bit_cast<std::array<char, sizeof(data)>>(data);
      for (const char c : chars)
      {
        result += c;
        if (c == '\0')
        {
          end_of_string = true;
          break;
        }
      }
    }

    return result;
  }

  static auto create_signal_mask_with_one_signal(const int signum)
  {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, signum);
    return mask;
  }

  static thread_local int global_signum_to_wait_for = 0;
  static thread_local bool global_signal_arrived = false;

  auto PtraceProcess::restart_child_and_wait_for_next_syscall() -> std::optional<SysCall>
  {
    Raw::SYSCALL(pid);
    auto still_running = Posix::wait_for_signal2(pid, {SIGTRAP | 0x80});
    if (!still_running)
      return {};

    auto regs = Raw::GETREGS(pid);

    const auto syscall_id = get_syscall_number_from_registers(regs);
    const static auto syscall_map = create_syscall_map();
    const auto syscall_info = syscall_map.at(syscall_id);
    const auto return_value = [&]() -> std::optional<SyscallDataType>
    {
      auto const val = get_syscall_return_value_from_registers(regs);

      // entering syscall?
      if (-val == ENOSYS)
      {
        return std::nullopt;
      }
      else
      {
        return std::make_optional(get_syscall_return_value_from_registers(regs));
      }
    }();
    const auto syscall_arguments = get_syscall_args(regs);

    return SysCall{pid, syscall_info, syscall_arguments, return_value};
  }

  [[nodiscard]] auto createChildProcess(std::vector<char *> const &prog_and_arguments) -> int
  {
    const pid_t pid = fork();
    spdlog::debug("fork() -> {}", pid);

    if (pid > 0)
    {
      // That's "us"
      spdlog::debug("main process, creating PtraceProcess({})...", pid);
      //wait_for_signal2(pid, {SIGTRAP, SIGSTOP});
      wait(NULL);
      spdlog::debug("main process, after wait");
      Raw::SETOPTIONS(pid, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE);

      return pid;
    }
    else if (pid == 0)
    {
      // Child
      spdlog::set_pattern("[%H:%M:%S %z] [%n]   [%^---%L---%$] [thread %t] %v");
      spdlog::debug("this is the child process");

      // Stpo at next syscall
      Raw::TRACEME();

      assert(prog_and_arguments.back() == nullptr);
      spdlog::debug("calling {}", prog_and_arguments[0]);
      execvp(prog_and_arguments[0], prog_and_arguments.data()); // noreturn
      spdlog::error("after calling {}", prog_and_arguments[0]);
      throw("this should never ever be reached");
    }
    else
    {
      throw "Forking failed";
    }
  }

  // Return type is system dependent.
  auto get_syscall_number_from_registers(const user_regs_struct &regs) -> SyscallDataType
  {
#if __x86_64__
    return regs.orig_rax;
#else
#error "Unsupported CPU architecture"
#endif
  }

  auto get_syscall_return_value_from_registers(const user_regs_struct &regs) -> SyscallDataType
  {
#if __x86_64__
    return regs.rax;
#else
#error "Unsupported CPU architecture"
#endif
  }

  auto get_syscall_args(const user_regs_struct &regs) -> std::array<SyscallDataType, 6>
  {
#if __x86_64__
    return {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};
#else
#error "Unsupported CPU architecture"
#endif
  }

} // namespace Ptrace
