#include "Posix.h"

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
#include "logging.h"

using gpcache::get_callstack;

static auto readable_ptrace_request(const enum __ptrace_request request) -> std::string
{
  switch (request)
  {
  case PTRACE_TRACEME:
    return "PTRACE_TRACEME";
  case PTRACE_SYSCALL:
    return "PTRACE_SYSCALL";
  case PTRACE_SETOPTIONS:
    return "PTRACE_SETOPTIONS";
  }
  return std::to_string(request);
}

static auto call_ptrace(const enum __ptrace_request request, const int pid, const auto addr, const auto data)
{
  /* TODO:
  On success, PTRACE_PEEK* requests return the requested data, while other requests return zero.
  On error, all requests return -1, and errno is set appropriately. Since the value returned by
  a successful PTRACE_PEEK* request may be -1, the caller must clear errno before the call, and
  then check it afterward to determine whether or not an error occurred.
  */
  errno = 0;
  const auto ret = ptrace(request, pid, addr, data);

  spdlog::debug("ptrace({}, {}, {}, {}) -> {}, {}", readable_ptrace_request(request), pid, addr, reinterpret_cast<void *>(data), ret, ::strerror(errno));

  if (ret == -1 || errno) // ToDo: improve detection. E.g. PEEKTEXT may return -1
  {
    throw fmt::format("ptrace({}, {}, {}, {}) failed: {}, {}", readable_ptrace_request(request), pid, addr, reinterpret_cast<void *>(data), ret, ::strerror(errno));
  }
  return ret;
}

namespace Posix
{
  auto waitpid(const int pid, const int options) -> StopReason
  {
    int status;

    spdlog::debug("before waitpid({}, -, {})", pid, options);
    ::waitpid(pid, &status, options);

    spdlog::debug("waitpid({}, {}, {})", pid, status, options);

    if (WIFEXITED(status))
      return {.state = StopReason::ProcessState::EXITED, .exit_status = WEXITSTATUS(status)};

    if (WIFSIGNALED(status))
      return {.state = StopReason::ProcessState::EXITED_BECAUSE_OF_SIGNAL, .signal_number = WTERMSIG(status)};

    if (WIFSTOPPED(status))
      return {.state = StopReason::ProcessState::STOPPED_BECAUSE_OF_SIGNAL, .signal_number = WSTOPSIG(status)};

    return {.state = StopReason::ProcessState::RUNNING};
  }

  namespace Ptrace
  {

    void CONT(const int pid)
    {
      call_ptrace(PTRACE_CONT, pid, nullptr, 0);
    }

    auto PEEKTEXT(const int pid, const uint8_t *const begin) -> long
    {
      return call_ptrace(PTRACE_PEEKTEXT, pid, begin, 0);
    }

    auto PEEKTEXT(const int pid, const uint8_t *const begin, const size_t count) -> std::string
    {
      gpcache::LogCallstack c("PEEKTEXT");
      std::string result;
      result.reserve(count);
      //result.resize(count);

      for (size_t pos_in_string = 0; pos_in_string < count; pos_in_string += sizeof(intptr_t))
      {
        const long data = PEEKTEXT(pid, begin + pos_in_string);
        std::memcpy(result.data() + pos_in_string, &data, std::max(count - pos_in_string, sizeof(intptr_t)));
      }

      return result;
    }

    auto GETREGS(const int pid) -> user_regs_struct
    {
      gpcache::LogCallstack c("GETREGS");
      user_regs_struct regs;
      call_ptrace(PTRACE_GETREGS, pid, 0, &regs);
      return regs;
    }

    auto TRACEME() -> void
    {
      gpcache::LogCallstack c("TRACEME");
      call_ptrace(PTRACE_TRACEME, 0, nullptr, 0);
    }

    auto SYSCALL(const int pid, const int signal) -> void
    {
      gpcache::LogCallstack c("SYSCALL");
      call_ptrace(PTRACE_SYSCALL, pid, nullptr, signal);
    }

    auto SETOPTIONS(const int pid, const int options) -> void
    {
      gpcache::LogCallstack c("SETOPTIONS");
      call_ptrace(PTRACE_SETOPTIONS, pid, nullptr, options);
    }
  } // namespace Ptrace
} // namespace PosixFunctions
