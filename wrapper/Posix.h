#pragma once

#include <optional>
#include <string>

#include <sys/user.h> // user_regs_struct

/// Other than language change (e.g. using return values), this is unmodified posix.
namespace Posix
{
  struct StopReason
  {
    enum class ProcessState
    {
      RUNNING,
      STOPPED_BECAUSE_OF_SIGNAL,
      EXITED,
      EXITED_BECAUSE_OF_SIGNAL,
    };
    ProcessState state;
    std::optional<int> signal_number;
    std::optional<int> exit_status;
  };
  auto waitpid(int pid, int options) -> StopReason;

  // ptrace is more than a simple function, each possible parameter has a separate wrapper.
  namespace Ptrace
  {
    auto CONT(int pid) -> void;
    auto PEEKTEXT(int pid, const uint8_t *const begin) -> long;
    auto PEEKTEXT(int pid, const uint8_t *const begin, size_t count) -> std::string;
    auto PEEKTEXT_string(int pid, char const *begin) -> std::string;
    auto GETREGS(int pid) -> user_regs_struct;
    auto TRACEME() -> void;
    auto SETOPTIONS(int pid, int options) -> void;

    /// Restart the stopped tracee and arrange for the tracee to be stopped at the next entry to or exit from a system call.
    auto SYSCALL(int pid, int signal = 0) -> void;
  };
}
