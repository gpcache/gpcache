#include "posix.h"

#include <spdlog/spdlog.h>

namespace posix
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
}
