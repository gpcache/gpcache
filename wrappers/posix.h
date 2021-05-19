#pragma once

#include <optional>

namespace posix
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

}
