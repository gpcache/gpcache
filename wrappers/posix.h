#pragma once

#include <optional>
#include <vector>

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
  [[nodiscard]] auto wait_for_signal2(int pid, std::vector<int> signum_to_wait_for) -> bool;
}
