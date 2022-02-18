#include "posix.h"

#include "utils/Utils.h" // contains

#include <spdlog/spdlog.h>

#include <sys/types.h>
#include <sys/wait.h>

namespace Posix
{
auto waitpid(const int pid, const int options) -> StopReason
{
    int status;

    // spdlog::debug("before waitpid({}, -, {})", pid, options);
    ::waitpid(pid, &status, options);

    // spdlog::debug("waitpid({}, {}, {})", pid, status, options);

    if (WIFEXITED(status))
        return {.state = StopReason::ProcessState::EXITED, .signal_number = {}, .exit_status = WEXITSTATUS(status)};

    if (WIFSIGNALED(status))
        return {.state = StopReason::ProcessState::EXITED_BECAUSE_OF_SIGNAL, .signal_number = WTERMSIG(status)};

    if (WIFSTOPPED(status))
        return {.state = StopReason::ProcessState::STOPPED_BECAUSE_OF_SIGNAL, .signal_number = WSTOPSIG(status)};

    return {.state = StopReason::ProcessState::RUNNING};
}

/// @returns false if process has already exited
auto wait_for_signal2(int const pid, std::vector<int> const signum_to_wait_for) -> bool
{
    // spdlog::debug("before waitpid");
    const auto status = Posix::waitpid(pid, 0);
    // spdlog::debug("after waitpid"); // todo trace status

    using Posix::StopReason;

    switch (status.state)
    {
    case StopReason::ProcessState::RUNNING:
        throw "Child is running";
    case StopReason::ProcessState::EXITED:
        return false;
    case StopReason::ProcessState::EXITED_BECAUSE_OF_SIGNAL:
        throw "Child has already exited because of signal";
    case StopReason::ProcessState::STOPPED_BECAUSE_OF_SIGNAL:
        if (!gpcache::contains(signum_to_wait_for, status.signal_number))
            throw fmt::format("Child is stopped for other signal: {}", status.signal_number.value());
        // fallthrough
    }

    return true;
}

} // namespace Posix
