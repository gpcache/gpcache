#include "PtraceProcess.h"
#include "wrapper/Posix.h"

#include <csignal>
#include <functional>
#include <unistd.h> // fork
#include <ranges>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <spdlog/spdlog.h>

#include "utils/Utils.h"

namespace gpcache
{
  static auto create_signal_mask_with_one_signal(const int signum)
  {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, signum);
    return mask;
  }

  static thread_local int global_signum_to_wait_for = 0;
  static thread_local bool global_signal_arrived = false;

  // Note: this will pause all other signal handlers while waiting
  // Alternative design: setup global signal handler. Probably the code will look better than.
  [[deprecated("Use wait_for_signal2")]] static auto wait_for_signal(const int signum_to_wait_for, auto call_once_ready)
  {
    // Setup receiving of signal:
    global_signum_to_wait_for = signum_to_wait_for;

    const auto old_signal_handler = std::signal(SIGINT, [](const int signum) {
      if (signum == global_signum_to_wait_for)
        global_signal_arrived = true;
    });

    if (old_signal_handler == SIG_ERR)
      throw "Setting signal handler failed";

    // Prepare waiting for signal:
    auto mask_for_signal = create_signal_mask_with_one_signal(signum_to_wait_for);

    // We are ready to receive signal, now call whatever will trigger it.
    call_once_ready();

    // Here the actual waiting happens (sigsuspend)
    sigset_t oldmask;
    sigprocmask(SIG_BLOCK, &mask_for_signal, &oldmask);
    while (!global_signal_arrived)
      sigsuspend(&oldmask);
    sigprocmask(SIG_UNBLOCK, &mask_for_signal, NULL);

    // Restore real signal handling
    std::signal(SIGINT, old_signal_handler);
  }

  /// @returns false if process has already exited
  [[nodiscard]] static auto wait_for_signal2(const int pid, const std::vector<int> signum_to_wait_for) -> bool
  {
    spdlog::debug("before waitpid");
    const auto status = Posix::waitpid(pid, 0);
    spdlog::debug("after waitpid"); // todo trace status

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
      if (!contains(signum_to_wait_for, status.signal_number))
        throw fmt::format("Child is stopped for other signal: {}", status.signal_number.value());
      // fallthrough
    }

    return true;
  }

  auto PtraceProcess::restart_child_and_wait_for_next_syscall() -> std::optional<SysCall>
  {
    spdlog::debug("restart_child_and_wait_for_next_syscall");
    Posix::Ptrace::SYSCALL(pid);
    auto still_running = wait_for_signal2(pid, {SIGTRAP | 0x80});
    if (!still_running)
      return {};

    auto regs = Posix::Ptrace::GETREGS(pid);

    const auto syscall_id = get_syscall_number_from_registers(regs);
    const static auto syscall_map = create_syscall_map();
    const auto syscall_info = syscall_map.at(syscall_id);
    const auto return_value = [&]() -> std::optional<SyscallDataType> {
      if (next_call == EnterExit::exit)
      {
        next_call = EnterExit::enter;
        return std::make_optional(get_syscall_return_value_from_registers(regs));
      }
      else
      {
        next_call = EnterExit::exit;
        return std::nullopt;
      }
    }();
    const auto syscall_arguments = get_syscall_args(regs);

    return SysCall{syscall_id, syscall_info, return_value, syscall_arguments};
  }

  [[nodiscard]] auto createChildProcess(const std::string program, const std::vector<std::string> arguments) -> int
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
      Posix::Ptrace::SETOPTIONS(pid, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE);

      return pid;
    }
    else if (pid == 0)
    {
      // Child
      spdlog::set_pattern("[%H:%M:%S %z] [%n]   [%^---%L---%$] [thread %t] %v");
      spdlog::debug("this is the child process");

      // Stpo at next syscall
      Posix::Ptrace::TRACEME();

      const std::vector<char *>
          charPtrArguments = [&program, &arguments]() {
            std::vector<char *> v;
            v.reserve(arguments.size() + 2);
            v.push_back(const_cast<char *>(program.c_str()));
            for (auto arg : arguments)
              v.push_back(const_cast<char *>(arg.c_str()));
            v.push_back(nullptr);
            return v;
          }();
      spdlog::debug("calling {}", program);
      execvp(program.c_str(), &charPtrArguments[0]); // noreturn
      spdlog::error("after calling {}", program);
      throw("this should never ever be reached");
    }
    else
    {
      throw "Forking failed";
    }
  }

}
