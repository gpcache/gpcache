#include <iostream>
#include <fmt/format.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/time/time.h"
#include "PtraceProcess.h"
#include "syscall_decoder.h"
#include "utils/enumerate.h"
#include "utils/join.h"
#include <asm/prctl.h>
#include <sys/prctl.h>
#include "spdlog/pattern_formatter.h"
#include "SyscallWrappers.h"
#include "SyscallMap.h"
#include "wrapper/Posix.h"
#include <any>
#include <variant>
#include "utils/Utils.h"
#include <spdlog/spdlog.h>

ABSL_FLAG(bool, verbose, false, "Add verbose output");
ABSL_FLAG(std::string, cache_dir, "~/.gpcache", "cache dir");

namespace gpcache
{
  auto cache_execution()
  {
    // true has probably the smallest possible amount of syscalls.
    PtraceProcess p = createChildProcess("true", {});
    spdlog::debug("after createChildProcess");

    std::vector ignore = {Syscall_brk::syscall_id, Syscall_arch_prctl::syscall_id};

    while (true)
    {
      SysCall syscall = p.restart_child_and_wait_for_next_syscall();
      if (syscall.return_value)
      {
        Syscall_Args syscall_args{syscall.syscall_arguments[0],
                                  syscall.syscall_arguments[1],
                                  syscall.syscall_arguments[2],
                                  syscall.syscall_arguments[3],
                                  syscall.syscall_arguments[4],
                                  syscall.syscall_arguments[5],
                                  syscall.return_value.value()};

        if (!contains(ignore, syscall.syscall_id))
        {
          fmt::print("Unsupported syscall {}", syscall_to_string(p.get_pid(), syscall));

          switch (syscall.syscall_id)
          {
          case Syscall_access::syscall_id:
          {
            auto syscall_access = static_cast<Syscall_access>(syscall_args);
            std::string filename = Posix::Ptrace::PEEKTEXT_string(p.get_pid(), syscall_access.filename());
            fmt::print("filename: {}\n", filename);
            break;
          }

          default:
            break;
          }
        }
      }
    }
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
}
