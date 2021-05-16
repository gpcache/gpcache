#include "PtraceProcess.h"
#include "syscall_decoder.h"
#include "utils/enumerate.h"
#include "utils/join.h"
#include <asm/prctl.h>
#include <sys/prctl.h>
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "catch2/catch.hpp"
#include "spdlog/pattern_formatter.h"
#include "SyscallWrappers.h"
#include "SyscallMap.h"
#include "wrapper/Posix.h"
#include "utils/Utils.h"
#include <any>
#include <variant>
#include <spdlog/spdlog.h>

using namespace gpcache;

TEST_CASE("Starting Sub Process", "test2")
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
