#include "PtraceProcess.h"
#include "wrapper/Strace.h"

#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "catch2/catch.hpp"
#include "spdlog/spdlog.h"

using namespace gpcache;

TEST_CASE("Starting Sub Process", "a")
{
  spdlog::set_level(spdlog::level::debug);
  spdlog::set_pattern("[%H:%M:%S %z] [%n] [%^---%L---%$] [thread %t] %v");

  PtraceProcess p = createChildProcess("echo", {"Hello, World!"});
  spdlog::info("after createChildProcess");
  SysCall syscall = p.restart_child_and_wait_for_next_syscall();
  spdlog::info("Child has executed a syscall: {}", syscall.syscall_info.name);

  auto llistxattr_attributes = {const char *, char *, size_t};
}
