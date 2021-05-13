#include "PtraceProcess.h"
#include "syscall_decoder.h"
#include "enumerate.h"
#include "join.h"
#include <asm/prctl.h>
#include <sys/prctl.h>
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "catch2/catch.hpp"
#include "logging.h"
#include "spdlog/pattern_formatter.h"
#include "SyscallEventCreator.h"

using namespace gpcache;

class my_formatter_flag : public spdlog::custom_flag_formatter
{
public:
  void format(const spdlog::details::log_msg &, const std::tm &, spdlog::memory_buf_t &dest) override
  {
    std::string some_txt = get_callstack();
    dest.append(some_txt.data(), some_txt.data() + some_txt.size());
  }

  std::unique_ptr<custom_flag_formatter> clone() const override
  {
    return spdlog::details::make_unique<my_formatter_flag>();
  }
};

// helper type for the visitor #4
template <class... Ts>
struct overloaded : Ts...
{
  using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

TEST_CASE("Starting Sub Process", "test1")
{
  LogCallstack("test1");
  //spdlog::set_level(spdlog::level::debug);

  auto formatter = std::make_unique<spdlog::pattern_formatter>();
  formatter->add_flag<my_formatter_flag>('*').set_pattern("[%H:%M:%S %z] [%n] [%^---%L---%$] [thread %t] [%*] %v");
  spdlog::set_formatter(std::move(formatter));

  // true has probably the smallest possible amount of syscalls.
  PtraceProcess p = createChildProcess("true", {});
  spdlog::debug("after createChildProcess");

  while (true)
  {
    SysCall syscall = p.restart_child_and_wait_for_next_syscall();
    if (syscall.return_value)
    {
      auto event = createEvent(syscall.syscall_id,
                               syscall.syscall_arguments[0],
                               syscall.syscall_arguments[1],
                               syscall.syscall_arguments[2],
                               syscall.syscall_arguments[3],
                               syscall.syscall_arguments[4],
                               syscall.syscall_arguments[5]);

      std::visit(overloaded{
                     [](auto arg) { std::cout << "Unsupported syscall " << arg.syscall_id << ' ' << std::endl; },
                     [](const Event_brk &brk) { std::cout << "brk: " << brk.brk << " --> " << brk.return_value << std::endl; },
                 },
                 event);
    }
  }
  // expected: brk(0) -> returns "the new program break on success.  On failure, the system call returns the current break."
  //                     = Different value on every execution?!
}
