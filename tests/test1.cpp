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
      // ToDo: use some clever algorithm... but how? in combination with enumerate! Probably only with the real views::enumerate
      const std::string params = [&]() {
        std::string params = "";
        for (auto [pos, param] : enumerate(syscall.syscall_info.params))
        {
          if (!params.empty())
            params += ", ";
          params += fmt::format("{} {} = {}", param.type, param.name, syscall.syscall_arguments[pos]);
        }
        return params;
      }();

      spdlog::info("Child has executed a syscall {}({}) -> {}", syscall.syscall_info.name, params, syscall.return_value.value());
    }
  }
  // expected: brk(0) -> returns "the new program break on success.  On failure, the system call returns the current break."
  //                     = Different value on every execution?!
}
