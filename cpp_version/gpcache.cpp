// ToDo: cleanup includes
#include <iostream>
#include <fmt/format.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/time/time.h"
#include "utils/enumerate.h"
#include "utils/join.h"
#include <asm/prctl.h>
#include <sys/prctl.h>
#include "spdlog/pattern_formatter.h"
#include "wrappers/hash.h"
#include "wrappers/posix.h"
#include "wrappers/ptrace.h"
#include "wrappers/ptrace/SyscallWrappers.h"
#include <any>
#include <variant>
#include <set>
#include "utils/Utils.h"
#include <spdlog/spdlog.h>
#include "inputs.h"
#include "outputs.h"
#include <sys/mman.h> // mmap PROT_READ
#include "wrappers/hash.h"
#include "backend/file.h"
#include "execution.h"

ABSL_FLAG(bool, verbose, false, "Add verbose output");
ABSL_FLAG(std::string, cache_dir, "~/.gpcache", "cache dir");
ABSL_FLAG(std::string, sloppy, "", "sloppiness");

namespace gpcache
{
  void print_inputs(auto inputs)
  {
    fmt::print("\n");
    for (auto &action : inputs.actions)
    {
      std::visit(
          [](auto &&cached_syscall)
          {
            fmt::print("Cached syscall: {}\n", json{cached_syscall}.dump());
          },
          action);
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

  if (absl::GetFlag(FLAGS_verbose))
    spdlog::set_level(spdlog::level::debug);
  else
    spdlog::set_level(spdlog::level::info);

  // later from args:
  try
  {
    auto [inputs, outputs] = gpcache::cache_execution("true", {});
    gpcache::print_inputs(inputs);
    auto backend = gpcache::FileBasedBackend();

    backend.store(inputs, outputs);
  }
  catch (const char *error)
  {
    fmt::print("\nerror: {}\n\n", error);
  }

  // todo proper return code
  return 0;
}
