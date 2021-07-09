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

  // unless we set up some in-place replacement logic like ccache just drop the first parameter
  params.erase(params.begin(), params.begin() + 1);

  spdlog::set_level(absl::GetFlag(FLAGS_verbose) ? spdlog::level::debug : spdlog::level::info);

  spdlog::debug("gpcache called with:");
  for (auto param : params)
    spdlog::debug("* {}", param);
  spdlog::debug("--------------------");

  params.push_back(nullptr); // required for syscalls so end of array can be detected.

  if (params[0] == nullptr)
  {
    fmt::print("Pass your executable to gpcache, e.g. gpcache echo 'Hello, World!'\n");
    exit(1);
  }

  // later from args:
  try
  {
    auto [inputs, outputs] = gpcache::cache_execution(params);
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
