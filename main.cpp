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
#include "execute_action.h"
#include "utils/stacktrace.h"

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
            fmt::print("Cached syscall: {}\n", json(cached_syscall).dump());
          },
          action);
    }
  }
}

int main(int argc, char **argv)
{
  std::set_terminate(gpcache::terminate_with_stacktrace);

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

  if (params.empty())
  {
    fmt::print("Pass your executable to gpcache, e.g. gpcache echo 'Hello, World!'\n");
    exit(1);
  }

  // later from args:
  std::vector<std::string> sloppiness;
  sloppiness.push_back("time of fstat 1");

  try
  {
    auto backend = gpcache::FileBasedBackend(std::filesystem::path(".gpcache"));

    // ToDo: add cwd tec
    json const params_json = {
        {"params", params}};

    auto cached = backend.retrieve(backend.cache_path, params_json);
    if (!cached.path.empty())
    {
      spdlog::info("Cached! Next action is {}", cached.next_action.dump());
      auto result = gpcache::execute_action(cached.next_action);
      auto cached2 = backend.retrieve(cached.path, result);
    }

    // ToDo: move/hide to where the syscalls happen
    params.push_back(nullptr); // required for syscalls so end of array can be detected.

    auto [inputs, outputs] = gpcache::execute_program(params);
    //gpcache::print_inputs(inputs);

    backend.store(params_json, inputs, outputs, sloppiness);
  }
  catch (const char *error)
  {
    fmt::print("\nerror: {}\n\n", error);
    gpcache::terminate_with_stacktrace();
  }

  // todo proper return code
  return 0;
}
