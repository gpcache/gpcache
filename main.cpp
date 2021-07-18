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
#include <sys/mman.h> // mmap PROT_READ
#include "wrappers/hash.h"
#include "backend/file.h"
#include "execution.h"
#include "execute_cached_syscall.h"
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

auto json_action_to_string(const json &action)
{
  // FIXME: rename 'action' to 'parameters'
  return action.at("input").get<std::string>() + action.at("action").dump();
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
    if (cached.ok())
    {
      // Program was executed before! Now start iterating.
      spdlog::info("Great, {} is cached. Now let's check all dependencies...", json(params).dump());

      while (cached.next_syscall)
      {
        auto execution_result = gpcache::execute_cached_syscall(cached.next_syscall.value());
        spdlog::info("Cached {} -> Real {}", json_action_to_string(cached.next_syscall.value()), execution_result.dump());

        // FIXME: retrieve should not assume that the next thing is an action.
        //        Instead here write something like backend.get_action(path) -> optional (same as get_output)
        auto new_cached = backend.retrieve(cached.path, execution_result);

        auto all_results = backend.get_all_possible_results(cached.path);
        if (new_cached.ok())
        {
          spdlog::info("Cached!");
          for (auto const &possible_result : all_results)
            if (possible_result != execution_result)
              spdlog::info("other cached results: {}", possible_result.dump());
        }
        else
        {
          spdlog::info("This is new! Will have to actually run the executable :-(");
          for (auto const &possible_result : backend.get_all_possible_results(cached.path))
            spdlog::info("Cached results would have been: {}", possible_result.dump());
        }

        cached = new_cached;
      }
    }

    // ToDo: move/hide to where the syscalls happen
    params.push_back(nullptr); // required for syscalls so end of array can be detected.

    std::vector<gpcache::CachedSyscall> execution_cache = gpcache::execute_program(params);
    //gpcache::print_inputs(inputs);

    backend.store(params_json, execution_cache, sloppiness);
  }
  catch (const char *error)
  {
    fmt::print("\nerror: {}\n\n", error);
    gpcache::terminate_with_stacktrace();
  }

  // todo proper return code
  return 0;
}
