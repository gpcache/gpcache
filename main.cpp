// ToDo: cleanup includes
#include "backends/file.h"

#include "main/cache_executed_syscall.h"
#include "main/execute_cached_syscall.h"
#include "main/inputs.h"

#include "wrappers/hash.h"
#include "wrappers/posix.h"
#include "wrappers/ptrace.h"
#include "wrappers/ptrace/SyscallWrappers.h"

#include "utils/Utils.h"
#include "utils/enumerate.h"
#include "utils/join.h"
#include "utils/stacktrace.h"

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/time/time.h"
#include "spdlog/pattern_formatter.h"
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <any>
#include <asm/prctl.h>
#include <iostream>
#include <set>
#include <sys/mman.h> // mmap PROT_READ
#include <sys/prctl.h>
#include <variant>

ABSL_FLAG(bool, verbose, false, "Add verbose output");
ABSL_FLAG(std::string, cache_dir, "~/.gpcache", "cache dir");
ABSL_FLAG(std::string, sloppy, "", "sloppiness");

auto json_cached_syscall_to_string(const json &cached_syscall)
{
    return cached_syscall.at("syscall_name").get<std::string>() + cached_syscall.at("parameters").dump();
}

auto set_terminate_handler()
{
    std::set_terminate(gpcache::terminate_with_stacktrace);
}

struct Config
{
    bool verbose;
    std::vector<char *> params;
};

auto parse_command_line(int argc, char **argv)
{
    absl::SetProgramUsageMessage("General Purpose Cache will speed up repetitios retesting, just as "
                                 "ccache speeds up repetitions recompilations.\n"
                                 "Examplory usage:\n"
                                 "* gpcache --version\n"
                                 "* gpcache echo 'This will be cached'\n");

    Config config;
    absl::ParseCommandLine(argc, argv);
    config.verbose = absl::GetFlag(FLAGS_verbose);
    config.params = std::vector<char *>(argv + 1, argv + argc);
    return config;
}

auto dump_command_line(std::vector<char *> params)
{
    spdlog::debug("gpcache called with:");
    for (auto param : params)
        spdlog::debug("* {}", param);
    spdlog::debug("--------------------");
}

// ToDo: proper return type... exit code? What is the return type??
auto retrieve_from_cache(auto backend, auto params) -> std::optional<std::string>
{
    // ToDo: add current user, cwd and whatever else is important
    json const cache_uid = {{"params", params}};

    auto cached = backend.retrieve_by_uid(cache_uid);
    if (cached)
    {
        // Program was executed before! Now start iterating.
        spdlog::info("Great, {} was executed before. Checking whether cached behavior is still valid...",
                     json(params).dump());
        gpcache::State state;

        while (cached && cached.next_syscall)
        {
            // Actually run the syscall, e.g. read some file.
            auto const execution_result = gpcache::execute_cached_json_syscall(state, cached.next_syscall.value());

            // Retrieve cache entry which matches the execution result, e.g. same file content.
            auto const next_cache_entry = backend.retrieve_by_dependency(cached.path, execution_result);

            if (next_cache_entry)
            {
                spdlog::info("Cached {} -> Real {} -> Cache Hit",
                             json_cached_syscall_to_string(cached.next_syscall.value()), execution_result.dump());
            }
            else
            {
                spdlog::warn("Cached {} -> Real {} -> Cache MISS",
                             json_cached_syscall_to_string(cached.next_syscall.value()), execution_result.dump());
                for (auto const &possible_result : backend.get_all_possible_results(cached.path))
                    spdlog::warn("Cached results would have been: {}", possible_result.dump());
            }

            cached = next_cache_entry;
        }
    }

    return cached;
}

auto startup(int argc, char **argv) -> Config
{
    set_terminate_handler();

    Config const config = parse_command_line(argc, argv);

    spdlog::set_level(config.verbose ? spdlog::level::debug : spdlog::level::info);

    dump_command_line(config.params);

    if (config.params.empty())
    {
        fmt::print("Pass your executable to gpcache, e.g. gpcache echo 'Hello, World!'\n");
        exit(1);
    }

    return config;
}

int main(int argc, char **argv)
{
    try
    {
        auto const config = startup(argc, argv);

        // later from args:
        std::vector<std::string> sloppiness;
        sloppiness.push_back("time of fstat 1");

        // use file based backend for now
        auto backend = gpcache::FileBasedBackend{std::filesystem::path(".gpcache")};

        auto const cached = retrieve_from_cache(backend, config.params);

        if (!cached)
        {
            // ToDo: move/hide to where the syscalls happen
            config.push_back(nullptr); // required for syscalls so end of array can be detected.

            std::vector<gpcache::CachedSyscall> execution_cache = gpcache::execute_program(config);

            backend.store(cache_uid, execution_cache, sloppiness);
        }
    }
    catch (const char *error)
    {
        fmt::print("\nerror: {}\n\n", error);
        gpcache::terminate_with_stacktrace();
    }

    // todo proper return code
    return 0;
}
