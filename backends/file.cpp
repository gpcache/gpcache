#include "file.h"

#include "wrappers/hash.h"

#include "utils/Utils.h"
#include "utils/enumerate.h"

#include <spdlog/spdlog.h>

#include <cerrno>
#include <fstream>
#include <string>

namespace gpcache
{
// Is there some reasonable C++ convinience library that provides such
// functions?
static auto read_file(const std::filesystem::path &path) -> std::variant<std::string, int>
{
    // todo: exact effect of binary
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in)
    {
        return errno;
    }
    else
    {
        std::string content;
        in.seekg(0, std::ios::end);
        content.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(&content[0], content.size());
        in.close();
        return content;
    }
}

static auto read_file_to_json(const std::filesystem::path &path) -> std::variant<json, int>
{
    auto res = read_file(path);
    if (std::string const *const str = std::get_if<std::string>(&res))
    {
        // todo: handle parser errors
        return json::parse(*str);
    }
    return std::get<int>(res);
}

// Is there some reasonable C++ convinience library that provides such
// functions?
static auto write_file(const std::filesystem::path &path, const std::string &content) -> std::variant<bool, int>
{
    // todo: exact effect of binary
    std::ofstream out(path, std::ios::out | std::ios::binary);
    if (!out)
    {
        return errno;
    }
    else
    {
        out.write(&content[0], content.size());
        out.close();
        return out.good();
    }
}

struct is_file_content_result
{
    std::optional<std::string> old_file_content;
    std::optional<int> error;

    bool ok()
    {
        return !old_file_content && !error;
    }
};

static auto is_file_content(const std::filesystem::path &file, const std::string &content) -> is_file_content_result
{
    auto const res = read_file(file);
    if (std::holds_alternative<std::string>(res))
    {
        const std::string existing_file_content = std::get<std::string>(res);

        if (existing_file_content == content)
            return {};
        else
            return {.old_file_content = existing_file_content, .error = {}};
    }
    return {.old_file_content = {}, .error = std::get<int>(res)};
}

struct ensure_file_content_error
{
    std::optional<std::string> old_file_content;
    std::optional<int> error;

    bool ok()
    {
        return !old_file_content && !error;
    }
};

static auto ensure_file_content(const std::filesystem::path &file, const std::string &content)
    -> ensure_file_content_error
{
    // use is_file_content ?!
    if (std::filesystem::exists(file))
    {
        auto res = read_file(file);
        if (std::holds_alternative<std::string>(res))
        {
            const std::string existing_file_content = std::get<std::string>(res);

            if (existing_file_content != content)
            {
                // store as action2.json, action3.json etc to facilitate good error
                // messages Todo: different behavior of program vs inussificient hashing
                // (hash length)
                spdlog::warn("file content mismatch");
                spdlog::debug(existing_file_content);
                spdlog::debug(content);
                return {.old_file_content = existing_file_content, .error = {}};
            }
            else
            {
                return {};
            }
        }
        else
        {
            auto const existing_file_error = std::get<int>(res);
            spdlog::warn("Cannot read cached file {} because of {}", file.string(), existing_file_error);
            // attempt to create it?
            return {.old_file_content = {}, .error = existing_file_error};
        }
    }
    else
    {
        std::filesystem::create_directories(file.parent_path());

        write_file(file, content);
    }
    return {};
}

auto cache_input(const std::filesystem::path &path, const std::string &input_name, const json &parameters, json result,
                 std::vector<std::string> const &sloppiness)
{
    // how to compare accounting for sloppiness?
    // easiest way is to drop sloppy data!
    // probably the correct way is to read the data, parse the json, compare while
    // ignoring sloppy fields... at least move this to fstat...
    if (input_name == "fstat" && contains(sloppiness, "time of fstat 1"))
    {
        auto fd = parameters.at("fd").get<int>();
        if (fd == 1)
        {
            result.at("stats").at("st_atim.tv_sec") = 0;
            result.at("stats").at("st_mtim.tv_sec") = 0;
            result.at("stats").at("st_ctim.tv_sec") = 0;
            result.at("stats").at("st_atim.tv_nsec") = 0;
            result.at("stats").at("st_mtim.tv_nsec") = 0;
            result.at("stats").at("st_ctim.tv_nsec") = 0;
        }
    }

    // ToDo: handle hash conflicts... somehow...
    auto const result_hash = calculate_hash_of_str(result.dump(), 3);
    auto const result_path = path / result_hash;

    const json action_file_content = {{"syscall_name", input_name}, {"parameters", parameters}};

    auto const action_file = path / "next_syscall.txt";
    auto const result_file = result_path / "readable_result.txt";

    if (auto action_match = ensure_file_content(action_file, action_file_content.dump()); action_match.ok())
    {
        if (auto result_match = ensure_file_content(result_file, result.dump()); result_match.ok())
            return result_path;
        else
            spdlog::warn("Same application has suddenly produced different results. "
                         "ToDo: Will no longer cache it!");
    }
    else
    {
        if (action_match.old_file_content)
        {
            spdlog::warn("Same application is suddenly performing a different syscall for no "
                         "obvious reason. ToDo: Will no longer cache it!");
            spdlog::warn("Old: {}", *action_match.old_file_content);
            spdlog::warn("New: {}", action_file_content.dump());
        }
        else
        {
            spdlog::warn("Cannot write cache file");
        }
    }

    throw std::runtime_error("cannot store cached data in cache");
}

auto FileBasedBackend::store_to_cache(json const &executable_and_params, std::vector<CachedSyscall> const &syscalls,
                                      std::vector<std::string> const &sloppiness) -> void
{
    auto directory = this->cache_path;
    directory = cache_input(directory, "params", json(), executable_and_params, sloppiness);
    for (const CachedSyscall &syscall : syscalls)
    {
        std::visit(
            [&directory, &sloppiness](auto &&typed_syscall) {
                directory = cache_input(directory, typed_syscall.name, json(typed_syscall.parameters),
                                        json(typed_syscall.result), sloppiness);
            },
            syscall);
    }
    spdlog::info("Execution cached in FileBasedBackend");
}

auto FileBasedBackend::retrieve_from_cache(const std::optional<retrieve_result> &previous_result,
                                           const json &syscall_result) -> retrieve_result
{
    auto const result_hash = calculate_hash_of_str(syscall_result.dump(), 3);
    auto const result_path = previous_result->detail_path / result_hash;

    auto const result_file = result_path / "readable_result.txt";
    auto const action_file = result_path / "next_syscall.txt";

    if (auto is = is_file_content(result_file, previous_result->dump()); is.ok())
    {
        auto res = read_file(action_file);
        if (std::holds_alternative<std::string>(res))
        {
            std::string const action_str = std::get<std::string>(res);
            json const next_action = json::parse(action_str); // parse!
            return {result_path, next_action};
        }
    }
    else
    {
        if (is.old_file_content)
        {
            spdlog::warn("Cannot use cached results because these two do not match");
            spdlog::warn("Old: {}", result.dump());
            spdlog::warn("New: {}", is.old_file_content.value());
        }
        else
        {
            if (is.error.value() != 2) // no such file
                spdlog::warn("Cannot use cached results because of error {}", is.error.value());
        }
    }

    // ToDo: result_path was partially constructed here! pass it along.
    return {};
}

auto FileBasedBackend::get_all_possible_results(const std::filesystem::path &pos) -> std::vector<json>
{
    std::vector<json> result;
    for (auto const &result_path : std::filesystem::directory_iterator(pos))
    {
        if (!result_path.is_directory())
            continue;

        auto const result_file = result_path.path() / "readable_result.txt";
        auto const content = read_file_to_json(result_file);
        if (json const *const data = std::get_if<json>(&content))
        {
            result.push_back(*data);
        }
        else
        {
            spdlog::warn("Error reading possible result {}: {}", result_file.string(), std::get<int>(content));
        }
    }
    return result;
}
} // namespace gpcache
