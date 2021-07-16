#include "backend/file.h"
#include "wrappers/hash.h"
#include "utils/enumerate.h"
#include "utils/Utils.h"

#include <spdlog/spdlog.h>

#include <fstream>
#include <string>
#include <cerrno>

namespace gpcache
{
  static auto make_safe_filename(const std::string_view input) -> std::string
  {
    return std::string(input); // todo
  }

  // Is there some reasonable C++ convinience library that provides such functions?
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

  // Is there some reasonable C++ convinience library that provides such functions?
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

    bool ok() { !old_file_content && !error; }
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
        return {.old_file_content = existing_file_content};
    }
    return {.error = std::get<int>(res)};
  }

  struct ensure_file_content_error
  {
    std::optional<std::string> old_file_content;
    std::optional<int> error;

    bool ok() { !old_file_content && !error; }
  };

  static auto ensure_file_content(const std::filesystem::path &file, const std::string &content) -> ensure_file_content_error
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
          // store as action2.json, action3.json etc to facilitate good error messages
          // Todo: different behavior of program vs inussificient hashing (hash length)
          spdlog::warn("file content mismatch");
          spdlog::debug(existing_file_content);
          spdlog::debug(content);
          return {.old_file_content = existing_file_content};
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
        return {.error = existing_file_error};
      }
    }
    else
    {
      std::filesystem::create_directories(file.parent_path());

      write_file(file, content);
    }
    return {};
  }

  auto cache_input(const std::filesystem::path &path,
                   const std::string &input_name,
                   const json &action,
                   json result,
                   std::vector<std::string> const &sloppiness)
  {
    // how to compare accounting for sloppiness?
    // easiest way is to drop sloppy data!
    // probably the correct way is to read the data, parse the json, compare while ignoring sloppy fields...
    if (input_name == "fstat" && contains(sloppiness, "time of fstat 1"))
    {
      spdlog::info("Action: {}", action.dump());

      // currently fd is encoded in path... omfg
      auto fs_path = action["path"].get<std::filesystem::path>();
      if (fs_path == std::filesystem::path("1"))
      {
        result["stats"]["st_atim.tv_sec"] = 0;
        result["stats"]["st_mtim.tv_sec"] = 0;
        result["stats"]["st_ctim.tv_sec"] = 0;
        result["stats"]["st_atim.tv_nsec"] = 0;
        result["stats"]["st_mtim.tv_nsec"] = 0;
        result["stats"]["st_ctim.tv_nsec"] = 0;
      }
    }

    // ToDo: handle hash conflicts... somehow...
    auto const result_hash = calculate_hash_of_str(result.dump(), 3);
    auto const result_path = path / result_hash;

    const json action_file_content = {{"input", input_name}, {"action", action}};

    auto const action_file = path / "action.txt";
    auto const result_file = result_path / "readable_result_for_debugging.txt";

    if (auto action_match = ensure_file_content(action_file, action_file_content.dump()); action_match.ok())
    {
      if (auto result_match = ensure_file_content(result_file, result.dump()); result_match.ok())
        return result_path;
      else
        spdlog::warn("Same application has suddenly produced different results. ToDo: Will no longer cache it!");
    }
    else
    {
      if (action_match.old_file_content)
      {
        spdlog::warn("Same application is suddenly performing a different action for no obvious reason. ToDo: Will no longer cache it!");
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

  // traverse_inputs?
  auto create_output_path(std::filesystem::path path, json const &params_json, const Inputs inputs, std::vector<std::string> const &sloppiness)
  {
    fmt::print("\n");

    path = cache_input(path, "params", json(), params_json, sloppiness);

    for (const Action &input : inputs)
    {
      std::visit(
          [&path, &sloppiness](auto &&typed_input)
          {
            path = cache_input(path, typed_input.name, json(typed_input.action), json(typed_input.result), sloppiness);
          },
          input);
    }

    return path;
  }

  auto store_outputs(const std::filesystem::path path, const Outputs &outputs)
  {
    for (auto const &[index, data] : enumerate(outputs))
    {
      ensure_file_content(path / fmt::format("output_{}.json", index), data.dump());
    }
  }

  auto FileBasedBackend::store(json const &params_json, Inputs const &inputs, Outputs const &outputs, std::vector<std::string> const &sloppiness) -> void
  {
    // ToDo: intermixed inpiuts and outputs...
    auto handle = create_output_path(this->cache_path, params_json, inputs, sloppiness);
    store_outputs(handle, outputs);
    spdlog::info("FileBasedBackend::store has cached inputs and outputs");
  }

  auto FileBasedBackend::retrieve(const std::filesystem::path &path, const json &result) -> retrieve_result
  {
    auto const result_hash = calculate_hash_of_str(result.dump(), 3);
    auto const result_path = path / result_hash;

    auto const result_file = result_path / "readable_result_for_debugging.txt";
    auto const action_file = result_path / "action.txt";

    spdlog::info("retrieve() called");

    if (auto is = is_file_content(result_file, result.dump()); is.ok())
    {
      spdlog::info("Found cache directory for executable with params: {}", result.dump());
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
        spdlog::warn("Cannot use cached results because of error {}", is.error.value());
      }
    }

    // ToDo: result_path was partially constructed here! pass it along.
    return {};
  }
} // namespace gpcache
