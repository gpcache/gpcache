#include "backend/file.h"
#include "wrappers/hash.h"
#include "utils/enumerate.h"

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
  auto read_file(const std::filesystem::path &path) -> std::variant<std::string, int>
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
  auto write_file(const std::filesystem::path &path, const std::string &content) -> std::variant<bool, int>
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

  /// @returns true on success (existing, created or updated)
  auto ensure_file_content(const std::filesystem::path &file, const std::string &content) -> bool
  {
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
          return false;
        }
        else
        {
          return true;
        }
      }
      else
      {
        const auto existing_file_error = std::get<int>(res);
        spdlog::warn("Cannot read cached file {} because of {}", file.string(), existing_file_error);
        // attempt to create it?
        return false;
      }
    }
    else
    {
      std::filesystem::create_directories(file.parent_path());

      write_file(file, content);
    }
    return true;
  }

  auto cache_input(const std::filesystem::path &path, const std::string &input_name, const json &action, const json &result)
  {
    // ToDo: handle hash conflicts... somehow...
    const auto result_hash = calculate_hash_of_str(result.dump(), 3);
    const auto result_path = path / result_hash;

    const json action_file_content = {{"input", input_name}, {"action", action}};

    const auto action_file = path / "action.txt";
    const auto result_file = result_path / "readable_result_for_debugging.txt";

    if (ensure_file_content(action_file, action_file_content.dump()))
      if (ensure_file_content(result_file, result.dump()))
        return result_path;

    throw std::runtime_error("cannot store cached data in cache");
  }

  // traverse_inputs?
  auto create_output_path(const Inputs inputs)
  {
    fmt::print("\n");

    std::filesystem::path path = ".gpcache/";

    for (const Action &input : inputs)
    {
      std::visit(
          [&path](auto &&typed_input)
          {
            path = cache_input(path, typed_input.name, json{typed_input.action}, json{typed_input.result});
          },
          input);
    }

    return path;
  }

  auto store_outputs(const std::filesystem::path path, const Outputs &outputs)
  {
    for (const auto &[index, data] : enumerate(outputs))
    {
      ensure_file_content(path / fmt::format("output_{}.json", index), data);
    }
  }

  auto FileBasedBackend::store(const Inputs &inputs, const Outputs &outputs) -> void
  {
    // ToDo: intermixed inpiuts and outputs...
    auto handle = create_output_path(inputs);
    store_outputs(handle, outputs);
    spdlog::info("FileBasedBackend::store has cached inputs and outputs");
  }
} // namespace gpcache
