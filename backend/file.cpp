#include "backend/file.h"
#include "wrappers/hash.h"

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

  auto ensure_json_content(const std::filesystem::path &file, const json &content) -> bool
  {
    return true;
  }

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

  auto cache_input(const std::filesystem::path &path, const std::string &input_name, const json &action, const json &result)
  {
    spdlog::info("Backend_File: cache_input()");

    // ToDo: handle hash conflicts... somehow...
    const auto result_hash = calculate_hash_of_str(result.dump(), 3);
    const auto result_path = path / result_hash;

    const json action_file_content = {{"input", input_name}, {"action", action}};
    const std::string action_file_content_str = action_file_content.dump();
    const json result_file_content = result;

    const auto action_file = path / "action.txt";
    const auto result_file = result_path / "readable_result_for_debugging.txt";

    if (std::filesystem::exists(action_file))
    {
      spdlog::info("action_file ({}) exists", action_file.string());

      auto res = read_file(action_file);
      if (std::holds_alternative<std::string>(res))
      {
        const std::string existing_file_content = std::get<std::string>(res);
        fmt::print("Existing action_file {} = {}", action_file.string(), existing_file_content);

        if (existing_file_content != action_file_content_str)
        {
          spdlog::warn("action hash match, but action file content mismatch. Why was it even compared? crap...");
        }
      }
      else
      {
        const auto existing_file_error = std::get<int>(res);
        fmt::print("Non Existing action_file {} because of {}", action_file.string(), existing_file_error);
      }
    }
    else
    {
      spdlog::info("action_file ({}) does not exists, creating path ({})...", action_file.string(), path.string());
      std::filesystem::create_directories(path);
    }
    //if(!path_exists(path))
    //create_directory(path);
    //if(file_exists) assert content is action_file_content

    fmt::print("{} = {}\n", action_file.string(), action_file_content.dump());
    fmt::print("{} = {}\n", result_file.string(), result_file_content.dump());

    return result_path;
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
  }

  auto FileBasedBackend::store(const Inputs &inputs, const Outputs &outputs) -> void
  {
    spdlog::info("FileBasedBackend::store called");
    auto handle = create_output_path(inputs);
    store_outputs(handle, outputs);
  }
} // namespace gpcache
