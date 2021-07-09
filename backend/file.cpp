#include "backend/file.h"
#include "wrappers/hash.h"

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
    // ToDo: handle hash conflicts... somehow...
    const auto result_hash = calculate_hash_of_str(result.dump(), 3);
    const auto result_path = path / result_hash;

    const json action_file_content = {{"input", input_name}, {"action", action}};
    const json result_file_content = result;

    const auto action_file = path / "action.txt";
    const auto result_file = result_path / "readable_result_for_debugging.txt";

    std::filesystem::create_directories(path);
    if (std::filesystem::exists(action_file))
    {
      auto res = read_file(action_file);
      if (const auto existing_file_content = std::get_if<std::string>(&res))
      {
        fmt::print("Existing action_file {} = {}", action_file, existing_file_content);
      }
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

    for (const Action &action : inputs.actions)
    {
      std::visit(
          [&path](auto &&input)
          {
            path = cache_input(path, input.name, json{input.action}, json{input.result});
          },
          action);
    }

    return path;
  }

  auto store_outputs(const std::filesystem::path path, const Outputs &outputs)
  {
  }

  auto FileBasedBackend::store(const Inputs &inputs, const Outputs &outputs) -> void
  {
    auto handle = create_output_path(inputs);
    store_outputs(handle, outputs);
  }
} // namespace gpcache
