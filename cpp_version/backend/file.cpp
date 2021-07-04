#include "backend/file.h"
#include "wrappers/hash.h"

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

  auto cache_input(const std::filesystem::path &path, const std::string &input_name, const json &action, const json &result)
  {
    // ToDo: handle hash conflicts... somehow...
    const auto result_hash = calculate_hash_of_str(result.dump(), 3);
    const auto result_path = path / result_hash;

    const json action_file_content = {{"input", input_name}, {"action", action}};
    const json result_file_content = result;

    const auto action_file = path / "action.txt";
    const auto result_file = result_path / "readable_result_for_debugging.txt";

    //if(!path_exists(path))
    //create_directory(path);
    //if(file_exists) assert content is action_file_content

    fmt::print("{} = {}\n", action_file.string(), action_file_content.dump());
    fmt::print("{} = {}\n", result_file.string(), result_file_content.dump());

    return result_path;
  }

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
