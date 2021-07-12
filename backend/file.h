#include "inputs.h"
#include "outputs.h"

#include <string_view>
#include <string>

namespace gpcache
{
  class FileBasedBackend
  {
  public:
    /// @returns input.action
    struct retrieve_result
    {
      std::filesystem::path path;
      json next_action;
      // ToDo: output, especially intermixed with actions
    };
    auto retrieve(const std::filesystem::path &pos, const json &input_result) -> retrieve_result;

    auto store(json const &params_json, Inputs const &inputs, Outputs const &outputs, std::vector<std::string> const &sloppiness) -> void;

    // set via constructor!
    std::filesystem::path cache_path;
  };
}
