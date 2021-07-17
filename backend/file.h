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

template <>
struct fmt::formatter<gpcache::FileBasedBackend::retrieve_result>
{
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(gpcache::FileBasedBackend::retrieve_result const &result, auto &ctx)
  {
    return fmt::format_to(ctx.out(), "{path: {}, next_action: {}}", result.path, result.next_action);
  }
};
