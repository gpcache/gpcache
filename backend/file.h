#include "inputs.h"
#include "outputs.h"
#include "execution.h" // ExecutionCache

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

      auto ok() { return !path.empty(); }
    };
    auto retrieve(const std::filesystem::path &pos, const json &input_result) -> retrieve_result;

    auto store(json const &params_json, const gpcache::ExecutionCache &execution_cache, std::vector<std::string> const &sloppiness) -> void;

    //auto get_all_possible_actions(const std::filesystem::path &pos) -> std::vector<json>;
    auto get_all_possible_results(const std::filesystem::path &pos) -> std::vector<json>;

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
