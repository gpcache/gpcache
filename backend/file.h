#include "main/inputs.h"

#include <string>
#include <string_view>

namespace gpcache {
class FileBasedBackend {
public:
  struct retrieve_result {
    std::filesystem::path
        path; // this exposes FileBasedBackend detail... bad idea...
    std::optional<json> next_syscall;

    auto ok() { return !path.empty(); }
  };
  auto retrieve(const std::filesystem::path &pos, const json &syscall_result)
      -> retrieve_result;

  auto store(json const &executable_and_params,
             std::vector<CachedSyscall> const &syscalls,
             std::vector<std::string> const &sloppiness) -> void;

  // auto get_all_possible_actions(const std::filesystem::path &pos) ->
  // std::vector<json>;
  auto get_all_possible_results(const std::filesystem::path &pos)
      -> std::vector<json>;

  // set via constructor!
  std::filesystem::path cache_path;
};
} // namespace gpcache

template <> struct fmt::formatter<gpcache::FileBasedBackend::retrieve_result> {
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(gpcache::FileBasedBackend::retrieve_result const &result,
              auto &ctx) {
    return fmt::format_to(ctx.out(), "{path: {}, next_action: {}}", result.path,
                          result.next_syscall ? result.next_syscall->dump()
                                              : "<END>");
  }
};
