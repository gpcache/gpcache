#include "main/inputs.h"

#include <string>
#include <string_view>

namespace gpcache
{
class FileBasedBackend
{
  public:
    FileBasedBackend(const std::filesystem::path &path) : cache_path(path)
    {
    }

    struct retrieve_result
    {
        std::optional<json> next_syscall;
        operator bool() const
        {
            return !detail_path.empty();
        }

        // FileBasedBackend details
        std::filesystem::path detail_path;
    };
    auto retrieve_from_cache(const std::optional<retrieve_result> &previous_result, const json &syscall_result)
        -> retrieve_result;

    auto store_to_cache(json const &executable_and_params, std::vector<CachedSyscall> const &syscalls,
                        std::vector<std::string> const &sloppiness) -> void;

    // auto get_all_possible_actions(const std::filesystem::path &pos) ->
    // std::vector<json>;
    auto get_all_possible_results(const std::filesystem::path &pos) -> std::vector<json>;

  private:
    std::filesystem::path cache_path;
};
} // namespace gpcache

template <> struct fmt::formatter<gpcache::FileBasedBackend::retrieve_result>
{
    constexpr auto parse(auto &ctx)
    {
        return ctx.begin();
    }

    auto format(gpcache::FileBasedBackend::retrieve_result const &result, auto &ctx)
    {
        return fmt::format_to(ctx.out(), "{path: {}, next_action: {}}", result.detail_path,
                              result.next_syscall ? result.next_syscall->dump() : "<END>");
    }
};
