#pragma once

#include <numeric>
#include <ranges>
#include <string>

namespace gpcache
{
// std::ranges::input_range<string>
std::string join(auto const &strings, std::string const glue)
{
    return std::accumulate(
        std::begin(strings), std::end(strings), std::string(),
        [&glue](const std::string &a, const std::string &b) -> std::string { return a + (a.empty() ? "" : glue) + b; });
}
} // namespace gpcache