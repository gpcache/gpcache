#pragma once

#include <string>
#include <ranges>
#include <numeric>

namespace gpcache
{
  // std::ranges::input_range<string>
  std::string join__(const auto &strings)
  {
    return std::accumulate(std::begin(strings), std::end(strings), std::string(),
                           [](const std::string &a, const std::string &b) -> std::string {
                             return a + (a.empty() ? "" : " > ") + b;
                           });
  }
}