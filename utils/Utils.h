#pragma once

namespace gpcache {
  auto contains(auto container, auto item)
{
  return std::ranges::find(container, item) != std::end(container);
}
}
