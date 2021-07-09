#pragma once

namespace gpcache
{
  auto contains(auto container, auto item)
  {
    return std::ranges::find(container, item) != std::end(container);
  }

  // overloaded according to 'https://en.cppreference.com/w/cpp/utility/variant/visit'
  template <class... Ts>
  struct overloaded : Ts...
  {
    using Ts::operator()...;
  };
  template <class... Ts>
  overloaded(Ts...) -> overloaded<Ts...>;

}
