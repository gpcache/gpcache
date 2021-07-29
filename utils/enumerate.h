#pragma once

#include <ranges>

// stripped down version of
// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2164r4.pdf

template <std::ranges::range T> constexpr auto enumerate(T &&iterable) {
  class counting_forward_iterator {
  public:
    std::ranges::iterator_t<T> iter;
    std::ranges::range_difference_t<T> i{};

    counting_forward_iterator(std::ranges::iterator_t<T> it) : iter(it) {}

    bool operator!=(const counting_forward_iterator &other) const {
      return iter != other.iter;
    }

    void operator++() {
      ++i;
      ++iter;
    }

    auto operator*() const { return std::tie(i, *iter); }
  };

  struct wrapper_for_begin_and_end {
    T iterable;
    auto begin() { return counting_forward_iterator{std::begin(iterable)}; }
    auto end() { return counting_forward_iterator{std::end(iterable)}; }
  };

  return wrapper_for_begin_and_end{std::forward<T>(iterable)};
}
