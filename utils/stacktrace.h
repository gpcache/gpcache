#pragma once

#include <ostream>

namespace gpcache {
auto print_current_stacktrace(std::ostream &) -> void;
auto terminate_with_stacktrace() -> void;
} // namespace gpcache
