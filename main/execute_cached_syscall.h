#pragma once

#include "inputs.h"

#include "main/state.h"

namespace gpcache {
auto execute_cached_json_syscall(State &, json const &) -> json;
}
