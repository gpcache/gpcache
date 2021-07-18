#include "inputs.h"

#include <variant>
#include <vector>

namespace gpcache
{
  using ExecutionCache = std::vector<Action>;

  auto execute_program(std::vector<char *> const &prog_and_arguments) -> ExecutionCache;
}
