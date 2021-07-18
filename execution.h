#include "inputs.h"
#include "outputs.h"

#include <variant>
#include <vector>

namespace gpcache
{
  using ActionOrOutput = std::variant<Action, Output>;
  using ExecutionCache = std::vector<ActionOrOutput>;

  auto execute_program(std::vector<char *> const &prog_and_arguments) -> ExecutionCache;
}
