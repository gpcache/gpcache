#include <string>

namespace gpcache
{
  struct ExecutionCache
  {
    Inputs inputs;
    Outputs outputs;
  };

  auto execute_program(std::vector<char *> const &prog_and_arguments) -> ExecutionCache;
}
