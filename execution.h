#include <string>

namespace gpcache
{
  struct ExecutionCache
  {
    Inputs inputs;
    Outputs outputs;
  };

  auto cache_execution(std::vector<char *> const &prog_and_arguments) -> ExecutionCache;
}
