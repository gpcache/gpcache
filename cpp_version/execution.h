#include <string>

namespace gpcache
{
  struct ExecutionCache
  {
    Inputs inputs;
    Outputs outputs;
  };

  auto cache_execution(std::string const program, std::vector<std::string> const arguments) -> ExecutionCache;
}
