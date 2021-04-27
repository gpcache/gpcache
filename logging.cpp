#include "logging.h"

namespace gpcache
{
  std::vector<std::string> callstack;

  std::string get_callstack()
  {
    return std::accumulate(callstack.begin(), callstack.end(), std::string(),
                           [](const std::string &a, const std::string &b) -> std::string {
                             return a + (a.empty() ? "" : " > ") + b;
                           });
  }
}
