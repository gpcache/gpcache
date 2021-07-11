#include "inputs.h"
#include "outputs.h"

#include <string_view>
#include <string>

namespace gpcache
{
  class FileBasedBackend
  {
  public:
    // ENV, executable, parameters etc
    auto retrieve(const Inputs &inputs) -> Outputs;

    auto store(Inputs const &inputs, Outputs const &outputs, std::vector<std::string> const &sloppiness) -> void;
  };
}
