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

    auto store(const Inputs &inputs, const Outputs &outputs) -> void;
  };
}
