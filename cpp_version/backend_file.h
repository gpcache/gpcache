#include "inputs.h"
#include "outputs.h"

#include <string_view>
#include <string>
#include <filesytem>

namespace
{

  auto make_safe_filename(const std::string_view input) -> std::string
  {
    return input; // todo
  }

  // ENV, executable, parameters etc
  auto retrieve(const Input &inputs) -> Outputs;

  auto store(const Input &inputs, const Outputs &outputs) -> Outputs;
}
