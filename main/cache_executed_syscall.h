#include "inputs.h"

#include <variant>
#include <vector>

namespace gpcache
{
auto execute_program(std::vector<char *> const &prog_and_arguments) -> std::vector<CachedSyscall>;
}
