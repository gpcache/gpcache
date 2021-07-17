#include "execute_action.h"

#include <unistd.h>

static auto execute_access(json const &action) -> json
{
  auto const filename = action.at("filename").get<std::string>();
  auto const mode = action.at("mode").get<int>();

  // No c++ equivalent? std::filesystem::status runs stats. Is anything running access?
  int result = access(filename.c_str(), mode);
  return json({"result", result});
}

namespace gpcache
{
  auto execute_action(json const &action) -> json
  {
    auto input_type = action.at("input").get<std::string>();
    if (input_type == "access")
      return execute_access(action);

    return {};
  }
}
