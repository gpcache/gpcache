#include "execute_action.h"

#include <unistd.h>

#include <spdlog/spdlog.h>

#include "utils/Utils.h"

static auto execute_access(json const &action) -> json
{
  auto const filename = action.at("filename").get<std::string>();
  auto const mode = action.at("mode").get<int>();

  // No c++ equivalent? std::filesystem::status runs stats. Is anything running access?
  int result = access(filename.c_str(), mode);
  // todo: store return_value and errno_value seperatly to avoid this crap
  if (result == -1)
    result = -errno;
  return json{{"result", result}};
}

static auto execute_open(json const &action) -> json
{
  gpcache::CachedSyscall_Open::Action a = action;
  return json(gpcache::execute_action(a));
}

namespace gpcache
{
  auto execute_action(json const &data) -> json
  {
    // todo: gracefully handle all kinds of invalid json
    if (!data.contains("input") || !data.contains("action"))
    {
      spdlog::warn("Missing key 'action'/'input' in {}", data.dump());
    }

    auto input_type = data.at("input").get<std::string>();
    auto &action = data.at("action");

    if (input_type == "access")
      return execute_access(action);
    if (input_type == "open")
      return execute_open(action);

    return {};
  }
}
