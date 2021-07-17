#include "execute_action.h"
#include "utils/flag_to_string.h"
#include "utils/Utils.h"

#include <spdlog/spdlog.h>
#include <fcntl.h> // O_RDONLY

#include <unistd.h>

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
  gpcache::OpenAction::Action a = action;
  static const std::vector<int> allowlist = {
      O_RDONLY,
      O_RDONLY | O_CLOEXEC | O_LARGEFILE,
      O_RDONLY | O_LARGEFILE,
      O_RDONLY | O_CLOEXEC,
  };
  if (!gpcache::contains(allowlist, a.mode))
  {
    spdlog::warn("Cannot execute {} from cache at the moment (not yet implemented)", action.dump());
    return {};
  }

  // ToDo: dirfd => full tracking of open files

  gpcache::OpenAction::Result result;
  int const fd = openat(0, a.filename.c_str(), a.flags, a.mode);
  result.success = fd != -1;
  result.errno_code = errno;
  return json(result);
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
