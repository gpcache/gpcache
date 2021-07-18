#include "execute_cached_syscall.h"

#include <unistd.h>

#include <spdlog/spdlog.h>

#include "utils/Utils.h"

template <class T>
static auto run_execute_action(json const &action) -> json
{
  return json(gpcache::execute_cached_syscall(static_cast<T::Parameters>(action)));
}

namespace gpcache
{
  auto execute_cached_syscall(json const &data) -> json
  {
    // todo: gracefully handle all kinds of invalid json
    if (!data.contains("input") || !data.contains("action"))
    {
      spdlog::warn("Missing key 'action'/'input' in {}", data.dump());
    }

    auto input_type = data.at("input").get<std::string>();
    auto &action = data.at("action");

    if (input_type == "access")
      return run_execute_action<CachedSyscall_Access>(action);
    if (input_type == "fstat")
      return run_execute_action<CachedSyscall_Fstat>(action);
    if (input_type == "open")
      return run_execute_action<CachedSyscall_Open>(action);
    if (input_type == "write")
      return run_execute_action<CachedSyscall_Write>(action);

    return {};
  }
}
