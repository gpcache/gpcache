#include "execute_cached_syscall.h"

#include <unistd.h>

#include <spdlog/spdlog.h>

#include "utils/Utils.h"

template <class T>
static auto execute_typed_cached_syscall(json const &parameters) -> json
{
  return json(gpcache::execute_cached_syscall(static_cast<T::Parameters>(parameters)));
}

namespace gpcache
{
  auto execute_cached_syscall(json const &data) -> json
  {
    // todo: gracefully handle all kinds of invalid json
    if (!data.contains("syscall_name") || !data.contains("parameters"))
    {
      spdlog::warn("Missing key 'parameters'/'syscall_name' in {}", data.dump());
    }

    auto syscall_name = data.at("syscall_name").get<std::string>();
    auto &parameters = data.at("parameters");

    if (syscall_name == "access")
      return execute_typed_cached_syscall<CachedSyscall_Access>(parameters);
    if (syscall_name == "fstat")
      return execute_typed_cached_syscall<CachedSyscall_Fstat>(parameters);
    if (syscall_name == "open")
      return execute_typed_cached_syscall<CachedSyscall_Open>(parameters);
    if (syscall_name == "write")
      return execute_typed_cached_syscall<CachedSyscall_Write>(parameters);

    return {};
  }
}
