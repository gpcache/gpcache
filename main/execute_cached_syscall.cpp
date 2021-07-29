#include "execute_cached_syscall.h"

#include "utils/Utils.h"

#include <spdlog/spdlog.h>

#include <unistd.h>

template <class T>
static auto execute_typed_cached_syscall(gpcache::State &state,
                                         json const &parameters) -> json {
  return json(gpcache::execute_cached_syscall(
      state, static_cast<typename T::Parameters>(parameters)));
}

namespace gpcache {
auto execute_cached_json_syscall(State &state, json const &data) -> json {
  // todo: gracefully handle all kinds of invalid json
  if (!data.contains("syscall_name") || !data.contains("parameters")) {
    spdlog::warn("Missing key 'parameters'/'syscall_name' in {}", data.dump());
  }

  auto syscall_name = data.at("syscall_name").get<std::string>();
  auto &parameters = data.at("parameters");

  if (syscall_name == "access")
    return execute_typed_cached_syscall<CachedSyscall_Access>(state,
                                                              parameters);
  if (syscall_name == "fstat")
    return execute_typed_cached_syscall<CachedSyscall_Fstat>(state, parameters);
  if (syscall_name == "open")
    return execute_typed_cached_syscall<CachedSyscall_Open>(state, parameters);
  if (syscall_name == "close")
    return execute_typed_cached_syscall<CachedSyscall_Close>(state, parameters);

  if (syscall_name == "read" || syscall_name == "pread64")
    return execute_typed_cached_syscall<CachedSyscall_Read>(state, parameters);
  if (syscall_name == "write")
    return execute_typed_cached_syscall<CachedSyscall_Write>(state, parameters);

  if (syscall_name == "mmap")
    return execute_typed_cached_syscall<CachedSyscall_Mmap>(state, parameters);

  return {};
}
} // namespace gpcache
