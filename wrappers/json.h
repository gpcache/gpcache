#define JSON_DIAGNOSTICS 1
#if DEBUG_JSON_ASSERT
#define JSON_ASSERT(x)            \
  if (!(x))                       \
  {                               \
    throw std::runtime_error(#x); \
  }
#endif

#include <nlohmann/json.hpp>
using json = nlohmann::json;
