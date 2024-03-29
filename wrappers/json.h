#define JSON_DIAGNOSTICS 1
#if DEBUG_JSON_ASSERT
#define JSON_ASSERT(x)                                                                                                 \
    if (!(x))                                                                                                          \
    {                                                                                                                  \
        throw std::runtime_error(#x);                                                                                  \
    }
#endif

#include <nlohmann/json.hpp>
using json = nlohmann::json;

// C++ boilerplate :-(
// fmt overloads will not be provided. Then all this overhead would need to be
// generated by python. For printing use `json(some_struct).dump()`.
#define BOILERPLATE(STRUCT, ...)                                                                                       \
    friend auto operator<=>(const STRUCT &, const STRUCT &) = default;                                                 \
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(STRUCT, __VA_ARGS__)
