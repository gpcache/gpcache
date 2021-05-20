#include <string>
#include <variant>
#include <vector>

struct AccessAction
{
  std::string filename;
  int mode;
  uint64_t result; // int? bool? SyscallDataType?
};

template <>
struct fmt::formatter<AccessAction>
{
  constexpr auto parse(auto &ctx) { return ctx.begin(); }

  auto format(AccessAction const &action, auto &ctx)
  {
    return fmt::format_to(ctx.out(), "access({}, {}) -> {}", action.filename, action.mode, action.result);
  }
};

using Action = std::variant<AccessAction>;

// Holds collection of all inputs which should lead to the same output.
struct Inputs
{
  // ToDo:
  // - cwd/pwd
  // - some env variables like SOURCE_DATE_EPOCH
  //   (never ending list... but adding everything would be overkill)
  // - uid, gid ?!

  std::vector<Action> actions;
};
