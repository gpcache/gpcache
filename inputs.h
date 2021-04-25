#include <string>
#include <vector>

struct Action
{
  std::string type; // enum
  std::string result;
};

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
