#pragma once

#include "wrappers/json.h"
#include "wrappers/filesystem.h"
#include <boost/pfr/core.hpp>
#include <fmt/format.h>

#include <string>
#include <variant>
#include <vector>
#include <sys/stat.h>

#include "utils/flag_to_string.h"

#include "cached_syscalls/access.h"
#include "cached_syscalls/open_close.h"
#include "cached_syscalls/fstat.h"

namespace gpcache
{
  struct FileHash
  {
    static constexpr char name[] = "filehash";

    struct Action
    {
      std::filesystem::path path;
      CONVENIENCE(Action, path)
    } action;

    struct Result
    {
      std::string hash;
      CONVENIENCE(Result, hash)
    } result;

    CONVENIENCE(FileHash, action, result)
  };

  struct ParamsInput
  {
    static constexpr char name[] = "params";

    struct Action
    {
      bool dummy = true;
      CONVENIENCE(Action, dummy)
    } action;

    struct Result
    {
      std::filesystem::path path; // cache this?
      std::vector<std::string> params;
      std::string cwd; // etc... ENV?

      CONVENIENCE(Result, path, params, cwd)
    } result;

    CONVENIENCE(ParamsInput, action, result)
  };

  struct UnsupportedInput
  {
    static constexpr char name[] = "unsupported";

    struct Action
    {
      bool thisIsJustCrazy;
      CONVENIENCE(Action, thisIsJustCrazy)
    } action;

    struct Result
    {
      bool thisIsJustCrazy;
      CONVENIENCE(Result, thisIsJustCrazy)
    } result;

    CONVENIENCE(UnsupportedInput, action, result)
  };

  // ToDo: rename to "Input"
  using Action = std::variant<CachedSyscall_Access, CachedSyscall_Open, CachedSyscall_Fstat, FileHash, ParamsInput, UnsupportedInput>;

  // Holds collection of all inputs which should lead to the same output.
  using Inputs = std::vector<Action>;

} // namespace gpcache
