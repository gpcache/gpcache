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
#include "cached_syscalls/fstat.h"
#include "cached_syscalls/open_close.h"
#include "cached_syscalls/write.h"

namespace gpcache
{
  struct FileHash
  {
    static constexpr char name[] = "filehash";

    struct Parameters
    {
      std::filesystem::path path;
      CONVENIENCE(Parameters, path)
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

    struct Parameters
    {
      bool dummy = true;
      CONVENIENCE(Parameters, dummy)
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

    struct Parameters
    {
      bool thisIsJustCrazy;
      CONVENIENCE(Parameters, thisIsJustCrazy)
    } action;

    struct Result
    {
      bool thisIsJustCrazy;
      CONVENIENCE(Result, thisIsJustCrazy)
    } result;

    CONVENIENCE(UnsupportedInput, action, result)
  };

  // ToDo: rename to "Input"
  using Parameters = std::variant<
      CachedSyscall_Access,
      CachedSyscall_Fstat,
      CachedSyscall_Open,
      CachedSyscall_Write,
      FileHash,
      ParamsInput,
      UnsupportedInput>;

  // Holds collection of all inputs which should lead to the same output.
  using Inputs = std::vector<Parameters>;

} // namespace gpcache
