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
#include "cached_syscalls/mmap_munmap.h"
#include "cached_syscalls/open_close.h"
#include "cached_syscalls/read.h"
#include "cached_syscalls/write.h"

namespace gpcache
{
  // ToDo: move to new structure
  struct FileHash
  {
    static constexpr char name[] = "filehash";

    struct Parameters
    {
      std::filesystem::path path;
      CONVENIENCE(Parameters, path)
    } parameters;

    struct Result
    {
      std::string hash;
      CONVENIENCE(Result, hash)
    } result;

    CONVENIENCE(FileHash, parameters, result)
  };

  // ToDo: move to new structure
  struct ParamsInput
  {
    static constexpr char name[] = "params";

    struct Parameters
    {
      bool dummy = true;
      CONVENIENCE(Parameters, dummy)
    } parameters;

    struct Result
    {
      std::filesystem::path path; // cache this?
      std::vector<std::string> params;
      std::string cwd; // etc... ENV?

      CONVENIENCE(Result, path, params, cwd)
    } result;

    CONVENIENCE(ParamsInput, parameters, result)
  };

  // ToDo: hmm
  struct UnsupportedInput
  {
    static constexpr char name[] = "unsupported";

    struct Parameters
    {
      bool thisIsJustCrazy;
      CONVENIENCE(Parameters, thisIsJustCrazy)
    } parameters;

    struct Result
    {
      bool thisIsJustCrazy;
      CONVENIENCE(Result, thisIsJustCrazy)
    } result;

    CONVENIENCE(UnsupportedInput, parameters, result)
  };

  using CachedSyscall = std::variant<
      CachedSyscall_Access,
      CachedSyscall_Fstat,
      CachedSyscall_Mmap,
      CachedSyscall_Open,
      CachedSyscall_Read,
      CachedSyscall_Write,
      FileHash,
      ParamsInput,
      UnsupportedInput>;

} // namespace gpcache
