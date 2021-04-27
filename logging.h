#pragma once

#include "spdlog/spdlog.h"
#include <numeric>

namespace gpcache
{
  extern std::vector<std::string> callstack;

  std::string get_callstack();

  struct LogCallstack
  {
    LogCallstack(std::string str)
    {
      callstack.push_back(str);
      spdlog::debug("enter");
    }
    ~LogCallstack()
    {
      spdlog::debug("exit");
      callstack.pop_back();
    }
  };
}
