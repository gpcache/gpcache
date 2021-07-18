#pragma once

#include <string>
#include <vector>

struct FdOutput
{
  static constexpr char name[] = "fd";

  int fd;
  std::string content;

  CONVENIENCE(FdOutput, fd, content)
};

// variant?
using Output = FdOutput;

// Holds collection of all inputs which should lead to the same output.
using Outputs = std::vector<Output>;
