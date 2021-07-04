#pragma once

#include <string>
#include <vector>

struct FileToWrite
{
  std::string filename;
  std::string content;
  // access rights etc
};

struct Outputs
{
  std::string out, err; // treat as files?!
  std::vector<FileToWrite> files;
};
