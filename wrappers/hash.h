#pragma once

#include <string_view>
#include <string>
#include <filesystem>

namespace gpcache
{
  auto calculate_hash_of_str(const std::string_view string, const int digest_size = 10) -> std::string;
  auto calculate_hash_of_file(const std::filesystem::path file, const int digest_size = 10) -> std::string;
}
