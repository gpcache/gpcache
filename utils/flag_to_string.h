#include <string>

namespace gpcache {
auto mmap_flag_to_string(int flags) -> std::string;
auto mmap_prot_to_string(int prot) -> std::string;
auto openat_flag_to_string(int val) -> std::string;
auto return_code_to_string(uint64_t result) -> std::string;
} // namespace gpcache
