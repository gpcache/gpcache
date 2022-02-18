#if __has_include(<filesystem>)
#include <filesystem>
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
// ToDo: proide instructions how to update libc++
// fails for me even fpr clang++10 (with g++-10 installed)
namespace std
{
using filesystem = ::std::experimental::filesystem;
}
#else
error "Missing the <filesystem> header."
#endif