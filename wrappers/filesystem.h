#if __has_include(<filesystem>)

// Modern compilers
#include <filesystem>

#elif __has_include(<experimental/filesystem>)

// Older compilers
#include <experimental/filesystem>
namespace std
{
using filesystem = ::std::experimental::filesystem;
}

#else

// Too old
error "Missing the <filesystem> header."

#endif
