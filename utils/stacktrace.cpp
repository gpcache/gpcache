#include "stacktrace.h"

#include <spdlog/spdlog.h>

#include <cxxabi.h>   // __cxa_demangle
#include <execinfo.h> // backtrace
#include <iostream>   // cerr
#include <memory>     // unique_ptr
#include <sstream>
#include <string>
#include <unistd.h> // getpid

#ifdef USE_ELFUTILS
#include <elfutils/libdwfl.h>

namespace
{
static auto demangle(const char *const name) -> std::string
{
    int status;
    std::unique_ptr<char, void (*)(void *)> res{abi::__cxa_demangle(name, NULL, NULL, &status), std::free};
    return status == 0 ? res.get() : name;
}

class DwflSession
{
  public:
    DwflSession()
    {
        callbacks.find_elf = dwfl_linux_proc_find_elf;
        callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
        callbacks.debuginfo_path = &debuginfo_path;
        dwfl = dwfl_begin(&callbacks);

        dwfl_linux_proc_report(dwfl, getpid());
        dwfl_report_end(dwfl, nullptr, nullptr);
    }

    ~DwflSession()
    {
        dwfl_end(dwfl);
    }

    auto session() const
    {
        return dwfl;
    }

  private:
    Dwfl_Callbacks callbacks = {};
    char *debuginfo_path = nullptr;
    Dwfl *dwfl = nullptr;

    DwflSession(DwflSession const &) = delete;
    DwflSession &operator=(DwflSession const &) = delete;
};

struct StackItem
{
    std::string file;
    int line;
    std::string function;
};

auto extractStackItemInfo(DwflSession const &dis, uintptr_t const addr) -> StackItem
{
    StackItem result;

    Dwfl_Module *const module = dwfl_addrmodule(dis.session(), addr);
    char const *const name = dwfl_module_addrname(module, addr);
    result.function = name ? demangle(name) : "<unknown>";

    if (Dwfl_Line *line_record = dwfl_module_getsrc(module, addr))
    {
        Dwarf_Addr dwarf_addr;
        result.file = dwfl_lineinfo(line_record, &dwarf_addr, &result.line, nullptr, nullptr, nullptr);
    }
    return result;
}
} // namespace

namespace gpcache
{
void print_current_stacktrace(std::ostream &stream)
{
    void *stack[512];
    int stack_size = ::backtrace(stack, sizeof stack / sizeof *stack);

    // Print the exception info, if any.
    if (auto ex = std::current_exception())
    {
        try
        {
            std::rethrow_exception(ex);
        }
        catch (std::exception &e)
        {
            stream << "Fatal exception " << demangle(typeid(e).name()) << ": " << e.what() << ".\n";
        }
        catch (...)
        {
            stream << "Fatal unknown exception.\n";
        }
    }

    DwflSession dis;
    stream << "\nStacktrace:\n";
    bool in_conan = false;
    for (int i = 0; i < stack_size; ++i)
    {
        auto stack_item = extractStackItemInfo(dis, reinterpret_cast<uintptr_t>(stack[i]));

        if (stack_item.file.find("/.conan/") != std::string::npos)
        {
            in_conan = true;
        }
        else if (in_conan)
        {
            in_conan = false;
            stream << "\n";
        }

        stream << i << ": ";
        if (!stack_item.file.empty())
            stream << stack_item.file << ':' << stack_item.line << " ";

        stream << stack_item.function << "\n";
    }
    stream.flush();
}

void terminate_with_stacktrace()
{
    std::stringstream ss;
    print_current_stacktrace(ss);
    spdlog::warn(ss.str());
    std::_Exit(EXIT_FAILURE);
}
} // namespace gpcache
#else
namespace gpcache
{
void terminate_with_stacktrace()
{
    spdlog::warn("terminating (currently no additional information available "
                 "when compioled with clang)");
    std::_Exit(EXIT_FAILURE);
}
} // namespace gpcache
#endif
