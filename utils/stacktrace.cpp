#include "stacktrace.h"

#include <memory>     // unique_ptr
#include <cxxabi.h>   // __cxa_demangle
#include <execinfo.h> // backtrace
#include <unistd.h>   // getpid
#include <iostream>   // cerr
#include <string>
#include <elfutils/libdwfl.h>

namespace
{
  static auto demangle(const char *const name) -> std::string
  {
    int status;
    std::unique_ptr<char, void (*)(void *)> res{
        abi::__cxa_demangle(name, NULL, NULL, &status),
        std::free};
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

    auto session() const { return dwfl; }

  private:
    Dwfl_Callbacks callbacks = {};
    char *debuginfo_path = nullptr;
    Dwfl *dwfl = nullptr;

    DwflSession(DwflSession const &) = delete;
    DwflSession &operator=(DwflSession const &) = delete;
  };

  struct DebugInfo
  {
    std::string file;
    int line;
    std::string function;
  };

  auto createDebugInfo(DwflSession const &dis, uintptr_t addr) -> DebugInfo
  {
    DebugInfo result;

    Dwfl_Module *module = dwfl_addrmodule(dis.session(), addr);
    char const *name = dwfl_module_addrname(module, addr);
    result.function = name ? demangle(name) : "<unknown>";

    // Get source filename and line number.
    if (Dwfl_Line *dwfl_line = dwfl_module_getsrc(module, addr))
    {
      Dwarf_Addr dwarf_addr;
      result.file = dwfl_lineinfo(dwfl_line, &dwarf_addr, &result.line, nullptr, nullptr, nullptr);
    }
    return result;
  }
}

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
      auto stack_item = createDebugInfo(dis, reinterpret_cast<uintptr_t>(stack[i]));

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
    print_current_stacktrace(std::cerr);
    std::_Exit(EXIT_FAILURE);
  }
}
