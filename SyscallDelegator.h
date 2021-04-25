#include <sys/user.h> // user_regs_struct

#include <optional>
#include <vector>
#include <string>

namespace gpcache
{
  class SyscallListener
  {
  public:
    virtual void read(unsigned int fd, std::string buf, size_t count, std::optional<long> result) = 0;
    virtual void llistxattr(std::string path, std::string list, size_t size, std::optional<long> result) = 0;
  };

  /// Translates system specific syscalls to human understandable SyscallListener calls.
  class SyscallDelegator
  {
  public:
    SyscallDelegator(const pid_t, SyscallListener &);
    auto delegate_syscall(const user_regs_struct &) -> void;

  private:
    pid_t pid;
    SyscallListener &listener;
    enum class EnterExit
    {
      enter,
      exit
    };
    EnterExit next_call = EnterExit::enter;
  };
}
