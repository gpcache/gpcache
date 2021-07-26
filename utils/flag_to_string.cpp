#include "utils/flag_to_string.h"

#include "utils/join.h"

#include <fmt/format.h>

#include <linux/aio_abi.h>
#include <sys/user.h>
#include <unistd.h>
#include <cstdint>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <mqueue.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>

#include <vector>

namespace gpcache
{
  auto return_code_to_string(uint64_t result) -> std::string
  {
    // wild guess:
    if (result > 0xF00000000000000)
      return fmt::format("Failed with '{}'", strerror(-result));
    else
      return std::to_string(result);
  }

  auto mmap_flag_to_string(int flags) -> std::string
  {
    std::vector<std::string> s;
#define FLAG(x)      \
  if (flags & x)     \
  {                  \
    s.push_back(#x); \
    flags &= ~x;     \
  }

#define FLAG2(x, str)    \
  if (flags & x)         \
  {                      \
    s.push_back(#x str); \
    flags &= ~x;         \
  }
    FLAG(MAP_SHARED);
    FLAG(MAP_SHARED_VALIDATE);
    FLAG(MAP_PRIVATE);
    FLAG(MAP_32BIT);
    FLAG(MAP_ANONYMOUS);
    FLAG2(MAP_DENYWRITE, " (ignored)");
    FLAG(MAP_FIXED);
    FLAG(MAP_FIXED_NOREPLACE);
    FLAG(MAP_GROWSDOWN);
    FLAG(MAP_HUGETLB);
    FLAG(MAP_LOCKED);
    FLAG(MAP_NONBLOCK);
    FLAG(MAP_NORESERVE);
    FLAG(MAP_POPULATE);
    FLAG(MAP_STACK);
    FLAG(MAP_SYNC);
    if (flags)
      s.push_back(fmt::format("Remaining flags: {}", flags));

#undef FLAG
#undef FLAG2

    return join(s, "|");
  }

  auto mmap_prot_to_string(int prot) -> std::string
  {
    std::vector<std::string> s;
#define FLAG(x)      \
  if (prot & x)      \
  {                  \
    s.push_back(#x); \
    prot &= ~x;      \
  }
    FLAG(PROT_EXEC);
    FLAG(PROT_READ);
    FLAG(PROT_WRITE);
    FLAG(PROT_NONE);
#undef FLAG

    if (prot)
      s.push_back(fmt::format("Remaining: {}", prot));

    return join(s, "|");
  }

  auto openat_flag_to_string(int val) -> std::string
  {
    std::vector<std::string> s;
#define FLAG(x)            \
  if (val & x || val == x) \
  {                        \
    s.push_back(#x);       \
    val &= ~x;             \
  }
    FLAG(O_APPEND);
    FLAG(O_ASYNC);
    FLAG(O_CLOEXEC);
    FLAG(O_CREAT);
    FLAG(O_DIRECT);
    FLAG(O_DIRECTORY);
    FLAG(O_DSYNC);
    FLAG(O_EXCL);
    FLAG(O_LARGEFILE);
    FLAG(O_NOATIME);
    FLAG(O_NOCTTY);
    FLAG(O_NOFOLLOW);
    FLAG(O_NONBLOCK);
    FLAG(O_NDELAY);
    FLAG(O_PATH);
    FLAG(O_SYNC);
    FLAG(O_TMPFILE);
    FLAG(O_TRUNC);
    FLAG(O_RDONLY);
    FLAG(O_WRONLY);
    FLAG(O_RDWR);

#undef FLAG

    if (val)
      s.push_back(fmt::format("Remaining: {}", val));

    return join(s, "|");
  }
}
