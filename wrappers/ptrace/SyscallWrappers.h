// Generated via ../gpcache/code_generator/generate_syscalls.py

#pragma once

#include <array>
#include <variant>
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
#include <linux/time_types.h>
#include <sys/uio.h>

namespace gpcache
{

  using SyscallDataType = decltype(user_regs_struct{}.rax);
  using Syscall_Args = std::array<SyscallDataType, 6>;

  struct Syscall_read : public Syscall_Args
  {
    Syscall_read(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 0;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto buf() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto count() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }
  };

  struct Syscall_write : public Syscall_Args
  {
    Syscall_write(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 1;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto buf() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto count() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }
  };

  struct Syscall_open : public Syscall_Args
  {
    Syscall_open(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 2;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](2));
    }
  };

  struct Syscall_close : public Syscall_Args
  {
    Syscall_close(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 3;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }
  };

  struct Syscall_stat : public Syscall_Args
  {
    Syscall_stat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 4;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto statbuf() const -> struct stat *
    {
      return reinterpret_cast<struct stat *>(operator[](1));
    }
  };

  struct Syscall_fstat : public Syscall_Args
  {
    Syscall_fstat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 5;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto statbuf() const -> struct stat *
    {
      return reinterpret_cast<struct stat *>(operator[](1));
    }
  };

  struct Syscall_lstat : public Syscall_Args
  {
    Syscall_lstat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 6;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto statbuf() const -> struct stat *
    {
      return reinterpret_cast<struct stat *>(operator[](1));
    }
  };

  struct Syscall_lseek : public Syscall_Args
  {
    Syscall_lseek(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 8;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto offset() const -> off_t
    {
      return static_cast<off_t>(operator[](1));
    }

    auto whence() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }
  };

  struct Syscall_mmap : public Syscall_Args
  {
    Syscall_mmap(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 9;

    auto addr() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto prot() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto fd() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }

    auto pgoff() const -> off_t
    {
      return static_cast<off_t>(operator[](5));
    }
  };

  struct Syscall_mprotect : public Syscall_Args
  {
    Syscall_mprotect(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 10;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }

    auto prot() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }
  };

  struct Syscall_munmap : public Syscall_Args
  {
    Syscall_munmap(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 11;

    auto addr() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }
  };

  struct Syscall_brk : public Syscall_Args
  {
    Syscall_brk(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 12;

    auto brk() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }
  };

  struct Syscall_rt_sigprocmask : public Syscall_Args
  {
    Syscall_rt_sigprocmask(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 14;

    auto how() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto set() const -> sigset_t *
    {
      return reinterpret_cast<sigset_t *>(operator[](1));
    }

    auto oset() const -> sigset_t *
    {
      return reinterpret_cast<sigset_t *>(operator[](2));
    }

    auto sigsetsize() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }
  };

  struct Syscall_rt_sigreturn : public Syscall_Args
  {
    Syscall_rt_sigreturn(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 15;

    auto regs() const -> struct pt_regs *
    {
      return reinterpret_cast<struct pt_regs *>(operator[](0));
    }
  };

  struct Syscall_ioctl : public Syscall_Args
  {
    Syscall_ioctl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 16;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto cmd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto arg() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }
  };

  struct Syscall_pread64 : public Syscall_Args
  {
    Syscall_pread64(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 17;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto buf() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto count() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }

    auto pos() const -> loff_t
    {
      return static_cast<loff_t>(operator[](3));
    }
  };

  struct Syscall_pwrite64 : public Syscall_Args
  {
    Syscall_pwrite64(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 18;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto buf() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto count() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }

    auto pos() const -> loff_t
    {
      return static_cast<loff_t>(operator[](3));
    }
  };

  struct Syscall_readv : public Syscall_Args
  {
    Syscall_readv(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 19;

    auto fd() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto vec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto vlen() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }
  };

  struct Syscall_writev : public Syscall_Args
  {
    Syscall_writev(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 20;

    auto fd() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto vec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto vlen() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }
  };

  struct Syscall_access : public Syscall_Args
  {
    Syscall_access(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 21;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto mode() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_pipe : public Syscall_Args
  {
    Syscall_pipe(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 22;

    auto fildes() const -> int *
    {
      return reinterpret_cast<int *>(operator[](0));
    }
  };

  struct Syscall_sched_yield : public Syscall_Args
  {
    Syscall_sched_yield(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 24;
  };

  struct Syscall_mremap : public Syscall_Args
  {
    Syscall_mremap(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 25;

    auto addr() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto old_len() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto new_len() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto new_addr() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }
  };

  struct Syscall_msync : public Syscall_Args
  {
    Syscall_msync(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 26;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_mincore : public Syscall_Args
  {
    Syscall_mincore(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 27;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }

    auto vec() const -> unsigned char *
    {
      return reinterpret_cast<unsigned char *>(operator[](2));
    }
  };

  struct Syscall_madvise : public Syscall_Args
  {
    Syscall_madvise(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 28;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }

    auto behavior() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_shmget : public Syscall_Args
  {
    Syscall_shmget(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 29;

    auto key() const -> key_t
    {
      return static_cast<key_t>(operator[](0));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }

    auto flag() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_shmat : public Syscall_Args
  {
    Syscall_shmat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 30;

    auto shmid() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto shmaddr() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto shmflg() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_dup : public Syscall_Args
  {
    Syscall_dup(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 32;

    auto fildes() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }
  };

  struct Syscall_dup2 : public Syscall_Args
  {
    Syscall_dup2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 33;

    auto oldfd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto newfd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }
  };

  struct Syscall_pause : public Syscall_Args
  {
    Syscall_pause(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 34;
  };

  struct Syscall_nanosleep : public Syscall_Args
  {
    Syscall_nanosleep(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 35;

    auto rqtp() const -> struct __kernel_timespec *
    {
      return reinterpret_cast<struct __kernel_timespec *>(operator[](0));
    }

    auto rmtp() const -> struct __kernel_timespec *
    {
      return reinterpret_cast<struct __kernel_timespec *>(operator[](1));
    }
  };

  struct Syscall_alarm : public Syscall_Args
  {
    Syscall_alarm(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 37;

    auto seconds() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }
  };

  struct Syscall_getpid : public Syscall_Args
  {
    Syscall_getpid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 39;
  };

  struct Syscall_sendfile : public Syscall_Args
  {
    Syscall_sendfile(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 40;

    auto out_fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto in_fd() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto offset() const -> loff_t *
    {
      return reinterpret_cast<loff_t *>(operator[](2));
    }

    auto count() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }
  };

  struct Syscall_socket : public Syscall_Args
  {
    Syscall_socket(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 41;
  };

  struct Syscall_connect : public Syscall_Args
  {
    Syscall_connect(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 42;
  };

  struct Syscall_accept : public Syscall_Args
  {
    Syscall_accept(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 43;
  };

  struct Syscall_sendto : public Syscall_Args
  {
    Syscall_sendto(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 44;
  };

  struct Syscall_recvfrom : public Syscall_Args
  {
    Syscall_recvfrom(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 45;
  };

  struct Syscall_shutdown : public Syscall_Args
  {
    Syscall_shutdown(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 48;
  };

  struct Syscall_bind : public Syscall_Args
  {
    Syscall_bind(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 49;
  };

  struct Syscall_listen : public Syscall_Args
  {
    Syscall_listen(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 50;
  };

  struct Syscall_getsockname : public Syscall_Args
  {
    Syscall_getsockname(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 51;
  };

  struct Syscall_getpeername : public Syscall_Args
  {
    Syscall_getpeername(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 52;
  };

  struct Syscall_socketpair : public Syscall_Args
  {
    Syscall_socketpair(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 53;
  };

  struct Syscall_setsockopt : public Syscall_Args
  {
    Syscall_setsockopt(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 54;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto level() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto optname() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto optval() const -> char *
    {
      return reinterpret_cast<char *>(operator[](3));
    }

    auto optlen() const -> int
    {
      return static_cast<int>(operator[](4));
    }
  };

  struct Syscall_getsockopt : public Syscall_Args
  {
    Syscall_getsockopt(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 55;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto level() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto optname() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto optval() const -> char *
    {
      return reinterpret_cast<char *>(operator[](3));
    }

    auto optlen() const -> int *
    {
      return reinterpret_cast<int *>(operator[](4));
    }
  };

  struct Syscall_clone : public Syscall_Args
  {
    Syscall_clone(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 56;
  };

  struct Syscall_fork : public Syscall_Args
  {
    Syscall_fork(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 57;
  };

  struct Syscall_vfork : public Syscall_Args
  {
    Syscall_vfork(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 58;
  };

  struct Syscall_execve : public Syscall_Args
  {
    Syscall_execve(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 59;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto argv() const -> const char *const *
    {
      return reinterpret_cast<const char *const *>(operator[](1));
    }

    auto envp() const -> const char *const *
    {
      return reinterpret_cast<const char *const *>(operator[](2));
    }
  };

  struct Syscall_exit : public Syscall_Args
  {
    Syscall_exit(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 60;

    auto error_code() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_kill : public Syscall_Args
  {
    Syscall_kill(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 62;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto sig() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_semget : public Syscall_Args
  {
    Syscall_semget(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 64;

    auto key() const -> key_t
    {
      return static_cast<key_t>(operator[](0));
    }

    auto nsems() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto semflg() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_semctl : public Syscall_Args
  {
    Syscall_semctl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 66;

    auto semid() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto semnum() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto cmd() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto arg() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }
  };

  struct Syscall_shmdt : public Syscall_Args
  {
    Syscall_shmdt(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 67;

    auto shmaddr() const -> char *
    {
      return reinterpret_cast<char *>(operator[](0));
    }
  };

  struct Syscall_msgget : public Syscall_Args
  {
    Syscall_msgget(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 68;

    auto key() const -> key_t
    {
      return static_cast<key_t>(operator[](0));
    }

    auto msgflg() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_fcntl : public Syscall_Args
  {
    Syscall_fcntl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 72;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto cmd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto arg() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }
  };

  struct Syscall_flock : public Syscall_Args
  {
    Syscall_flock(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 73;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto cmd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }
  };

  struct Syscall_fsync : public Syscall_Args
  {
    Syscall_fsync(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 74;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }
  };

  struct Syscall_fdatasync : public Syscall_Args
  {
    Syscall_fdatasync(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 75;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }
  };

  struct Syscall_truncate : public Syscall_Args
  {
    Syscall_truncate(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 76;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto length() const -> long
    {
      return static_cast<long>(operator[](1));
    }
  };

  struct Syscall_ftruncate : public Syscall_Args
  {
    Syscall_ftruncate(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 77;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto length() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }
  };

  struct Syscall_getcwd : public Syscall_Args
  {
    Syscall_getcwd(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 79;

    auto buf() const -> char *
    {
      return reinterpret_cast<char *>(operator[](0));
    }

    auto size() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }
  };

  struct Syscall_chdir : public Syscall_Args
  {
    Syscall_chdir(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 80;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }
  };

  struct Syscall_fchdir : public Syscall_Args
  {
    Syscall_fchdir(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 81;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }
  };

  struct Syscall_rename : public Syscall_Args
  {
    Syscall_rename(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 82;

    auto oldname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto newname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }
  };

  struct Syscall_mkdir : public Syscall_Args
  {
    Syscall_mkdir(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 83;

    auto pathname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](1));
    }
  };

  struct Syscall_rmdir : public Syscall_Args
  {
    Syscall_rmdir(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 84;

    auto pathname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }
  };

  struct Syscall_creat : public Syscall_Args
  {
    Syscall_creat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 85;

    auto pathname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](1));
    }
  };

  struct Syscall_link : public Syscall_Args
  {
    Syscall_link(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 86;

    auto oldname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto newname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }
  };

  struct Syscall_unlink : public Syscall_Args
  {
    Syscall_unlink(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 87;

    auto pathname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }
  };

  struct Syscall_symlink : public Syscall_Args
  {
    Syscall_symlink(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 88;

    auto old() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto new__() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }
  };

  struct Syscall_readlink : public Syscall_Args
  {
    Syscall_readlink(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 89;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto buf() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto bufsiz() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_chmod : public Syscall_Args
  {
    Syscall_chmod(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 90;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](1));
    }
  };

  struct Syscall_fchmod : public Syscall_Args
  {
    Syscall_fchmod(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 91;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](1));
    }
  };

  struct Syscall_chown : public Syscall_Args
  {
    Syscall_chown(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 92;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto user() const -> uid_t
    {
      return static_cast<uid_t>(operator[](1));
    }

    auto group() const -> gid_t
    {
      return static_cast<gid_t>(operator[](2));
    }
  };

  struct Syscall_fchown : public Syscall_Args
  {
    Syscall_fchown(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 93;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto user() const -> uid_t
    {
      return static_cast<uid_t>(operator[](1));
    }

    auto group() const -> gid_t
    {
      return static_cast<gid_t>(operator[](2));
    }
  };

  struct Syscall_lchown : public Syscall_Args
  {
    Syscall_lchown(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 94;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto user() const -> uid_t
    {
      return static_cast<uid_t>(operator[](1));
    }

    auto group() const -> gid_t
    {
      return static_cast<gid_t>(operator[](2));
    }
  };

  struct Syscall_umask : public Syscall_Args
  {
    Syscall_umask(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 95;

    auto mask() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_ptrace : public Syscall_Args
  {
    Syscall_ptrace(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 101;

    auto request() const -> long
    {
      return static_cast<long>(operator[](0));
    }

    auto pid() const -> long
    {
      return static_cast<long>(operator[](1));
    }

    auto addr() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto data() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }
  };

  struct Syscall_getuid : public Syscall_Args
  {
    Syscall_getuid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 102;
  };

  struct Syscall_syslog : public Syscall_Args
  {
    Syscall_syslog(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 103;

    auto type() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto buf() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto len() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_getgid : public Syscall_Args
  {
    Syscall_getgid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 104;
  };

  struct Syscall_setuid : public Syscall_Args
  {
    Syscall_setuid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 105;

    auto uid() const -> uid_t
    {
      return static_cast<uid_t>(operator[](0));
    }
  };

  struct Syscall_setgid : public Syscall_Args
  {
    Syscall_setgid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 106;

    auto gid() const -> gid_t
    {
      return static_cast<gid_t>(operator[](0));
    }
  };

  struct Syscall_geteuid : public Syscall_Args
  {
    Syscall_geteuid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 107;
  };

  struct Syscall_getegid : public Syscall_Args
  {
    Syscall_getegid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 108;
  };

  struct Syscall_setpgid : public Syscall_Args
  {
    Syscall_setpgid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 109;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto pgid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](1));
    }
  };

  struct Syscall_getppid : public Syscall_Args
  {
    Syscall_getppid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 110;
  };

  struct Syscall_getpgrp : public Syscall_Args
  {
    Syscall_getpgrp(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 111;
  };

  struct Syscall_setsid : public Syscall_Args
  {
    Syscall_setsid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 112;
  };

  struct Syscall_setreuid : public Syscall_Args
  {
    Syscall_setreuid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 113;

    auto ruid() const -> uid_t
    {
      return static_cast<uid_t>(operator[](0));
    }

    auto euid() const -> uid_t
    {
      return static_cast<uid_t>(operator[](1));
    }
  };

  struct Syscall_setregid : public Syscall_Args
  {
    Syscall_setregid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 114;

    auto rgid() const -> gid_t
    {
      return static_cast<gid_t>(operator[](0));
    }

    auto egid() const -> gid_t
    {
      return static_cast<gid_t>(operator[](1));
    }
  };

  struct Syscall_getgroups : public Syscall_Args
  {
    Syscall_getgroups(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 115;

    auto gidsetsize() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto grouplist() const -> gid_t *
    {
      return reinterpret_cast<gid_t *>(operator[](1));
    }
  };

  struct Syscall_setgroups : public Syscall_Args
  {
    Syscall_setgroups(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 116;

    auto gidsetsize() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto grouplist() const -> gid_t *
    {
      return reinterpret_cast<gid_t *>(operator[](1));
    }
  };

  struct Syscall_setresuid : public Syscall_Args
  {
    Syscall_setresuid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 117;

    auto ruid() const -> uid_t
    {
      return static_cast<uid_t>(operator[](0));
    }

    auto euid() const -> uid_t
    {
      return static_cast<uid_t>(operator[](1));
    }

    auto suid() const -> uid_t
    {
      return static_cast<uid_t>(operator[](2));
    }
  };

  struct Syscall_getresuid : public Syscall_Args
  {
    Syscall_getresuid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 118;

    auto ruid() const -> uid_t *
    {
      return reinterpret_cast<uid_t *>(operator[](0));
    }

    auto euid() const -> uid_t *
    {
      return reinterpret_cast<uid_t *>(operator[](1));
    }

    auto suid() const -> uid_t *
    {
      return reinterpret_cast<uid_t *>(operator[](2));
    }
  };

  struct Syscall_setresgid : public Syscall_Args
  {
    Syscall_setresgid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 119;

    auto rgid() const -> gid_t
    {
      return static_cast<gid_t>(operator[](0));
    }

    auto egid() const -> gid_t
    {
      return static_cast<gid_t>(operator[](1));
    }

    auto sgid() const -> gid_t
    {
      return static_cast<gid_t>(operator[](2));
    }
  };

  struct Syscall_getresgid : public Syscall_Args
  {
    Syscall_getresgid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 120;

    auto rgid() const -> gid_t *
    {
      return reinterpret_cast<gid_t *>(operator[](0));
    }

    auto egid() const -> gid_t *
    {
      return reinterpret_cast<gid_t *>(operator[](1));
    }

    auto sgid() const -> gid_t *
    {
      return reinterpret_cast<gid_t *>(operator[](2));
    }
  };

  struct Syscall_getpgid : public Syscall_Args
  {
    Syscall_getpgid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 121;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }
  };

  struct Syscall_setfsuid : public Syscall_Args
  {
    Syscall_setfsuid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 122;

    auto uid() const -> uid_t
    {
      return static_cast<uid_t>(operator[](0));
    }
  };

  struct Syscall_setfsgid : public Syscall_Args
  {
    Syscall_setfsgid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 123;

    auto gid() const -> gid_t
    {
      return static_cast<gid_t>(operator[](0));
    }
  };

  struct Syscall_getsid : public Syscall_Args
  {
    Syscall_getsid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 124;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }
  };

  struct Syscall_rt_sigpending : public Syscall_Args
  {
    Syscall_rt_sigpending(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 127;

    auto set() const -> sigset_t *
    {
      return reinterpret_cast<sigset_t *>(operator[](0));
    }

    auto sigsetsize() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }
  };

  struct Syscall_rt_sigtimedwait : public Syscall_Args
  {
    Syscall_rt_sigtimedwait(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 128;

    auto uthese() const -> const sigset_t *
    {
      return reinterpret_cast<const sigset_t *>(operator[](0));
    }

    auto uinfo() const -> siginfo_t *
    {
      return reinterpret_cast<siginfo_t *>(operator[](1));
    }

    auto uts() const -> const struct __kernel_timespec *
    {
      return reinterpret_cast<const struct __kernel_timespec *>(operator[](2));
    }

    auto sigsetsize() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }
  };

  struct Syscall_rt_sigqueueinfo : public Syscall_Args
  {
    Syscall_rt_sigqueueinfo(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 129;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto sig() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto uinfo() const -> siginfo_t *
    {
      return reinterpret_cast<siginfo_t *>(operator[](2));
    }
  };

  struct Syscall_rt_sigsuspend : public Syscall_Args
  {
    Syscall_rt_sigsuspend(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 130;

    auto unewset() const -> sigset_t *
    {
      return reinterpret_cast<sigset_t *>(operator[](0));
    }

    auto sigsetsize() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }
  };

  struct Syscall_sigaltstack : public Syscall_Args
  {
    Syscall_sigaltstack(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 131;

    auto uss() const -> const struct sigaltstack *
    {
      return reinterpret_cast<const struct sigaltstack *>(operator[](0));
    }

    auto uoss() const -> struct sigaltstack *
    {
      return reinterpret_cast<struct sigaltstack *>(operator[](1));
    }
  };

  struct Syscall_mknod : public Syscall_Args
  {
    Syscall_mknod(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 133;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](1));
    }

    auto dev() const -> unsigned
    {
      return static_cast<unsigned>(operator[](2));
    }
  };

  struct Syscall_personality : public Syscall_Args
  {
    Syscall_personality(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 135;

    auto personality() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }
  };

  struct Syscall_ustat : public Syscall_Args
  {
    Syscall_ustat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 136;

    auto dev() const -> unsigned
    {
      return static_cast<unsigned>(operator[](0));
    }

    auto ubuf() const -> struct ustat *
    {
      return reinterpret_cast<struct ustat *>(operator[](1));
    }
  };

  struct Syscall_statfs : public Syscall_Args
  {
    Syscall_statfs(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 137;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto buf() const -> struct statfs *
    {
      return reinterpret_cast<struct statfs *>(operator[](1));
    }
  };

  struct Syscall_fstatfs : public Syscall_Args
  {
    Syscall_fstatfs(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 138;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto buf() const -> struct statfs *
    {
      return reinterpret_cast<struct statfs *>(operator[](1));
    }
  };

  struct Syscall_sysfs : public Syscall_Args
  {
    Syscall_sysfs(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 139;

    auto option() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto arg1() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto arg2() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }
  };

  struct Syscall_getpriority : public Syscall_Args
  {
    Syscall_getpriority(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 140;

    auto which() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto who() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_setpriority : public Syscall_Args
  {
    Syscall_setpriority(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 141;

    auto which() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto who() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto niceval() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_sched_getscheduler : public Syscall_Args
  {
    Syscall_sched_getscheduler(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 145;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }
  };

  struct Syscall_sched_get_priority_max : public Syscall_Args
  {
    Syscall_sched_get_priority_max(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 146;

    auto policy() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_sched_get_priority_min : public Syscall_Args
  {
    Syscall_sched_get_priority_min(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 147;

    auto policy() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_sched_rr_get_interval : public Syscall_Args
  {
    Syscall_sched_rr_get_interval(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 148;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto interval() const -> struct __kernel_timespec *
    {
      return reinterpret_cast<struct __kernel_timespec *>(operator[](1));
    }
  };

  struct Syscall_mlock : public Syscall_Args
  {
    Syscall_mlock(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 149;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }
  };

  struct Syscall_munlock : public Syscall_Args
  {
    Syscall_munlock(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 150;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }
  };

  struct Syscall_mlockall : public Syscall_Args
  {
    Syscall_mlockall(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 151;

    auto flags() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_munlockall : public Syscall_Args
  {
    Syscall_munlockall(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 152;
  };

  struct Syscall_vhangup : public Syscall_Args
  {
    Syscall_vhangup(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 153;
  };

  struct Syscall_modify_ldt : public Syscall_Args
  {
    Syscall_modify_ldt(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 154;
  };

  struct Syscall_pivot_root : public Syscall_Args
  {
    Syscall_pivot_root(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 155;

    auto new_root() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto put_old() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }
  };

  struct Syscall__sysctl : public Syscall_Args
  {
    Syscall__sysctl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 156;
  };

  struct Syscall_prctl : public Syscall_Args
  {
    Syscall_prctl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 157;

    auto option() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto arg2() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto arg3() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto arg4() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto arg5() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }
  };

  struct Syscall_arch_prctl : public Syscall_Args
  {
    Syscall_arch_prctl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 158;
  };

  struct Syscall_chroot : public Syscall_Args
  {
    Syscall_chroot(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 161;

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }
  };

  struct Syscall_sync : public Syscall_Args
  {
    Syscall_sync(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 162;
  };

  struct Syscall_acct : public Syscall_Args
  {
    Syscall_acct(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 163;

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }
  };

  struct Syscall_mount : public Syscall_Args
  {
    Syscall_mount(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 165;

    auto dev_name() const -> char *
    {
      return reinterpret_cast<char *>(operator[](0));
    }

    auto dir_name() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto type() const -> char *
    {
      return reinterpret_cast<char *>(operator[](2));
    }

    auto flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto data() const -> void *
    {
      return reinterpret_cast<void *>(operator[](4));
    }
  };

  struct Syscall_umount2 : public Syscall_Args
  {
    Syscall_umount2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 166;

    auto name() const -> char *
    {
      return reinterpret_cast<char *>(operator[](0));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_swapon : public Syscall_Args
  {
    Syscall_swapon(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 167;

    auto specialfile() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto swap_flags() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_swapoff : public Syscall_Args
  {
    Syscall_swapoff(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 168;

    auto specialfile() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }
  };

  struct Syscall_reboot : public Syscall_Args
  {
    Syscall_reboot(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 169;

    auto magic1() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto magic2() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto cmd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }

    auto arg() const -> void *
    {
      return reinterpret_cast<void *>(operator[](3));
    }
  };

  struct Syscall_sethostname : public Syscall_Args
  {
    Syscall_sethostname(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 170;

    auto name() const -> char *
    {
      return reinterpret_cast<char *>(operator[](0));
    }

    auto len() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_setdomainname : public Syscall_Args
  {
    Syscall_setdomainname(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 171;

    auto name() const -> char *
    {
      return reinterpret_cast<char *>(operator[](0));
    }

    auto len() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_iopl : public Syscall_Args
  {
    Syscall_iopl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 172;
  };

  struct Syscall_ioperm : public Syscall_Args
  {
    Syscall_ioperm(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 173;

    auto from() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto num() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto on() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_init_module : public Syscall_Args
  {
    Syscall_init_module(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 175;

    auto umod() const -> void *
    {
      return reinterpret_cast<void *>(operator[](0));
    }

    auto len() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto uargs() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](2));
    }
  };

  struct Syscall_delete_module : public Syscall_Args
  {
    Syscall_delete_module(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 176;

    auto name_user() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }
  };

  struct Syscall_quotactl : public Syscall_Args
  {
    Syscall_quotactl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 179;

    auto cmd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto special() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto id() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto addr() const -> void *
    {
      return reinterpret_cast<void *>(operator[](3));
    }
  };

  struct Syscall_gettid : public Syscall_Args
  {
    Syscall_gettid(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 186;
  };

  struct Syscall_readahead : public Syscall_Args
  {
    Syscall_readahead(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 187;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto offset() const -> loff_t
    {
      return static_cast<loff_t>(operator[](1));
    }

    auto count() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }
  };

  struct Syscall_setxattr : public Syscall_Args
  {
    Syscall_setxattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 188;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto value() const -> const void *
    {
      return reinterpret_cast<const void *>(operator[](2));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](4));
    }
  };

  struct Syscall_lsetxattr : public Syscall_Args
  {
    Syscall_lsetxattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 189;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto value() const -> const void *
    {
      return reinterpret_cast<const void *>(operator[](2));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](4));
    }
  };

  struct Syscall_fsetxattr : public Syscall_Args
  {
    Syscall_fsetxattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 190;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto value() const -> const void *
    {
      return reinterpret_cast<const void *>(operator[](2));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](4));
    }
  };

  struct Syscall_getxattr : public Syscall_Args
  {
    Syscall_getxattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 191;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto value() const -> void *
    {
      return reinterpret_cast<void *>(operator[](2));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }
  };

  struct Syscall_lgetxattr : public Syscall_Args
  {
    Syscall_lgetxattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 192;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto value() const -> void *
    {
      return reinterpret_cast<void *>(operator[](2));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }
  };

  struct Syscall_fgetxattr : public Syscall_Args
  {
    Syscall_fgetxattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 193;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto value() const -> void *
    {
      return reinterpret_cast<void *>(operator[](2));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }
  };

  struct Syscall_listxattr : public Syscall_Args
  {
    Syscall_listxattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 194;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto list() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }
  };

  struct Syscall_llistxattr : public Syscall_Args
  {
    Syscall_llistxattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 195;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto list() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }
  };

  struct Syscall_flistxattr : public Syscall_Args
  {
    Syscall_flistxattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 196;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto list() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }
  };

  struct Syscall_removexattr : public Syscall_Args
  {
    Syscall_removexattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 197;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }
  };

  struct Syscall_lremovexattr : public Syscall_Args
  {
    Syscall_lremovexattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 198;

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }
  };

  struct Syscall_fremovexattr : public Syscall_Args
  {
    Syscall_fremovexattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 199;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }
  };

  struct Syscall_tkill : public Syscall_Args
  {
    Syscall_tkill(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 200;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto sig() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_time : public Syscall_Args
  {
    Syscall_time(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 201;

    auto tloc() const -> __kernel_time_t *
    {
      return reinterpret_cast<__kernel_time_t *>(operator[](0));
    }
  };

  struct Syscall_futex : public Syscall_Args
  {
    Syscall_futex(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 202;

    auto uaddr() const -> uint32_t *
    {
      return reinterpret_cast<uint32_t *>(operator[](0));
    }

    auto op() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto val() const -> uint32_t
    {
      return static_cast<uint32_t>(operator[](2));
    }

    auto utime() const -> const struct __kernel_timespec *
    {
      return reinterpret_cast<const struct __kernel_timespec *>(operator[](3));
    }

    auto uaddr2() const -> uint32_t *
    {
      return reinterpret_cast<uint32_t *>(operator[](4));
    }

    auto val3() const -> uint32_t
    {
      return static_cast<uint32_t>(operator[](5));
    }
  };

  struct Syscall_sched_setaffinity : public Syscall_Args
  {
    Syscall_sched_setaffinity(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 203;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto len() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto user_mask_ptr() const -> unsigned long *
    {
      return reinterpret_cast<unsigned long *>(operator[](2));
    }
  };

  struct Syscall_sched_getaffinity : public Syscall_Args
  {
    Syscall_sched_getaffinity(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 204;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto len() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto user_mask_ptr() const -> unsigned long *
    {
      return reinterpret_cast<unsigned long *>(operator[](2));
    }
  };

  struct Syscall_io_setup : public Syscall_Args
  {
    Syscall_io_setup(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 206;

    auto nr_reqs() const -> unsigned
    {
      return static_cast<unsigned>(operator[](0));
    }

    auto ctx() const -> aio_context_t *
    {
      return reinterpret_cast<aio_context_t *>(operator[](1));
    }
  };

  struct Syscall_io_destroy : public Syscall_Args
  {
    Syscall_io_destroy(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 207;

    auto ctx() const -> aio_context_t
    {
      return static_cast<aio_context_t>(operator[](0));
    }
  };

  struct Syscall_io_getevents : public Syscall_Args
  {
    Syscall_io_getevents(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 208;

    auto ctx_id() const -> aio_context_t
    {
      return static_cast<aio_context_t>(operator[](0));
    }

    auto min_nr() const -> long
    {
      return static_cast<long>(operator[](1));
    }

    auto nr() const -> long
    {
      return static_cast<long>(operator[](2));
    }

    auto events() const -> struct io_event *
    {
      return reinterpret_cast<struct io_event *>(operator[](3));
    }

    auto timeout() const -> struct __kernel_timespec *
    {
      return reinterpret_cast<struct __kernel_timespec *>(operator[](4));
    }
  };

  struct Syscall_lookup_dcookie : public Syscall_Args
  {
    Syscall_lookup_dcookie(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 212;

    auto cookie64() const -> uint64_t
    {
      return static_cast<uint64_t>(operator[](0));
    }

    auto buf() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }
  };

  struct Syscall_epoll_create : public Syscall_Args
  {
    Syscall_epoll_create(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 213;

    auto size() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_remap_file_pages : public Syscall_Args
  {
    Syscall_remap_file_pages(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 216;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto size() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto prot() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto pgoff() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }
  };

  struct Syscall_set_tid_address : public Syscall_Args
  {
    Syscall_set_tid_address(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 218;

    auto tidptr() const -> int *
    {
      return reinterpret_cast<int *>(operator[](0));
    }
  };

  struct Syscall_restart_syscall : public Syscall_Args
  {
    Syscall_restart_syscall(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 219;
  };

  struct Syscall_fadvise64 : public Syscall_Args
  {
    Syscall_fadvise64(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 221;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto offset() const -> loff_t
    {
      return static_cast<loff_t>(operator[](1));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }

    auto advice() const -> int
    {
      return static_cast<int>(operator[](3));
    }
  };

  struct Syscall_timer_create : public Syscall_Args
  {
    Syscall_timer_create(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 222;

    auto which_clock() const -> clockid_t
    {
      return static_cast<clockid_t>(operator[](0));
    }

    auto timer_event_spec() const -> struct sigevent *
    {
      return reinterpret_cast<struct sigevent *>(operator[](1));
    }

    auto created_timer_id() const -> timer_t *
    {
      return reinterpret_cast<timer_t *>(operator[](2));
    }
  };

  struct Syscall_timer_settime : public Syscall_Args
  {
    Syscall_timer_settime(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 223;

    auto timer_id() const -> timer_t
    {
      return reinterpret_cast<timer_t>(operator[](0));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto new_setting() const -> const struct __kernel_itimerspec *
    {
      return reinterpret_cast<const struct __kernel_itimerspec *>(operator[](2));
    }

    auto old_setting() const -> struct __kernel_itimerspec *
    {
      return reinterpret_cast<struct __kernel_itimerspec *>(operator[](3));
    }
  };

  struct Syscall_timer_gettime : public Syscall_Args
  {
    Syscall_timer_gettime(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 224;

    auto timer_id() const -> timer_t
    {
      return reinterpret_cast<timer_t>(operator[](0));
    }

    auto setting() const -> struct __kernel_itimerspec *
    {
      return reinterpret_cast<struct __kernel_itimerspec *>(operator[](1));
    }
  };

  struct Syscall_timer_getoverrun : public Syscall_Args
  {
    Syscall_timer_getoverrun(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 225;

    auto timer_id() const -> timer_t
    {
      return reinterpret_cast<timer_t>(operator[](0));
    }
  };

  struct Syscall_timer_delete : public Syscall_Args
  {
    Syscall_timer_delete(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 226;

    auto timer_id() const -> timer_t
    {
      return reinterpret_cast<timer_t>(operator[](0));
    }
  };

  struct Syscall_clock_settime : public Syscall_Args
  {
    Syscall_clock_settime(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 227;

    auto which_clock() const -> clockid_t
    {
      return static_cast<clockid_t>(operator[](0));
    }

    auto tp() const -> const struct __kernel_timespec *
    {
      return reinterpret_cast<const struct __kernel_timespec *>(operator[](1));
    }
  };

  struct Syscall_clock_gettime : public Syscall_Args
  {
    Syscall_clock_gettime(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 228;

    auto which_clock() const -> clockid_t
    {
      return static_cast<clockid_t>(operator[](0));
    }

    auto tp() const -> struct __kernel_timespec *
    {
      return reinterpret_cast<struct __kernel_timespec *>(operator[](1));
    }
  };

  struct Syscall_clock_getres : public Syscall_Args
  {
    Syscall_clock_getres(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 229;

    auto which_clock() const -> clockid_t
    {
      return static_cast<clockid_t>(operator[](0));
    }

    auto tp() const -> struct __kernel_timespec *
    {
      return reinterpret_cast<struct __kernel_timespec *>(operator[](1));
    }
  };

  struct Syscall_clock_nanosleep : public Syscall_Args
  {
    Syscall_clock_nanosleep(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 230;

    auto which_clock() const -> clockid_t
    {
      return static_cast<clockid_t>(operator[](0));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto rqtp() const -> const struct __kernel_timespec *
    {
      return reinterpret_cast<const struct __kernel_timespec *>(operator[](2));
    }

    auto rmtp() const -> struct __kernel_timespec *
    {
      return reinterpret_cast<struct __kernel_timespec *>(operator[](3));
    }
  };

  struct Syscall_exit_group : public Syscall_Args
  {
    Syscall_exit_group(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 231;

    auto error_code() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_epoll_wait : public Syscall_Args
  {
    Syscall_epoll_wait(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 232;

    auto epfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto events() const -> struct epoll_event *
    {
      return reinterpret_cast<struct epoll_event *>(operator[](1));
    }

    auto maxevents() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto timeout() const -> int
    {
      return static_cast<int>(operator[](3));
    }
  };

  struct Syscall_epoll_ctl : public Syscall_Args
  {
    Syscall_epoll_ctl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 233;

    auto epfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto op() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto fd() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto event() const -> struct epoll_event *
    {
      return reinterpret_cast<struct epoll_event *>(operator[](3));
    }
  };

  struct Syscall_tgkill : public Syscall_Args
  {
    Syscall_tgkill(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 234;

    auto tgid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](1));
    }

    auto sig() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_mbind : public Syscall_Args
  {
    Syscall_mbind(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 237;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto mode() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto nmask() const -> const unsigned long *
    {
      return reinterpret_cast<const unsigned long *>(operator[](3));
    }

    auto maxnode() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }

    auto flags() const -> unsigned
    {
      return static_cast<unsigned>(operator[](5));
    }
  };

  struct Syscall_set_mempolicy : public Syscall_Args
  {
    Syscall_set_mempolicy(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 238;

    auto mode() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto nmask() const -> const unsigned long *
    {
      return reinterpret_cast<const unsigned long *>(operator[](1));
    }

    auto maxnode() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }
  };

  struct Syscall_get_mempolicy : public Syscall_Args
  {
    Syscall_get_mempolicy(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 239;

    auto policy() const -> int *
    {
      return reinterpret_cast<int *>(operator[](0));
    }

    auto nmask() const -> unsigned long *
    {
      return reinterpret_cast<unsigned long *>(operator[](1));
    }

    auto maxnode() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto addr() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }
  };

  struct Syscall_mq_open : public Syscall_Args
  {
    Syscall_mq_open(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 240;

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto oflag() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](2));
    }

    auto attr() const -> struct mq_attr *
    {
      return reinterpret_cast<struct mq_attr *>(operator[](3));
    }
  };

  struct Syscall_mq_unlink : public Syscall_Args
  {
    Syscall_mq_unlink(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 241;

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }
  };

  struct Syscall_mq_timedsend : public Syscall_Args
  {
    Syscall_mq_timedsend(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 242;

    auto mqdes() const -> mqd_t
    {
      return static_cast<mqd_t>(operator[](0));
    }

    auto msg_ptr() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto msg_len() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }

    auto msg_prio() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](3));
    }

    auto abs_timeout() const -> const struct __kernel_timespec *
    {
      return reinterpret_cast<const struct __kernel_timespec *>(operator[](4));
    }
  };

  struct Syscall_mq_timedreceive : public Syscall_Args
  {
    Syscall_mq_timedreceive(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 243;

    auto mqdes() const -> mqd_t
    {
      return static_cast<mqd_t>(operator[](0));
    }

    auto msg_ptr() const -> char *
    {
      return reinterpret_cast<char *>(operator[](1));
    }

    auto msg_len() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }

    auto msg_prio() const -> unsigned int *
    {
      return reinterpret_cast<unsigned int *>(operator[](3));
    }

    auto abs_timeout() const -> const struct __kernel_timespec *
    {
      return reinterpret_cast<const struct __kernel_timespec *>(operator[](4));
    }
  };

  struct Syscall_mq_notify : public Syscall_Args
  {
    Syscall_mq_notify(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 244;

    auto mqdes() const -> mqd_t
    {
      return static_cast<mqd_t>(operator[](0));
    }

    auto notification() const -> const struct sigevent *
    {
      return reinterpret_cast<const struct sigevent *>(operator[](1));
    }
  };

  struct Syscall_mq_getsetattr : public Syscall_Args
  {
    Syscall_mq_getsetattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 245;

    auto mqdes() const -> mqd_t
    {
      return static_cast<mqd_t>(operator[](0));
    }

    auto mqstat() const -> const struct mq_attr *
    {
      return reinterpret_cast<const struct mq_attr *>(operator[](1));
    }

    auto omqstat() const -> struct mq_attr *
    {
      return reinterpret_cast<struct mq_attr *>(operator[](2));
    }
  };

  struct Syscall_keyctl : public Syscall_Args
  {
    Syscall_keyctl(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 250;

    auto cmd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto arg2() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto arg3() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto arg4() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto arg5() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }
  };

  struct Syscall_ioprio_set : public Syscall_Args
  {
    Syscall_ioprio_set(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 251;

    auto which() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto who() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto ioprio() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_ioprio_get : public Syscall_Args
  {
    Syscall_ioprio_get(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 252;

    auto which() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto who() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_inotify_init : public Syscall_Args
  {
    Syscall_inotify_init(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 253;
  };

  struct Syscall_inotify_add_watch : public Syscall_Args
  {
    Syscall_inotify_add_watch(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 254;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto mask() const -> uint32_t
    {
      return static_cast<uint32_t>(operator[](2));
    }
  };

  struct Syscall_inotify_rm_watch : public Syscall_Args
  {
    Syscall_inotify_rm_watch(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 255;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto wd() const -> __s32
    {
      return static_cast<__s32>(operator[](1));
    }
  };

  struct Syscall_migrate_pages : public Syscall_Args
  {
    Syscall_migrate_pages(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 256;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto maxnode() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto from() const -> const unsigned long *
    {
      return reinterpret_cast<const unsigned long *>(operator[](2));
    }

    auto to() const -> const unsigned long *
    {
      return reinterpret_cast<const unsigned long *>(operator[](3));
    }
  };

  struct Syscall_openat : public Syscall_Args
  {
    Syscall_openat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 257;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](3));
    }
  };

  struct Syscall_mkdirat : public Syscall_Args
  {
    Syscall_mkdirat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 258;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto pathname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](2));
    }
  };

  struct Syscall_mknodat : public Syscall_Args
  {
    Syscall_mknodat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 259;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](2));
    }

    auto dev() const -> unsigned
    {
      return static_cast<unsigned>(operator[](3));
    }
  };

  struct Syscall_fchownat : public Syscall_Args
  {
    Syscall_fchownat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 260;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto user() const -> uid_t
    {
      return static_cast<uid_t>(operator[](2));
    }

    auto group() const -> gid_t
    {
      return static_cast<gid_t>(operator[](3));
    }

    auto flag() const -> int
    {
      return static_cast<int>(operator[](4));
    }
  };

  struct Syscall_newfstatat : public Syscall_Args
  {
    Syscall_newfstatat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 262;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto statbuf() const -> struct stat *
    {
      return reinterpret_cast<struct stat *>(operator[](2));
    }

    auto flag() const -> int
    {
      return static_cast<int>(operator[](3));
    }
  };

  struct Syscall_unlinkat : public Syscall_Args
  {
    Syscall_unlinkat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 263;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto pathname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto flag() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_renameat : public Syscall_Args
  {
    Syscall_renameat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 264;

    auto olddfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto oldname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto newdfd() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto newname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](3));
    }
  };

  struct Syscall_linkat : public Syscall_Args
  {
    Syscall_linkat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 265;

    auto olddfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto oldname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto newdfd() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto newname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](3));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](4));
    }
  };

  struct Syscall_symlinkat : public Syscall_Args
  {
    Syscall_symlinkat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 266;

    auto oldname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto newdfd() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto newname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](2));
    }
  };

  struct Syscall_readlinkat : public Syscall_Args
  {
    Syscall_readlinkat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 267;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto buf() const -> char *
    {
      return reinterpret_cast<char *>(operator[](2));
    }

    auto bufsiz() const -> int
    {
      return static_cast<int>(operator[](3));
    }
  };

  struct Syscall_fchmodat : public Syscall_Args
  {
    Syscall_fchmodat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 268;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto mode() const -> mode_t
    {
      return static_cast<mode_t>(operator[](2));
    }
  };

  struct Syscall_faccessat : public Syscall_Args
  {
    Syscall_faccessat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 269;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto mode() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_pselect6 : public Syscall_Args
  {
    Syscall_pselect6(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 270;
  };

  struct Syscall_unshare : public Syscall_Args
  {
    Syscall_unshare(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 272;

    auto unshare_flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }
  };

  struct Syscall_splice : public Syscall_Args
  {
    Syscall_splice(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 275;

    auto fd_in() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto off_in() const -> loff_t *
    {
      return reinterpret_cast<loff_t *>(operator[](1));
    }

    auto fd_out() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto off_out() const -> loff_t *
    {
      return reinterpret_cast<loff_t *>(operator[](3));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](4));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](5));
    }
  };

  struct Syscall_tee : public Syscall_Args
  {
    Syscall_tee(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 276;

    auto fdin() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto fdout() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](3));
    }
  };

  struct Syscall_sync_file_range : public Syscall_Args
  {
    Syscall_sync_file_range(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 277;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto offset() const -> loff_t
    {
      return static_cast<loff_t>(operator[](1));
    }

    auto nbytes() const -> loff_t
    {
      return static_cast<loff_t>(operator[](2));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](3));
    }
  };

  struct Syscall_vmsplice : public Syscall_Args
  {
    Syscall_vmsplice(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 278;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto iov() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto nr_segs() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](3));
    }
  };

  struct Syscall_move_pages : public Syscall_Args
  {
    Syscall_move_pages(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 279;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto nr_pages() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }

    auto pages() const -> const void **
    {
      return reinterpret_cast<const void **>(operator[](2));
    }

    auto nodes() const -> const int *
    {
      return reinterpret_cast<const int *>(operator[](3));
    }

    auto status() const -> int *
    {
      return reinterpret_cast<int *>(operator[](4));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](5));
    }
  };

  struct Syscall_utimensat : public Syscall_Args
  {
    Syscall_utimensat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 280;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto utimes() const -> struct __kernel_timespec *
    {
      return reinterpret_cast<struct __kernel_timespec *>(operator[](2));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](3));
    }
  };

  struct Syscall_epoll_pwait : public Syscall_Args
  {
    Syscall_epoll_pwait(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 281;

    auto epfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto events() const -> struct epoll_event *
    {
      return reinterpret_cast<struct epoll_event *>(operator[](1));
    }

    auto maxevents() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto timeout() const -> int
    {
      return static_cast<int>(operator[](3));
    }

    auto SignMask() const -> const sigset_t *
    {
      return reinterpret_cast<const sigset_t *>(operator[](4));
    }

    auto sigsetsize() const -> size_t
    {
      return static_cast<size_t>(operator[](5));
    }
  };

  struct Syscall_signalfd : public Syscall_Args
  {
    Syscall_signalfd(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 282;

    auto ufd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto user_mask() const -> sigset_t *
    {
      return reinterpret_cast<sigset_t *>(operator[](1));
    }

    auto sizemask() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }
  };

  struct Syscall_timerfd_create : public Syscall_Args
  {
    Syscall_timerfd_create(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 283;

    auto clockid() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_eventfd : public Syscall_Args
  {
    Syscall_eventfd(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 284;

    auto count() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }
  };

  struct Syscall_fallocate : public Syscall_Args
  {
    Syscall_fallocate(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 285;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto mode() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto offset() const -> loff_t
    {
      return static_cast<loff_t>(operator[](2));
    }

    auto len() const -> loff_t
    {
      return static_cast<loff_t>(operator[](3));
    }
  };

  struct Syscall_timerfd_settime : public Syscall_Args
  {
    Syscall_timerfd_settime(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 286;

    auto ufd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto utmr() const -> const struct __kernel_itimerspec *
    {
      return reinterpret_cast<const struct __kernel_itimerspec *>(operator[](2));
    }

    auto otmr() const -> struct __kernel_itimerspec *
    {
      return reinterpret_cast<struct __kernel_itimerspec *>(operator[](3));
    }
  };

  struct Syscall_timerfd_gettime : public Syscall_Args
  {
    Syscall_timerfd_gettime(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 287;

    auto ufd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto otmr() const -> struct __kernel_itimerspec *
    {
      return reinterpret_cast<struct __kernel_itimerspec *>(operator[](1));
    }
  };

  struct Syscall_accept4 : public Syscall_Args
  {
    Syscall_accept4(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 288;
  };

  struct Syscall_signalfd4 : public Syscall_Args
  {
    Syscall_signalfd4(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 289;

    auto ufd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto user_mask() const -> sigset_t *
    {
      return reinterpret_cast<sigset_t *>(operator[](1));
    }

    auto sizemask() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](3));
    }
  };

  struct Syscall_eventfd2 : public Syscall_Args
  {
    Syscall_eventfd2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 290;

    auto count() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_epoll_create1 : public Syscall_Args
  {
    Syscall_epoll_create1(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 291;

    auto flags() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_dup3 : public Syscall_Args
  {
    Syscall_dup3(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 292;

    auto oldfd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto newfd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_pipe2 : public Syscall_Args
  {
    Syscall_pipe2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 293;

    auto fildes() const -> int *
    {
      return reinterpret_cast<int *>(operator[](0));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_inotify_init1 : public Syscall_Args
  {
    Syscall_inotify_init1(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 294;

    auto flags() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_preadv : public Syscall_Args
  {
    Syscall_preadv(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 295;

    auto fd() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto vec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto vlen() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto pos_l() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto pos_h() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }
  };

  struct Syscall_pwritev : public Syscall_Args
  {
    Syscall_pwritev(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 296;

    auto fd() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto vec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto vlen() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto pos_l() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto pos_h() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }
  };

  struct Syscall_rt_tgsigqueueinfo : public Syscall_Args
  {
    Syscall_rt_tgsigqueueinfo(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 297;

    auto tgid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](1));
    }

    auto sig() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto uinfo() const -> siginfo_t *
    {
      return reinterpret_cast<siginfo_t *>(operator[](3));
    }
  };

  struct Syscall_recvmmsg : public Syscall_Args
  {
    Syscall_recvmmsg(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 299;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto msg() const -> struct mmsghdr *
    {
      return reinterpret_cast<struct mmsghdr *>(operator[](1));
    }

    auto vlen() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }

    auto flags() const -> unsigned
    {
      return static_cast<unsigned>(operator[](3));
    }

    auto timeout() const -> struct __kernel_timespec *
    {
      return reinterpret_cast<struct __kernel_timespec *>(operator[](4));
    }
  };

  struct Syscall_fanotify_init : public Syscall_Args
  {
    Syscall_fanotify_init(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 300;

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto event_f_flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }
  };

  struct Syscall_fanotify_mark : public Syscall_Args
  {
    Syscall_fanotify_mark(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 301;

    auto fanotify_fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto mask() const -> uint64_t
    {
      return static_cast<uint64_t>(operator[](2));
    }

    auto fd() const -> int
    {
      return static_cast<int>(operator[](3));
    }

    auto pathname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](4));
    }
  };

  struct Syscall_name_to_handle_at : public Syscall_Args
  {
    Syscall_name_to_handle_at(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 303;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto handle() const -> struct file_handle *
    {
      return reinterpret_cast<struct file_handle *>(operator[](2));
    }

    auto mnt_id() const -> int *
    {
      return reinterpret_cast<int *>(operator[](3));
    }

    auto flag() const -> int
    {
      return static_cast<int>(operator[](4));
    }
  };

  struct Syscall_open_by_handle_at : public Syscall_Args
  {
    Syscall_open_by_handle_at(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 304;

    auto mountdirfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto handle() const -> struct file_handle *
    {
      return reinterpret_cast<struct file_handle *>(operator[](1));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_syncfs : public Syscall_Args
  {
    Syscall_syncfs(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 306;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_sendmmsg : public Syscall_Args
  {
    Syscall_sendmmsg(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 307;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto msg() const -> struct mmsghdr *
    {
      return reinterpret_cast<struct mmsghdr *>(operator[](1));
    }

    auto vlen() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }

    auto flags() const -> unsigned
    {
      return static_cast<unsigned>(operator[](3));
    }
  };

  struct Syscall_setns : public Syscall_Args
  {
    Syscall_setns(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 308;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto nstype() const -> int
    {
      return static_cast<int>(operator[](1));
    }
  };

  struct Syscall_getcpu : public Syscall_Args
  {
    Syscall_getcpu(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 309;

    auto cpu() const -> unsigned *
    {
      return reinterpret_cast<unsigned *>(operator[](0));
    }

    auto node() const -> unsigned *
    {
      return reinterpret_cast<unsigned *>(operator[](1));
    }

    auto cache() const -> struct getcpu_cache *
    {
      return reinterpret_cast<struct getcpu_cache *>(operator[](2));
    }
  };

  struct Syscall_process_vm_readv : public Syscall_Args
  {
    Syscall_process_vm_readv(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 310;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto lvec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto liovcnt() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto rvec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](3));
    }

    auto riovcnt() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }

    auto flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](5));
    }
  };

  struct Syscall_process_vm_writev : public Syscall_Args
  {
    Syscall_process_vm_writev(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 311;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto lvec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto liovcnt() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto rvec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](3));
    }

    auto riovcnt() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }

    auto flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](5));
    }
  };

  struct Syscall_kcmp : public Syscall_Args
  {
    Syscall_kcmp(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 312;

    auto pid1() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto pid2() const -> pid_t
    {
      return static_cast<pid_t>(operator[](1));
    }

    auto type() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto idx1() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto idx2() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }
  };

  struct Syscall_finit_module : public Syscall_Args
  {
    Syscall_finit_module(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 313;

    auto fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto uargs() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_sched_setattr : public Syscall_Args
  {
    Syscall_sched_setattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 314;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto attr() const -> struct sched_attr *
    {
      return reinterpret_cast<struct sched_attr *>(operator[](1));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }
  };

  struct Syscall_sched_getattr : public Syscall_Args
  {
    Syscall_sched_getattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 315;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto attr() const -> struct sched_attr *
    {
      return reinterpret_cast<struct sched_attr *>(operator[](1));
    }

    auto size() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](3));
    }
  };

  struct Syscall_renameat2 : public Syscall_Args
  {
    Syscall_renameat2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 316;

    auto olddfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto oldname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto newdfd() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto newname() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](3));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](4));
    }
  };

  struct Syscall_seccomp : public Syscall_Args
  {
    Syscall_seccomp(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 317;

    auto op() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto uargs() const -> void *
    {
      return reinterpret_cast<void *>(operator[](2));
    }
  };

  struct Syscall_getrandom : public Syscall_Args
  {
    Syscall_getrandom(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 318;

    auto buf() const -> char *
    {
      return reinterpret_cast<char *>(operator[](0));
    }

    auto count() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }
  };

  struct Syscall_memfd_create : public Syscall_Args
  {
    Syscall_memfd_create(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 319;

    auto uname_ptr() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }
  };

  struct Syscall_kexec_file_load : public Syscall_Args
  {
    Syscall_kexec_file_load(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 320;

    auto kernel_fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto initrd_fd() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto cmdline_len() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto cmdline_ptr() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](3));
    }

    auto flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }
  };

  struct Syscall_bpf : public Syscall_Args
  {
    Syscall_bpf(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 321;

    auto cmd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto attr() const -> union bpf_attr *
    {
      return reinterpret_cast<union bpf_attr *>(operator[](1));
    }

    auto size() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }
  };

  struct Syscall_execveat : public Syscall_Args
  {
    Syscall_execveat(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 322;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto argv() const -> const char *const *
    {
      return reinterpret_cast<const char *const *>(operator[](2));
    }

    auto envp() const -> const char *const *
    {
      return reinterpret_cast<const char *const *>(operator[](3));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](4));
    }
  };

  struct Syscall_userfaultfd : public Syscall_Args
  {
    Syscall_userfaultfd(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 323;

    auto flags() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_membarrier : public Syscall_Args
  {
    Syscall_membarrier(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 324;

    auto cmd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto cpu_id() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_mlock2 : public Syscall_Args
  {
    Syscall_mlock2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 325;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](2));
    }
  };

  struct Syscall_copy_file_range : public Syscall_Args
  {
    Syscall_copy_file_range(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 326;

    auto fd_in() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto off_in() const -> loff_t *
    {
      return reinterpret_cast<loff_t *>(operator[](1));
    }

    auto fd_out() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto off_out() const -> loff_t *
    {
      return reinterpret_cast<loff_t *>(operator[](3));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](4));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](5));
    }
  };

  struct Syscall_preadv2 : public Syscall_Args
  {
    Syscall_preadv2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 327;

    auto fd() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto vec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto vlen() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto pos_l() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto pos_h() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](5));
    }
  };

  struct Syscall_pwritev2 : public Syscall_Args
  {
    Syscall_pwritev2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 328;

    auto fd() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto vec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto vlen() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto pos_l() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](3));
    }

    auto pos_h() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](4));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](5));
    }
  };

  struct Syscall_pkey_mprotect : public Syscall_Args
  {
    Syscall_pkey_mprotect(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 329;

    auto start() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto len() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }

    auto prot() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](2));
    }

    auto pkey() const -> int
    {
      return static_cast<int>(operator[](3));
    }
  };

  struct Syscall_pkey_alloc : public Syscall_Args
  {
    Syscall_pkey_alloc(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 330;

    auto flags() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](0));
    }

    auto init_val() const -> unsigned long
    {
      return static_cast<unsigned long>(operator[](1));
    }
  };

  struct Syscall_pkey_free : public Syscall_Args
  {
    Syscall_pkey_free(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 331;

    auto pkey() const -> int
    {
      return static_cast<int>(operator[](0));
    }
  };

  struct Syscall_statx : public Syscall_Args
  {
    Syscall_statx(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 332;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto flags() const -> unsigned
    {
      return static_cast<unsigned>(operator[](2));
    }

    auto mask() const -> unsigned
    {
      return static_cast<unsigned>(operator[](3));
    }

    auto buffer() const -> struct statx *
    {
      return reinterpret_cast<struct statx *>(operator[](4));
    }
  };

  struct Syscall_rseq : public Syscall_Args
  {
    Syscall_rseq(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 334;

    auto rseq() const -> struct rseq *
    {
      return reinterpret_cast<struct rseq *>(operator[](0));
    }

    auto rseq_len() const -> uint32_t
    {
      return static_cast<uint32_t>(operator[](1));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto sig() const -> uint32_t
    {
      return static_cast<uint32_t>(operator[](3));
    }
  };

  struct Syscall_pidfd_send_signal : public Syscall_Args
  {
    Syscall_pidfd_send_signal(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 424;

    auto pidfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto sig() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto info() const -> siginfo_t *
    {
      return reinterpret_cast<siginfo_t *>(operator[](2));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](3));
    }
  };

  struct Syscall_io_uring_enter : public Syscall_Args
  {
    Syscall_io_uring_enter(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 426;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto to_submit() const -> uint32_t
    {
      return static_cast<uint32_t>(operator[](1));
    }

    auto min_complete() const -> uint32_t
    {
      return static_cast<uint32_t>(operator[](2));
    }

    auto flags() const -> uint32_t
    {
      return static_cast<uint32_t>(operator[](3));
    }

    auto argp() const -> const void *
    {
      return reinterpret_cast<const void *>(operator[](4));
    }

    auto argsz() const -> size_t
    {
      return static_cast<size_t>(operator[](5));
    }
  };

  struct Syscall_io_uring_register : public Syscall_Args
  {
    Syscall_io_uring_register(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 427;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto op() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto arg() const -> void *
    {
      return reinterpret_cast<void *>(operator[](2));
    }

    auto nr_args() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](3));
    }
  };

  struct Syscall_open_tree : public Syscall_Args
  {
    Syscall_open_tree(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 428;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto flags() const -> unsigned
    {
      return static_cast<unsigned>(operator[](2));
    }
  };

  struct Syscall_move_mount : public Syscall_Args
  {
    Syscall_move_mount(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 429;

    auto from_dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto from_path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto to_dfd() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto to_path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](3));
    }

    auto ms_flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](4));
    }
  };

  struct Syscall_fsopen : public Syscall_Args
  {
    Syscall_fsopen(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 430;

    auto fs_name() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](0));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }
  };

  struct Syscall_fsconfig : public Syscall_Args
  {
    Syscall_fsconfig(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 431;

    auto fs_fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto cmd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto key() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](2));
    }

    auto value() const -> const void *
    {
      return reinterpret_cast<const void *>(operator[](3));
    }

    auto aux() const -> int
    {
      return static_cast<int>(operator[](4));
    }
  };

  struct Syscall_fsmount : public Syscall_Args
  {
    Syscall_fsmount(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 432;

    auto fs_fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto ms_flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }
  };

  struct Syscall_fspick : public Syscall_Args
  {
    Syscall_fspick(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 433;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }
  };

  struct Syscall_pidfd_open : public Syscall_Args
  {
    Syscall_pidfd_open(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 434;

    auto pid() const -> pid_t
    {
      return static_cast<pid_t>(operator[](0));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }
  };

  struct Syscall_clone3 : public Syscall_Args
  {
    Syscall_clone3(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 435;

    auto uargs() const -> struct clone_args *
    {
      return reinterpret_cast<struct clone_args *>(operator[](0));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }
  };

  struct Syscall_close_range : public Syscall_Args
  {
    Syscall_close_range(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 436;

    auto fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](0));
    }

    auto max_fd() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](1));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }
  };

  struct Syscall_openat2 : public Syscall_Args
  {
    Syscall_openat2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 437;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto how() const -> struct open_how *
    {
      return reinterpret_cast<struct open_how *>(operator[](2));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](3));
    }
  };

  struct Syscall_pidfd_getfd : public Syscall_Args
  {
    Syscall_pidfd_getfd(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 438;

    auto pidfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto fd() const -> int
    {
      return static_cast<int>(operator[](1));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }
  };

  struct Syscall_faccessat2 : public Syscall_Args
  {
    Syscall_faccessat2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 439;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto filename() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto mode() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto flags() const -> int
    {
      return static_cast<int>(operator[](3));
    }
  };

  struct Syscall_process_madvise : public Syscall_Args
  {
    Syscall_process_madvise(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 440;

    auto pidfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto vec() const -> const struct iovec *
    {
      return reinterpret_cast<const struct iovec *>(operator[](1));
    }

    auto vlen() const -> size_t
    {
      return static_cast<size_t>(operator[](2));
    }

    auto behavior() const -> int
    {
      return static_cast<int>(operator[](3));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](4));
    }
  };

  struct Syscall_epoll_pwait2 : public Syscall_Args
  {
    Syscall_epoll_pwait2(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 441;

    auto epfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto events() const -> struct epoll_event *
    {
      return reinterpret_cast<struct epoll_event *>(operator[](1));
    }

    auto maxevents() const -> int
    {
      return static_cast<int>(operator[](2));
    }

    auto timeout() const -> const struct __kernel_timespec *
    {
      return reinterpret_cast<const struct __kernel_timespec *>(operator[](3));
    }

    auto SignMask() const -> const sigset_t *
    {
      return reinterpret_cast<const sigset_t *>(operator[](4));
    }

    auto sigsetsize() const -> size_t
    {
      return static_cast<size_t>(operator[](5));
    }
  };

  struct Syscall_mount_setattr : public Syscall_Args
  {
    Syscall_mount_setattr(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 442;

    auto dfd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto path() const -> const char *
    {
      return reinterpret_cast<const char *>(operator[](1));
    }

    auto flags() const -> unsigned int
    {
      return static_cast<unsigned int>(operator[](2));
    }

    auto uattr() const -> struct mount_attr *
    {
      return reinterpret_cast<struct mount_attr *>(operator[](3));
    }

    auto usize() const -> size_t
    {
      return static_cast<size_t>(operator[](4));
    }
  };

  struct Syscall_landlock_create_ruleset : public Syscall_Args
  {
    Syscall_landlock_create_ruleset(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 444;

    auto attr() const -> const struct landlock_ruleset_attr *
    {
      return reinterpret_cast<const struct landlock_ruleset_attr *>(operator[](0));
    }

    auto size() const -> size_t
    {
      return static_cast<size_t>(operator[](1));
    }

    auto flags() const -> __uint32_t
    {
      return static_cast<__uint32_t>(operator[](2));
    }
  };

  struct Syscall_landlock_restrict_self : public Syscall_Args
  {
    Syscall_landlock_restrict_self(Syscall_Args args) : Syscall_Args(args) {}

    static SyscallDataType constexpr syscall_id = 446;

    auto ruleset_fd() const -> int
    {
      return static_cast<int>(operator[](0));
    }

    auto flags() const -> __uint32_t
    {
      return static_cast<__uint32_t>(operator[](1));
    }
  };

  // Unsupported: Syscall(id=7, name='poll', kernal_internal_function_name='sys_poll', params=[Param(cpptype='struct pollfd *', name='ufds'), Param(cpptype='unsigned int', name='nfds'), Param(cpptype='int', name='timeout')], supported=False)
  // Unsupported: Syscall(id=13, name='rt_sigaction', kernal_internal_function_name='sys_rt_sigaction', params=[Param(cpptype='int', name=''), Param(cpptype='const struct sigaction *', name=''), Param(cpptype='struct sigaction *', name=''), Param(cpptype='size_t', name='')], supported=False)
  // Unsupported: Syscall(id=23, name='select', kernal_internal_function_name='sys_select', params=[Param(cpptype='int', name='n'), Param(cpptype='fd_set *', name='inp'), Param(cpptype='fd_set *', name='outp'), Param(cpptype='fd_set *', name='exp'), Param(cpptype='struct __kernel_timeval *', name='tvp')], supported=False)
  // Unsupported: Syscall(id=31, name='shmctl', kernal_internal_function_name='sys_shmctl', params=[Param(cpptype='int', name='shmid'), Param(cpptype='int', name='cmd'), Param(cpptype='struct shmid_ds *', name='buf')], supported=False)
  // Unsupported: Syscall(id=36, name='getitimer', kernal_internal_function_name='sys_getitimer', params=[Param(cpptype='int', name='which'), Param(cpptype='struct __kernel_itimerval *', name='value')], supported=False)
  // Unsupported: Syscall(id=38, name='setitimer', kernal_internal_function_name='sys_setitimer', params=[Param(cpptype='int', name='which'), Param(cpptype='struct __kernel_itimerval *', name='value'), Param(cpptype='struct __kernel_itimerval *', name='ovalue')], supported=False)
  // Unsupported: Syscall(id=46, name='sendmsg', kernal_internal_function_name='sys_sendmsg', params=[Param(cpptype='int', name='fd'), Param(cpptype='struct user_msghdr *', name='msg'), Param(cpptype='unsigned', name='flags')], supported=False)
  // Unsupported: Syscall(id=47, name='recvmsg', kernal_internal_function_name='sys_recvmsg', params=[Param(cpptype='int', name='fd'), Param(cpptype='struct user_msghdr *', name='msg'), Param(cpptype='unsigned', name='flags')], supported=False)
  // Unsupported: Syscall(id=61, name='wait4', kernal_internal_function_name='sys_wait4', params=[Param(cpptype='pid_t', name='pid'), Param(cpptype='int *', name='stat_addr'), Param(cpptype='int', name='options'), Param(cpptype='struct rusage *', name='ru')], supported=False)
  // Unsupported: Syscall(id=63, name='uname', kernal_internal_function_name='sys_newuname', params=[Param(cpptype='struct new_utsname *', name='name')], supported=False)
  // Unsupported: Syscall(id=65, name='semop', kernal_internal_function_name='sys_semop', params=[Param(cpptype='int', name='semid'), Param(cpptype='struct sembuf *', name='sops'), Param(cpptype='unsigned', name='nsops')], supported=False)
  // Unsupported: Syscall(id=69, name='msgsnd', kernal_internal_function_name='sys_msgsnd', params=[Param(cpptype='int', name='msqid'), Param(cpptype='struct msgbuf *', name='msgp'), Param(cpptype='size_t', name='msgsz'), Param(cpptype='int', name='msgflg')], supported=False)
  // Unsupported: Syscall(id=70, name='msgrcv', kernal_internal_function_name='sys_msgrcv', params=[Param(cpptype='int', name='msqid'), Param(cpptype='struct msgbuf *', name='msgp'), Param(cpptype='size_t', name='msgsz'), Param(cpptype='long', name='msgtyp'), Param(cpptype='int', name='msgflg')], supported=False)
  // Unsupported: Syscall(id=71, name='msgctl', kernal_internal_function_name='sys_msgctl', params=[Param(cpptype='int', name='msqid'), Param(cpptype='int', name='cmd'), Param(cpptype='struct msqid_ds *', name='buf')], supported=False)
  // Unsupported: Syscall(id=78, name='getdents', kernal_internal_function_name='sys_getdents', params=[Param(cpptype='unsigned int', name='fd'), Param(cpptype='struct linux_dirent *', name='dirent'), Param(cpptype='unsigned int', name='count')], supported=False)
  // Unsupported: Syscall(id=96, name='gettimeofday', kernal_internal_function_name='sys_gettimeofday', params=[Param(cpptype='struct __kernel_timeval *', name='tv'), Param(cpptype='struct timezone *', name='tz')], supported=False)
  // Unsupported: Syscall(id=97, name='getrlimit', kernal_internal_function_name='sys_getrlimit', params=[Param(cpptype='unsigned int', name='resource'), Param(cpptype='struct rlimit *', name='rlim')], supported=False)
  // Unsupported: Syscall(id=98, name='getrusage', kernal_internal_function_name='sys_getrusage', params=[Param(cpptype='int', name='who'), Param(cpptype='struct rusage *', name='ru')], supported=False)
  // Unsupported: Syscall(id=99, name='sysinfo', kernal_internal_function_name='sys_sysinfo', params=[Param(cpptype='struct sysinfo *', name='info')], supported=False)
  // Unsupported: Syscall(id=100, name='times', kernal_internal_function_name='sys_times', params=[Param(cpptype='struct tms *', name='tbuf')], supported=False)
  // Unsupported: Syscall(id=125, name='capget', kernal_internal_function_name='sys_capget', params=[Param(cpptype='cap_user_header_t', name='header'), Param(cpptype='cap_user_data_t', name='dataptr')], supported=False)
  // Unsupported: Syscall(id=126, name='capset', kernal_internal_function_name='sys_capset', params=[Param(cpptype='cap_user_header_t', name='header'), Param(cpptype='const cap_user_data_t', name='data')], supported=False)
  // Unsupported: Syscall(id=132, name='utime', kernal_internal_function_name='sys_utime', params=[Param(cpptype='char *', name='filename'), Param(cpptype='struct utimbuf *', name='times')], supported=False)
  // Unsupported: Syscall(id=134, name='uselib', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=142, name='sched_setparam', kernal_internal_function_name='sys_sched_setparam', params=[Param(cpptype='pid_t', name='pid'), Param(cpptype='struct sched_param *', name='param')], supported=False)
  // Unsupported: Syscall(id=143, name='sched_getparam', kernal_internal_function_name='sys_sched_getparam', params=[Param(cpptype='pid_t', name='pid'), Param(cpptype='struct sched_param *', name='param')], supported=False)
  // Unsupported: Syscall(id=144, name='sched_setscheduler', kernal_internal_function_name='sys_sched_setscheduler', params=[Param(cpptype='pid_t', name='pid'), Param(cpptype='int', name='policy'), Param(cpptype='struct sched_param *', name='param')], supported=False)
  // Unsupported: Syscall(id=159, name='adjtimex', kernal_internal_function_name='sys_adjtimex', params=[Param(cpptype='struct __kernel_timex *', name='txc_p')], supported=False)
  // Unsupported: Syscall(id=160, name='setrlimit', kernal_internal_function_name='sys_setrlimit', params=[Param(cpptype='unsigned int', name='resource'), Param(cpptype='struct rlimit *', name='rlim')], supported=False)
  // Unsupported: Syscall(id=164, name='settimeofday', kernal_internal_function_name='sys_settimeofday', params=[Param(cpptype='struct __kernel_timeval *', name='tv'), Param(cpptype='struct timezone *', name='tz')], supported=False)
  // Unsupported: Syscall(id=174, name='create_module', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=177, name='get_kernel_syms', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=178, name='query_module', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=180, name='nfsservctl', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=181, name='getpmsg', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=182, name='putpmsg', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=183, name='afs_syscall', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=184, name='tuxcall', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=185, name='security', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=205, name='set_thread_area', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=209, name='io_submit', kernal_internal_function_name='sys_io_submit', params=[Param(cpptype='aio_context_t', name=''), Param(cpptype='long', name=''), Param(cpptype='struct iocb * *', name='')], supported=False)
  // Unsupported: Syscall(id=210, name='io_cancel', kernal_internal_function_name='sys_io_cancel', params=[Param(cpptype='aio_context_t', name='ctx_id'), Param(cpptype='struct iocb *', name='iocb'), Param(cpptype='struct io_event *', name='result')], supported=False)
  // Unsupported: Syscall(id=211, name='get_thread_area', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=214, name='epoll_ctl_old', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=215, name='epoll_wait_old', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=217, name='getdents64', kernal_internal_function_name='sys_getdents64', params=[Param(cpptype='unsigned int', name='fd'), Param(cpptype='struct linux_dirent64 *', name='dirent'), Param(cpptype='unsigned int', name='count')], supported=False)
  // Unsupported: Syscall(id=220, name='semtimedop', kernal_internal_function_name='sys_semtimedop', params=[Param(cpptype='int', name='semid'), Param(cpptype='struct sembuf *', name='sops'), Param(cpptype='unsigned', name='nsops'), Param(cpptype='const struct __kernel_timespec *', name='timeout')], supported=False)
  // Unsupported: Syscall(id=235, name='utimes', kernal_internal_function_name='sys_utimes', params=[Param(cpptype='char *', name='filename'), Param(cpptype='struct __kernel_timeval *', name='utimes')], supported=False)
  // Unsupported: Syscall(id=236, name='vserver', kernal_internal_function_name=None, params=[], supported=False)
  // Unsupported: Syscall(id=246, name='kexec_load', kernal_internal_function_name='sys_kexec_load', params=[Param(cpptype='unsigned long', name='entry'), Param(cpptype='unsigned long', name='nr_segments'), Param(cpptype='struct kexec_segment *', name='segments'), Param(cpptype='unsigned long', name='flags')], supported=False)
  // Unsupported: Syscall(id=247, name='waitid', kernal_internal_function_name='sys_waitid', params=[Param(cpptype='int', name='which'), Param(cpptype='pid_t', name='pid'), Param(cpptype='struct siginfo *', name='infop'), Param(cpptype='int', name='options'), Param(cpptype='struct rusage *', name='ru')], supported=False)
  // Unsupported: Syscall(id=248, name='add_key', kernal_internal_function_name='sys_add_key', params=[Param(cpptype='const char *', name='_type'), Param(cpptype='const char *', name='_description'), Param(cpptype='const void *', name='_payload'), Param(cpptype='size_t', name='plen'), Param(cpptype='key_serial_t', name='destringid')], supported=False)
  // Unsupported: Syscall(id=249, name='request_key', kernal_internal_function_name='sys_request_key', params=[Param(cpptype='const char *', name='_type'), Param(cpptype='const char *', name='_description'), Param(cpptype='const char *', name='_callout_info'), Param(cpptype='key_serial_t', name='destringid')], supported=False)
  // Unsupported: Syscall(id=261, name='futimesat', kernal_internal_function_name='sys_futimesat', params=[Param(cpptype='int', name='dfd'), Param(cpptype='const char *', name='filename'), Param(cpptype='struct __kernel_timeval *', name='utimes')], supported=False)
  // Unsupported: Syscall(id=271, name='ppoll', kernal_internal_function_name='sys_ppoll', params=[Param(cpptype='struct pollfd *', name=''), Param(cpptype='unsigned int', name=''), Param(cpptype='struct __kernel_timespec *', name=''), Param(cpptype='const sigset_t *', name=''), Param(cpptype='size_t', name='')], supported=False)
  // Unsupported: Syscall(id=273, name='set_robust_list', kernal_internal_function_name='sys_set_robust_list', params=[Param(cpptype='struct robust_list_head *', name='head'), Param(cpptype='size_t', name='len')], supported=False)
  // Unsupported: Syscall(id=274, name='get_robust_list', kernal_internal_function_name='sys_get_robust_list', params=[Param(cpptype='int', name='pid'), Param(cpptype='struct robust_list_head * *', name='head_ptr'), Param(cpptype='size_t *', name='len_ptr')], supported=False)
  // Unsupported: Syscall(id=298, name='perf_event_open', kernal_internal_function_name='sys_perf_event_open', params=[Param(cpptype='struct perf_event_attr *', name='attr_uptr'), Param(cpptype='pid_t', name='pid'), Param(cpptype='int', name='cpu'), Param(cpptype='int', name='group_fd'), Param(cpptype='unsigned long', name='flags')], supported=False)
  // Unsupported: Syscall(id=302, name='prlimit64', kernal_internal_function_name='sys_prlimit64', params=[Param(cpptype='pid_t', name='pid'), Param(cpptype='unsigned int', name='resource'), Param(cpptype='const struct rlimit64 *', name='new_rlim'), Param(cpptype='struct rlimit64 *', name='old_rlim')], supported=False)
  // Unsupported: Syscall(id=305, name='clock_adjtime', kernal_internal_function_name='sys_clock_adjtime', params=[Param(cpptype='clockid_t', name='which_clock'), Param(cpptype='struct __kernel_timex *', name='tx')], supported=False)
  // Unsupported: Syscall(id=333, name='io_pgetevents', kernal_internal_function_name='sys_io_pgetevents', params=[Param(cpptype='aio_context_t', name='ctx_id'), Param(cpptype='long', name='min_nr'), Param(cpptype='long', name='nr'), Param(cpptype='struct io_event *', name='events'), Param(cpptype='struct __kernel_timespec *', name='timeout'), Param(cpptype='const struct __aio_sigset *', name='sig')], supported=False)
  // Unsupported: Syscall(id=425, name='io_uring_setup', kernal_internal_function_name='sys_io_uring_setup', params=[Param(cpptype='uint32_t', name='entries'), Param(cpptype='struct io_uring_params *', name='p')], supported=False)
  // Unsupported: Syscall(id=445, name='landlock_add_rule', kernal_internal_function_name='sys_landlock_add_rule', params=[Param(cpptype='int', name='ruleset_fd'), Param(cpptype='enum landlock_rule_type', name='rule_type'), Param(cpptype='const void *', name='rule_attr'), Param(cpptype='__uint32_t', name='flags')], supported=False)
} // namespace
