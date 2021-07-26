// Generated via ../gpcache/code_generator/generate_syscalls.py
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
#include <sys/uio.h>

namespace gpcache
{

  using SyscallDataType = decltype(user_regs_struct{}.rax);

  struct Event_Unsupported
  {
    SyscallDataType syscall_id;
    SyscallDataType arg1;
    SyscallDataType arg2;
    SyscallDataType arg3;
    SyscallDataType arg4;
    SyscallDataType arg5;
    SyscallDataType arg6;
  };

  struct Event_read
  {
    static SyscallDataType constexpr syscall_id = 0;
    unsigned int fd;
    char *buf;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_write
  {
    static SyscallDataType constexpr syscall_id = 1;
    unsigned int fd;
    const char *buf;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_open
  {
    static SyscallDataType constexpr syscall_id = 2;
    const char *filename;
    int flags;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_close
  {
    static SyscallDataType constexpr syscall_id = 3;
    unsigned int fd;
    SyscallDataType return_value;
  };

  struct Event_stat
  {
    static SyscallDataType constexpr syscall_id = 4;
    const char *filename;
    struct stat *statbuf;
    SyscallDataType return_value;
  };

  struct Event_fstat
  {
    static SyscallDataType constexpr syscall_id = 5;
    unsigned int fd;
    struct stat *statbuf;
    SyscallDataType return_value;
  };

  struct Event_lstat
  {
    static SyscallDataType constexpr syscall_id = 6;
    const char *filename;
    struct stat *statbuf;
    SyscallDataType return_value;
  };

  struct Event_lseek
  {
    static SyscallDataType constexpr syscall_id = 8;
    unsigned int fd;
    off_t offset;
    unsigned int whence;
    SyscallDataType return_value;
  };

  struct Event_mmap
  {
    static SyscallDataType constexpr syscall_id = 9;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    off_t pgoff;
    SyscallDataType return_value;
  };

  struct Event_mprotect
  {
    static SyscallDataType constexpr syscall_id = 10;
    unsigned long start;
    size_t len;
    unsigned long prot;
    SyscallDataType return_value;
  };

  struct Event_munmap
  {
    static SyscallDataType constexpr syscall_id = 11;
    unsigned long addr;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_brk
  {
    static SyscallDataType constexpr syscall_id = 12;
    unsigned long brk;
    SyscallDataType return_value;
  };

  struct Event_rt_sigprocmask
  {
    static SyscallDataType constexpr syscall_id = 14;
    int how;
    sigset_t *set;
    sigset_t *oset;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_rt_sigreturn
  {
    static SyscallDataType constexpr syscall_id = 15;
    struct pt_regs *regs;
    SyscallDataType return_value;
  };

  struct Event_ioctl
  {
    static SyscallDataType constexpr syscall_id = 16;
    unsigned int fd;
    unsigned int cmd;
    unsigned long arg;
    SyscallDataType return_value;
  };

  struct Event_pread64
  {
    static SyscallDataType constexpr syscall_id = 17;
    unsigned int fd;
    char *buf;
    size_t count;
    loff_t pos;
    SyscallDataType return_value;
  };

  struct Event_pwrite64
  {
    static SyscallDataType constexpr syscall_id = 18;
    unsigned int fd;
    const char *buf;
    size_t count;
    loff_t pos;
    SyscallDataType return_value;
  };

  struct Event_readv
  {
    static SyscallDataType constexpr syscall_id = 19;
    unsigned long fd;
    const struct iovec *vec;
    unsigned long vlen;
    SyscallDataType return_value;
  };

  struct Event_writev
  {
    static SyscallDataType constexpr syscall_id = 20;
    unsigned long fd;
    const struct iovec *vec;
    unsigned long vlen;
    SyscallDataType return_value;
  };

  struct Event_access
  {
    static SyscallDataType constexpr syscall_id = 21;
    const char *filename;
    int mode;
    SyscallDataType return_value;
  };

  struct Event_pipe
  {
    static SyscallDataType constexpr syscall_id = 22;
    int *fildes;
    SyscallDataType return_value;
  };

  struct Event_sched_yield
  {
    static SyscallDataType constexpr syscall_id = 24;
    SyscallDataType return_value;
  };

  struct Event_mremap
  {
    static SyscallDataType constexpr syscall_id = 25;
    unsigned long addr;
    unsigned long old_len;
    unsigned long new_len;
    unsigned long flags;
    unsigned long new_addr;
    SyscallDataType return_value;
  };

  struct Event_msync
  {
    static SyscallDataType constexpr syscall_id = 26;
    unsigned long start;
    size_t len;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_mincore
  {
    static SyscallDataType constexpr syscall_id = 27;
    unsigned long start;
    size_t len;
    unsigned char *vec;
    SyscallDataType return_value;
  };

  struct Event_madvise
  {
    static SyscallDataType constexpr syscall_id = 28;
    unsigned long start;
    size_t len;
    int behavior;
    SyscallDataType return_value;
  };

  struct Event_shmget
  {
    static SyscallDataType constexpr syscall_id = 29;
    key_t key;
    size_t size;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_shmat
  {
    static SyscallDataType constexpr syscall_id = 30;
    int shmid;
    char *shmaddr;
    int shmflg;
    SyscallDataType return_value;
  };

  struct Event_dup
  {
    static SyscallDataType constexpr syscall_id = 32;
    unsigned int fildes;
    SyscallDataType return_value;
  };

  struct Event_dup2
  {
    static SyscallDataType constexpr syscall_id = 33;
    unsigned int oldfd;
    unsigned int newfd;
    SyscallDataType return_value;
  };

  struct Event_pause
  {
    static SyscallDataType constexpr syscall_id = 34;
    SyscallDataType return_value;
  };

  struct Event_nanosleep
  {
    static SyscallDataType constexpr syscall_id = 35;
    struct __kernel_timespec *rqtp;
    struct __kernel_timespec *rmtp;
    SyscallDataType return_value;
  };

  struct Event_alarm
  {
    static SyscallDataType constexpr syscall_id = 37;
    unsigned int seconds;
    SyscallDataType return_value;
  };

  struct Event_getpid
  {
    static SyscallDataType constexpr syscall_id = 39;
    SyscallDataType return_value;
  };

  struct Event_sendfile
  {
    static SyscallDataType constexpr syscall_id = 40;
    int out_fd;
    int in_fd;
    loff_t *offset;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_socket
  {
    static SyscallDataType constexpr syscall_id = 41;
    int unnamed0;
    int unnamed1;
    int unnamed2;
    SyscallDataType return_value;
  };

  struct Event_connect
  {
    static SyscallDataType constexpr syscall_id = 42;
    int unnamed0;
    struct sockaddr *unnamed1;
    int unnamed2;
    SyscallDataType return_value;
  };

  struct Event_accept
  {
    static SyscallDataType constexpr syscall_id = 43;
    int unnamed0;
    struct sockaddr *unnamed1;
    int *unnamed2;
    SyscallDataType return_value;
  };

  struct Event_sendto
  {
    static SyscallDataType constexpr syscall_id = 44;
    int unnamed0;
    void *unnamed1;
    size_t unnamed2;
    unsigned unnamed3;
    struct sockaddr *unnamed4;
    int unnamed5;
    SyscallDataType return_value;
  };

  struct Event_recvfrom
  {
    static SyscallDataType constexpr syscall_id = 45;
    int unnamed0;
    void *unnamed1;
    size_t unnamed2;
    unsigned unnamed3;
    struct sockaddr *unnamed4;
    int *unnamed5;
    SyscallDataType return_value;
  };

  struct Event_shutdown
  {
    static SyscallDataType constexpr syscall_id = 48;
    int unnamed0;
    int unnamed1;
    SyscallDataType return_value;
  };

  struct Event_bind
  {
    static SyscallDataType constexpr syscall_id = 49;
    int unnamed0;
    struct sockaddr *unnamed1;
    int unnamed2;
    SyscallDataType return_value;
  };

  struct Event_listen
  {
    static SyscallDataType constexpr syscall_id = 50;
    int unnamed0;
    int unnamed1;
    SyscallDataType return_value;
  };

  struct Event_getsockname
  {
    static SyscallDataType constexpr syscall_id = 51;
    int unnamed0;
    struct sockaddr *unnamed1;
    int *unnamed2;
    SyscallDataType return_value;
  };

  struct Event_getpeername
  {
    static SyscallDataType constexpr syscall_id = 52;
    int unnamed0;
    struct sockaddr *unnamed1;
    int *unnamed2;
    SyscallDataType return_value;
  };

  struct Event_socketpair
  {
    static SyscallDataType constexpr syscall_id = 53;
    int unnamed0;
    int unnamed1;
    int unnamed2;
    int *unnamed3;
    SyscallDataType return_value;
  };

  struct Event_setsockopt
  {
    static SyscallDataType constexpr syscall_id = 54;
    int fd;
    int level;
    int optname;
    char *optval;
    int optlen;
    SyscallDataType return_value;
  };

  struct Event_getsockopt
  {
    static SyscallDataType constexpr syscall_id = 55;
    int fd;
    int level;
    int optname;
    char *optval;
    int *optlen;
    SyscallDataType return_value;
  };

  struct Event_clone
  {
    static SyscallDataType constexpr syscall_id = 56;
    unsigned long unnamed0;
    unsigned long unnamed1;
    int *unnamed2;
    unsigned long unnamed3;
    int *unnamed4;
    unsigned long unnamed5;
    unsigned long unnamed6;
    int unnamed7;
    int *unnamed8;
    int *unnamed9;
    unsigned long unnamed10;
    unsigned long unnamed11;
    unsigned long unnamed12;
    int *unnamed13;
    int *unnamed14;
    unsigned long unnamed15;
    SyscallDataType return_value;
  };

  struct Event_fork
  {
    static SyscallDataType constexpr syscall_id = 57;
    SyscallDataType return_value;
  };

  struct Event_vfork
  {
    static SyscallDataType constexpr syscall_id = 58;
    SyscallDataType return_value;
  };

  struct Event_execve
  {
    static SyscallDataType constexpr syscall_id = 59;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
    SyscallDataType return_value;
  };

  struct Event_exit
  {
    static SyscallDataType constexpr syscall_id = 60;
    int error_code;
    SyscallDataType return_value;
  };

  struct Event_kill
  {
    static SyscallDataType constexpr syscall_id = 62;
    pid_t pid;
    int sig;
    SyscallDataType return_value;
  };

  struct Event_semget
  {
    static SyscallDataType constexpr syscall_id = 64;
    key_t key;
    int nsems;
    int semflg;
    SyscallDataType return_value;
  };

  struct Event_semctl
  {
    static SyscallDataType constexpr syscall_id = 66;
    int semid;
    int semnum;
    int cmd;
    unsigned long arg;
    SyscallDataType return_value;
  };

  struct Event_shmdt
  {
    static SyscallDataType constexpr syscall_id = 67;
    char *shmaddr;
    SyscallDataType return_value;
  };

  struct Event_msgget
  {
    static SyscallDataType constexpr syscall_id = 68;
    key_t key;
    int msgflg;
    SyscallDataType return_value;
  };

  struct Event_fcntl
  {
    static SyscallDataType constexpr syscall_id = 72;
    unsigned int fd;
    unsigned int cmd;
    unsigned long arg;
    SyscallDataType return_value;
  };

  struct Event_flock
  {
    static SyscallDataType constexpr syscall_id = 73;
    unsigned int fd;
    unsigned int cmd;
    SyscallDataType return_value;
  };

  struct Event_fsync
  {
    static SyscallDataType constexpr syscall_id = 74;
    unsigned int fd;
    SyscallDataType return_value;
  };

  struct Event_fdatasync
  {
    static SyscallDataType constexpr syscall_id = 75;
    unsigned int fd;
    SyscallDataType return_value;
  };

  struct Event_truncate
  {
    static SyscallDataType constexpr syscall_id = 76;
    const char *path;
    long length;
    SyscallDataType return_value;
  };

  struct Event_ftruncate
  {
    static SyscallDataType constexpr syscall_id = 77;
    unsigned int fd;
    unsigned long length;
    SyscallDataType return_value;
  };

  struct Event_getcwd
  {
    static SyscallDataType constexpr syscall_id = 79;
    char *buf;
    unsigned long size;
    SyscallDataType return_value;
  };

  struct Event_chdir
  {
    static SyscallDataType constexpr syscall_id = 80;
    const char *filename;
    SyscallDataType return_value;
  };

  struct Event_fchdir
  {
    static SyscallDataType constexpr syscall_id = 81;
    unsigned int fd;
    SyscallDataType return_value;
  };

  struct Event_rename
  {
    static SyscallDataType constexpr syscall_id = 82;
    const char *oldname;
    const char *newname;
    SyscallDataType return_value;
  };

  struct Event_mkdir
  {
    static SyscallDataType constexpr syscall_id = 83;
    const char *pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_rmdir
  {
    static SyscallDataType constexpr syscall_id = 84;
    const char *pathname;
    SyscallDataType return_value;
  };

  struct Event_creat
  {
    static SyscallDataType constexpr syscall_id = 85;
    const char *pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_link
  {
    static SyscallDataType constexpr syscall_id = 86;
    const char *oldname;
    const char *newname;
    SyscallDataType return_value;
  };

  struct Event_unlink
  {
    static SyscallDataType constexpr syscall_id = 87;
    const char *pathname;
    SyscallDataType return_value;
  };

  struct Event_symlink
  {
    static SyscallDataType constexpr syscall_id = 88;
    const char *old;
    const char *new__;
    SyscallDataType return_value;
  };

  struct Event_readlink
  {
    static SyscallDataType constexpr syscall_id = 89;
    const char *path;
    char *buf;
    int bufsiz;
    SyscallDataType return_value;
  };

  struct Event_chmod
  {
    static SyscallDataType constexpr syscall_id = 90;
    const char *filename;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_fchmod
  {
    static SyscallDataType constexpr syscall_id = 91;
    unsigned int fd;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_chown
  {
    static SyscallDataType constexpr syscall_id = 92;
    const char *filename;
    uid_t user;
    gid_t group;
    SyscallDataType return_value;
  };

  struct Event_fchown
  {
    static SyscallDataType constexpr syscall_id = 93;
    unsigned int fd;
    uid_t user;
    gid_t group;
    SyscallDataType return_value;
  };

  struct Event_lchown
  {
    static SyscallDataType constexpr syscall_id = 94;
    const char *filename;
    uid_t user;
    gid_t group;
    SyscallDataType return_value;
  };

  struct Event_umask
  {
    static SyscallDataType constexpr syscall_id = 95;
    int mask;
    SyscallDataType return_value;
  };

  struct Event_ptrace
  {
    static SyscallDataType constexpr syscall_id = 101;
    long request;
    long pid;
    unsigned long addr;
    unsigned long data;
    SyscallDataType return_value;
  };

  struct Event_getuid
  {
    static SyscallDataType constexpr syscall_id = 102;
    SyscallDataType return_value;
  };

  struct Event_syslog
  {
    static SyscallDataType constexpr syscall_id = 103;
    int type;
    char *buf;
    int len;
    SyscallDataType return_value;
  };

  struct Event_getgid
  {
    static SyscallDataType constexpr syscall_id = 104;
    SyscallDataType return_value;
  };

  struct Event_setuid
  {
    static SyscallDataType constexpr syscall_id = 105;
    uid_t uid;
    SyscallDataType return_value;
  };

  struct Event_setgid
  {
    static SyscallDataType constexpr syscall_id = 106;
    gid_t gid;
    SyscallDataType return_value;
  };

  struct Event_geteuid
  {
    static SyscallDataType constexpr syscall_id = 107;
    SyscallDataType return_value;
  };

  struct Event_getegid
  {
    static SyscallDataType constexpr syscall_id = 108;
    SyscallDataType return_value;
  };

  struct Event_setpgid
  {
    static SyscallDataType constexpr syscall_id = 109;
    pid_t pid;
    pid_t pgid;
    SyscallDataType return_value;
  };

  struct Event_getppid
  {
    static SyscallDataType constexpr syscall_id = 110;
    SyscallDataType return_value;
  };

  struct Event_getpgrp
  {
    static SyscallDataType constexpr syscall_id = 111;
    SyscallDataType return_value;
  };

  struct Event_setsid
  {
    static SyscallDataType constexpr syscall_id = 112;
    SyscallDataType return_value;
  };

  struct Event_setreuid
  {
    static SyscallDataType constexpr syscall_id = 113;
    uid_t ruid;
    uid_t euid;
    SyscallDataType return_value;
  };

  struct Event_setregid
  {
    static SyscallDataType constexpr syscall_id = 114;
    gid_t rgid;
    gid_t egid;
    SyscallDataType return_value;
  };

  struct Event_getgroups
  {
    static SyscallDataType constexpr syscall_id = 115;
    int gidsetsize;
    gid_t *grouplist;
    SyscallDataType return_value;
  };

  struct Event_setgroups
  {
    static SyscallDataType constexpr syscall_id = 116;
    int gidsetsize;
    gid_t *grouplist;
    SyscallDataType return_value;
  };

  struct Event_setresuid
  {
    static SyscallDataType constexpr syscall_id = 117;
    uid_t ruid;
    uid_t euid;
    uid_t suid;
    SyscallDataType return_value;
  };

  struct Event_getresuid
  {
    static SyscallDataType constexpr syscall_id = 118;
    uid_t *ruid;
    uid_t *euid;
    uid_t *suid;
    SyscallDataType return_value;
  };

  struct Event_setresgid
  {
    static SyscallDataType constexpr syscall_id = 119;
    gid_t rgid;
    gid_t egid;
    gid_t sgid;
    SyscallDataType return_value;
  };

  struct Event_getresgid
  {
    static SyscallDataType constexpr syscall_id = 120;
    gid_t *rgid;
    gid_t *egid;
    gid_t *sgid;
    SyscallDataType return_value;
  };

  struct Event_getpgid
  {
    static SyscallDataType constexpr syscall_id = 121;
    pid_t pid;
    SyscallDataType return_value;
  };

  struct Event_setfsuid
  {
    static SyscallDataType constexpr syscall_id = 122;
    uid_t uid;
    SyscallDataType return_value;
  };

  struct Event_setfsgid
  {
    static SyscallDataType constexpr syscall_id = 123;
    gid_t gid;
    SyscallDataType return_value;
  };

  struct Event_getsid
  {
    static SyscallDataType constexpr syscall_id = 124;
    pid_t pid;
    SyscallDataType return_value;
  };

  struct Event_rt_sigpending
  {
    static SyscallDataType constexpr syscall_id = 127;
    sigset_t *set;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_rt_sigtimedwait
  {
    static SyscallDataType constexpr syscall_id = 128;
    const sigset_t *uthese;
    siginfo_t *uinfo;
    const struct __kernel_timespec *uts;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_rt_sigqueueinfo
  {
    static SyscallDataType constexpr syscall_id = 129;
    pid_t pid;
    int sig;
    siginfo_t *uinfo;
    SyscallDataType return_value;
  };

  struct Event_rt_sigsuspend
  {
    static SyscallDataType constexpr syscall_id = 130;
    sigset_t *unewset;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_sigaltstack
  {
    static SyscallDataType constexpr syscall_id = 131;
    const struct sigaltstack *uss;
    struct sigaltstack *uoss;
    SyscallDataType return_value;
  };

  struct Event_mknod
  {
    static SyscallDataType constexpr syscall_id = 133;
    const char *filename;
    mode_t mode;
    unsigned dev;
    SyscallDataType return_value;
  };

  struct Event_personality
  {
    static SyscallDataType constexpr syscall_id = 135;
    unsigned int personality;
    SyscallDataType return_value;
  };

  struct Event_ustat
  {
    static SyscallDataType constexpr syscall_id = 136;
    unsigned dev;
    struct ustat *ubuf;
    SyscallDataType return_value;
  };

  struct Event_statfs
  {
    static SyscallDataType constexpr syscall_id = 137;
    const char *path;
    struct statfs *buf;
    SyscallDataType return_value;
  };

  struct Event_fstatfs
  {
    static SyscallDataType constexpr syscall_id = 138;
    unsigned int fd;
    struct statfs *buf;
    SyscallDataType return_value;
  };

  struct Event_sysfs
  {
    static SyscallDataType constexpr syscall_id = 139;
    int option;
    unsigned long arg1;
    unsigned long arg2;
    SyscallDataType return_value;
  };

  struct Event_getpriority
  {
    static SyscallDataType constexpr syscall_id = 140;
    int which;
    int who;
    SyscallDataType return_value;
  };

  struct Event_setpriority
  {
    static SyscallDataType constexpr syscall_id = 141;
    int which;
    int who;
    int niceval;
    SyscallDataType return_value;
  };

  struct Event_sched_getscheduler
  {
    static SyscallDataType constexpr syscall_id = 145;
    pid_t pid;
    SyscallDataType return_value;
  };

  struct Event_sched_get_priority_max
  {
    static SyscallDataType constexpr syscall_id = 146;
    int policy;
    SyscallDataType return_value;
  };

  struct Event_sched_get_priority_min
  {
    static SyscallDataType constexpr syscall_id = 147;
    int policy;
    SyscallDataType return_value;
  };

  struct Event_sched_rr_get_interval
  {
    static SyscallDataType constexpr syscall_id = 148;
    pid_t pid;
    struct __kernel_timespec *interval;
    SyscallDataType return_value;
  };

  struct Event_mlock
  {
    static SyscallDataType constexpr syscall_id = 149;
    unsigned long start;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_munlock
  {
    static SyscallDataType constexpr syscall_id = 150;
    unsigned long start;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_mlockall
  {
    static SyscallDataType constexpr syscall_id = 151;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_munlockall
  {
    static SyscallDataType constexpr syscall_id = 152;
    SyscallDataType return_value;
  };

  struct Event_vhangup
  {
    static SyscallDataType constexpr syscall_id = 153;
    SyscallDataType return_value;
  };

  struct Event_modify_ldt
  {
    static SyscallDataType constexpr syscall_id = 154;
    SyscallDataType return_value;
  };

  struct Event_pivot_root
  {
    static SyscallDataType constexpr syscall_id = 155;
    const char *new_root;
    const char *put_old;
    SyscallDataType return_value;
  };

  struct Event__sysctl
  {
    static SyscallDataType constexpr syscall_id = 156;
    SyscallDataType return_value;
  };

  struct Event_prctl
  {
    static SyscallDataType constexpr syscall_id = 157;
    int option;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    SyscallDataType return_value;
  };

  struct Event_arch_prctl
  {
    static SyscallDataType constexpr syscall_id = 158;
    SyscallDataType return_value;
  };

  struct Event_chroot
  {
    static SyscallDataType constexpr syscall_id = 161;
    const char *filename;
    SyscallDataType return_value;
  };

  struct Event_sync
  {
    static SyscallDataType constexpr syscall_id = 162;
    SyscallDataType return_value;
  };

  struct Event_acct
  {
    static SyscallDataType constexpr syscall_id = 163;
    const char *name;
    SyscallDataType return_value;
  };

  struct Event_mount
  {
    static SyscallDataType constexpr syscall_id = 165;
    char *dev_name;
    char *dir_name;
    char *type;
    unsigned long flags;
    void *data;
    SyscallDataType return_value;
  };

  struct Event_umount2
  {
    static SyscallDataType constexpr syscall_id = 166;
    char *name;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_swapon
  {
    static SyscallDataType constexpr syscall_id = 167;
    const char *specialfile;
    int swap_flags;
    SyscallDataType return_value;
  };

  struct Event_swapoff
  {
    static SyscallDataType constexpr syscall_id = 168;
    const char *specialfile;
    SyscallDataType return_value;
  };

  struct Event_reboot
  {
    static SyscallDataType constexpr syscall_id = 169;
    int magic1;
    int magic2;
    unsigned int cmd;
    void *arg;
    SyscallDataType return_value;
  };

  struct Event_sethostname
  {
    static SyscallDataType constexpr syscall_id = 170;
    char *name;
    int len;
    SyscallDataType return_value;
  };

  struct Event_setdomainname
  {
    static SyscallDataType constexpr syscall_id = 171;
    char *name;
    int len;
    SyscallDataType return_value;
  };

  struct Event_iopl
  {
    static SyscallDataType constexpr syscall_id = 172;
    SyscallDataType return_value;
  };

  struct Event_ioperm
  {
    static SyscallDataType constexpr syscall_id = 173;
    unsigned long from;
    unsigned long num;
    int on;
    SyscallDataType return_value;
  };

  struct Event_init_module
  {
    static SyscallDataType constexpr syscall_id = 175;
    void *umod;
    unsigned long len;
    const char *uargs;
    SyscallDataType return_value;
  };

  struct Event_delete_module
  {
    static SyscallDataType constexpr syscall_id = 176;
    const char *name_user;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_quotactl
  {
    static SyscallDataType constexpr syscall_id = 179;
    unsigned int cmd;
    const char *special;
    int id;
    void *addr;
    SyscallDataType return_value;
  };

  struct Event_gettid
  {
    static SyscallDataType constexpr syscall_id = 186;
    SyscallDataType return_value;
  };

  struct Event_readahead
  {
    static SyscallDataType constexpr syscall_id = 187;
    int fd;
    loff_t offset;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_setxattr
  {
    static SyscallDataType constexpr syscall_id = 188;
    const char *path;
    const char *name;
    const void *value;
    size_t size;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_lsetxattr
  {
    static SyscallDataType constexpr syscall_id = 189;
    const char *path;
    const char *name;
    const void *value;
    size_t size;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_fsetxattr
  {
    static SyscallDataType constexpr syscall_id = 190;
    int fd;
    const char *name;
    const void *value;
    size_t size;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_getxattr
  {
    static SyscallDataType constexpr syscall_id = 191;
    const char *path;
    const char *name;
    void *value;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_lgetxattr
  {
    static SyscallDataType constexpr syscall_id = 192;
    const char *path;
    const char *name;
    void *value;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_fgetxattr
  {
    static SyscallDataType constexpr syscall_id = 193;
    int fd;
    const char *name;
    void *value;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_listxattr
  {
    static SyscallDataType constexpr syscall_id = 194;
    const char *path;
    char *list;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_llistxattr
  {
    static SyscallDataType constexpr syscall_id = 195;
    const char *path;
    char *list;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_flistxattr
  {
    static SyscallDataType constexpr syscall_id = 196;
    int fd;
    char *list;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_removexattr
  {
    static SyscallDataType constexpr syscall_id = 197;
    const char *path;
    const char *name;
    SyscallDataType return_value;
  };

  struct Event_lremovexattr
  {
    static SyscallDataType constexpr syscall_id = 198;
    const char *path;
    const char *name;
    SyscallDataType return_value;
  };

  struct Event_fremovexattr
  {
    static SyscallDataType constexpr syscall_id = 199;
    int fd;
    const char *name;
    SyscallDataType return_value;
  };

  struct Event_tkill
  {
    static SyscallDataType constexpr syscall_id = 200;
    pid_t pid;
    int sig;
    SyscallDataType return_value;
  };

  struct Event_time
  {
    static SyscallDataType constexpr syscall_id = 201;
    __kernel_time_t *tloc;
    SyscallDataType return_value;
  };

  struct Event_futex
  {
    static SyscallDataType constexpr syscall_id = 202;
    uint32_t *uaddr;
    int op;
    uint32_t val;
    const struct __kernel_timespec *utime;
    uint32_t *uaddr2;
    uint32_t val3;
    SyscallDataType return_value;
  };

  struct Event_sched_setaffinity
  {
    static SyscallDataType constexpr syscall_id = 203;
    pid_t pid;
    unsigned int len;
    unsigned long *user_mask_ptr;
    SyscallDataType return_value;
  };

  struct Event_sched_getaffinity
  {
    static SyscallDataType constexpr syscall_id = 204;
    pid_t pid;
    unsigned int len;
    unsigned long *user_mask_ptr;
    SyscallDataType return_value;
  };

  struct Event_io_setup
  {
    static SyscallDataType constexpr syscall_id = 206;
    unsigned nr_reqs;
    aio_context_t *ctx;
    SyscallDataType return_value;
  };

  struct Event_io_destroy
  {
    static SyscallDataType constexpr syscall_id = 207;
    aio_context_t ctx;
    SyscallDataType return_value;
  };

  struct Event_io_getevents
  {
    static SyscallDataType constexpr syscall_id = 208;
    aio_context_t ctx_id;
    long min_nr;
    long nr;
    struct io_event *events;
    struct __kernel_timespec *timeout;
    SyscallDataType return_value;
  };

  struct Event_lookup_dcookie
  {
    static SyscallDataType constexpr syscall_id = 212;
    uint64_t cookie64;
    char *buf;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_epoll_create
  {
    static SyscallDataType constexpr syscall_id = 213;
    int size;
    SyscallDataType return_value;
  };

  struct Event_remap_file_pages
  {
    static SyscallDataType constexpr syscall_id = 216;
    unsigned long start;
    unsigned long size;
    unsigned long prot;
    unsigned long pgoff;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_set_tid_address
  {
    static SyscallDataType constexpr syscall_id = 218;
    int *tidptr;
    SyscallDataType return_value;
  };

  struct Event_restart_syscall
  {
    static SyscallDataType constexpr syscall_id = 219;
    SyscallDataType return_value;
  };

  struct Event_fadvise64
  {
    static SyscallDataType constexpr syscall_id = 221;
    int fd;
    loff_t offset;
    size_t len;
    int advice;
    SyscallDataType return_value;
  };

  struct Event_timer_create
  {
    static SyscallDataType constexpr syscall_id = 222;
    clockid_t which_clock;
    struct sigevent *timer_event_spec;
    timer_t *created_timer_id;
    SyscallDataType return_value;
  };

  struct Event_timer_settime
  {
    static SyscallDataType constexpr syscall_id = 223;
    timer_t timer_id;
    int flags;
    const struct __kernel_itimerspec *new_setting;
    struct __kernel_itimerspec *old_setting;
    SyscallDataType return_value;
  };

  struct Event_timer_gettime
  {
    static SyscallDataType constexpr syscall_id = 224;
    timer_t timer_id;
    struct __kernel_itimerspec *setting;
    SyscallDataType return_value;
  };

  struct Event_timer_getoverrun
  {
    static SyscallDataType constexpr syscall_id = 225;
    timer_t timer_id;
    SyscallDataType return_value;
  };

  struct Event_timer_delete
  {
    static SyscallDataType constexpr syscall_id = 226;
    timer_t timer_id;
    SyscallDataType return_value;
  };

  struct Event_clock_settime
  {
    static SyscallDataType constexpr syscall_id = 227;
    clockid_t which_clock;
    const struct __kernel_timespec *tp;
    SyscallDataType return_value;
  };

  struct Event_clock_gettime
  {
    static SyscallDataType constexpr syscall_id = 228;
    clockid_t which_clock;
    struct __kernel_timespec *tp;
    SyscallDataType return_value;
  };

  struct Event_clock_getres
  {
    static SyscallDataType constexpr syscall_id = 229;
    clockid_t which_clock;
    struct __kernel_timespec *tp;
    SyscallDataType return_value;
  };

  struct Event_clock_nanosleep
  {
    static SyscallDataType constexpr syscall_id = 230;
    clockid_t which_clock;
    int flags;
    const struct __kernel_timespec *rqtp;
    struct __kernel_timespec *rmtp;
    SyscallDataType return_value;
  };

  struct Event_exit_group
  {
    static SyscallDataType constexpr syscall_id = 231;
    int error_code;
    SyscallDataType return_value;
  };

  struct Event_epoll_wait
  {
    static SyscallDataType constexpr syscall_id = 232;
    int epfd;
    struct epoll_event *events;
    int maxevents;
    int timeout;
    SyscallDataType return_value;
  };

  struct Event_epoll_ctl
  {
    static SyscallDataType constexpr syscall_id = 233;
    int epfd;
    int op;
    int fd;
    struct epoll_event *event;
    SyscallDataType return_value;
  };

  struct Event_tgkill
  {
    static SyscallDataType constexpr syscall_id = 234;
    pid_t tgid;
    pid_t pid;
    int sig;
    SyscallDataType return_value;
  };

  struct Event_mbind
  {
    static SyscallDataType constexpr syscall_id = 237;
    unsigned long start;
    unsigned long len;
    unsigned long mode;
    const unsigned long *nmask;
    unsigned long maxnode;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_set_mempolicy
  {
    static SyscallDataType constexpr syscall_id = 238;
    int mode;
    const unsigned long *nmask;
    unsigned long maxnode;
    SyscallDataType return_value;
  };

  struct Event_get_mempolicy
  {
    static SyscallDataType constexpr syscall_id = 239;
    int *policy;
    unsigned long *nmask;
    unsigned long maxnode;
    unsigned long addr;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_mq_open
  {
    static SyscallDataType constexpr syscall_id = 240;
    const char *name;
    int oflag;
    mode_t mode;
    struct mq_attr *attr;
    SyscallDataType return_value;
  };

  struct Event_mq_unlink
  {
    static SyscallDataType constexpr syscall_id = 241;
    const char *name;
    SyscallDataType return_value;
  };

  struct Event_mq_timedsend
  {
    static SyscallDataType constexpr syscall_id = 242;
    mqd_t mqdes;
    const char *msg_ptr;
    size_t msg_len;
    unsigned int msg_prio;
    const struct __kernel_timespec *abs_timeout;
    SyscallDataType return_value;
  };

  struct Event_mq_timedreceive
  {
    static SyscallDataType constexpr syscall_id = 243;
    mqd_t mqdes;
    char *msg_ptr;
    size_t msg_len;
    unsigned int *msg_prio;
    const struct __kernel_timespec *abs_timeout;
    SyscallDataType return_value;
  };

  struct Event_mq_notify
  {
    static SyscallDataType constexpr syscall_id = 244;
    mqd_t mqdes;
    const struct sigevent *notification;
    SyscallDataType return_value;
  };

  struct Event_mq_getsetattr
  {
    static SyscallDataType constexpr syscall_id = 245;
    mqd_t mqdes;
    const struct mq_attr *mqstat;
    struct mq_attr *omqstat;
    SyscallDataType return_value;
  };

  struct Event_keyctl
  {
    static SyscallDataType constexpr syscall_id = 250;
    int cmd;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    SyscallDataType return_value;
  };

  struct Event_ioprio_set
  {
    static SyscallDataType constexpr syscall_id = 251;
    int which;
    int who;
    int ioprio;
    SyscallDataType return_value;
  };

  struct Event_ioprio_get
  {
    static SyscallDataType constexpr syscall_id = 252;
    int which;
    int who;
    SyscallDataType return_value;
  };

  struct Event_inotify_init
  {
    static SyscallDataType constexpr syscall_id = 253;
    SyscallDataType return_value;
  };

  struct Event_inotify_add_watch
  {
    static SyscallDataType constexpr syscall_id = 254;
    int fd;
    const char *path;
    uint32_t mask;
    SyscallDataType return_value;
  };

  struct Event_inotify_rm_watch
  {
    static SyscallDataType constexpr syscall_id = 255;
    int fd;
    __s32 wd;
    SyscallDataType return_value;
  };

  struct Event_migrate_pages
  {
    static SyscallDataType constexpr syscall_id = 256;
    pid_t pid;
    unsigned long maxnode;
    const unsigned long *from;
    const unsigned long *to;
    SyscallDataType return_value;
  };

  struct Event_openat
  {
    static SyscallDataType constexpr syscall_id = 257;
    int dfd;
    const char *filename;
    int flags;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_mkdirat
  {
    static SyscallDataType constexpr syscall_id = 258;
    int dfd;
    const char *pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_mknodat
  {
    static SyscallDataType constexpr syscall_id = 259;
    int dfd;
    const char *filename;
    mode_t mode;
    unsigned dev;
    SyscallDataType return_value;
  };

  struct Event_fchownat
  {
    static SyscallDataType constexpr syscall_id = 260;
    int dfd;
    const char *filename;
    uid_t user;
    gid_t group;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_newfstatat
  {
    static SyscallDataType constexpr syscall_id = 262;
    int dfd;
    const char *filename;
    struct stat *statbuf;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_unlinkat
  {
    static SyscallDataType constexpr syscall_id = 263;
    int dfd;
    const char *pathname;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_renameat
  {
    static SyscallDataType constexpr syscall_id = 264;
    int olddfd;
    const char *oldname;
    int newdfd;
    const char *newname;
    SyscallDataType return_value;
  };

  struct Event_linkat
  {
    static SyscallDataType constexpr syscall_id = 265;
    int olddfd;
    const char *oldname;
    int newdfd;
    const char *newname;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_symlinkat
  {
    static SyscallDataType constexpr syscall_id = 266;
    const char *oldname;
    int newdfd;
    const char *newname;
    SyscallDataType return_value;
  };

  struct Event_readlinkat
  {
    static SyscallDataType constexpr syscall_id = 267;
    int dfd;
    const char *path;
    char *buf;
    int bufsiz;
    SyscallDataType return_value;
  };

  struct Event_fchmodat
  {
    static SyscallDataType constexpr syscall_id = 268;
    int dfd;
    const char *filename;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_faccessat
  {
    static SyscallDataType constexpr syscall_id = 269;
    int dfd;
    const char *filename;
    int mode;
    SyscallDataType return_value;
  };

  struct Event_pselect6
  {
    static SyscallDataType constexpr syscall_id = 270;
    int unnamed0;
    fd_set *unnamed1;
    fd_set *unnamed2;
    fd_set *unnamed3;
    struct __kernel_timespec *unnamed4;
    void *unnamed5;
    SyscallDataType return_value;
  };

  struct Event_unshare
  {
    static SyscallDataType constexpr syscall_id = 272;
    unsigned long unshare_flags;
    SyscallDataType return_value;
  };

  struct Event_splice
  {
    static SyscallDataType constexpr syscall_id = 275;
    int fd_in;
    loff_t *off_in;
    int fd_out;
    loff_t *off_out;
    size_t len;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_tee
  {
    static SyscallDataType constexpr syscall_id = 276;
    int fdin;
    int fdout;
    size_t len;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_sync_file_range
  {
    static SyscallDataType constexpr syscall_id = 277;
    int fd;
    loff_t offset;
    loff_t nbytes;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_vmsplice
  {
    static SyscallDataType constexpr syscall_id = 278;
    int fd;
    const struct iovec *iov;
    unsigned long nr_segs;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_move_pages
  {
    static SyscallDataType constexpr syscall_id = 279;
    pid_t pid;
    unsigned long nr_pages;
    const void **pages;
    const int *nodes;
    int *status;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_utimensat
  {
    static SyscallDataType constexpr syscall_id = 280;
    int dfd;
    const char *filename;
    struct __kernel_timespec *utimes;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_epoll_pwait
  {
    static SyscallDataType constexpr syscall_id = 281;
    int epfd;
    struct epoll_event *events;
    int maxevents;
    int timeout;
    const sigset_t *SignMask;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_signalfd
  {
    static SyscallDataType constexpr syscall_id = 282;
    int ufd;
    sigset_t *user_mask;
    size_t sizemask;
    SyscallDataType return_value;
  };

  struct Event_timerfd_create
  {
    static SyscallDataType constexpr syscall_id = 283;
    int clockid;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_eventfd
  {
    static SyscallDataType constexpr syscall_id = 284;
    unsigned int count;
    SyscallDataType return_value;
  };

  struct Event_fallocate
  {
    static SyscallDataType constexpr syscall_id = 285;
    int fd;
    int mode;
    loff_t offset;
    loff_t len;
    SyscallDataType return_value;
  };

  struct Event_timerfd_settime
  {
    static SyscallDataType constexpr syscall_id = 286;
    int ufd;
    int flags;
    const struct __kernel_itimerspec *utmr;
    struct __kernel_itimerspec *otmr;
    SyscallDataType return_value;
  };

  struct Event_timerfd_gettime
  {
    static SyscallDataType constexpr syscall_id = 287;
    int ufd;
    struct __kernel_itimerspec *otmr;
    SyscallDataType return_value;
  };

  struct Event_accept4
  {
    static SyscallDataType constexpr syscall_id = 288;
    int unnamed0;
    struct sockaddr *unnamed1;
    int *unnamed2;
    int unnamed3;
    SyscallDataType return_value;
  };

  struct Event_signalfd4
  {
    static SyscallDataType constexpr syscall_id = 289;
    int ufd;
    sigset_t *user_mask;
    size_t sizemask;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_eventfd2
  {
    static SyscallDataType constexpr syscall_id = 290;
    unsigned int count;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_epoll_create1
  {
    static SyscallDataType constexpr syscall_id = 291;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_dup3
  {
    static SyscallDataType constexpr syscall_id = 292;
    unsigned int oldfd;
    unsigned int newfd;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_pipe2
  {
    static SyscallDataType constexpr syscall_id = 293;
    int *fildes;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_inotify_init1
  {
    static SyscallDataType constexpr syscall_id = 294;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_preadv
  {
    static SyscallDataType constexpr syscall_id = 295;
    unsigned long fd;
    const struct iovec *vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    SyscallDataType return_value;
  };

  struct Event_pwritev
  {
    static SyscallDataType constexpr syscall_id = 296;
    unsigned long fd;
    const struct iovec *vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    SyscallDataType return_value;
  };

  struct Event_rt_tgsigqueueinfo
  {
    static SyscallDataType constexpr syscall_id = 297;
    pid_t tgid;
    pid_t pid;
    int sig;
    siginfo_t *uinfo;
    SyscallDataType return_value;
  };

  struct Event_recvmmsg
  {
    static SyscallDataType constexpr syscall_id = 299;
    int fd;
    struct mmsghdr *msg;
    unsigned int vlen;
    unsigned flags;
    struct __kernel_timespec *timeout;
    SyscallDataType return_value;
  };

  struct Event_fanotify_init
  {
    static SyscallDataType constexpr syscall_id = 300;
    unsigned int flags;
    unsigned int event_f_flags;
    SyscallDataType return_value;
  };

  struct Event_fanotify_mark
  {
    static SyscallDataType constexpr syscall_id = 301;
    int fanotify_fd;
    unsigned int flags;
    uint64_t mask;
    int fd;
    const char *pathname;
    SyscallDataType return_value;
  };

  struct Event_name_to_handle_at
  {
    static SyscallDataType constexpr syscall_id = 303;
    int dfd;
    const char *name;
    struct file_handle *handle;
    int *mnt_id;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_open_by_handle_at
  {
    static SyscallDataType constexpr syscall_id = 304;
    int mountdirfd;
    struct file_handle *handle;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_syncfs
  {
    static SyscallDataType constexpr syscall_id = 306;
    int fd;
    SyscallDataType return_value;
  };

  struct Event_sendmmsg
  {
    static SyscallDataType constexpr syscall_id = 307;
    int fd;
    struct mmsghdr *msg;
    unsigned int vlen;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_setns
  {
    static SyscallDataType constexpr syscall_id = 308;
    int fd;
    int nstype;
    SyscallDataType return_value;
  };

  struct Event_getcpu
  {
    static SyscallDataType constexpr syscall_id = 309;
    unsigned *cpu;
    unsigned *node;
    struct getcpu_cache *cache;
    SyscallDataType return_value;
  };

  struct Event_process_vm_readv
  {
    static SyscallDataType constexpr syscall_id = 310;
    pid_t pid;
    const struct iovec *lvec;
    unsigned long liovcnt;
    const struct iovec *rvec;
    unsigned long riovcnt;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_process_vm_writev
  {
    static SyscallDataType constexpr syscall_id = 311;
    pid_t pid;
    const struct iovec *lvec;
    unsigned long liovcnt;
    const struct iovec *rvec;
    unsigned long riovcnt;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_kcmp
  {
    static SyscallDataType constexpr syscall_id = 312;
    pid_t pid1;
    pid_t pid2;
    int type;
    unsigned long idx1;
    unsigned long idx2;
    SyscallDataType return_value;
  };

  struct Event_finit_module
  {
    static SyscallDataType constexpr syscall_id = 313;
    int fd;
    const char *uargs;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_sched_setattr
  {
    static SyscallDataType constexpr syscall_id = 314;
    pid_t pid;
    struct sched_attr *attr;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_sched_getattr
  {
    static SyscallDataType constexpr syscall_id = 315;
    pid_t pid;
    struct sched_attr *attr;
    unsigned int size;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_renameat2
  {
    static SyscallDataType constexpr syscall_id = 316;
    int olddfd;
    const char *oldname;
    int newdfd;
    const char *newname;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_seccomp
  {
    static SyscallDataType constexpr syscall_id = 317;
    unsigned int op;
    unsigned int flags;
    void *uargs;
    SyscallDataType return_value;
  };

  struct Event_getrandom
  {
    static SyscallDataType constexpr syscall_id = 318;
    char *buf;
    size_t count;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_memfd_create
  {
    static SyscallDataType constexpr syscall_id = 319;
    const char *uname_ptr;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_kexec_file_load
  {
    static SyscallDataType constexpr syscall_id = 320;
    int kernel_fd;
    int initrd_fd;
    unsigned long cmdline_len;
    const char *cmdline_ptr;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_bpf
  {
    static SyscallDataType constexpr syscall_id = 321;
    int cmd;
    union bpf_attr *attr;
    unsigned int size;
    SyscallDataType return_value;
  };

  struct Event_execveat
  {
    static SyscallDataType constexpr syscall_id = 322;
    int dfd;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_userfaultfd
  {
    static SyscallDataType constexpr syscall_id = 323;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_membarrier
  {
    static SyscallDataType constexpr syscall_id = 324;
    int cmd;
    unsigned int flags;
    int cpu_id;
    SyscallDataType return_value;
  };

  struct Event_mlock2
  {
    static SyscallDataType constexpr syscall_id = 325;
    unsigned long start;
    size_t len;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_copy_file_range
  {
    static SyscallDataType constexpr syscall_id = 326;
    int fd_in;
    loff_t *off_in;
    int fd_out;
    loff_t *off_out;
    size_t len;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_preadv2
  {
    static SyscallDataType constexpr syscall_id = 327;
    unsigned long fd;
    const struct iovec *vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_pwritev2
  {
    static SyscallDataType constexpr syscall_id = 328;
    unsigned long fd;
    const struct iovec *vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_pkey_mprotect
  {
    static SyscallDataType constexpr syscall_id = 329;
    unsigned long start;
    size_t len;
    unsigned long prot;
    int pkey;
    SyscallDataType return_value;
  };

  struct Event_pkey_alloc
  {
    static SyscallDataType constexpr syscall_id = 330;
    unsigned long flags;
    unsigned long init_val;
    SyscallDataType return_value;
  };

  struct Event_pkey_free
  {
    static SyscallDataType constexpr syscall_id = 331;
    int pkey;
    SyscallDataType return_value;
  };

  struct Event_statx
  {
    static SyscallDataType constexpr syscall_id = 332;
    int dfd;
    const char *path;
    unsigned flags;
    unsigned mask;
    struct statx *buffer;
    SyscallDataType return_value;
  };

  struct Event_rseq
  {
    static SyscallDataType constexpr syscall_id = 334;
    struct rseq *rseq;
    uint32_t rseq_len;
    int flags;
    uint32_t sig;
    SyscallDataType return_value;
  };

  struct Event_pidfd_send_signal
  {
    static SyscallDataType constexpr syscall_id = 424;
    int pidfd;
    int sig;
    siginfo_t *info;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_io_uring_enter
  {
    static SyscallDataType constexpr syscall_id = 426;
    unsigned int fd;
    uint32_t to_submit;
    uint32_t min_complete;
    uint32_t flags;
    const void *argp;
    size_t argsz;
    SyscallDataType return_value;
  };

  struct Event_io_uring_register
  {
    static SyscallDataType constexpr syscall_id = 427;
    unsigned int fd;
    unsigned int op;
    void *arg;
    unsigned int nr_args;
    SyscallDataType return_value;
  };

  struct Event_open_tree
  {
    static SyscallDataType constexpr syscall_id = 428;
    int dfd;
    const char *path;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_move_mount
  {
    static SyscallDataType constexpr syscall_id = 429;
    int from_dfd;
    const char *from_path;
    int to_dfd;
    const char *to_path;
    unsigned int ms_flags;
    SyscallDataType return_value;
  };

  struct Event_fsopen
  {
    static SyscallDataType constexpr syscall_id = 430;
    const char *fs_name;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_fsconfig
  {
    static SyscallDataType constexpr syscall_id = 431;
    int fs_fd;
    unsigned int cmd;
    const char *key;
    const void *value;
    int aux;
    SyscallDataType return_value;
  };

  struct Event_fsmount
  {
    static SyscallDataType constexpr syscall_id = 432;
    int fs_fd;
    unsigned int flags;
    unsigned int ms_flags;
    SyscallDataType return_value;
  };

  struct Event_fspick
  {
    static SyscallDataType constexpr syscall_id = 433;
    int dfd;
    const char *path;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_pidfd_open
  {
    static SyscallDataType constexpr syscall_id = 434;
    pid_t pid;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_clone3
  {
    static SyscallDataType constexpr syscall_id = 435;
    struct clone_args *uargs;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_close_range
  {
    static SyscallDataType constexpr syscall_id = 436;
    unsigned int fd;
    unsigned int max_fd;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_openat2
  {
    static SyscallDataType constexpr syscall_id = 437;
    int dfd;
    const char *filename;
    struct open_how *how;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_pidfd_getfd
  {
    static SyscallDataType constexpr syscall_id = 438;
    int pidfd;
    int fd;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_faccessat2
  {
    static SyscallDataType constexpr syscall_id = 439;
    int dfd;
    const char *filename;
    int mode;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_process_madvise
  {
    static SyscallDataType constexpr syscall_id = 440;
    int pidfd;
    const struct iovec *vec;
    size_t vlen;
    int behavior;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_epoll_pwait2
  {
    static SyscallDataType constexpr syscall_id = 441;
    int epfd;
    struct epoll_event *events;
    int maxevents;
    const struct __kernel_timespec *timeout;
    const sigset_t *SignMask;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_mount_setattr
  {
    static SyscallDataType constexpr syscall_id = 442;
    int dfd;
    const char *path;
    unsigned int flags;
    struct mount_attr *uattr;
    size_t usize;
    SyscallDataType return_value;
  };

  struct Event_landlock_create_ruleset
  {
    static SyscallDataType constexpr syscall_id = 444;
    const struct landlock_ruleset_attr *attr;
    size_t size;
    __uint32_t flags;
    SyscallDataType return_value;
  };

  struct Event_landlock_restrict_self
  {
    static SyscallDataType constexpr syscall_id = 446;
    int ruleset_fd;
    __uint32_t flags;
    SyscallDataType return_value;
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
