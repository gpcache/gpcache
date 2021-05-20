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
#include <linux/time_types.h>
#include <sys/uio.h>

namespace gpcache {

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
    SyscallDataType return_value;
  };

  struct Event_write
  {
    static SyscallDataType constexpr syscall_id = 1;
    unsigned int fd;
    const char * buf;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_open
  {
    static SyscallDataType constexpr syscall_id = 2;
    const char * filename;
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
    unsigned long pgoff;
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
    sigset_t * set;
    sigset_t * oset;
    size_t sigsetsize;
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
    char * buf;
    size_t count;
    loff_t pos;
    SyscallDataType return_value;
  };

  struct Event_pwrite64
  {
    static SyscallDataType constexpr syscall_id = 18;
    unsigned int fd;
    const char * buf;
    size_t count;
    loff_t pos;
    SyscallDataType return_value;
  };

  struct Event_readv
  {
    static SyscallDataType constexpr syscall_id = 19;
    unsigned long fd;
    const iovec * vec;
    unsigned long vlen;
    SyscallDataType return_value;
  };

  struct Event_writev
  {
    static SyscallDataType constexpr syscall_id = 20;
    unsigned long fd;
    const iovec * vec;
    unsigned long vlen;
    SyscallDataType return_value;
  };

  struct Event_access
  {
    static SyscallDataType constexpr syscall_id = 21;
    const char * filename;
    int mode;
    SyscallDataType return_value;
  };

  struct Event_pipe
  {
    static SyscallDataType constexpr syscall_id = 22;
    int * fildes;
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
    unsigned char * vec;
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
    char * shmaddr;
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
     __kernel_timespec * rqtp;
     __kernel_timespec * rmtp;
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

  struct Event_sendfile64
  {
    static SyscallDataType constexpr syscall_id = 40;
    int out_fd;
    int in_fd;
    loff_t * offset;
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
     sockaddr * unnamed1;
    int unnamed2;
    SyscallDataType return_value;
  };

  struct Event_accept
  {
    static SyscallDataType constexpr syscall_id = 43;
    int unnamed0;
     sockaddr * unnamed1;
    int * unnamed2;
    SyscallDataType return_value;
  };

  struct Event_sendto
  {
    static SyscallDataType constexpr syscall_id = 44;
    int unnamed0;
    void * unnamed1;
    size_t unnamed2;
    unsigned unnamed3;
     sockaddr * unnamed4;
    int unnamed5;
    SyscallDataType return_value;
  };

  struct Event_recvfrom
  {
    static SyscallDataType constexpr syscall_id = 45;
    int unnamed0;
    void * unnamed1;
    size_t unnamed2;
    unsigned unnamed3;
     sockaddr * unnamed4;
    int * unnamed5;
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
     sockaddr * unnamed1;
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
     sockaddr * unnamed1;
    int * unnamed2;
    SyscallDataType return_value;
  };

  struct Event_getpeername
  {
    static SyscallDataType constexpr syscall_id = 52;
    int unnamed0;
     sockaddr * unnamed1;
    int * unnamed2;
    SyscallDataType return_value;
  };

  struct Event_socketpair
  {
    static SyscallDataType constexpr syscall_id = 53;
    int unnamed0;
    int unnamed1;
    int unnamed2;
    int * unnamed3;
    SyscallDataType return_value;
  };

  struct Event_setsockopt
  {
    static SyscallDataType constexpr syscall_id = 54;
    int fd;
    int level;
    int optname;
    char * optval;
    int optlen;
    SyscallDataType return_value;
  };

  struct Event_getsockopt
  {
    static SyscallDataType constexpr syscall_id = 55;
    int fd;
    int level;
    int optname;
    char * optval;
    int * optlen;
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
    char * shmaddr;
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
    const char * path;
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
    char * buf;
    unsigned long size;
    SyscallDataType return_value;
  };

  struct Event_chdir
  {
    static SyscallDataType constexpr syscall_id = 80;
    const char * filename;
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
    const char * oldname;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_mkdir
  {
    static SyscallDataType constexpr syscall_id = 83;
    const char * pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_rmdir
  {
    static SyscallDataType constexpr syscall_id = 84;
    const char * pathname;
    SyscallDataType return_value;
  };

  struct Event_creat
  {
    static SyscallDataType constexpr syscall_id = 85;
    const char * pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_link
  {
    static SyscallDataType constexpr syscall_id = 86;
    const char * oldname;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_unlink
  {
    static SyscallDataType constexpr syscall_id = 87;
    const char * pathname;
    SyscallDataType return_value;
  };

  struct Event_symlink
  {
    static SyscallDataType constexpr syscall_id = 88;
    const char * old;
    const char * linkpath;
    SyscallDataType return_value;
  };

  struct Event_readlink
  {
    static SyscallDataType constexpr syscall_id = 89;
    const char * path;
    char * buf;
    int bufsiz;
    SyscallDataType return_value;
  };

  struct Event_chmod
  {
    static SyscallDataType constexpr syscall_id = 90;
    const char * filename;
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
    const char * filename;
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
    const char * filename;
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
    char * buf;
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
    gid_t * grouplist;
    SyscallDataType return_value;
  };

  struct Event_setgroups
  {
    static SyscallDataType constexpr syscall_id = 116;
    int gidsetsize;
    gid_t * grouplist;
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
    uid_t * ruid;
    uid_t * euid;
    uid_t * suid;
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
    gid_t * rgid;
    gid_t * egid;
    gid_t * sgid;
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
    sigset_t * set;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_rt_sigtimedwait
  {
    static SyscallDataType constexpr syscall_id = 128;
    const sigset_t * uthese;
    siginfo_t * uinfo;
    const __kernel_timespec * uts;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_rt_sigqueueinfo
  {
    static SyscallDataType constexpr syscall_id = 129;
    pid_t pid;
    int sig;
    siginfo_t * uinfo;
    SyscallDataType return_value;
  };

  struct Event_rt_sigsuspend
  {
    static SyscallDataType constexpr syscall_id = 130;
    sigset_t * unewset;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_mknod
  {
    static SyscallDataType constexpr syscall_id = 133;
    const char * filename;
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
     __kernel_timespec * interval;
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
    const char * new_root;
    const char * put_old;
    SyscallDataType return_value;
  };

  struct Event_sysctl
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
    const char * filename;
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
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_mount
  {
    static SyscallDataType constexpr syscall_id = 165;
    char * dev_name;
    char * dir_name;
    char * type;
    unsigned long flags;
    void * data;
    SyscallDataType return_value;
  };

  struct Event_umount
  {
    static SyscallDataType constexpr syscall_id = 166;
    char * name;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_swapon
  {
    static SyscallDataType constexpr syscall_id = 167;
    const char * specialfile;
    int swap_flags;
    SyscallDataType return_value;
  };

  struct Event_swapoff
  {
    static SyscallDataType constexpr syscall_id = 168;
    const char * specialfile;
    SyscallDataType return_value;
  };

  struct Event_reboot
  {
    static SyscallDataType constexpr syscall_id = 169;
    int magic1;
    int magic2;
    unsigned int cmd;
    void * arg;
    SyscallDataType return_value;
  };

  struct Event_sethostname
  {
    static SyscallDataType constexpr syscall_id = 170;
    char * name;
    int len;
    SyscallDataType return_value;
  };

  struct Event_setdomainname
  {
    static SyscallDataType constexpr syscall_id = 171;
    char * name;
    int len;
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
    void * umod;
    unsigned long len;
    const char * uargs;
    SyscallDataType return_value;
  };

  struct Event_delete_module
  {
    static SyscallDataType constexpr syscall_id = 176;
    const char * name_user;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_quotactl
  {
    static SyscallDataType constexpr syscall_id = 179;
    unsigned int cmd;
    const char * special;
    int id;
    void * addr;
    SyscallDataType return_value;
  };

  struct Event_nfsservctl
  {
    static SyscallDataType constexpr syscall_id = 180;
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
    const char * path;
    const char * name;
    const void * value;
    size_t size;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_lsetxattr
  {
    static SyscallDataType constexpr syscall_id = 189;
    const char * path;
    const char * name;
    const void * value;
    size_t size;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_fsetxattr
  {
    static SyscallDataType constexpr syscall_id = 190;
    int fd;
    const char * name;
    const void * value;
    size_t size;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_getxattr
  {
    static SyscallDataType constexpr syscall_id = 191;
    const char * path;
    const char * name;
    void * value;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_lgetxattr
  {
    static SyscallDataType constexpr syscall_id = 192;
    const char * path;
    const char * name;
    void * value;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_fgetxattr
  {
    static SyscallDataType constexpr syscall_id = 193;
    int fd;
    const char * name;
    void * value;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_listxattr
  {
    static SyscallDataType constexpr syscall_id = 194;
    const char * path;
    char * list;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_llistxattr
  {
    static SyscallDataType constexpr syscall_id = 195;
    const char * path;
    char * list;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_flistxattr
  {
    static SyscallDataType constexpr syscall_id = 196;
    int fd;
    char * list;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_removexattr
  {
    static SyscallDataType constexpr syscall_id = 197;
    const char * path;
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_lremovexattr
  {
    static SyscallDataType constexpr syscall_id = 198;
    const char * path;
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_fremovexattr
  {
    static SyscallDataType constexpr syscall_id = 199;
    int fd;
    const char * name;
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
    __kernel_time_t * tloc;
    SyscallDataType return_value;
  };

  struct Event_futex
  {
    static SyscallDataType constexpr syscall_id = 202;
    uint32_t * uaddr;
    int op;
    uint32_t val;
    const __kernel_timespec * utime;
    uint32_t * uaddr2;
    uint32_t val3;
    SyscallDataType return_value;
  };

  struct Event_sched_setaffinity
  {
    static SyscallDataType constexpr syscall_id = 203;
    pid_t pid;
    unsigned int len;
    unsigned long * user_mask_ptr;
    SyscallDataType return_value;
  };

  struct Event_sched_getaffinity
  {
    static SyscallDataType constexpr syscall_id = 204;
    pid_t pid;
    unsigned int len;
    unsigned long * user_mask_ptr;
    SyscallDataType return_value;
  };

  struct Event_io_setup
  {
    static SyscallDataType constexpr syscall_id = 206;
    unsigned nr_reqs;
    aio_context_t * ctx;
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
     io_event * events;
     __kernel_timespec * timeout;
    SyscallDataType return_value;
  };

  struct Event_lookup_dcookie
  {
    static SyscallDataType constexpr syscall_id = 212;
    uint64_t cookie64;
    char * buf;
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
    int * tidptr;
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
     sigevent * timer_event_spec;
    timer_t * created_timer_id;
    SyscallDataType return_value;
  };

  struct Event_timer_settime
  {
    static SyscallDataType constexpr syscall_id = 223;
    timer_t timer_id;
    int flags;
    const __kernel_itimerspec * new_setting;
     __kernel_itimerspec * old_setting;
    SyscallDataType return_value;
  };

  struct Event_timer_gettime
  {
    static SyscallDataType constexpr syscall_id = 224;
    timer_t timer_id;
     __kernel_itimerspec * setting;
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
    const __kernel_timespec * tp;
    SyscallDataType return_value;
  };

  struct Event_clock_gettime
  {
    static SyscallDataType constexpr syscall_id = 228;
    clockid_t which_clock;
     __kernel_timespec * tp;
    SyscallDataType return_value;
  };

  struct Event_clock_getres
  {
    static SyscallDataType constexpr syscall_id = 229;
    clockid_t which_clock;
     __kernel_timespec * tp;
    SyscallDataType return_value;
  };

  struct Event_clock_nanosleep
  {
    static SyscallDataType constexpr syscall_id = 230;
    clockid_t which_clock;
    int flags;
    const __kernel_timespec * rqtp;
     __kernel_timespec * rmtp;
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
     epoll_event * events;
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
     epoll_event * event;
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
    const unsigned long * nmask;
    unsigned long maxnode;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_set_mempolicy
  {
    static SyscallDataType constexpr syscall_id = 238;
    int mode;
    const unsigned long * nmask;
    unsigned long maxnode;
    SyscallDataType return_value;
  };

  struct Event_get_mempolicy
  {
    static SyscallDataType constexpr syscall_id = 239;
    int * policy;
    unsigned long * nmask;
    unsigned long maxnode;
    unsigned long addr;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_mq_open
  {
    static SyscallDataType constexpr syscall_id = 240;
    const char * name;
    int oflag;
    mode_t mode;
     mq_attr * attr;
    SyscallDataType return_value;
  };

  struct Event_mq_unlink
  {
    static SyscallDataType constexpr syscall_id = 241;
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_mq_timedsend
  {
    static SyscallDataType constexpr syscall_id = 242;
    mqd_t mqdes;
    const char * msg_ptr;
    size_t msg_len;
    unsigned int msg_prio;
    const __kernel_timespec * abs_timeout;
    SyscallDataType return_value;
  };

  struct Event_mq_timedreceive
  {
    static SyscallDataType constexpr syscall_id = 243;
    mqd_t mqdes;
    char * msg_ptr;
    size_t msg_len;
    unsigned int * msg_prio;
    const __kernel_timespec * abs_timeout;
    SyscallDataType return_value;
  };

  struct Event_mq_notify
  {
    static SyscallDataType constexpr syscall_id = 244;
    mqd_t mqdes;
    const sigevent * notification;
    SyscallDataType return_value;
  };

  struct Event_mq_getsetattr
  {
    static SyscallDataType constexpr syscall_id = 245;
    mqd_t mqdes;
    const mq_attr * mqstat;
     mq_attr * omqstat;
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
    const char * path;
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
    const unsigned long * from;
    const unsigned long * to;
    SyscallDataType return_value;
  };

  struct Event_openat
  {
    static SyscallDataType constexpr syscall_id = 257;
    int dfd;
    const char * filename;
    int flags;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_mkdirat
  {
    static SyscallDataType constexpr syscall_id = 258;
    int dfd;
    const char * pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_mknodat
  {
    static SyscallDataType constexpr syscall_id = 259;
    int dfd;
    const char * filename;
    mode_t mode;
    unsigned dev;
    SyscallDataType return_value;
  };

  struct Event_fchownat
  {
    static SyscallDataType constexpr syscall_id = 260;
    int dfd;
    const char * filename;
    uid_t user;
    gid_t group;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_unlinkat
  {
    static SyscallDataType constexpr syscall_id = 263;
    int dfd;
    const char * pathname;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_renameat
  {
    static SyscallDataType constexpr syscall_id = 264;
    int olddfd;
    const char * oldname;
    int newdfd;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_linkat
  {
    static SyscallDataType constexpr syscall_id = 265;
    int olddfd;
    const char * oldname;
    int newdfd;
    const char * newname;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_symlinkat
  {
    static SyscallDataType constexpr syscall_id = 266;
    const char * oldname;
    int newdfd;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_readlinkat
  {
    static SyscallDataType constexpr syscall_id = 267;
    int dfd;
    const char * path;
    char * buf;
    int bufsiz;
    SyscallDataType return_value;
  };

  struct Event_fchmodat
  {
    static SyscallDataType constexpr syscall_id = 268;
    int dfd;
    const char * filename;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_faccessat
  {
    static SyscallDataType constexpr syscall_id = 269;
    int dfd;
    const char * filename;
    int mode;
    SyscallDataType return_value;
  };

  struct Event_pselect6
  {
    static SyscallDataType constexpr syscall_id = 270;
    int unnamed0;
    fd_set * unnamed1;
    fd_set * unnamed2;
    fd_set * unnamed3;
     __kernel_timespec * unnamed4;
    void * unnamed5;
    SyscallDataType return_value;
  };

  struct Event_splice
  {
    static SyscallDataType constexpr syscall_id = 275;
    int fd_in;
    loff_t * off_in;
    int fd_out;
    loff_t * off_out;
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
    const iovec * iov;
    unsigned long nr_segs;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_move_pages
  {
    static SyscallDataType constexpr syscall_id = 279;
    pid_t pid;
    unsigned long nr_pages;
    const void * * pages;
    const int * nodes;
    int * status;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_utimensat
  {
    static SyscallDataType constexpr syscall_id = 280;
    int dfd;
    const char * filename;
     __kernel_timespec * utimes;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_epoll_pwait
  {
    static SyscallDataType constexpr syscall_id = 281;
    int epfd;
     epoll_event * events;
    int maxevents;
    int timeout;
    const sigset_t * SignMask;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_signalfd
  {
    static SyscallDataType constexpr syscall_id = 282;
    int ufd;
    sigset_t * user_mask;
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
    const __kernel_itimerspec * utmr;
     __kernel_itimerspec * otmr;
    SyscallDataType return_value;
  };

  struct Event_timerfd_gettime
  {
    static SyscallDataType constexpr syscall_id = 287;
    int ufd;
     __kernel_itimerspec * otmr;
    SyscallDataType return_value;
  };

  struct Event_accept4
  {
    static SyscallDataType constexpr syscall_id = 288;
    int unnamed0;
     sockaddr * unnamed1;
    int * unnamed2;
    int unnamed3;
    SyscallDataType return_value;
  };

  struct Event_signalfd4
  {
    static SyscallDataType constexpr syscall_id = 289;
    int ufd;
    sigset_t * user_mask;
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
    int * fildes;
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
    const iovec * vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    SyscallDataType return_value;
  };

  struct Event_pwritev
  {
    static SyscallDataType constexpr syscall_id = 296;
    unsigned long fd;
    const iovec * vec;
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
    siginfo_t * uinfo;
    SyscallDataType return_value;
  };

  // Unsupported: Syscall(id=4, name='newstat', params=[Param(cpptype='const char *', name='filename'), Param(cpptype=' stat *', name='statbuf')], supported=False)
  // Unsupported: Syscall(id=5, name='newfstat', params=[Param(cpptype='unsigned int', name='fd'), Param(cpptype=' stat *', name='statbuf')], supported=False)
  // Unsupported: Syscall(id=6, name='newlstat', params=[Param(cpptype='const char *', name='filename'), Param(cpptype=' stat *', name='statbuf')], supported=False)
  // Unsupported: Syscall(id=7, name='poll', params=[Param(cpptype=' pollfd *', name='ufds'), Param(cpptype='unsigned int', name='nfds'), Param(cpptype='int', name='timeout')], supported=False)
  // Unsupported: Syscall(id=13, name='rt_sigaction', params=[Param(cpptype='int', name=''), Param(cpptype='const sigaction *', name=''), Param(cpptype=' sigaction *', name=''), Param(cpptype='size_t', name='')], supported=False)
  // Unsupported: Syscall(id=23, name='select', params=[Param(cpptype='int', name='n'), Param(cpptype='fd_set *', name='inp'), Param(cpptype='fd_set *', name='outp'), Param(cpptype='fd_set *', name='exp'), Param(cpptype=' __kernel_timeval *', name='tvp')], supported=False)
  // Unsupported: Syscall(id=31, name='shmctl', params=[Param(cpptype='int', name='shmid'), Param(cpptype='int', name='cmd'), Param(cpptype=' shmid_ds *', name='buf')], supported=False)
  // Unsupported: Syscall(id=36, name='getitimer', params=[Param(cpptype='int', name='which'), Param(cpptype=' __kernel_itimerval *', name='value')], supported=False)
  // Unsupported: Syscall(id=38, name='setitimer', params=[Param(cpptype='int', name='which'), Param(cpptype=' __kernel_itimerval *', name='value'), Param(cpptype=' __kernel_itimerval *', name='ovalue')], supported=False)
  // Unsupported: Syscall(id=46, name='sendmsg', params=[Param(cpptype='int', name='fd'), Param(cpptype=' user_msghdr *', name='msg'), Param(cpptype='unsigned', name='flags')], supported=False)
  // Unsupported: Syscall(id=47, name='recvmsg', params=[Param(cpptype='int', name='fd'), Param(cpptype=' user_msghdr *', name='msg'), Param(cpptype='unsigned', name='flags')], supported=False)
  // Unsupported: Syscall(id=61, name='wait4', params=[Param(cpptype='pid_t', name='pid'), Param(cpptype='int *', name='stat_addr'), Param(cpptype='int', name='options'), Param(cpptype=' rusage *', name='ru')], supported=False)
  // Unsupported: Syscall(id=63, name='uname', params=[Param(cpptype=' utsname *', name='')], supported=False)
  // Unsupported: Syscall(id=65, name='semop', params=[Param(cpptype='int', name='semid'), Param(cpptype=' sembuf *', name='sops'), Param(cpptype='unsigned', name='nsops')], supported=False)
  // Unsupported: Syscall(id=69, name='msgsnd', params=[Param(cpptype='int', name='msqid'), Param(cpptype=' msgbuf *', name='msgp'), Param(cpptype='size_t', name='msgsz'), Param(cpptype='int', name='msgflg')], supported=False)
  // Unsupported: Syscall(id=70, name='msgrcv', params=[Param(cpptype='int', name='msqid'), Param(cpptype=' msgbuf *', name='msgp'), Param(cpptype='size_t', name='msgsz'), Param(cpptype='long', name='msgtyp'), Param(cpptype='int', name='msgflg')], supported=False)
  // Unsupported: Syscall(id=71, name='msgctl', params=[Param(cpptype='int', name='msqid'), Param(cpptype='int', name='cmd'), Param(cpptype=' msqid_ds *', name='buf')], supported=False)
  // Unsupported: Syscall(id=78, name='getdents', params=[Param(cpptype='unsigned int', name='fd'), Param(cpptype=' linux_dirent *', name='dirent'), Param(cpptype='unsigned int', name='count')], supported=False)
  // Unsupported: Syscall(id=96, name='gettimeofday', params=[Param(cpptype=' __kernel_timeval *', name='tv'), Param(cpptype=' timezone *', name='tz')], supported=False)
  // Unsupported: Syscall(id=97, name='getrlimit', params=[Param(cpptype='unsigned int', name='resource'), Param(cpptype=' rlimit *', name='rlim')], supported=False)
  // Unsupported: Syscall(id=98, name='getrusage', params=[Param(cpptype='int', name='who'), Param(cpptype=' rusage *', name='ru')], supported=False)
  // Unsupported: Syscall(id=99, name='sysinfo', params=[Param(cpptype=' sysinfo *', name='info')], supported=False)
  // Unsupported: Syscall(id=100, name='times', params=[Param(cpptype=' tms *', name='tbuf')], supported=False)
  // Unsupported: Syscall(id=125, name='capget', params=[Param(cpptype='cap_user_header_t', name='header'), Param(cpptype='cap_user_data_t', name='dataptr')], supported=False)
  // Unsupported: Syscall(id=126, name='capset', params=[Param(cpptype='cap_user_header_t', name='header'), Param(cpptype='const cap_user_data_t', name='data')], supported=False)
  // Unsupported: Syscall(id=132, name='utime', params=[Param(cpptype='char *', name='filename'), Param(cpptype=' utimbuf *', name='times')], supported=False)
  // Unsupported: Syscall(id=134, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=136, name='ustat', params=[Param(cpptype='unsigned', name='dev'), Param(cpptype=' ustat *', name='ubuf')], supported=False)
  // Unsupported: Syscall(id=137, name='statfs', params=[Param(cpptype='const char *', name='path'), Param(cpptype=' statfs *', name='buf')], supported=False)
  // Unsupported: Syscall(id=138, name='fstatfs', params=[Param(cpptype='unsigned int', name='fd'), Param(cpptype=' statfs *', name='buf')], supported=False)
  // Unsupported: Syscall(id=142, name='sched_setparam', params=[Param(cpptype='pid_t', name='pid'), Param(cpptype=' sched_param *', name='param')], supported=False)
  // Unsupported: Syscall(id=143, name='sched_getparam', params=[Param(cpptype='pid_t', name='pid'), Param(cpptype=' sched_param *', name='param')], supported=False)
  // Unsupported: Syscall(id=144, name='sched_setscheduler', params=[Param(cpptype='pid_t', name='pid'), Param(cpptype='int', name='policy'), Param(cpptype=' sched_param *', name='param')], supported=False)
  // Unsupported: Syscall(id=159, name='adjtimex', params=[Param(cpptype=' __kernel_timex *', name='txc_p')], supported=False)
  // Unsupported: Syscall(id=160, name='setrlimit', params=[Param(cpptype='unsigned int', name='resource'), Param(cpptype=' rlimit *', name='rlim')], supported=False)
  // Unsupported: Syscall(id=164, name='settimeofday', params=[Param(cpptype=' __kernel_timeval *', name='tv'), Param(cpptype=' timezone *', name='tz')], supported=False)
  // Unsupported: Syscall(id=174, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=177, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=178, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=181, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=182, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=183, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=184, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=185, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=205, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=209, name='io_submit', params=[Param(cpptype='aio_context_t', name=''), Param(cpptype='long', name=''), Param(cpptype=' iocb * *', name='')], supported=False)
  // Unsupported: Syscall(id=210, name='io_cancel', params=[Param(cpptype='aio_context_t', name='ctx_id'), Param(cpptype=' iocb *', name='iocb'), Param(cpptype=' io_event *', name='result')], supported=False)
  // Unsupported: Syscall(id=211, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=214, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=215, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=217, name='getdents64', params=[Param(cpptype='unsigned int', name='fd'), Param(cpptype=' linux_dirent64 *', name='dirent'), Param(cpptype='unsigned int', name='count')], supported=False)
  // Unsupported: Syscall(id=220, name='semtimedop', params=[Param(cpptype='int', name='semid'), Param(cpptype=' sembuf *', name='sops'), Param(cpptype='unsigned', name='nsops'), Param(cpptype='const __kernel_timespec *', name='timeout')], supported=False)
  // Unsupported: Syscall(id=235, name='utimes', params=[Param(cpptype='char *', name='filename'), Param(cpptype=' __kernel_timeval *', name='utimes')], supported=False)
  // Unsupported: Syscall(id=236, name='ni_syscall', params=[], supported=False)
  // Unsupported: Syscall(id=246, name='kexec_load', params=[Param(cpptype='unsigned long', name='entry'), Param(cpptype='unsigned long', name='nr_segments'), Param(cpptype=' kexec_segment *', name='segments'), Param(cpptype='unsigned long', name='flags')], supported=False)
  // Unsupported: Syscall(id=247, name='waitid', params=[Param(cpptype='int', name='which'), Param(cpptype='pid_t', name='pid'), Param(cpptype=' siginfo *', name='infop'), Param(cpptype='int', name='options'), Param(cpptype=' rusage *', name='ru')], supported=False)
  // Unsupported: Syscall(id=248, name='add_key', params=[Param(cpptype='const char *', name='_type'), Param(cpptype='const char *', name='_description'), Param(cpptype='const void *', name='_payload'), Param(cpptype='size_t', name='plen'), Param(cpptype='key_serial_t', name='destringid')], supported=False)
  // Unsupported: Syscall(id=249, name='request_key', params=[Param(cpptype='const char *', name='_type'), Param(cpptype='const char *', name='_description'), Param(cpptype='const char *', name='_callout_info'), Param(cpptype='key_serial_t', name='destringid')], supported=False)
  // Unsupported: Syscall(id=261, name='futimesat', params=[Param(cpptype='int', name='dfd'), Param(cpptype='const char *', name='filename'), Param(cpptype=' __kernel_timeval *', name='utimes')], supported=False)
  // Unsupported: Syscall(id=262, name='newfstatat', params=[Param(cpptype='int', name='dfd'), Param(cpptype='const char *', name='filename'), Param(cpptype=' stat *', name='statbuf'), Param(cpptype='int', name='flag')], supported=False)
  // Unsupported: Syscall(id=273, name='set_robust_list', params=[Param(cpptype=' robust_list_head *', name='head'), Param(cpptype='size_t', name='len')], supported=False)
  // Unsupported: Syscall(id=274, name='get_robust_list', params=[Param(cpptype='int', name='pid'), Param(cpptype=' robust_list_head * *', name='head_ptr'), Param(cpptype='size_t *', name='len_ptr')], supported=False)
  // Unsupported: Syscall(id=298, name='perf_event_open', params=[Param(cpptype=' perf_event_attr *', name='attr_uptr'), Param(cpptype='pid_t', name='pid'), Param(cpptype='int', name='cpu'), Param(cpptype='int', name='group_fd'), Param(cpptype='unsigned long', name='flags')], supported=False)
} // namespace