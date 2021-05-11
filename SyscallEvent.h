// Generated via code_generator/generate_syscalls.py
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

  struct Event_read
  {
    SyscallDataType return_value;
  };

  struct Event_write
  {
    unsigned int fd;
    const char * buf;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_open
  {
    const char * filename;
    int flags;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_close
  {
    unsigned int fd;
    SyscallDataType return_value;
  };

  struct Event_newstat
  {
    const char * filename;
     stat * statbuf;
    SyscallDataType return_value;
  };

  struct Event_newfstat
  {
    unsigned int fd;
     stat * statbuf;
    SyscallDataType return_value;
  };

  struct Event_newlstat
  {
    const char * filename;
     stat * statbuf;
    SyscallDataType return_value;
  };

  struct Event_poll
  {
     pollfd * ufds;
    unsigned int nfds;
    int timeout;
    SyscallDataType return_value;
  };

  struct Event_lseek
  {
    unsigned int fd;
    off_t offset;
    unsigned int whence;
    SyscallDataType return_value;
  };

  struct Event_mmap
  {
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
    unsigned long start;
    size_t len;
    unsigned long prot;
    SyscallDataType return_value;
  };

  struct Event_munmap
  {
    unsigned long addr;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_brk
  {
    unsigned long brk;
    SyscallDataType return_value;
  };

  struct Event_rt_sigaction
  {
    int unnamed0;
    const sigaction * unnamed1;
     sigaction * unnamed2;
    size_t unnamed3;
    SyscallDataType return_value;
  };

  struct Event_rt_sigprocmask
  {
    int how;
    sigset_t * set;
    sigset_t * oset;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_ioctl
  {
    unsigned int fd;
    unsigned int cmd;
    unsigned long arg;
    SyscallDataType return_value;
  };

  struct Event_pread64
  {
    unsigned int fd;
    char * buf;
    size_t count;
    loff_t pos;
    SyscallDataType return_value;
  };

  struct Event_pwrite64
  {
    unsigned int fd;
    const char * buf;
    size_t count;
    loff_t pos;
    SyscallDataType return_value;
  };

  struct Event_readv
  {
    unsigned long fd;
    const iovec * vec;
    unsigned long vlen;
    SyscallDataType return_value;
  };

  struct Event_writev
  {
    unsigned long fd;
    const iovec * vec;
    unsigned long vlen;
    SyscallDataType return_value;
  };

  struct Event_access
  {
    const char * filename;
    int mode;
    SyscallDataType return_value;
  };

  struct Event_pipe
  {
    int * fildes;
    SyscallDataType return_value;
  };

  struct Event_select
  {
    int n;
    fd_set * inp;
    fd_set * outp;
    fd_set * exp;
     __kernel_timeval * tvp;
    SyscallDataType return_value;
  };

  struct Event_sched_yield
  {
    SyscallDataType return_value;
  };

  struct Event_mremap
  {
    unsigned long addr;
    unsigned long old_len;
    unsigned long new_len;
    unsigned long flags;
    unsigned long new_addr;
    SyscallDataType return_value;
  };

  struct Event_msync
  {
    unsigned long start;
    size_t len;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_mincore
  {
    unsigned long start;
    size_t len;
    unsigned char * vec;
    SyscallDataType return_value;
  };

  struct Event_madvise
  {
    unsigned long start;
    size_t len;
    int behavior;
    SyscallDataType return_value;
  };

  struct Event_shmget
  {
    key_t key;
    size_t size;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_shmat
  {
    int shmid;
    char * shmaddr;
    int shmflg;
    SyscallDataType return_value;
  };

  struct Event_shmctl
  {
    int shmid;
    int cmd;
     shmid_ds * buf;
    SyscallDataType return_value;
  };

  struct Event_dup
  {
    unsigned int fildes;
    SyscallDataType return_value;
  };

  struct Event_dup2
  {
    unsigned int oldfd;
    unsigned int newfd;
    SyscallDataType return_value;
  };

  struct Event_pause
  {
    SyscallDataType return_value;
  };

  struct Event_nanosleep
  {
     __kernel_timespec * rqtp;
     __kernel_timespec * rmtp;
    SyscallDataType return_value;
  };

  struct Event_getitimer
  {
    int which;
     __kernel_itimerval * value;
    SyscallDataType return_value;
  };

  struct Event_alarm
  {
    unsigned int seconds;
    SyscallDataType return_value;
  };

  struct Event_setitimer
  {
    int which;
     __kernel_itimerval * value;
     __kernel_itimerval * ovalue;
    SyscallDataType return_value;
  };

  struct Event_getpid
  {
    SyscallDataType return_value;
  };

  struct Event_sendfile64
  {
    int out_fd;
    int in_fd;
    loff_t * offset;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_socket
  {
    int unnamed0;
    int unnamed1;
    int unnamed2;
    SyscallDataType return_value;
  };

  struct Event_connect
  {
    int unnamed0;
     sockaddr * unnamed1;
    int unnamed2;
    SyscallDataType return_value;
  };

  struct Event_accept
  {
    int unnamed0;
     sockaddr * unnamed1;
    int * unnamed2;
    SyscallDataType return_value;
  };

  struct Event_sendto
  {
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
    int unnamed0;
    void * unnamed1;
    size_t unnamed2;
    unsigned unnamed3;
     sockaddr * unnamed4;
    int * unnamed5;
    SyscallDataType return_value;
  };

  struct Event_sendmsg
  {
    int fd;
     user_msghdr * msg;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_recvmsg
  {
    int fd;
     user_msghdr * msg;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_shutdown
  {
    int unnamed0;
    int unnamed1;
    SyscallDataType return_value;
  };

  struct Event_bind
  {
    int unnamed0;
     sockaddr * unnamed1;
    int unnamed2;
    SyscallDataType return_value;
  };

  struct Event_listen
  {
    int unnamed0;
    int unnamed1;
    SyscallDataType return_value;
  };

  struct Event_getsockname
  {
    int unnamed0;
     sockaddr * unnamed1;
    int * unnamed2;
    SyscallDataType return_value;
  };

  struct Event_getpeername
  {
    int unnamed0;
     sockaddr * unnamed1;
    int * unnamed2;
    SyscallDataType return_value;
  };

  struct Event_socketpair
  {
    int unnamed0;
    int unnamed1;
    int unnamed2;
    int * unnamed3;
    SyscallDataType return_value;
  };

  struct Event_setsockopt
  {
    int fd;
    int level;
    int optname;
    char * optval;
    int optlen;
    SyscallDataType return_value;
  };

  struct Event_getsockopt
  {
    int fd;
    int level;
    int optname;
    char * optval;
    int * optlen;
    SyscallDataType return_value;
  };

  struct Event_exit
  {
    int error_code;
    SyscallDataType return_value;
  };

  struct Event_wait4
  {
    pid_t pid;
    int * stat_addr;
    int options;
     rusage * ru;
    SyscallDataType return_value;
  };

  struct Event_kill
  {
    pid_t pid;
    int sig;
    SyscallDataType return_value;
  };

  struct Event_uname
  {
     utsname * unnamed0;
    SyscallDataType return_value;
  };

  struct Event_semget
  {
    key_t key;
    int nsems;
    int semflg;
    SyscallDataType return_value;
  };

  struct Event_semop
  {
    int semid;
     sembuf * sops;
    unsigned nsops;
    SyscallDataType return_value;
  };

  struct Event_semctl
  {
    int semid;
    int semnum;
    int cmd;
    unsigned long arg;
    SyscallDataType return_value;
  };

  struct Event_shmdt
  {
    char * shmaddr;
    SyscallDataType return_value;
  };

  struct Event_msgget
  {
    key_t key;
    int msgflg;
    SyscallDataType return_value;
  };

  struct Event_msgsnd
  {
    int msqid;
     msgbuf * msgp;
    size_t msgsz;
    int msgflg;
    SyscallDataType return_value;
  };

  struct Event_msgrcv
  {
    int msqid;
     msgbuf * msgp;
    size_t msgsz;
    long msgtyp;
    int msgflg;
    SyscallDataType return_value;
  };

  struct Event_msgctl
  {
    int msqid;
    int cmd;
     msqid_ds * buf;
    SyscallDataType return_value;
  };

  struct Event_fcntl
  {
    unsigned int fd;
    unsigned int cmd;
    unsigned long arg;
    SyscallDataType return_value;
  };

  struct Event_flock
  {
    unsigned int fd;
    unsigned int cmd;
    SyscallDataType return_value;
  };

  struct Event_fsync
  {
    unsigned int fd;
    SyscallDataType return_value;
  };

  struct Event_fdatasync
  {
    unsigned int fd;
    SyscallDataType return_value;
  };

  struct Event_truncate
  {
    const char * path;
    long length;
    SyscallDataType return_value;
  };

  struct Event_ftruncate
  {
    unsigned int fd;
    unsigned long length;
    SyscallDataType return_value;
  };

  struct Event_getdents
  {
    unsigned int fd;
     linux_dirent * dirent;
    unsigned int count;
    SyscallDataType return_value;
  };

  struct Event_getcwd
  {
    char * buf;
    unsigned long size;
    SyscallDataType return_value;
  };

  struct Event_chdir
  {
    const char * filename;
    SyscallDataType return_value;
  };

  struct Event_fchdir
  {
    unsigned int fd;
    SyscallDataType return_value;
  };

  struct Event_rename
  {
    const char * oldname;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_mkdir
  {
    const char * pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_rmdir
  {
    const char * pathname;
    SyscallDataType return_value;
  };

  struct Event_creat
  {
    const char * pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_link
  {
    const char * oldname;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_unlink
  {
    const char * pathname;
    SyscallDataType return_value;
  };

  struct Event_symlink
  {
    const char * old;
    const char * linkpath;
    SyscallDataType return_value;
  };

  struct Event_readlink
  {
    const char * path;
    char * buf;
    int bufsiz;
    SyscallDataType return_value;
  };

  struct Event_chmod
  {
    const char * filename;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_fchmod
  {
    unsigned int fd;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_chown
  {
    const char * filename;
    uid_t user;
    gid_t group;
    SyscallDataType return_value;
  };

  struct Event_fchown
  {
    unsigned int fd;
    uid_t user;
    gid_t group;
    SyscallDataType return_value;
  };

  struct Event_lchown
  {
    const char * filename;
    uid_t user;
    gid_t group;
    SyscallDataType return_value;
  };

  struct Event_umask
  {
    int mask;
    SyscallDataType return_value;
  };

  struct Event_gettimeofday
  {
     __kernel_timeval * tv;
     timezone * tz;
    SyscallDataType return_value;
  };

  struct Event_getrlimit
  {
    unsigned int resource;
     rlimit * rlim;
    SyscallDataType return_value;
  };

  struct Event_getrusage
  {
    int who;
     rusage * ru;
    SyscallDataType return_value;
  };

  struct Event_sysinfo
  {
     sysinfo * info;
    SyscallDataType return_value;
  };

  struct Event_times
  {
     tms * tbuf;
    SyscallDataType return_value;
  };

  struct Event_ptrace
  {
    long request;
    long pid;
    unsigned long addr;
    unsigned long data;
    SyscallDataType return_value;
  };

  struct Event_getuid
  {
    SyscallDataType return_value;
  };

  struct Event_syslog
  {
    int type;
    char * buf;
    int len;
    SyscallDataType return_value;
  };

  struct Event_getgid
  {
    SyscallDataType return_value;
  };

  struct Event_setuid
  {
    uid_t uid;
    SyscallDataType return_value;
  };

  struct Event_setgid
  {
    gid_t gid;
    SyscallDataType return_value;
  };

  struct Event_geteuid
  {
    SyscallDataType return_value;
  };

  struct Event_getegid
  {
    SyscallDataType return_value;
  };

  struct Event_setpgid
  {
    pid_t pid;
    pid_t pgid;
    SyscallDataType return_value;
  };

  struct Event_getppid
  {
    SyscallDataType return_value;
  };

  struct Event_getpgrp
  {
    SyscallDataType return_value;
  };

  struct Event_setsid
  {
    SyscallDataType return_value;
  };

  struct Event_setreuid
  {
    uid_t ruid;
    uid_t euid;
    SyscallDataType return_value;
  };

  struct Event_setregid
  {
    gid_t rgid;
    gid_t egid;
    SyscallDataType return_value;
  };

  struct Event_getgroups
  {
    int gidsetsize;
    gid_t * grouplist;
    SyscallDataType return_value;
  };

  struct Event_setgroups
  {
    int gidsetsize;
    gid_t * grouplist;
    SyscallDataType return_value;
  };

  struct Event_setresuid
  {
    uid_t ruid;
    uid_t euid;
    uid_t suid;
    SyscallDataType return_value;
  };

  struct Event_getresuid
  {
    uid_t * ruid;
    uid_t * euid;
    uid_t * suid;
    SyscallDataType return_value;
  };

  struct Event_setresgid
  {
    gid_t rgid;
    gid_t egid;
    gid_t sgid;
    SyscallDataType return_value;
  };

  struct Event_getresgid
  {
    gid_t * rgid;
    gid_t * egid;
    gid_t * sgid;
    SyscallDataType return_value;
  };

  struct Event_getpgid
  {
    pid_t pid;
    SyscallDataType return_value;
  };

  struct Event_setfsuid
  {
    uid_t uid;
    SyscallDataType return_value;
  };

  struct Event_setfsgid
  {
    gid_t gid;
    SyscallDataType return_value;
  };

  struct Event_getsid
  {
    pid_t pid;
    SyscallDataType return_value;
  };

  struct Event_rt_sigpending
  {
    sigset_t * set;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_rt_sigtimedwait
  {
    const sigset_t * uthese;
    siginfo_t * uinfo;
    const __kernel_timespec * uts;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_rt_sigqueueinfo
  {
    pid_t pid;
    int sig;
    siginfo_t * uinfo;
    SyscallDataType return_value;
  };

  struct Event_rt_sigsuspend
  {
    sigset_t * unewset;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_utime
  {
    char * filename;
     utimbuf * times;
    SyscallDataType return_value;
  };

  struct Event_mknod
  {
    const char * filename;
    mode_t mode;
    unsigned dev;
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_personality
  {
    unsigned int personality;
    SyscallDataType return_value;
  };

  struct Event_ustat
  {
    unsigned dev;
     ustat * ubuf;
    SyscallDataType return_value;
  };

  struct Event_statfs
  {
    const char * path;
     statfs * buf;
    SyscallDataType return_value;
  };

  struct Event_fstatfs
  {
    unsigned int fd;
     statfs * buf;
    SyscallDataType return_value;
  };

  struct Event_sysfs
  {
    int option;
    unsigned long arg1;
    unsigned long arg2;
    SyscallDataType return_value;
  };

  struct Event_getpriority
  {
    int which;
    int who;
    SyscallDataType return_value;
  };

  struct Event_setpriority
  {
    int which;
    int who;
    int niceval;
    SyscallDataType return_value;
  };

  struct Event_sched_setparam
  {
    pid_t pid;
     sched_param * param;
    SyscallDataType return_value;
  };

  struct Event_sched_getparam
  {
    pid_t pid;
     sched_param * param;
    SyscallDataType return_value;
  };

  struct Event_sched_setscheduler
  {
    pid_t pid;
    int policy;
     sched_param * param;
    SyscallDataType return_value;
  };

  struct Event_sched_getscheduler
  {
    pid_t pid;
    SyscallDataType return_value;
  };

  struct Event_sched_get_priority_max
  {
    int policy;
    SyscallDataType return_value;
  };

  struct Event_sched_get_priority_min
  {
    int policy;
    SyscallDataType return_value;
  };

  struct Event_sched_rr_get_interval
  {
    pid_t pid;
     __kernel_timespec * interval;
    SyscallDataType return_value;
  };

  struct Event_mlock
  {
    unsigned long start;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_munlock
  {
    unsigned long start;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_mlockall
  {
    int flags;
    SyscallDataType return_value;
  };

  struct Event_munlockall
  {
    SyscallDataType return_value;
  };

  struct Event_vhangup
  {
    SyscallDataType return_value;
  };

  struct Event_modify_ldt
  {
    SyscallDataType return_value;
  };

  struct Event_pivot_root
  {
    const char * new_root;
    const char * put_old;
    SyscallDataType return_value;
  };

  struct Event_sysctl
  {
    SyscallDataType return_value;
  };

  struct Event_prctl
  {
    int option;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    SyscallDataType return_value;
  };

  struct Event_arch_prctl
  {
    SyscallDataType return_value;
  };

  struct Event_adjtimex
  {
     __kernel_timex * txc_p;
    SyscallDataType return_value;
  };

  struct Event_setrlimit
  {
    unsigned int resource;
     rlimit * rlim;
    SyscallDataType return_value;
  };

  struct Event_chroot
  {
    const char * filename;
    SyscallDataType return_value;
  };

  struct Event_sync
  {
    SyscallDataType return_value;
  };

  struct Event_acct
  {
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_settimeofday
  {
     __kernel_timeval * tv;
     timezone * tz;
    SyscallDataType return_value;
  };

  struct Event_mount
  {
    char * dev_name;
    char * dir_name;
    char * type;
    unsigned long flags;
    void * data;
    SyscallDataType return_value;
  };

  struct Event_umount
  {
    char * name;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_swapon
  {
    const char * specialfile;
    int swap_flags;
    SyscallDataType return_value;
  };

  struct Event_swapoff
  {
    const char * specialfile;
    SyscallDataType return_value;
  };

  struct Event_reboot
  {
    int magic1;
    int magic2;
    unsigned int cmd;
    void * arg;
    SyscallDataType return_value;
  };

  struct Event_sethostname
  {
    char * name;
    int len;
    SyscallDataType return_value;
  };

  struct Event_setdomainname
  {
    char * name;
    int len;
    SyscallDataType return_value;
  };

  struct Event_ioperm
  {
    unsigned long from;
    unsigned long num;
    int on;
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_init_module
  {
    void * umod;
    unsigned long len;
    const char * uargs;
    SyscallDataType return_value;
  };

  struct Event_delete_module
  {
    const char * name_user;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_quotactl
  {
    unsigned int cmd;
    const char * special;
    int id;
    void * addr;
    SyscallDataType return_value;
  };

  struct Event_nfsservctl
  {
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_gettid
  {
    SyscallDataType return_value;
  };

  struct Event_readahead
  {
    int fd;
    loff_t offset;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_setxattr
  {
    const char * path;
    const char * name;
    const void * value;
    size_t size;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_lsetxattr
  {
    const char * path;
    const char * name;
    const void * value;
    size_t size;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_fsetxattr
  {
    int fd;
    const char * name;
    const void * value;
    size_t size;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_getxattr
  {
    const char * path;
    const char * name;
    void * value;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_lgetxattr
  {
    const char * path;
    const char * name;
    void * value;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_fgetxattr
  {
    int fd;
    const char * name;
    void * value;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_listxattr
  {
    const char * path;
    char * list;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_llistxattr
  {
    const char * path;
    char * list;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_flistxattr
  {
    int fd;
    char * list;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_removexattr
  {
    const char * path;
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_lremovexattr
  {
    const char * path;
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_fremovexattr
  {
    int fd;
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_tkill
  {
    pid_t pid;
    int sig;
    SyscallDataType return_value;
  };

  struct Event_time
  {
    __kernel_time_t * tloc;
    SyscallDataType return_value;
  };

  struct Event_futex
  {
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
    pid_t pid;
    unsigned int len;
    unsigned long * user_mask_ptr;
    SyscallDataType return_value;
  };

  struct Event_sched_getaffinity
  {
    pid_t pid;
    unsigned int len;
    unsigned long * user_mask_ptr;
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_io_setup
  {
    unsigned nr_reqs;
    aio_context_t * ctx;
    SyscallDataType return_value;
  };

  struct Event_io_destroy
  {
    aio_context_t ctx;
    SyscallDataType return_value;
  };

  struct Event_io_getevents
  {
    aio_context_t ctx_id;
    long min_nr;
    long nr;
     io_event * events;
     __kernel_timespec * timeout;
    SyscallDataType return_value;
  };

  struct Event_io_submit
  {
    aio_context_t unnamed0;
    long unnamed1;
     iocb * * unnamed2;
    SyscallDataType return_value;
  };

  struct Event_io_cancel
  {
    aio_context_t ctx_id;
     iocb * iocb;
     io_event * result;
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_lookup_dcookie
  {
    uint64_t cookie64;
    char * buf;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_epoll_create
  {
    int size;
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_remap_file_pages
  {
    unsigned long start;
    unsigned long size;
    unsigned long prot;
    unsigned long pgoff;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_getdents64
  {
    unsigned int fd;
     linux_dirent64 * dirent;
    unsigned int count;
    SyscallDataType return_value;
  };

  struct Event_set_tid_address
  {
    int * tidptr;
    SyscallDataType return_value;
  };

  struct Event_restart_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_semtimedop
  {
    int semid;
     sembuf * sops;
    unsigned nsops;
    const __kernel_timespec * timeout;
    SyscallDataType return_value;
  };

  struct Event_fadvise64
  {
    int fd;
    loff_t offset;
    size_t len;
    int advice;
    SyscallDataType return_value;
  };

  struct Event_timer_create
  {
    clockid_t which_clock;
     sigevent * timer_event_spec;
    timer_t * created_timer_id;
    SyscallDataType return_value;
  };

  struct Event_timer_settime
  {
    timer_t timer_id;
    int flags;
    const __kernel_itimerspec * new_setting;
     __kernel_itimerspec * old_setting;
    SyscallDataType return_value;
  };

  struct Event_timer_gettime
  {
    timer_t timer_id;
     __kernel_itimerspec * setting;
    SyscallDataType return_value;
  };

  struct Event_timer_getoverrun
  {
    timer_t timer_id;
    SyscallDataType return_value;
  };

  struct Event_timer_delete
  {
    timer_t timer_id;
    SyscallDataType return_value;
  };

  struct Event_clock_settime
  {
    clockid_t which_clock;
    const __kernel_timespec * tp;
    SyscallDataType return_value;
  };

  struct Event_clock_gettime
  {
    clockid_t which_clock;
     __kernel_timespec * tp;
    SyscallDataType return_value;
  };

  struct Event_clock_getres
  {
    clockid_t which_clock;
     __kernel_timespec * tp;
    SyscallDataType return_value;
  };

  struct Event_clock_nanosleep
  {
    clockid_t which_clock;
    int flags;
    const __kernel_timespec * rqtp;
     __kernel_timespec * rmtp;
    SyscallDataType return_value;
  };

  struct Event_exit_group
  {
    int error_code;
    SyscallDataType return_value;
  };

  struct Event_epoll_wait
  {
    int epfd;
     epoll_event * events;
    int maxevents;
    int timeout;
    SyscallDataType return_value;
  };

  struct Event_epoll_ctl
  {
    int epfd;
    int op;
    int fd;
     epoll_event * event;
    SyscallDataType return_value;
  };

  struct Event_tgkill
  {
    pid_t tgid;
    pid_t pid;
    int sig;
    SyscallDataType return_value;
  };

  struct Event_utimes
  {
    char * filename;
     __kernel_timeval * utimes;
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_mbind
  {
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
    int mode;
    const unsigned long * nmask;
    unsigned long maxnode;
    SyscallDataType return_value;
  };

  struct Event_get_mempolicy
  {
    int * policy;
    unsigned long * nmask;
    unsigned long maxnode;
    unsigned long addr;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_mq_open
  {
    const char * name;
    int oflag;
    mode_t mode;
     mq_attr * attr;
    SyscallDataType return_value;
  };

  struct Event_mq_unlink
  {
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_mq_timedsend
  {
    mqd_t mqdes;
    const char * msg_ptr;
    size_t msg_len;
    unsigned int msg_prio;
    const __kernel_timespec * abs_timeout;
    SyscallDataType return_value;
  };

  struct Event_mq_timedreceive
  {
    mqd_t mqdes;
    char * msg_ptr;
    size_t msg_len;
    unsigned int * msg_prio;
    const __kernel_timespec * abs_timeout;
    SyscallDataType return_value;
  };

  struct Event_mq_notify
  {
    mqd_t mqdes;
    const sigevent * notification;
    SyscallDataType return_value;
  };

  struct Event_mq_getsetattr
  {
    mqd_t mqdes;
    const mq_attr * mqstat;
     mq_attr * omqstat;
    SyscallDataType return_value;
  };

  struct Event_kexec_load
  {
    unsigned long entry;
    unsigned long nr_segments;
     kexec_segment * segments;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_waitid
  {
    int which;
    pid_t pid;
     siginfo * infop;
    int options;
     rusage * ru;
    SyscallDataType return_value;
  };

  struct Event_keyctl
  {
    int cmd;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    SyscallDataType return_value;
  };

  struct Event_ioprio_set
  {
    int which;
    int who;
    int ioprio;
    SyscallDataType return_value;
  };

  struct Event_ioprio_get
  {
    int which;
    int who;
    SyscallDataType return_value;
  };

  struct Event_inotify_init
  {
    SyscallDataType return_value;
  };

  struct Event_inotify_add_watch
  {
    int fd;
    const char * path;
    uint32_t mask;
    SyscallDataType return_value;
  };

  struct Event_inotify_rm_watch
  {
    int fd;
    __s32 wd;
    SyscallDataType return_value;
  };

  struct Event_migrate_pages
  {
    pid_t pid;
    unsigned long maxnode;
    const unsigned long * from;
    const unsigned long * to;
    SyscallDataType return_value;
  };

  struct Event_openat
  {
    int dfd;
    const char * filename;
    int flags;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_mkdirat
  {
    int dfd;
    const char * pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_mknodat
  {
    int dfd;
    const char * filename;
    mode_t mode;
    unsigned dev;
    SyscallDataType return_value;
  };

  struct Event_fchownat
  {
    int dfd;
    const char * filename;
    uid_t user;
    gid_t group;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_futimesat
  {
    int dfd;
    const char * filename;
     __kernel_timeval * utimes;
    SyscallDataType return_value;
  };

  struct Event_newfstatat
  {
    int dfd;
    const char * filename;
     stat * statbuf;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_unlinkat
  {
    int dfd;
    const char * pathname;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_renameat
  {
    int olddfd;
    const char * oldname;
    int newdfd;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_linkat
  {
    int olddfd;
    const char * oldname;
    int newdfd;
    const char * newname;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_symlinkat
  {
    const char * oldname;
    int newdfd;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_readlinkat
  {
    int dfd;
    const char * path;
    char * buf;
    int bufsiz;
    SyscallDataType return_value;
  };

  struct Event_fchmodat
  {
    int dfd;
    const char * filename;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_faccessat
  {
    int dfd;
    const char * filename;
    int mode;
    SyscallDataType return_value;
  };

  struct Event_pselect6
  {
    int unnamed0;
    fd_set * unnamed1;
    fd_set * unnamed2;
    fd_set * unnamed3;
     __kernel_timespec * unnamed4;
    void * unnamed5;
    SyscallDataType return_value;
  };

  struct Event_set_robust_list
  {
     robust_list_head * head;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_get_robust_list
  {
    int pid;
     robust_list_head * * head_ptr;
    size_t * len_ptr;
    SyscallDataType return_value;
  };

  struct Event_splice
  {
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
    int fdin;
    int fdout;
    size_t len;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_sync_file_range
  {
    int fd;
    loff_t offset;
    loff_t nbytes;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_vmsplice
  {
    int fd;
    const iovec * iov;
    unsigned long nr_segs;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_move_pages
  {
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
    int dfd;
    const char * filename;
     __kernel_timespec * utimes;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_epoll_pwait
  {
    int epfd;
     epoll_event * events;
    int maxevents;
    int timeout;
    const sigset_t * sigmask;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_signalfd
  {
    int ufd;
    sigset_t * user_mask;
    size_t sizemask;
    SyscallDataType return_value;
  };

  struct Event_timerfd_create
  {
    int clockid;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_eventfd
  {
    unsigned int count;
    SyscallDataType return_value;
  };

  struct Event_fallocate
  {
    int fd;
    int mode;
    loff_t offset;
    loff_t len;
    SyscallDataType return_value;
  };

  struct Event_timerfd_settime
  {
    int ufd;
    int flags;
    const __kernel_itimerspec * utmr;
     __kernel_itimerspec * otmr;
    SyscallDataType return_value;
  };

  struct Event_timerfd_gettime
  {
    int ufd;
     __kernel_itimerspec * otmr;
    SyscallDataType return_value;
  };

  struct Event_accept4
  {
    int unnamed0;
     sockaddr * unnamed1;
    int * unnamed2;
    int unnamed3;
    SyscallDataType return_value;
  };

  struct Event_signalfd4
  {
    int ufd;
    sigset_t * user_mask;
    size_t sizemask;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_eventfd2
  {
    unsigned int count;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_epoll_create1
  {
    int flags;
    SyscallDataType return_value;
  };

  struct Event_dup3
  {
    unsigned int oldfd;
    unsigned int newfd;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_pipe2
  {
    int * fildes;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_inotify_init1
  {
    int flags;
    SyscallDataType return_value;
  };

  struct Event_preadv
  {
    unsigned long fd;
    const iovec * vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    SyscallDataType return_value;
  };

  struct Event_pwritev
  {
    unsigned long fd;
    const iovec * vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    SyscallDataType return_value;
  };

  struct Event_rt_tgsigqueueinfo
  {
    pid_t tgid;
    pid_t pid;
    int sig;
    siginfo_t * uinfo;
    SyscallDataType return_value;
  };

  struct Event_perf_event_open
  {
     perf_event_attr * attr_uptr;
    pid_t pid;
    int cpu;
    int group_fd;
    unsigned long flags;
    SyscallDataType return_value;
  };

  using SyscallEvent = std::variant<
    Event_read,
    Event_write,
    Event_open,
    Event_close,
    Event_newstat,
    Event_newfstat,
    Event_newlstat,
    Event_poll,
    Event_lseek,
    Event_mmap,
    Event_mprotect,
    Event_munmap,
    Event_brk,
    Event_rt_sigaction,
    Event_rt_sigprocmask,
    Event_ioctl,
    Event_pread64,
    Event_pwrite64,
    Event_readv,
    Event_writev,
    Event_access,
    Event_pipe,
    Event_select,
    Event_sched_yield,
    Event_mremap,
    Event_msync,
    Event_mincore,
    Event_madvise,
    Event_shmget,
    Event_shmat,
    Event_shmctl,
    Event_dup,
    Event_dup2,
    Event_pause,
    Event_nanosleep,
    Event_getitimer,
    Event_alarm,
    Event_setitimer,
    Event_getpid,
    Event_sendfile64,
    Event_socket,
    Event_connect,
    Event_accept,
    Event_sendto,
    Event_recvfrom,
    Event_sendmsg,
    Event_recvmsg,
    Event_shutdown,
    Event_bind,
    Event_listen,
    Event_getsockname,
    Event_getpeername,
    Event_socketpair,
    Event_setsockopt,
    Event_getsockopt,
    Event_exit,
    Event_wait4,
    Event_kill,
    Event_uname,
    Event_semget,
    Event_semop,
    Event_semctl,
    Event_shmdt,
    Event_msgget,
    Event_msgsnd,
    Event_msgrcv,
    Event_msgctl,
    Event_fcntl,
    Event_flock,
    Event_fsync,
    Event_fdatasync,
    Event_truncate,
    Event_ftruncate,
    Event_getdents,
    Event_getcwd,
    Event_chdir,
    Event_fchdir,
    Event_rename,
    Event_mkdir,
    Event_rmdir,
    Event_creat,
    Event_link,
    Event_unlink,
    Event_symlink,
    Event_readlink,
    Event_chmod,
    Event_fchmod,
    Event_chown,
    Event_fchown,
    Event_lchown,
    Event_umask,
    Event_gettimeofday,
    Event_getrlimit,
    Event_getrusage,
    Event_sysinfo,
    Event_times,
    Event_ptrace,
    Event_getuid,
    Event_syslog,
    Event_getgid,
    Event_setuid,
    Event_setgid,
    Event_geteuid,
    Event_getegid,
    Event_setpgid,
    Event_getppid,
    Event_getpgrp,
    Event_setsid,
    Event_setreuid,
    Event_setregid,
    Event_getgroups,
    Event_setgroups,
    Event_setresuid,
    Event_getresuid,
    Event_setresgid,
    Event_getresgid,
    Event_getpgid,
    Event_setfsuid,
    Event_setfsgid,
    Event_getsid,
    Event_rt_sigpending,
    Event_rt_sigtimedwait,
    Event_rt_sigqueueinfo,
    Event_rt_sigsuspend,
    Event_utime,
    Event_mknod,
    Event_ni_syscall,
    Event_personality,
    Event_ustat,
    Event_statfs,
    Event_fstatfs,
    Event_sysfs,
    Event_getpriority,
    Event_setpriority,
    Event_sched_setparam,
    Event_sched_getparam,
    Event_sched_setscheduler,
    Event_sched_getscheduler,
    Event_sched_get_priority_max,
    Event_sched_get_priority_min,
    Event_sched_rr_get_interval,
    Event_mlock,
    Event_munlock,
    Event_mlockall,
    Event_munlockall,
    Event_vhangup,
    Event_modify_ldt,
    Event_pivot_root,
    Event_sysctl,
    Event_prctl,
    Event_arch_prctl,
    Event_adjtimex,
    Event_setrlimit,
    Event_chroot,
    Event_sync,
    Event_acct,
    Event_settimeofday,
    Event_mount,
    Event_umount,
    Event_swapon,
    Event_swapoff,
    Event_reboot,
    Event_sethostname,
    Event_setdomainname,
    Event_ioperm,
    Event_ni_syscall,
    Event_init_module,
    Event_delete_module,
    Event_ni_syscall,
    Event_ni_syscall,
    Event_quotactl,
    Event_nfsservctl,
    Event_ni_syscall,
    Event_ni_syscall,
    Event_ni_syscall,
    Event_ni_syscall,
    Event_ni_syscall,
    Event_gettid,
    Event_readahead,
    Event_setxattr,
    Event_lsetxattr,
    Event_fsetxattr,
    Event_getxattr,
    Event_lgetxattr,
    Event_fgetxattr,
    Event_listxattr,
    Event_llistxattr,
    Event_flistxattr,
    Event_removexattr,
    Event_lremovexattr,
    Event_fremovexattr,
    Event_tkill,
    Event_time,
    Event_futex,
    Event_sched_setaffinity,
    Event_sched_getaffinity,
    Event_ni_syscall,
    Event_io_setup,
    Event_io_destroy,
    Event_io_getevents,
    Event_io_submit,
    Event_io_cancel,
    Event_ni_syscall,
    Event_lookup_dcookie,
    Event_epoll_create,
    Event_ni_syscall,
    Event_ni_syscall,
    Event_remap_file_pages,
    Event_getdents64,
    Event_set_tid_address,
    Event_restart_syscall,
    Event_semtimedop,
    Event_fadvise64,
    Event_timer_create,
    Event_timer_settime,
    Event_timer_gettime,
    Event_timer_getoverrun,
    Event_timer_delete,
    Event_clock_settime,
    Event_clock_gettime,
    Event_clock_getres,
    Event_clock_nanosleep,
    Event_exit_group,
    Event_epoll_wait,
    Event_epoll_ctl,
    Event_tgkill,
    Event_utimes,
    Event_ni_syscall,
    Event_mbind,
    Event_set_mempolicy,
    Event_get_mempolicy,
    Event_mq_open,
    Event_mq_unlink,
    Event_mq_timedsend,
    Event_mq_timedreceive,
    Event_mq_notify,
    Event_mq_getsetattr,
    Event_kexec_load,
    Event_waitid,
    Event_keyctl,
    Event_ioprio_set,
    Event_ioprio_get,
    Event_inotify_init,
    Event_inotify_add_watch,
    Event_inotify_rm_watch,
    Event_migrate_pages,
    Event_openat,
    Event_mkdirat,
    Event_mknodat,
    Event_fchownat,
    Event_futimesat,
    Event_newfstatat,
    Event_unlinkat,
    Event_renameat,
    Event_linkat,
    Event_symlinkat,
    Event_readlinkat,
    Event_fchmodat,
    Event_faccessat,
    Event_pselect6,
    Event_set_robust_list,
    Event_get_robust_list,
    Event_splice,
    Event_tee,
    Event_sync_file_range,
    Event_vmsplice,
    Event_move_pages,
    Event_utimensat,
    Event_epoll_pwait,
    Event_signalfd,
    Event_timerfd_create,
    Event_eventfd,
    Event_fallocate,
    Event_timerfd_settime,
    Event_timerfd_gettime,
    Event_accept4,
    Event_signalfd4,
    Event_eventfd2,
    Event_epoll_create1,
    Event_dup3,
    Event_pipe2,
    Event_inotify_init1,
    Event_preadv,
    Event_pwritev,
    Event_rt_tgsigqueueinfo,
    Event_perf_event_open
  >;
  // Unsupported: Syscall(id=125, name='capget', params=[Param(cpptype='int /* unsupported */', name='header'), Param(cpptype='int /* unsupported */', name='dataptr')], supported=False)
  // Unsupported: Syscall(id=126, name='capset', params=[Param(cpptype='int /* unsupported */', name='header'), Param(cpptype='const int /* unsupported */', name='data')], supported=False)
  // Unsupported: Syscall(id=248, name='add_key', params=[Param(cpptype='const char *', name='_type'), Param(cpptype='const char *', name='_description'), Param(cpptype='const void *', name='_payload'), Param(cpptype='size_t', name='plen'), Param(cpptype='int /* unsupported */', name='destringid')], supported=False)
  // Unsupported: Syscall(id=249, name='request_key', params=[Param(cpptype='const char *', name='_type'), Param(cpptype='const char *', name='_description'), Param(cpptype='const char *', name='_callout_info'), Param(cpptype='int /* unsupported */', name='destringid')], supported=False)
} // namespace
