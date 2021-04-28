// Generated via ../code_generator/generate_syscalls.py
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
#include <sys/uio.h>

namespace gpcache {

  using SyscallDataType = decltype(user_regs_struct{}.rax);

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

  struct Event_io_submit
  {
     aio_context_t;
    long unnamed;
    struct iocb * * unnamed;
    SyscallDataType return_value;
  };

  struct Event_io_cancel
  {
    aio_context_t ctx_id;
    struct iocb * iocb;
    struct io_event * result;
    SyscallDataType return_value;
  };

  struct Event_io_getevents
  {
    aio_context_t ctx_id;
    long min_nr;
    long nr;
    struct io_event * events;
    struct __kernel_timespec * timeout;
    SyscallDataType return_value;
  };

  struct Event_io_pgetevents
  {
    aio_context_t ctx_id;
    long min_nr;
    long nr;
    struct io_event * events;
    struct __kernel_timespec * timeout;
    const struct __aio_sigset * sig;
    SyscallDataType return_value;
  };

  struct Event_io_uring_setup
  {
    uint32_t entries;
    struct io_uring_params * p;
    SyscallDataType return_value;
  };

  struct Event_io_uring_enter
  {
    unsigned int fd;
    uint32_t to_submit;
    uint32_t min_complete;
    uint32_t flags;
    const void * argp;
    size_t argsz;
    SyscallDataType return_value;
  };

  struct Event_io_uring_register
  {
    unsigned int fd;
    unsigned int op;
    void * arg;
    unsigned int nr_args;
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

  struct Event_getcwd
  {
    char * buf;
    unsigned long size;
    SyscallDataType return_value;
  };

  struct Event_lookup_dcookie
  {
    uint64_t cookie64;
    char * buf;
    size_t len;
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

  struct Event_epoll_ctl
  {
    int epfd;
    int op;
    int fd;
    struct epoll_event * event;
    SyscallDataType return_value;
  };

  struct Event_epoll_pwait
  {
    int epfd;
    struct epoll_event * events;
    int maxevents;
    int timeout;
    const sigset_t * sigmask;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_epoll_pwait2
  {
    int epfd;
    struct epoll_event * events;
    int maxevents;
    const struct __kernel_timespec * timeout;
    const sigset_t * sigmask;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_dup
  {
    unsigned int fildes;
    SyscallDataType return_value;
  };

  struct Event_dup3
  {
    unsigned int oldfd;
    unsigned int newfd;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_fcntl
  {
    unsigned int fd;
    unsigned int cmd;
    unsigned long arg;
    SyscallDataType return_value;
  };

  struct Event_fcntl64
  {
    unsigned int fd;
    unsigned int cmd;
    unsigned long arg;
    SyscallDataType return_value;
  };

  struct Event_inotify_init1
  {
    int flags;
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

  struct Event_ioctl
  {
    unsigned int fd;
    unsigned int cmd;
    unsigned long arg;
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

  struct Event_flock
  {
    unsigned int fd;
    unsigned int cmd;
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

  struct Event_mkdirat
  {
    int dfd;
    const char * pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_unlinkat
  {
    int dfd;
    const char * pathname;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_symlinkat
  {
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

  struct Event_renameat
  {
    int olddfd;
    const char * oldname;
    int newdfd;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_umount
  {
    char * name;
    int flags;
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

  struct Event_pivot_root
  {
    const char * new_root;
    const char * put_old;
    SyscallDataType return_value;
  };

  struct Event_statfs
  {
    const char * path;
    struct statfs * buf;
    SyscallDataType return_value;
  };

  struct Event_statfs64
  {
    const char * path;
    size_t sz;
    struct statfs64 * buf;
    SyscallDataType return_value;
  };

  struct Event_fstatfs
  {
    unsigned int fd;
    struct statfs * buf;
    SyscallDataType return_value;
  };

  struct Event_fstatfs64
  {
    unsigned int fd;
    size_t sz;
    struct statfs64 * buf;
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

  struct Event_truncate64
  {
    const char * path;
    loff_t length;
    SyscallDataType return_value;
  };

  struct Event_ftruncate64
  {
    unsigned int fd;
    loff_t length;
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

  struct Event_faccessat
  {
    int dfd;
    const char * filename;
    int mode;
    SyscallDataType return_value;
  };

  struct Event_faccessat2
  {
    int dfd;
    const char * filename;
    int mode;
    int flags;
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

  struct Event_chroot
  {
    const char * filename;
    SyscallDataType return_value;
  };

  struct Event_fchmod
  {
    unsigned int fd;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_fchmodat
  {
    int dfd;
    const char * filename;
    mode_t mode;
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

  struct Event_fchown
  {
    unsigned int fd;
    uid_t user;
    gid_t group;
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

  struct Event_openat2
  {
    int dfd;
    const char * filename;
    struct open_how * how;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_close
  {
    unsigned int fd;
    SyscallDataType return_value;
  };

  struct Event_close_range
  {
    unsigned int fd;
    unsigned int max_fd;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_vhangup
  {
    SyscallDataType return_value;
  };

  struct Event_pipe2
  {
    int * fildes;
    int flags;
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

  struct Event_getdents64
  {
    unsigned int fd;
    struct linux_dirent64 * dirent;
    unsigned int count;
    SyscallDataType return_value;
  };

  struct Event_llseek
  {
    unsigned int fd;
    unsigned long offset_high;
    unsigned long offset_low;
    loff_t * result;
    unsigned int whence;
    SyscallDataType return_value;
  };

  struct Event_lseek
  {
    unsigned int fd;
    off_t offset;
    unsigned int whence;
    SyscallDataType return_value;
  };

  struct Event_read
  {
    unsigned int fd;
    char * buf;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_write
  {
    unsigned int fd;
    const char * buf;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_readv
  {
    unsigned long fd;
    const struct iovec * vec;
    unsigned long vlen;
    SyscallDataType return_value;
  };

  struct Event_writev
  {
    unsigned long fd;
    const struct iovec * vec;
    unsigned long vlen;
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

  struct Event_preadv
  {
    unsigned long fd;
    const struct iovec * vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    SyscallDataType return_value;
  };

  struct Event_pwritev
  {
    unsigned long fd;
    const struct iovec * vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
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

  struct Event_pselect6
  {
    int unnamed;
    fd_set * unnamed;
    fd_set * unnamed;
    fd_set * unnamed;
    struct __kernel_timespec * unnamed;
    void * unnamed;
    SyscallDataType return_value;
  };

  struct Event_ppoll
  {
    struct pollfd * unnamed;
    unsigned int unnamed;
    struct __kernel_timespec * unnamed;
    const sigset_t * unnamed;
    size_t unnamed;
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

  struct Event_vmsplice
  {
    int fd;
    const struct iovec * iov;
    unsigned long nr_segs;
    unsigned int flags;
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

  struct Event_readlinkat
  {
    int dfd;
    const char * path;
    char * buf;
    int bufsiz;
    SyscallDataType return_value;
  };

  struct Event_newfstatat
  {
    int dfd;
    const char * filename;
    struct stat * statbuf;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_newfstat
  {
    unsigned int fd;
    struct stat * statbuf;
    SyscallDataType return_value;
  };

  struct Event_fstat64
  {
    unsigned long fd;
    struct stat64 * statbuf;
    SyscallDataType return_value;
  };

  struct Event_fstatat64
  {
    int dfd;
    const char * filename;
    struct stat64 * statbuf;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_sync
  {
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

  struct Event_sync_file_range2
  {
    int fd;
    unsigned int flags;
    loff_t offset;
    loff_t nbytes;
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

  struct Event_timerfd_create
  {
    int clockid;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_timerfd_settime
  {
    int ufd;
    int flags;
    const struct __kernel_itimerspec * utmr;
    struct __kernel_itimerspec * otmr;
    SyscallDataType return_value;
  };

  struct Event_timerfd_gettime
  {
    int ufd;
    struct __kernel_itimerspec * otmr;
    SyscallDataType return_value;
  };

  struct Event_utimensat
  {
    int dfd;
    const char * filename;
    struct __kernel_timespec * utimes;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_acct
  {
    const char * name;
    SyscallDataType return_value;
  };

  struct Event_capget
  {
    int header;
    int dataptr;
    SyscallDataType return_value;
  };

  struct Event_capset
  {
    int header;
    const int data;
    SyscallDataType return_value;
  };

  struct Event_personality
  {
    unsigned int personality;
    SyscallDataType return_value;
  };

  struct Event_exit
  {
    int error_code;
    SyscallDataType return_value;
  };

  struct Event_exit_group
  {
    int error_code;
    SyscallDataType return_value;
  };

  struct Event_waitid
  {
    int which;
    pid_t pid;
    struct siginfo * infop;
    int options;
    struct rusage * ru;
    SyscallDataType return_value;
  };

  struct Event_set_tid_address
  {
    int * tidptr;
    SyscallDataType return_value;
  };

  struct Event_unshare
  {
    unsigned long unshare_flags;
    SyscallDataType return_value;
  };

  struct Event_futex
  {
    uint32_t * uaddr;
    int op;
    uint32_t val;
    const struct __kernel_timespec * utime;
    uint32_t * uaddr2;
    uint32_t val3;
    SyscallDataType return_value;
  };

  struct Event_get_robust_list
  {
    int pid;
    struct robust_list_head * * head_ptr;
    size_t * len_ptr;
    SyscallDataType return_value;
  };

  struct Event_set_robust_list
  {
    struct robust_list_head * head;
    size_t len;
    SyscallDataType return_value;
  };

  struct Event_nanosleep
  {
    struct __kernel_timespec * rqtp;
    struct __kernel_timespec * rmtp;
    SyscallDataType return_value;
  };

  struct Event_getitimer
  {
    int which;
    struct __kernel_itimerval * value;
    SyscallDataType return_value;
  };

  struct Event_setitimer
  {
    int which;
    struct __kernel_itimerval * value;
    struct __kernel_itimerval * ovalue;
    SyscallDataType return_value;
  };

  struct Event_kexec_load
  {
    unsigned long entry;
    unsigned long nr_segments;
    struct kexec_segment * segments;
    unsigned long flags;
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

  struct Event_timer_create
  {
    clockid_t which_clock;
    struct sigevent * timer_event_spec;
    timer_t * created_timer_id;
    SyscallDataType return_value;
  };

  struct Event_timer_gettime
  {
    timer_t timer_id;
    struct __kernel_itimerspec * setting;
    SyscallDataType return_value;
  };

  struct Event_timer_getoverrun
  {
    timer_t timer_id;
    SyscallDataType return_value;
  };

  struct Event_timer_settime
  {
    timer_t timer_id;
    int flags;
    const struct __kernel_itimerspec * new_setting;
    struct __kernel_itimerspec * old_setting;
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
    const struct __kernel_timespec * tp;
    SyscallDataType return_value;
  };

  struct Event_clock_gettime
  {
    clockid_t which_clock;
    struct __kernel_timespec * tp;
    SyscallDataType return_value;
  };

  struct Event_clock_getres
  {
    clockid_t which_clock;
    struct __kernel_timespec * tp;
    SyscallDataType return_value;
  };

  struct Event_clock_nanosleep
  {
    clockid_t which_clock;
    int flags;
    const struct __kernel_timespec * rqtp;
    struct __kernel_timespec * rmtp;
    SyscallDataType return_value;
  };

  struct Event_syslog
  {
    int type;
    char * buf;
    int len;
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

  struct Event_sched_setparam
  {
    pid_t pid;
    struct sched_param * param;
    SyscallDataType return_value;
  };

  struct Event_sched_setscheduler
  {
    pid_t pid;
    int policy;
    struct sched_param * param;
    SyscallDataType return_value;
  };

  struct Event_sched_getscheduler
  {
    pid_t pid;
    SyscallDataType return_value;
  };

  struct Event_sched_getparam
  {
    pid_t pid;
    struct sched_param * param;
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

  struct Event_sched_yield
  {
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
    struct __kernel_timespec * interval;
    SyscallDataType return_value;
  };

  struct Event_restart_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_kill
  {
    pid_t pid;
    int sig;
    SyscallDataType return_value;
  };

  struct Event_tkill
  {
    pid_t pid;
    int sig;
    SyscallDataType return_value;
  };

  struct Event_tgkill
  {
    pid_t tgid;
    pid_t pid;
    int sig;
    SyscallDataType return_value;
  };

  struct Event_sigaltstack
  {
    const struct sigaltstack * uss;
    struct sigaltstack * uoss;
    SyscallDataType return_value;
  };

  struct Event_rt_sigsuspend
  {
    sigset_t * unewset;
    size_t sigsetsize;
    SyscallDataType return_value;
  };

  struct Event_rt_sigaction
  {
    int unnamed;
    const struct sigaction * unnamed;
    struct sigaction * unnamed;
    size_t unnamed;
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
    const struct __kernel_timespec * uts;
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

  struct Event_setpriority
  {
    int which;
    int who;
    int niceval;
    SyscallDataType return_value;
  };

  struct Event_getpriority
  {
    int which;
    int who;
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

  struct Event_setregid
  {
    gid_t rgid;
    gid_t egid;
    SyscallDataType return_value;
  };

  struct Event_setgid
  {
    gid_t gid;
    SyscallDataType return_value;
  };

  struct Event_setreuid
  {
    uid_t ruid;
    uid_t euid;
    SyscallDataType return_value;
  };

  struct Event_setuid
  {
    uid_t uid;
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

  struct Event_times
  {
    struct tms * tbuf;
    SyscallDataType return_value;
  };

  struct Event_setpgid
  {
    pid_t pid;
    pid_t pgid;
    SyscallDataType return_value;
  };

  struct Event_getpgid
  {
    pid_t pid;
    SyscallDataType return_value;
  };

  struct Event_getsid
  {
    pid_t pid;
    SyscallDataType return_value;
  };

  struct Event_setsid
  {
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

  struct Event_newuname
  {
    struct new_utsname * name;
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

  struct Event_getrlimit
  {
    unsigned int resource;
    struct rlimit * rlim;
    SyscallDataType return_value;
  };

  struct Event_setrlimit
  {
    unsigned int resource;
    struct rlimit * rlim;
    SyscallDataType return_value;
  };

  struct Event_getrusage
  {
    int who;
    struct rusage * ru;
    SyscallDataType return_value;
  };

  struct Event_umask
  {
    int mask;
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

  struct Event_getcpu
  {
    unsigned * cpu;
    unsigned * node;
    struct getcpu_cache * cache;
    SyscallDataType return_value;
  };

  struct Event_gettimeofday
  {
    struct __kernel_timeval * tv;
    struct timezone * tz;
    SyscallDataType return_value;
  };

  struct Event_settimeofday
  {
    struct __kernel_timeval * tv;
    struct timezone * tz;
    SyscallDataType return_value;
  };

  struct Event_adjtimex
  {
    struct __kernel_timex * txc_p;
    SyscallDataType return_value;
  };

  struct Event_getpid
  {
    SyscallDataType return_value;
  };

  struct Event_getppid
  {
    SyscallDataType return_value;
  };

  struct Event_getuid
  {
    SyscallDataType return_value;
  };

  struct Event_geteuid
  {
    SyscallDataType return_value;
  };

  struct Event_getgid
  {
    SyscallDataType return_value;
  };

  struct Event_getegid
  {
    SyscallDataType return_value;
  };

  struct Event_gettid
  {
    SyscallDataType return_value;
  };

  struct Event_sysinfo
  {
    struct sysinfo * info;
    SyscallDataType return_value;
  };

  struct Event_mq_open
  {
    const char * name;
    int oflag;
    mode_t mode;
    struct mq_attr * attr;
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
    const struct __kernel_timespec * abs_timeout;
    SyscallDataType return_value;
  };

  struct Event_mq_timedreceive
  {
    mqd_t mqdes;
    char * msg_ptr;
    size_t msg_len;
    unsigned int * msg_prio;
    const struct __kernel_timespec * abs_timeout;
    SyscallDataType return_value;
  };

  struct Event_mq_notify
  {
    mqd_t mqdes;
    const struct sigevent * notification;
    SyscallDataType return_value;
  };

  struct Event_mq_getsetattr
  {
    mqd_t mqdes;
    const struct mq_attr * mqstat;
    struct mq_attr * omqstat;
    SyscallDataType return_value;
  };

  struct Event_msgget
  {
    key_t key;
    int msgflg;
    SyscallDataType return_value;
  };

  struct Event_old_msgctl
  {
    int msqid;
    int cmd;
    struct msqid_ds * buf;
    SyscallDataType return_value;
  };

  struct Event_msgctl
  {
    int msqid;
    int cmd;
    struct msqid_ds * buf;
    SyscallDataType return_value;
  };

  struct Event_msgrcv
  {
    int msqid;
    struct msgbuf * msgp;
    size_t msgsz;
    long msgtyp;
    int msgflg;
    SyscallDataType return_value;
  };

  struct Event_msgsnd
  {
    int msqid;
    struct msgbuf * msgp;
    size_t msgsz;
    int msgflg;
    SyscallDataType return_value;
  };

  struct Event_semget
  {
    key_t key;
    int nsems;
    int semflg;
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

  struct Event_old_semctl
  {
    int semid;
    int semnum;
    int cmd;
    unsigned long arg;
    SyscallDataType return_value;
  };

  struct Event_semtimedop
  {
    int semid;
    struct sembuf * sops;
    unsigned nsops;
    const struct __kernel_timespec * timeout;
    SyscallDataType return_value;
  };

  struct Event_semop
  {
    int semid;
    struct sembuf * sops;
    unsigned nsops;
    SyscallDataType return_value;
  };

  struct Event_shmget
  {
    key_t key;
    size_t size;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_old_shmctl
  {
    int shmid;
    int cmd;
    struct shmid_ds * buf;
    SyscallDataType return_value;
  };

  struct Event_shmctl
  {
    int shmid;
    int cmd;
    struct shmid_ds * buf;
    SyscallDataType return_value;
  };

  struct Event_shmat
  {
    int shmid;
    char * shmaddr;
    int shmflg;
    SyscallDataType return_value;
  };

  struct Event_shmdt
  {
    char * shmaddr;
    SyscallDataType return_value;
  };

  struct Event_socket
  {
    int unnamed;
    int unnamed;
    int unnamed;
    SyscallDataType return_value;
  };

  struct Event_socketpair
  {
    int unnamed;
    int unnamed;
    int unnamed;
    int * unnamed;
    SyscallDataType return_value;
  };

  struct Event_bind
  {
    int unnamed;
    struct sockaddr * unnamed;
    int unnamed;
    SyscallDataType return_value;
  };

  struct Event_listen
  {
    int unnamed;
    int unnamed;
    SyscallDataType return_value;
  };

  struct Event_accept
  {
    int unnamed;
    struct sockaddr * unnamed;
    int * unnamed;
    SyscallDataType return_value;
  };

  struct Event_connect
  {
    int unnamed;
    struct sockaddr * unnamed;
    int unnamed;
    SyscallDataType return_value;
  };

  struct Event_getsockname
  {
    int unnamed;
    struct sockaddr * unnamed;
    int * unnamed;
    SyscallDataType return_value;
  };

  struct Event_getpeername
  {
    int unnamed;
    struct sockaddr * unnamed;
    int * unnamed;
    SyscallDataType return_value;
  };

  struct Event_sendto
  {
    int unnamed;
    void * unnamed;
    size_t unnamed;
     unsigned;
    struct sockaddr * unnamed;
    int unnamed;
    SyscallDataType return_value;
  };

  struct Event_recvfrom
  {
    int unnamed;
    void * unnamed;
    size_t unnamed;
     unsigned;
    struct sockaddr * unnamed;
    int * unnamed;
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

  struct Event_shutdown
  {
    int unnamed;
    int unnamed;
    SyscallDataType return_value;
  };

  struct Event_sendmsg
  {
    int fd;
    struct user_msghdr * msg;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_recvmsg
  {
    int fd;
    struct user_msghdr * msg;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_readahead
  {
    int fd;
    loff_t offset;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_brk
  {
    unsigned long brk;
    SyscallDataType return_value;
  };

  struct Event_munmap
  {
    unsigned long addr;
    size_t len;
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

  struct Event_add_key
  {
    const char * _type;
    const char * _description;
    const void * _payload;
    size_t plen;
    int destringid;
    SyscallDataType return_value;
  };

  struct Event_request_key
  {
    const char * _type;
    const char * _description;
    const char * _callout_info;
    int destringid;
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

  struct Event_clone
  {
    unsigned long unnamed;
    unsigned long unnamed;
    int * unnamed;
    int * unnamed;
    unsigned long unnamed;
    SyscallDataType return_value;
  };

  struct Event_clone3
  {
    struct clone_args * uargs;
    size_t size;
    SyscallDataType return_value;
  };

  struct Event_execve
  {
    const char * filename;
    const char *const * argv;
    const char *const * envp;
    SyscallDataType return_value;
  };

  struct Event_fadvise64_64
  {
    int fd;
    loff_t offset;
    loff_t len;
    int advice;
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

  struct Event_mprotect
  {
    unsigned long start;
    size_t len;
    unsigned long prot;
    SyscallDataType return_value;
  };

  struct Event_msync
  {
    unsigned long start;
    size_t len;
    int flags;
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

  struct Event_process_madvise
  {
    int pidfd;
    const struct iovec * vec;
    size_t vlen;
    int behavior;
    unsigned int flags;
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

  struct Event_get_mempolicy
  {
    int * policy;
    unsigned long * nmask;
    unsigned long maxnode;
    unsigned long addr;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_set_mempolicy
  {
    int mode;
    const unsigned long * nmask;
    unsigned long maxnode;
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
    struct perf_event_attr * attr_uptr;
    pid_t pid;
    int cpu;
    int group_fd;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_accept4
  {
    int unnamed;
    struct sockaddr * unnamed;
    int * unnamed;
    int unnamed;
    SyscallDataType return_value;
  };

  struct Event_recvmmsg
  {
    int fd;
    struct mmsghdr * msg;
    unsigned int vlen;
    unsigned flags;
    struct __kernel_timespec * timeout;
    SyscallDataType return_value;
  };

  struct Event_wait4
  {
    pid_t pid;
    int * stat_addr;
    int options;
    struct rusage * ru;
    SyscallDataType return_value;
  };

  struct Event_prlimit64
  {
    pid_t pid;
    unsigned int resource;
    const struct rlimit64 * new_rlim;
    struct rlimit64 * old_rlim;
    SyscallDataType return_value;
  };

  struct Event_fanotify_init
  {
    unsigned int flags;
    unsigned int event_f_flags;
    SyscallDataType return_value;
  };

  struct Event_fanotify_mark
  {
    int fanotify_fd;
    unsigned int flags;
    uint64_t mask;
    int fd;
    const char  * pathname;
    SyscallDataType return_value;
  };

  struct Event_name_to_handle_at
  {
    int dfd;
    const char * name;
    struct file_handle * handle;
    int * mnt_id;
    int flag;
    SyscallDataType return_value;
  };

  struct Event_open_by_handle_at
  {
    int mountdirfd;
    struct file_handle * handle;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_clock_adjtime
  {
    clockid_t which_clock;
    struct __kernel_timex * tx;
    SyscallDataType return_value;
  };

  struct Event_syncfs
  {
    int fd;
    SyscallDataType return_value;
  };

  struct Event_setns
  {
    int fd;
    int nstype;
    SyscallDataType return_value;
  };

  struct Event_pidfd_open
  {
    pid_t pid;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_sendmmsg
  {
    int fd;
    struct mmsghdr * msg;
    unsigned int vlen;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_process_vm_readv
  {
    pid_t pid;
    const struct iovec * lvec;
    unsigned long liovcnt;
    const struct iovec * rvec;
    unsigned long riovcnt;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_process_vm_writev
  {
    pid_t pid;
    const struct iovec * lvec;
    unsigned long liovcnt;
    const struct iovec * rvec;
    unsigned long riovcnt;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_kcmp
  {
    pid_t pid1;
    pid_t pid2;
    int type;
    unsigned long idx1;
    unsigned long idx2;
    SyscallDataType return_value;
  };

  struct Event_finit_module
  {
    int fd;
    const char * uargs;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_sched_setattr
  {
    pid_t pid;
    struct sched_attr * attr;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_sched_getattr
  {
    pid_t pid;
    struct sched_attr * attr;
    unsigned int size;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_renameat2
  {
    int olddfd;
    const char * oldname;
    int newdfd;
    const char * newname;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_seccomp
  {
    unsigned int op;
    unsigned int flags;
    void * uargs;
    SyscallDataType return_value;
  };

  struct Event_getrandom
  {
    char * buf;
    size_t count;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_memfd_create
  {
    const char * uname_ptr;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_bpf
  {
    int cmd;
    union bpf_attr * attr;
    unsigned int size;
    SyscallDataType return_value;
  };

  struct Event_execveat
  {
    int dfd;
    const char * filename;
    const char *const * argv;
    const char *const * envp;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_userfaultfd
  {
    int flags;
    SyscallDataType return_value;
  };

  struct Event_membarrier
  {
    int cmd;
    unsigned int flags;
    int cpu_id;
    SyscallDataType return_value;
  };

  struct Event_mlock2
  {
    unsigned long start;
    size_t len;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_copy_file_range
  {
    int fd_in;
    loff_t * off_in;
    int fd_out;
    loff_t * off_out;
    size_t len;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_preadv2
  {
    unsigned long fd;
    const struct iovec * vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_pwritev2
  {
    unsigned long fd;
    const struct iovec * vec;
    unsigned long vlen;
    unsigned long pos_l;
    unsigned long pos_h;
    int flags;
    SyscallDataType return_value;
  };

  struct Event_pkey_mprotect
  {
    unsigned long start;
    size_t len;
    unsigned long prot;
    int pkey;
    SyscallDataType return_value;
  };

  struct Event_pkey_alloc
  {
    unsigned long flags;
    unsigned long init_val;
    SyscallDataType return_value;
  };

  struct Event_pkey_free
  {
    int pkey;
    SyscallDataType return_value;
  };

  struct Event_statx
  {
    int dfd;
    const char * path;
    unsigned flags;
    unsigned mask;
    struct statx * buffer;
    SyscallDataType return_value;
  };

  struct Event_rseq
  {
    struct rseq * rseq;
    uint32_t rseq_len;
    int flags;
    uint32_t sig;
    SyscallDataType return_value;
  };

  struct Event_open_tree
  {
    int dfd;
    const char * path;
    unsigned flags;
    SyscallDataType return_value;
  };

  struct Event_move_mount
  {
    int from_dfd;
    const char * from_path;
    int to_dfd;
    const char * to_path;
    unsigned int ms_flags;
    SyscallDataType return_value;
  };

  struct Event_mount_setattr
  {
    int dfd;
    const char * path;
    unsigned int flags;
    struct mount_attr * uattr;
    size_t usize;
    SyscallDataType return_value;
  };

  struct Event_fsopen
  {
    const char * fs_name;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_fsconfig
  {
    int fs_fd;
    unsigned int cmd;
    const char * key;
    const void * value;
    int aux;
    SyscallDataType return_value;
  };

  struct Event_fsmount
  {
    int fs_fd;
    unsigned int flags;
    unsigned int ms_flags;
    SyscallDataType return_value;
  };

  struct Event_fspick
  {
    int dfd;
    const char * path;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_pidfd_send_signal
  {
    int pidfd;
    int sig;
    siginfo_t * info;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_pidfd_getfd
  {
    int pidfd;
    int fd;
    unsigned int flags;
    SyscallDataType return_value;
  };

  struct Event_ioperm
  {
    unsigned long from;
    unsigned long num;
    int on;
    SyscallDataType return_value;
  };

  struct Event_pciconfig_read
  {
    unsigned long bus;
    unsigned long dfn;
    unsigned long off;
    unsigned long len;
    void * buf;
    SyscallDataType return_value;
  };

  struct Event_pciconfig_write
  {
    unsigned long bus;
    unsigned long dfn;
    unsigned long off;
    unsigned long len;
    void * buf;
    SyscallDataType return_value;
  };

  struct Event_pciconfig_iobase
  {
    long which;
    unsigned long bus;
    unsigned long devfn;
    SyscallDataType return_value;
  };

  struct Event_spu_run
  {
    int fd;
    __uint32_t * unpc;
    __uint32_t * ustatus;
    SyscallDataType return_value;
  };

  struct Event_spu_create
  {
    const char * name;
    unsigned int flags;
    mode_t mode;
    int fd;
    SyscallDataType return_value;
  };

  struct Event_open
  {
    const char * filename;
    int flags;
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

  struct Event_mknod
  {
    const char * filename;
    mode_t mode;
    unsigned dev;
    SyscallDataType return_value;
  };

  struct Event_chmod
  {
    const char * filename;
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

  struct Event_lchown
  {
    const char * filename;
    uid_t user;
    gid_t group;
    SyscallDataType return_value;
  };

  struct Event_access
  {
    const char * filename;
    int mode;
    SyscallDataType return_value;
  };

  struct Event_rename
  {
    const char * oldname;
    const char * newname;
    SyscallDataType return_value;
  };

  struct Event_symlink
  {
    const char * old;
    const char* linkpath;
    SyscallDataType return_value;
  };

  struct Event_stat64
  {
    const char * filename;
    struct stat64 * statbuf;
    SyscallDataType return_value;
  };

  struct Event_lstat64
  {
    const char * filename;
    struct stat64 * statbuf;
    SyscallDataType return_value;
  };

  struct Event_pipe
  {
    int * fildes;
    SyscallDataType return_value;
  };

  struct Event_dup2
  {
    unsigned int oldfd;
    unsigned int newfd;
    SyscallDataType return_value;
  };

  struct Event_epoll_create
  {
    int size;
    SyscallDataType return_value;
  };

  struct Event_inotify_init
  {
    SyscallDataType return_value;
  };

  struct Event_eventfd
  {
    unsigned int count;
    SyscallDataType return_value;
  };

  struct Event_signalfd
  {
    int ufd;
    sigset_t * user_mask;
    size_t sizemask;
    SyscallDataType return_value;
  };

  struct Event_sendfile
  {
    int out_fd;
    int in_fd;
    off_t * offset;
    size_t count;
    SyscallDataType return_value;
  };

  struct Event_newstat
  {
    const char * filename;
    struct stat * statbuf;
    SyscallDataType return_value;
  };

  struct Event_newlstat
  {
    const char * filename;
    struct stat * statbuf;
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

  struct Event_alarm
  {
    unsigned int seconds;
    SyscallDataType return_value;
  };

  struct Event_getpgrp
  {
    SyscallDataType return_value;
  };

  struct Event_pause
  {
    SyscallDataType return_value;
  };

  struct Event_time
  {
    __kernel_time_t * tloc;
    SyscallDataType return_value;
  };

  struct Event_utime
  {
    char * filename;
    struct utimbuf * times;
    SyscallDataType return_value;
  };

  struct Event_utimes
  {
    char * filename;
    struct __kernel_timeval * utimes;
    SyscallDataType return_value;
  };

  struct Event_futimesat
  {
    int dfd;
    const char * filename;
    struct __kernel_timeval * utimes;
    SyscallDataType return_value;
  };

  struct Event_creat
  {
    const char * pathname;
    mode_t mode;
    SyscallDataType return_value;
  };

  struct Event_getdents
  {
    unsigned int fd;
    struct linux_dirent * dirent;
    unsigned int count;
    SyscallDataType return_value;
  };

  struct Event_select
  {
    int n;
    fd_set * inp;
    fd_set * outp;
    fd_set * exp;
    struct __kernel_timeval * tvp;
    SyscallDataType return_value;
  };

  struct Event_poll
  {
    struct pollfd * ufds;
    unsigned int nfds;
    int timeout;
    SyscallDataType return_value;
  };

  struct Event_epoll_wait
  {
    int epfd;
    struct epoll_event * events;
    int maxevents;
    int timeout;
    SyscallDataType return_value;
  };

  struct Event_ustat
  {
    unsigned dev;
    struct ustat * ubuf;
    SyscallDataType return_value;
  };

  struct Event_vfork
  {
    SyscallDataType return_value;
  };

  struct Event_recv
  {
    int unnamed;
    void * unnamed;
    size_t unnamed;
     unsigned;
    SyscallDataType return_value;
  };

  struct Event_send
  {
    int unnamed;
    void * unnamed;
    size_t unnamed;
     unsigned;
    SyscallDataType return_value;
  };

  struct Event_bdflush
  {
    int func;
    long data;
    SyscallDataType return_value;
  };

  struct Event_oldumount
  {
    char * name;
    SyscallDataType return_value;
  };

  struct Event_uselib
  {
    const char * library;
    SyscallDataType return_value;
  };

  struct Event_sysfs
  {
    int option;
    unsigned long arg1;
    unsigned long arg2;
    SyscallDataType return_value;
  };

  struct Event_fork
  {
    SyscallDataType return_value;
  };

  struct Event_stime
  {
    __kernel_time_t * tptr;
    SyscallDataType return_value;
  };

  struct Event_sigpending
  {
    sigset_t * uset;
    SyscallDataType return_value;
  };

  struct Event_sigprocmask
  {
    int how;
    sigset_t * set;
    sigset_t * oset;
    SyscallDataType return_value;
  };

  struct Event_sigsuspend
  {
    int unused1;
    int unused2;
    sigset_t mask;
    SyscallDataType return_value;
  };

  struct Event_sigaction
  {
    int unnamed;
    const struct sigaction * unnamed;
    struct sigaction * unnamed;
    SyscallDataType return_value;
  };

  struct Event_sgetmask
  {
    SyscallDataType return_value;
  };

  struct Event_ssetmask
  {
    int newmask;
    SyscallDataType return_value;
  };

  struct Event_signal
  {
    int sig;
    __sighandler_t handler;
    SyscallDataType return_value;
  };

  struct Event_nice
  {
    int increment;
    SyscallDataType return_value;
  };

  struct Event_kexec_file_load
  {
    int kernel_fd;
    int initrd_fd;
    unsigned long cmdline_len;
    const char * cmdline_ptr;
    unsigned long flags;
    SyscallDataType return_value;
  };

  struct Event_waitpid
  {
    pid_t pid;
    int * stat_addr;
    int options;
    SyscallDataType return_value;
  };

  struct Event_socketcall
  {
    int call;
    unsigned long * args;
    SyscallDataType return_value;
  };

  struct Event_stat
  {
    const char * filename;
    struct __kernel_stat * statbuf;
    SyscallDataType return_value;
  };

  struct Event_lstat
  {
    const char * filename;
    struct __kernel_stat * statbuf;
    SyscallDataType return_value;
  };

  struct Event_fstat
  {
    unsigned int fd;
    struct __kernel_stat * statbuf;
    SyscallDataType return_value;
  };

  struct Event_readlink
  {
    const char * path;
    char * buf;
    int bufsiz;
    SyscallDataType return_value;
  };

  struct Event_old_select
  {
    struct sel_arg_struct * arg;
    SyscallDataType return_value;
  };

  struct Event_old_readdir
  {
    unsigned int unnamed;
    struct linux_dirent * unnamed;
    unsigned int unnamed;
    SyscallDataType return_value;
  };

  struct Event_gethostname
  {
    char * name;
    int len;
    SyscallDataType return_value;
  };

  struct Event_uname
  {
    struct utsname * unnamed;
    SyscallDataType return_value;
  };

  struct Event_olduname
  {
    struct oldutsname * unnamed;
    SyscallDataType return_value;
  };

  struct Event_old_getrlimit
  {
    unsigned int resource;
    struct rlimit * rlim;
    SyscallDataType return_value;
  };

  struct Event_ipc
  {
    unsigned int call;
    int first;
    unsigned long second;
    unsigned long third;
    void * ptr;
    long fifth;
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

  struct Event_old_mmap
  {
    struct mmap_arg_struct * arg;
    SyscallDataType return_value;
  };

  struct Event_ni_syscall
  {
    SyscallDataType return_value;
  };

  struct Event_arch_prctl
  {
    int code;
    unsigned long addr;
    SyscallDataType return_value;
  };

  using SyscallEvent = std::variant<
    Event_io_setup,
    Event_io_destroy,
    Event_io_submit,
    Event_io_cancel,
    Event_io_getevents,
    Event_io_pgetevents,
    Event_io_uring_setup,
    Event_io_uring_enter,
    Event_io_uring_register,
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
    Event_getcwd,
    Event_lookup_dcookie,
    Event_eventfd2,
    Event_epoll_create1,
    Event_epoll_ctl,
    Event_epoll_pwait,
    Event_epoll_pwait2,
    Event_dup,
    Event_dup3,
    Event_fcntl,
    Event_fcntl64,
    Event_inotify_init1,
    Event_inotify_add_watch,
    Event_inotify_rm_watch,
    Event_ioctl,
    Event_ioprio_set,
    Event_ioprio_get,
    Event_flock,
    Event_mknodat,
    Event_mkdirat,
    Event_unlinkat,
    Event_symlinkat,
    Event_linkat,
    Event_renameat,
    Event_umount,
    Event_mount,
    Event_pivot_root,
    Event_statfs,
    Event_statfs64,
    Event_fstatfs,
    Event_fstatfs64,
    Event_truncate,
    Event_ftruncate,
    Event_truncate64,
    Event_ftruncate64,
    Event_fallocate,
    Event_faccessat,
    Event_faccessat2,
    Event_chdir,
    Event_fchdir,
    Event_chroot,
    Event_fchmod,
    Event_fchmodat,
    Event_fchownat,
    Event_fchown,
    Event_openat,
    Event_openat2,
    Event_close,
    Event_close_range,
    Event_vhangup,
    Event_pipe2,
    Event_quotactl,
    Event_getdents64,
    Event_llseek,
    Event_lseek,
    Event_read,
    Event_write,
    Event_readv,
    Event_writev,
    Event_pread64,
    Event_pwrite64,
    Event_preadv,
    Event_pwritev,
    Event_sendfile64,
    Event_pselect6,
    Event_ppoll,
    Event_signalfd4,
    Event_vmsplice,
    Event_splice,
    Event_tee,
    Event_readlinkat,
    Event_newfstatat,
    Event_newfstat,
    Event_fstat64,
    Event_fstatat64,
    Event_sync,
    Event_fsync,
    Event_fdatasync,
    Event_sync_file_range2,
    Event_sync_file_range,
    Event_timerfd_create,
    Event_timerfd_settime,
    Event_timerfd_gettime,
    Event_utimensat,
    Event_acct,
    Event_capget,
    Event_capset,
    Event_personality,
    Event_exit,
    Event_exit_group,
    Event_waitid,
    Event_set_tid_address,
    Event_unshare,
    Event_futex,
    Event_get_robust_list,
    Event_set_robust_list,
    Event_nanosleep,
    Event_getitimer,
    Event_setitimer,
    Event_kexec_load,
    Event_init_module,
    Event_delete_module,
    Event_timer_create,
    Event_timer_gettime,
    Event_timer_getoverrun,
    Event_timer_settime,
    Event_timer_delete,
    Event_clock_settime,
    Event_clock_gettime,
    Event_clock_getres,
    Event_clock_nanosleep,
    Event_syslog,
    Event_ptrace,
    Event_sched_setparam,
    Event_sched_setscheduler,
    Event_sched_getscheduler,
    Event_sched_getparam,
    Event_sched_setaffinity,
    Event_sched_getaffinity,
    Event_sched_yield,
    Event_sched_get_priority_max,
    Event_sched_get_priority_min,
    Event_sched_rr_get_interval,
    Event_restart_syscall,
    Event_kill,
    Event_tkill,
    Event_tgkill,
    Event_sigaltstack,
    Event_rt_sigsuspend,
    Event_rt_sigaction,
    Event_rt_sigprocmask,
    Event_rt_sigpending,
    Event_rt_sigtimedwait,
    Event_rt_sigqueueinfo,
    Event_setpriority,
    Event_getpriority,
    Event_reboot,
    Event_setregid,
    Event_setgid,
    Event_setreuid,
    Event_setuid,
    Event_setresuid,
    Event_getresuid,
    Event_setresgid,
    Event_getresgid,
    Event_setfsuid,
    Event_setfsgid,
    Event_times,
    Event_setpgid,
    Event_getpgid,
    Event_getsid,
    Event_setsid,
    Event_getgroups,
    Event_setgroups,
    Event_newuname,
    Event_sethostname,
    Event_setdomainname,
    Event_getrlimit,
    Event_setrlimit,
    Event_getrusage,
    Event_umask,
    Event_prctl,
    Event_getcpu,
    Event_gettimeofday,
    Event_settimeofday,
    Event_adjtimex,
    Event_getpid,
    Event_getppid,
    Event_getuid,
    Event_geteuid,
    Event_getgid,
    Event_getegid,
    Event_gettid,
    Event_sysinfo,
    Event_mq_open,
    Event_mq_unlink,
    Event_mq_timedsend,
    Event_mq_timedreceive,
    Event_mq_notify,
    Event_mq_getsetattr,
    Event_msgget,
    Event_old_msgctl,
    Event_msgctl,
    Event_msgrcv,
    Event_msgsnd,
    Event_semget,
    Event_semctl,
    Event_old_semctl,
    Event_semtimedop,
    Event_semop,
    Event_shmget,
    Event_old_shmctl,
    Event_shmctl,
    Event_shmat,
    Event_shmdt,
    Event_socket,
    Event_socketpair,
    Event_bind,
    Event_listen,
    Event_accept,
    Event_connect,
    Event_getsockname,
    Event_getpeername,
    Event_sendto,
    Event_recvfrom,
    Event_setsockopt,
    Event_getsockopt,
    Event_shutdown,
    Event_sendmsg,
    Event_recvmsg,
    Event_readahead,
    Event_brk,
    Event_munmap,
    Event_mremap,
    Event_add_key,
    Event_request_key,
    Event_keyctl,
    Event_clone,
    Event_clone3,
    Event_execve,
    Event_fadvise64_64,
    Event_swapon,
    Event_swapoff,
    Event_mprotect,
    Event_msync,
    Event_mlock,
    Event_munlock,
    Event_mlockall,
    Event_munlockall,
    Event_mincore,
    Event_madvise,
    Event_process_madvise,
    Event_remap_file_pages,
    Event_mbind,
    Event_get_mempolicy,
    Event_set_mempolicy,
    Event_migrate_pages,
    Event_move_pages,
    Event_rt_tgsigqueueinfo,
    Event_perf_event_open,
    Event_accept4,
    Event_recvmmsg,
    Event_wait4,
    Event_prlimit64,
    Event_fanotify_init,
    Event_fanotify_mark,
    Event_name_to_handle_at,
    Event_open_by_handle_at,
    Event_clock_adjtime,
    Event_syncfs,
    Event_setns,
    Event_pidfd_open,
    Event_sendmmsg,
    Event_process_vm_readv,
    Event_process_vm_writev,
    Event_kcmp,
    Event_finit_module,
    Event_sched_setattr,
    Event_sched_getattr,
    Event_renameat2,
    Event_seccomp,
    Event_getrandom,
    Event_memfd_create,
    Event_bpf,
    Event_execveat,
    Event_userfaultfd,
    Event_membarrier,
    Event_mlock2,
    Event_copy_file_range,
    Event_preadv2,
    Event_pwritev2,
    Event_pkey_mprotect,
    Event_pkey_alloc,
    Event_pkey_free,
    Event_statx,
    Event_rseq,
    Event_open_tree,
    Event_move_mount,
    Event_mount_setattr,
    Event_fsopen,
    Event_fsconfig,
    Event_fsmount,
    Event_fspick,
    Event_pidfd_send_signal,
    Event_pidfd_getfd,
    Event_ioperm,
    Event_pciconfig_read,
    Event_pciconfig_write,
    Event_pciconfig_iobase,
    Event_spu_run,
    Event_spu_create,
    Event_open,
    Event_link,
    Event_unlink,
    Event_mknod,
    Event_chmod,
    Event_chown,
    Event_mkdir,
    Event_rmdir,
    Event_lchown,
    Event_access,
    Event_rename,
    Event_symlink,
    Event_stat64,
    Event_lstat64,
    Event_pipe,
    Event_dup2,
    Event_epoll_create,
    Event_inotify_init,
    Event_eventfd,
    Event_signalfd,
    Event_sendfile,
    Event_newstat,
    Event_newlstat,
    Event_fadvise64,
    Event_alarm,
    Event_getpgrp,
    Event_pause,
    Event_time,
    Event_utime,
    Event_utimes,
    Event_futimesat,
    Event_creat,
    Event_getdents,
    Event_select,
    Event_poll,
    Event_epoll_wait,
    Event_ustat,
    Event_vfork,
    Event_recv,
    Event_send,
    Event_bdflush,
    Event_oldumount,
    Event_uselib,
    Event_sysfs,
    Event_fork,
    Event_stime,
    Event_sigpending,
    Event_sigprocmask,
    Event_sigsuspend,
    Event_sigaction,
    Event_sgetmask,
    Event_ssetmask,
    Event_signal,
    Event_nice,
    Event_kexec_file_load,
    Event_waitpid,
    Event_socketcall,
    Event_stat,
    Event_lstat,
    Event_fstat,
    Event_readlink,
    Event_old_select,
    Event_old_readdir,
    Event_gethostname,
    Event_uname,
    Event_olduname,
    Event_old_getrlimit,
    Event_ipc,
    Event_mmap,
    Event_old_mmap,
    Event_ni_syscall,
    Event_arch_prctl
  >;
} // namespace
