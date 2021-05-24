#include <SyscallEventCreator.h>

namespace gpcache
{

  // This variant compiles for ~42 seconds on my PC
  using SyscallEvent = std::variant<
    Event_Unsupported,
    Event_read,
    Event_write,
    Event_open,
    Event_close,
    Event_newstat,
    Event_newfstat,
    Event_newlstat,
    Event_lseek,
    Event_mmap,
    Event_mprotect,
    Event_munmap,
    Event_brk,
    Event_rt_sigprocmask,
    Event_ioctl,
    Event_pread64,
    Event_pwrite64,
    Event_readv,
    Event_writev,
    Event_access,
    Event_pipe,
    Event_sched_yield,
    Event_mremap,
    Event_msync,
    Event_mincore,
    Event_madvise,
    Event_shmget,
    Event_shmat,
    Event_dup,
    Event_dup2,
    Event_pause,
    Event_nanosleep,
    Event_alarm,
    Event_getpid,
    Event_sendfile64,
    Event_socket,
    Event_connect,
    Event_accept,
    Event_sendto,
    Event_recvfrom,
    Event_shutdown,
    Event_bind,
    Event_listen,
    Event_getsockname,
    Event_getpeername,
    Event_socketpair,
    Event_setsockopt,
    Event_getsockopt,
    Event_exit,
    Event_kill,
    Event_semget,
    Event_semctl,
    Event_shmdt,
    Event_msgget,
    Event_fcntl,
    Event_flock,
    Event_fsync,
    Event_fdatasync,
    Event_truncate,
    Event_ftruncate,
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
    Event_mknod,
    Event_personality,
    Event_ustat,
    Event_statfs,
    Event_fstatfs,
    Event_sysfs,
    Event_getpriority,
    Event_setpriority,
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
    Event_chroot,
    Event_sync,
    Event_acct,
    Event_mount,
    Event_umount,
    Event_swapon,
    Event_swapoff,
    Event_reboot,
    Event_sethostname,
    Event_setdomainname,
    Event_ioperm,
    Event_init_module,
    Event_delete_module,
    Event_quotactl,
    Event_nfsservctl,
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
    Event_io_setup,
    Event_io_destroy,
    Event_io_getevents,
    Event_lookup_dcookie,
    Event_epoll_create,
    Event_remap_file_pages,
    Event_set_tid_address,
    Event_restart_syscall,
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
    Event_mbind,
    Event_set_mempolicy,
    Event_get_mempolicy,
    Event_mq_open,
    Event_mq_unlink,
    Event_mq_timedsend,
    Event_mq_timedreceive,
    Event_mq_notify,
    Event_mq_getsetattr,
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
    Event_newfstatat,
    Event_unlinkat,
    Event_renameat,
    Event_linkat,
    Event_symlinkat,
    Event_readlinkat,
    Event_fchmodat,
    Event_faccessat,
    Event_pselect6,
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
    Event_rt_tgsigqueueinfo
  >;
  auto createEvent(SyscallDataType syscall_id, SyscallDataType arg1, SyscallDataType arg2, SyscallDataType arg3, SyscallDataType arg4, SyscallDataType arg5, SyscallDataType arg6) -> SyscallEvent
  {
    switch (syscall_id)
    {
    case 0: 
      return Event_read
      {
      .fd = static_cast<unsigned int>(arg1),
      .buf = reinterpret_cast<char *>(arg2),
      .count = static_cast<size_t>(arg3),
      };
    case 1: 
      return Event_write
      {
      .fd = static_cast<unsigned int>(arg1),
      .buf = reinterpret_cast<const char *>(arg2),
      .count = static_cast<size_t>(arg3),
      };
    case 2: 
      return Event_open
      {
      .filename = reinterpret_cast<const char *>(arg1),
      .flags = static_cast<int>(arg2),
      .mode = static_cast<mode_t>(arg3),
      };
    case 3: 
      return Event_close
      {
      .fd = static_cast<unsigned int>(arg1),
      };
    case 4: 
      return Event_newstat
      {
      .filename = reinterpret_cast<const char *>(arg1),
      .statbuf = reinterpret_cast<struct stat *>(arg2),
      };
    case 5: 
      return Event_newfstat
      {
      .fd = static_cast<unsigned int>(arg1),
      .statbuf = reinterpret_cast<struct stat *>(arg2),
      };
    case 6: 
      return Event_newlstat
      {
      .filename = reinterpret_cast<const char *>(arg1),
      .statbuf = reinterpret_cast<struct stat *>(arg2),
      };
    case 8: 
      return Event_lseek
      {
      .fd = static_cast<unsigned int>(arg1),
      .offset = static_cast<off_t>(arg2),
      .whence = static_cast<unsigned int>(arg3),
      };
    case 9: 
      return Event_mmap
      {
      .addr = static_cast<unsigned long>(arg1),
      .len = static_cast<unsigned long>(arg2),
      .prot = static_cast<unsigned long>(arg3),
      .flags = static_cast<unsigned long>(arg4),
      .fd = static_cast<unsigned long>(arg5),
      .pgoff = static_cast<unsigned long>(arg6),
      };
    case 10: 
      return Event_mprotect
      {
      .start = static_cast<unsigned long>(arg1),
      .len = static_cast<size_t>(arg2),
      .prot = static_cast<unsigned long>(arg3),
      };
    case 11: 
      return Event_munmap
      {
      .addr = static_cast<unsigned long>(arg1),
      .len = static_cast<size_t>(arg2),
      };
    case 12: 
      return Event_brk
      {
      .brk = static_cast<unsigned long>(arg1),
      };
    case 14: 
      return Event_rt_sigprocmask
      {
      .how = static_cast<int>(arg1),
      .set = reinterpret_cast<sigset_t *>(arg2),
      .oset = reinterpret_cast<sigset_t *>(arg3),
      .sigsetsize = static_cast<size_t>(arg4),
      };
    case 16: 
      return Event_ioctl
      {
      .fd = static_cast<unsigned int>(arg1),
      .cmd = static_cast<unsigned int>(arg2),
      .arg = static_cast<unsigned long>(arg3),
      };
    case 17: 
      return Event_pread64
      {
      .fd = static_cast<unsigned int>(arg1),
      .buf = reinterpret_cast<char *>(arg2),
      .count = static_cast<size_t>(arg3),
      .pos = static_cast<loff_t>(arg4),
      };
    case 18: 
      return Event_pwrite64
      {
      .fd = static_cast<unsigned int>(arg1),
      .buf = reinterpret_cast<const char *>(arg2),
      .count = static_cast<size_t>(arg3),
      .pos = static_cast<loff_t>(arg4),
      };
    case 19: 
      return Event_readv
      {
      .fd = static_cast<unsigned long>(arg1),
      .vec = reinterpret_cast<const struct iovec *>(arg2),
      .vlen = static_cast<unsigned long>(arg3),
      };
    case 20: 
      return Event_writev
      {
      .fd = static_cast<unsigned long>(arg1),
      .vec = reinterpret_cast<const struct iovec *>(arg2),
      .vlen = static_cast<unsigned long>(arg3),
      };
    case 21: 
      return Event_access
      {
      .filename = reinterpret_cast<const char *>(arg1),
      .mode = static_cast<int>(arg2),
      };
    case 22: 
      return Event_pipe
      {
      .fildes = reinterpret_cast<int *>(arg1),
      };
    case 24: 
      return Event_sched_yield
      {
      };
    case 25: 
      return Event_mremap
      {
      .addr = static_cast<unsigned long>(arg1),
      .old_len = static_cast<unsigned long>(arg2),
      .new_len = static_cast<unsigned long>(arg3),
      .flags = static_cast<unsigned long>(arg4),
      .new_addr = static_cast<unsigned long>(arg5),
      };
    case 26: 
      return Event_msync
      {
      .start = static_cast<unsigned long>(arg1),
      .len = static_cast<size_t>(arg2),
      .flags = static_cast<int>(arg3),
      };
    case 27: 
      return Event_mincore
      {
      .start = static_cast<unsigned long>(arg1),
      .len = static_cast<size_t>(arg2),
      .vec = reinterpret_cast<unsigned char *>(arg3),
      };
    case 28: 
      return Event_madvise
      {
      .start = static_cast<unsigned long>(arg1),
      .len = static_cast<size_t>(arg2),
      .behavior = static_cast<int>(arg3),
      };
    case 29: 
      return Event_shmget
      {
      .key = static_cast<key_t>(arg1),
      .size = static_cast<size_t>(arg2),
      .flag = static_cast<int>(arg3),
      };
    case 30: 
      return Event_shmat
      {
      .shmid = static_cast<int>(arg1),
      .shmaddr = reinterpret_cast<char *>(arg2),
      .shmflg = static_cast<int>(arg3),
      };
    case 32: 
      return Event_dup
      {
      .fildes = static_cast<unsigned int>(arg1),
      };
    case 33: 
      return Event_dup2
      {
      .oldfd = static_cast<unsigned int>(arg1),
      .newfd = static_cast<unsigned int>(arg2),
      };
    case 34: 
      return Event_pause
      {
      };
    case 35: 
      return Event_nanosleep
      {
      .rqtp = reinterpret_cast<struct __kernel_timespec *>(arg1),
      .rmtp = reinterpret_cast<struct __kernel_timespec *>(arg2),
      };
    case 37: 
      return Event_alarm
      {
      .seconds = static_cast<unsigned int>(arg1),
      };
    case 39: 
      return Event_getpid
      {
      };
    case 40: 
      return Event_sendfile64
      {
      .out_fd = static_cast<int>(arg1),
      .in_fd = static_cast<int>(arg2),
      .offset = reinterpret_cast<loff_t *>(arg3),
      .count = static_cast<size_t>(arg4),
      };
    case 41: 
      return Event_socket
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = static_cast<int>(arg2),
      .unnamed2 = static_cast<int>(arg3),
      };
    case 42: 
      return Event_connect
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = reinterpret_cast<struct sockaddr *>(arg2),
      .unnamed2 = static_cast<int>(arg3),
      };
    case 43: 
      return Event_accept
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = reinterpret_cast<struct sockaddr *>(arg2),
      .unnamed2 = reinterpret_cast<int *>(arg3),
      };
    case 44: 
      return Event_sendto
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = reinterpret_cast<void *>(arg2),
      .unnamed2 = static_cast<size_t>(arg3),
      .unnamed3 = static_cast<unsigned>(arg4),
      .unnamed4 = reinterpret_cast<struct sockaddr *>(arg5),
      .unnamed5 = static_cast<int>(arg6),
      };
    case 45: 
      return Event_recvfrom
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = reinterpret_cast<void *>(arg2),
      .unnamed2 = static_cast<size_t>(arg3),
      .unnamed3 = static_cast<unsigned>(arg4),
      .unnamed4 = reinterpret_cast<struct sockaddr *>(arg5),
      .unnamed5 = reinterpret_cast<int *>(arg6),
      };
    case 48: 
      return Event_shutdown
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = static_cast<int>(arg2),
      };
    case 49: 
      return Event_bind
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = reinterpret_cast<struct sockaddr *>(arg2),
      .unnamed2 = static_cast<int>(arg3),
      };
    case 50: 
      return Event_listen
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = static_cast<int>(arg2),
      };
    case 51: 
      return Event_getsockname
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = reinterpret_cast<struct sockaddr *>(arg2),
      .unnamed2 = reinterpret_cast<int *>(arg3),
      };
    case 52: 
      return Event_getpeername
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = reinterpret_cast<struct sockaddr *>(arg2),
      .unnamed2 = reinterpret_cast<int *>(arg3),
      };
    case 53: 
      return Event_socketpair
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = static_cast<int>(arg2),
      .unnamed2 = static_cast<int>(arg3),
      .unnamed3 = reinterpret_cast<int *>(arg4),
      };
    case 54: 
      return Event_setsockopt
      {
      .fd = static_cast<int>(arg1),
      .level = static_cast<int>(arg2),
      .optname = static_cast<int>(arg3),
      .optval = reinterpret_cast<char *>(arg4),
      .optlen = static_cast<int>(arg5),
      };
    case 55: 
      return Event_getsockopt
      {
      .fd = static_cast<int>(arg1),
      .level = static_cast<int>(arg2),
      .optname = static_cast<int>(arg3),
      .optval = reinterpret_cast<char *>(arg4),
      .optlen = reinterpret_cast<int *>(arg5),
      };
    case 60: 
      return Event_exit
      {
      .error_code = static_cast<int>(arg1),
      };
    case 62: 
      return Event_kill
      {
      .pid = static_cast<pid_t>(arg1),
      .sig = static_cast<int>(arg2),
      };
    case 64: 
      return Event_semget
      {
      .key = static_cast<key_t>(arg1),
      .nsems = static_cast<int>(arg2),
      .semflg = static_cast<int>(arg3),
      };
    case 66: 
      return Event_semctl
      {
      .semid = static_cast<int>(arg1),
      .semnum = static_cast<int>(arg2),
      .cmd = static_cast<int>(arg3),
      .arg = static_cast<unsigned long>(arg4),
      };
    case 67: 
      return Event_shmdt
      {
      .shmaddr = reinterpret_cast<char *>(arg1),
      };
    case 68: 
      return Event_msgget
      {
      .key = static_cast<key_t>(arg1),
      .msgflg = static_cast<int>(arg2),
      };
    case 72: 
      return Event_fcntl
      {
      .fd = static_cast<unsigned int>(arg1),
      .cmd = static_cast<unsigned int>(arg2),
      .arg = static_cast<unsigned long>(arg3),
      };
    case 73: 
      return Event_flock
      {
      .fd = static_cast<unsigned int>(arg1),
      .cmd = static_cast<unsigned int>(arg2),
      };
    case 74: 
      return Event_fsync
      {
      .fd = static_cast<unsigned int>(arg1),
      };
    case 75: 
      return Event_fdatasync
      {
      .fd = static_cast<unsigned int>(arg1),
      };
    case 76: 
      return Event_truncate
      {
      .path = reinterpret_cast<const char *>(arg1),
      .length = static_cast<long>(arg2),
      };
    case 77: 
      return Event_ftruncate
      {
      .fd = static_cast<unsigned int>(arg1),
      .length = static_cast<unsigned long>(arg2),
      };
    case 79: 
      return Event_getcwd
      {
      .buf = reinterpret_cast<char *>(arg1),
      .size = static_cast<unsigned long>(arg2),
      };
    case 80: 
      return Event_chdir
      {
      .filename = reinterpret_cast<const char *>(arg1),
      };
    case 81: 
      return Event_fchdir
      {
      .fd = static_cast<unsigned int>(arg1),
      };
    case 82: 
      return Event_rename
      {
      .oldname = reinterpret_cast<const char *>(arg1),
      .newname = reinterpret_cast<const char *>(arg2),
      };
    case 83: 
      return Event_mkdir
      {
      .pathname = reinterpret_cast<const char *>(arg1),
      .mode = static_cast<mode_t>(arg2),
      };
    case 84: 
      return Event_rmdir
      {
      .pathname = reinterpret_cast<const char *>(arg1),
      };
    case 85: 
      return Event_creat
      {
      .pathname = reinterpret_cast<const char *>(arg1),
      .mode = static_cast<mode_t>(arg2),
      };
    case 86: 
      return Event_link
      {
      .oldname = reinterpret_cast<const char *>(arg1),
      .newname = reinterpret_cast<const char *>(arg2),
      };
    case 87: 
      return Event_unlink
      {
      .pathname = reinterpret_cast<const char *>(arg1),
      };
    case 88: 
      return Event_symlink
      {
      .old = reinterpret_cast<const char *>(arg1),
      .linkpath = reinterpret_cast<const char *>(arg2),
      };
    case 89: 
      return Event_readlink
      {
      .path = reinterpret_cast<const char *>(arg1),
      .buf = reinterpret_cast<char *>(arg2),
      .bufsiz = static_cast<int>(arg3),
      };
    case 90: 
      return Event_chmod
      {
      .filename = reinterpret_cast<const char *>(arg1),
      .mode = static_cast<mode_t>(arg2),
      };
    case 91: 
      return Event_fchmod
      {
      .fd = static_cast<unsigned int>(arg1),
      .mode = static_cast<mode_t>(arg2),
      };
    case 92: 
      return Event_chown
      {
      .filename = reinterpret_cast<const char *>(arg1),
      .user = static_cast<uid_t>(arg2),
      .group = static_cast<gid_t>(arg3),
      };
    case 93: 
      return Event_fchown
      {
      .fd = static_cast<unsigned int>(arg1),
      .user = static_cast<uid_t>(arg2),
      .group = static_cast<gid_t>(arg3),
      };
    case 94: 
      return Event_lchown
      {
      .filename = reinterpret_cast<const char *>(arg1),
      .user = static_cast<uid_t>(arg2),
      .group = static_cast<gid_t>(arg3),
      };
    case 95: 
      return Event_umask
      {
      .mask = static_cast<int>(arg1),
      };
    case 101: 
      return Event_ptrace
      {
      .request = static_cast<long>(arg1),
      .pid = static_cast<long>(arg2),
      .addr = static_cast<unsigned long>(arg3),
      .data = static_cast<unsigned long>(arg4),
      };
    case 102: 
      return Event_getuid
      {
      };
    case 103: 
      return Event_syslog
      {
      .type = static_cast<int>(arg1),
      .buf = reinterpret_cast<char *>(arg2),
      .len = static_cast<int>(arg3),
      };
    case 104: 
      return Event_getgid
      {
      };
    case 105: 
      return Event_setuid
      {
      .uid = static_cast<uid_t>(arg1),
      };
    case 106: 
      return Event_setgid
      {
      .gid = static_cast<gid_t>(arg1),
      };
    case 107: 
      return Event_geteuid
      {
      };
    case 108: 
      return Event_getegid
      {
      };
    case 109: 
      return Event_setpgid
      {
      .pid = static_cast<pid_t>(arg1),
      .pgid = static_cast<pid_t>(arg2),
      };
    case 110: 
      return Event_getppid
      {
      };
    case 111: 
      return Event_getpgrp
      {
      };
    case 112: 
      return Event_setsid
      {
      };
    case 113: 
      return Event_setreuid
      {
      .ruid = static_cast<uid_t>(arg1),
      .euid = static_cast<uid_t>(arg2),
      };
    case 114: 
      return Event_setregid
      {
      .rgid = static_cast<gid_t>(arg1),
      .egid = static_cast<gid_t>(arg2),
      };
    case 115: 
      return Event_getgroups
      {
      .gidsetsize = static_cast<int>(arg1),
      .grouplist = reinterpret_cast<gid_t *>(arg2),
      };
    case 116: 
      return Event_setgroups
      {
      .gidsetsize = static_cast<int>(arg1),
      .grouplist = reinterpret_cast<gid_t *>(arg2),
      };
    case 117: 
      return Event_setresuid
      {
      .ruid = static_cast<uid_t>(arg1),
      .euid = static_cast<uid_t>(arg2),
      .suid = static_cast<uid_t>(arg3),
      };
    case 118: 
      return Event_getresuid
      {
      .ruid = reinterpret_cast<uid_t *>(arg1),
      .euid = reinterpret_cast<uid_t *>(arg2),
      .suid = reinterpret_cast<uid_t *>(arg3),
      };
    case 119: 
      return Event_setresgid
      {
      .rgid = static_cast<gid_t>(arg1),
      .egid = static_cast<gid_t>(arg2),
      .sgid = static_cast<gid_t>(arg3),
      };
    case 120: 
      return Event_getresgid
      {
      .rgid = reinterpret_cast<gid_t *>(arg1),
      .egid = reinterpret_cast<gid_t *>(arg2),
      .sgid = reinterpret_cast<gid_t *>(arg3),
      };
    case 121: 
      return Event_getpgid
      {
      .pid = static_cast<pid_t>(arg1),
      };
    case 122: 
      return Event_setfsuid
      {
      .uid = static_cast<uid_t>(arg1),
      };
    case 123: 
      return Event_setfsgid
      {
      .gid = static_cast<gid_t>(arg1),
      };
    case 124: 
      return Event_getsid
      {
      .pid = static_cast<pid_t>(arg1),
      };
    case 127: 
      return Event_rt_sigpending
      {
      .set = reinterpret_cast<sigset_t *>(arg1),
      .sigsetsize = static_cast<size_t>(arg2),
      };
    case 128: 
      return Event_rt_sigtimedwait
      {
      .uthese = reinterpret_cast<const sigset_t *>(arg1),
      .uinfo = reinterpret_cast<siginfo_t *>(arg2),
      .uts = reinterpret_cast<const struct __kernel_timespec *>(arg3),
      .sigsetsize = static_cast<size_t>(arg4),
      };
    case 129: 
      return Event_rt_sigqueueinfo
      {
      .pid = static_cast<pid_t>(arg1),
      .sig = static_cast<int>(arg2),
      .uinfo = reinterpret_cast<siginfo_t *>(arg3),
      };
    case 130: 
      return Event_rt_sigsuspend
      {
      .unewset = reinterpret_cast<sigset_t *>(arg1),
      .sigsetsize = static_cast<size_t>(arg2),
      };
    case 133: 
      return Event_mknod
      {
      .filename = reinterpret_cast<const char *>(arg1),
      .mode = static_cast<mode_t>(arg2),
      .dev = static_cast<unsigned>(arg3),
      };
    case 135: 
      return Event_personality
      {
      .personality = static_cast<unsigned int>(arg1),
      };
    case 136: 
      return Event_ustat
      {
      .dev = static_cast<unsigned>(arg1),
      .ubuf = reinterpret_cast<struct ustat *>(arg2),
      };
    case 137: 
      return Event_statfs
      {
      .path = reinterpret_cast<const char *>(arg1),
      .buf = reinterpret_cast<struct statfs *>(arg2),
      };
    case 138: 
      return Event_fstatfs
      {
      .fd = static_cast<unsigned int>(arg1),
      .buf = reinterpret_cast<struct statfs *>(arg2),
      };
    case 139: 
      return Event_sysfs
      {
      .option = static_cast<int>(arg1),
      .arg1 = static_cast<unsigned long>(arg2),
      .arg2 = static_cast<unsigned long>(arg3),
      };
    case 140: 
      return Event_getpriority
      {
      .which = static_cast<int>(arg1),
      .who = static_cast<int>(arg2),
      };
    case 141: 
      return Event_setpriority
      {
      .which = static_cast<int>(arg1),
      .who = static_cast<int>(arg2),
      .niceval = static_cast<int>(arg3),
      };
    case 145: 
      return Event_sched_getscheduler
      {
      .pid = static_cast<pid_t>(arg1),
      };
    case 146: 
      return Event_sched_get_priority_max
      {
      .policy = static_cast<int>(arg1),
      };
    case 147: 
      return Event_sched_get_priority_min
      {
      .policy = static_cast<int>(arg1),
      };
    case 148: 
      return Event_sched_rr_get_interval
      {
      .pid = static_cast<pid_t>(arg1),
      .interval = reinterpret_cast<struct __kernel_timespec *>(arg2),
      };
    case 149: 
      return Event_mlock
      {
      .start = static_cast<unsigned long>(arg1),
      .len = static_cast<size_t>(arg2),
      };
    case 150: 
      return Event_munlock
      {
      .start = static_cast<unsigned long>(arg1),
      .len = static_cast<size_t>(arg2),
      };
    case 151: 
      return Event_mlockall
      {
      .flags = static_cast<int>(arg1),
      };
    case 152: 
      return Event_munlockall
      {
      };
    case 153: 
      return Event_vhangup
      {
      };
    case 154: 
      return Event_modify_ldt
      {
      };
    case 155: 
      return Event_pivot_root
      {
      .new_root = reinterpret_cast<const char *>(arg1),
      .put_old = reinterpret_cast<const char *>(arg2),
      };
    case 156: 
      return Event_sysctl
      {
      };
    case 157: 
      return Event_prctl
      {
      .option = static_cast<int>(arg1),
      .arg2 = static_cast<unsigned long>(arg2),
      .arg3 = static_cast<unsigned long>(arg3),
      .arg4 = static_cast<unsigned long>(arg4),
      .arg5 = static_cast<unsigned long>(arg5),
      };
    case 158: 
      return Event_arch_prctl
      {
      };
    case 161: 
      return Event_chroot
      {
      .filename = reinterpret_cast<const char *>(arg1),
      };
    case 162: 
      return Event_sync
      {
      };
    case 163: 
      return Event_acct
      {
      .name = reinterpret_cast<const char *>(arg1),
      };
    case 165: 
      return Event_mount
      {
      .dev_name = reinterpret_cast<char *>(arg1),
      .dir_name = reinterpret_cast<char *>(arg2),
      .type = reinterpret_cast<char *>(arg3),
      .flags = static_cast<unsigned long>(arg4),
      .data = reinterpret_cast<void *>(arg5),
      };
    case 166: 
      return Event_umount
      {
      .name = reinterpret_cast<char *>(arg1),
      .flags = static_cast<int>(arg2),
      };
    case 167: 
      return Event_swapon
      {
      .specialfile = reinterpret_cast<const char *>(arg1),
      .swap_flags = static_cast<int>(arg2),
      };
    case 168: 
      return Event_swapoff
      {
      .specialfile = reinterpret_cast<const char *>(arg1),
      };
    case 169: 
      return Event_reboot
      {
      .magic1 = static_cast<int>(arg1),
      .magic2 = static_cast<int>(arg2),
      .cmd = static_cast<unsigned int>(arg3),
      .arg = reinterpret_cast<void *>(arg4),
      };
    case 170: 
      return Event_sethostname
      {
      .name = reinterpret_cast<char *>(arg1),
      .len = static_cast<int>(arg2),
      };
    case 171: 
      return Event_setdomainname
      {
      .name = reinterpret_cast<char *>(arg1),
      .len = static_cast<int>(arg2),
      };
    case 173: 
      return Event_ioperm
      {
      .from = static_cast<unsigned long>(arg1),
      .num = static_cast<unsigned long>(arg2),
      .on = static_cast<int>(arg3),
      };
    case 175: 
      return Event_init_module
      {
      .umod = reinterpret_cast<void *>(arg1),
      .len = static_cast<unsigned long>(arg2),
      .uargs = reinterpret_cast<const char *>(arg3),
      };
    case 176: 
      return Event_delete_module
      {
      .name_user = reinterpret_cast<const char *>(arg1),
      .flags = static_cast<unsigned int>(arg2),
      };
    case 179: 
      return Event_quotactl
      {
      .cmd = static_cast<unsigned int>(arg1),
      .special = reinterpret_cast<const char *>(arg2),
      .id = static_cast<int>(arg3),
      .addr = reinterpret_cast<void *>(arg4),
      };
    case 180: 
      return Event_nfsservctl
      {
      };
    case 186: 
      return Event_gettid
      {
      };
    case 187: 
      return Event_readahead
      {
      .fd = static_cast<int>(arg1),
      .offset = static_cast<loff_t>(arg2),
      .count = static_cast<size_t>(arg3),
      };
    case 188: 
      return Event_setxattr
      {
      .path = reinterpret_cast<const char *>(arg1),
      .name = reinterpret_cast<const char *>(arg2),
      .value = reinterpret_cast<const void *>(arg3),
      .size = static_cast<size_t>(arg4),
      .flags = static_cast<int>(arg5),
      };
    case 189: 
      return Event_lsetxattr
      {
      .path = reinterpret_cast<const char *>(arg1),
      .name = reinterpret_cast<const char *>(arg2),
      .value = reinterpret_cast<const void *>(arg3),
      .size = static_cast<size_t>(arg4),
      .flags = static_cast<int>(arg5),
      };
    case 190: 
      return Event_fsetxattr
      {
      .fd = static_cast<int>(arg1),
      .name = reinterpret_cast<const char *>(arg2),
      .value = reinterpret_cast<const void *>(arg3),
      .size = static_cast<size_t>(arg4),
      .flags = static_cast<int>(arg5),
      };
    case 191: 
      return Event_getxattr
      {
      .path = reinterpret_cast<const char *>(arg1),
      .name = reinterpret_cast<const char *>(arg2),
      .value = reinterpret_cast<void *>(arg3),
      .size = static_cast<size_t>(arg4),
      };
    case 192: 
      return Event_lgetxattr
      {
      .path = reinterpret_cast<const char *>(arg1),
      .name = reinterpret_cast<const char *>(arg2),
      .value = reinterpret_cast<void *>(arg3),
      .size = static_cast<size_t>(arg4),
      };
    case 193: 
      return Event_fgetxattr
      {
      .fd = static_cast<int>(arg1),
      .name = reinterpret_cast<const char *>(arg2),
      .value = reinterpret_cast<void *>(arg3),
      .size = static_cast<size_t>(arg4),
      };
    case 194: 
      return Event_listxattr
      {
      .path = reinterpret_cast<const char *>(arg1),
      .list = reinterpret_cast<char *>(arg2),
      .size = static_cast<size_t>(arg3),
      };
    case 195: 
      return Event_llistxattr
      {
      .path = reinterpret_cast<const char *>(arg1),
      .list = reinterpret_cast<char *>(arg2),
      .size = static_cast<size_t>(arg3),
      };
    case 196: 
      return Event_flistxattr
      {
      .fd = static_cast<int>(arg1),
      .list = reinterpret_cast<char *>(arg2),
      .size = static_cast<size_t>(arg3),
      };
    case 197: 
      return Event_removexattr
      {
      .path = reinterpret_cast<const char *>(arg1),
      .name = reinterpret_cast<const char *>(arg2),
      };
    case 198: 
      return Event_lremovexattr
      {
      .path = reinterpret_cast<const char *>(arg1),
      .name = reinterpret_cast<const char *>(arg2),
      };
    case 199: 
      return Event_fremovexattr
      {
      .fd = static_cast<int>(arg1),
      .name = reinterpret_cast<const char *>(arg2),
      };
    case 200: 
      return Event_tkill
      {
      .pid = static_cast<pid_t>(arg1),
      .sig = static_cast<int>(arg2),
      };
    case 201: 
      return Event_time
      {
      .tloc = reinterpret_cast<__kernel_time_t *>(arg1),
      };
    case 202: 
      return Event_futex
      {
      .uaddr = reinterpret_cast<uint32_t *>(arg1),
      .op = static_cast<int>(arg2),
      .val = static_cast<uint32_t>(arg3),
      .utime = reinterpret_cast<const struct __kernel_timespec *>(arg4),
      .uaddr2 = reinterpret_cast<uint32_t *>(arg5),
      .val3 = static_cast<uint32_t>(arg6),
      };
    case 203: 
      return Event_sched_setaffinity
      {
      .pid = static_cast<pid_t>(arg1),
      .len = static_cast<unsigned int>(arg2),
      .user_mask_ptr = reinterpret_cast<unsigned long *>(arg3),
      };
    case 204: 
      return Event_sched_getaffinity
      {
      .pid = static_cast<pid_t>(arg1),
      .len = static_cast<unsigned int>(arg2),
      .user_mask_ptr = reinterpret_cast<unsigned long *>(arg3),
      };
    case 206: 
      return Event_io_setup
      {
      .nr_reqs = static_cast<unsigned>(arg1),
      .ctx = reinterpret_cast<aio_context_t *>(arg2),
      };
    case 207: 
      return Event_io_destroy
      {
      .ctx = static_cast<aio_context_t>(arg1),
      };
    case 208: 
      return Event_io_getevents
      {
      .ctx_id = static_cast<aio_context_t>(arg1),
      .min_nr = static_cast<long>(arg2),
      .nr = static_cast<long>(arg3),
      .events = reinterpret_cast<struct io_event *>(arg4),
      .timeout = reinterpret_cast<struct __kernel_timespec *>(arg5),
      };
    case 212: 
      return Event_lookup_dcookie
      {
      .cookie64 = static_cast<uint64_t>(arg1),
      .buf = reinterpret_cast<char *>(arg2),
      .len = static_cast<size_t>(arg3),
      };
    case 213: 
      return Event_epoll_create
      {
      .size = static_cast<int>(arg1),
      };
    case 216: 
      return Event_remap_file_pages
      {
      .start = static_cast<unsigned long>(arg1),
      .size = static_cast<unsigned long>(arg2),
      .prot = static_cast<unsigned long>(arg3),
      .pgoff = static_cast<unsigned long>(arg4),
      .flags = static_cast<unsigned long>(arg5),
      };
    case 218: 
      return Event_set_tid_address
      {
      .tidptr = reinterpret_cast<int *>(arg1),
      };
    case 219: 
      return Event_restart_syscall
      {
      };
    case 221: 
      return Event_fadvise64
      {
      .fd = static_cast<int>(arg1),
      .offset = static_cast<loff_t>(arg2),
      .len = static_cast<size_t>(arg3),
      .advice = static_cast<int>(arg4),
      };
    case 222: 
      return Event_timer_create
      {
      .which_clock = static_cast<clockid_t>(arg1),
      .timer_event_spec = reinterpret_cast<struct sigevent *>(arg2),
      .created_timer_id = reinterpret_cast<timer_t *>(arg3),
      };
    case 223: 
      return Event_timer_settime
      {
      .timer_id = reinterpret_cast<timer_t>(arg1),
      .flags = static_cast<int>(arg2),
      .new_setting = reinterpret_cast<const struct __kernel_itimerspec *>(arg3),
      .old_setting = reinterpret_cast<struct __kernel_itimerspec *>(arg4),
      };
    case 224: 
      return Event_timer_gettime
      {
      .timer_id = reinterpret_cast<timer_t>(arg1),
      .setting = reinterpret_cast<struct __kernel_itimerspec *>(arg2),
      };
    case 225: 
      return Event_timer_getoverrun
      {
      .timer_id = reinterpret_cast<timer_t>(arg1),
      };
    case 226: 
      return Event_timer_delete
      {
      .timer_id = reinterpret_cast<timer_t>(arg1),
      };
    case 227: 
      return Event_clock_settime
      {
      .which_clock = static_cast<clockid_t>(arg1),
      .tp = reinterpret_cast<const struct __kernel_timespec *>(arg2),
      };
    case 228: 
      return Event_clock_gettime
      {
      .which_clock = static_cast<clockid_t>(arg1),
      .tp = reinterpret_cast<struct __kernel_timespec *>(arg2),
      };
    case 229: 
      return Event_clock_getres
      {
      .which_clock = static_cast<clockid_t>(arg1),
      .tp = reinterpret_cast<struct __kernel_timespec *>(arg2),
      };
    case 230: 
      return Event_clock_nanosleep
      {
      .which_clock = static_cast<clockid_t>(arg1),
      .flags = static_cast<int>(arg2),
      .rqtp = reinterpret_cast<const struct __kernel_timespec *>(arg3),
      .rmtp = reinterpret_cast<struct __kernel_timespec *>(arg4),
      };
    case 231: 
      return Event_exit_group
      {
      .error_code = static_cast<int>(arg1),
      };
    case 232: 
      return Event_epoll_wait
      {
      .epfd = static_cast<int>(arg1),
      .events = reinterpret_cast<struct epoll_event *>(arg2),
      .maxevents = static_cast<int>(arg3),
      .timeout = static_cast<int>(arg4),
      };
    case 233: 
      return Event_epoll_ctl
      {
      .epfd = static_cast<int>(arg1),
      .op = static_cast<int>(arg2),
      .fd = static_cast<int>(arg3),
      .event = reinterpret_cast<struct epoll_event *>(arg4),
      };
    case 234: 
      return Event_tgkill
      {
      .tgid = static_cast<pid_t>(arg1),
      .pid = static_cast<pid_t>(arg2),
      .sig = static_cast<int>(arg3),
      };
    case 237: 
      return Event_mbind
      {
      .start = static_cast<unsigned long>(arg1),
      .len = static_cast<unsigned long>(arg2),
      .mode = static_cast<unsigned long>(arg3),
      .nmask = reinterpret_cast<const unsigned long *>(arg4),
      .maxnode = static_cast<unsigned long>(arg5),
      .flags = static_cast<unsigned>(arg6),
      };
    case 238: 
      return Event_set_mempolicy
      {
      .mode = static_cast<int>(arg1),
      .nmask = reinterpret_cast<const unsigned long *>(arg2),
      .maxnode = static_cast<unsigned long>(arg3),
      };
    case 239: 
      return Event_get_mempolicy
      {
      .policy = reinterpret_cast<int *>(arg1),
      .nmask = reinterpret_cast<unsigned long *>(arg2),
      .maxnode = static_cast<unsigned long>(arg3),
      .addr = static_cast<unsigned long>(arg4),
      .flags = static_cast<unsigned long>(arg5),
      };
    case 240: 
      return Event_mq_open
      {
      .name = reinterpret_cast<const char *>(arg1),
      .oflag = static_cast<int>(arg2),
      .mode = static_cast<mode_t>(arg3),
      .attr = reinterpret_cast<struct mq_attr *>(arg4),
      };
    case 241: 
      return Event_mq_unlink
      {
      .name = reinterpret_cast<const char *>(arg1),
      };
    case 242: 
      return Event_mq_timedsend
      {
      .mqdes = static_cast<mqd_t>(arg1),
      .msg_ptr = reinterpret_cast<const char *>(arg2),
      .msg_len = static_cast<size_t>(arg3),
      .msg_prio = static_cast<unsigned int>(arg4),
      .abs_timeout = reinterpret_cast<const struct __kernel_timespec *>(arg5),
      };
    case 243: 
      return Event_mq_timedreceive
      {
      .mqdes = static_cast<mqd_t>(arg1),
      .msg_ptr = reinterpret_cast<char *>(arg2),
      .msg_len = static_cast<size_t>(arg3),
      .msg_prio = reinterpret_cast<unsigned int *>(arg4),
      .abs_timeout = reinterpret_cast<const struct __kernel_timespec *>(arg5),
      };
    case 244: 
      return Event_mq_notify
      {
      .mqdes = static_cast<mqd_t>(arg1),
      .notification = reinterpret_cast<const struct sigevent *>(arg2),
      };
    case 245: 
      return Event_mq_getsetattr
      {
      .mqdes = static_cast<mqd_t>(arg1),
      .mqstat = reinterpret_cast<const struct mq_attr *>(arg2),
      .omqstat = reinterpret_cast<struct mq_attr *>(arg3),
      };
    case 250: 
      return Event_keyctl
      {
      .cmd = static_cast<int>(arg1),
      .arg2 = static_cast<unsigned long>(arg2),
      .arg3 = static_cast<unsigned long>(arg3),
      .arg4 = static_cast<unsigned long>(arg4),
      .arg5 = static_cast<unsigned long>(arg5),
      };
    case 251: 
      return Event_ioprio_set
      {
      .which = static_cast<int>(arg1),
      .who = static_cast<int>(arg2),
      .ioprio = static_cast<int>(arg3),
      };
    case 252: 
      return Event_ioprio_get
      {
      .which = static_cast<int>(arg1),
      .who = static_cast<int>(arg2),
      };
    case 253: 
      return Event_inotify_init
      {
      };
    case 254: 
      return Event_inotify_add_watch
      {
      .fd = static_cast<int>(arg1),
      .path = reinterpret_cast<const char *>(arg2),
      .mask = static_cast<uint32_t>(arg3),
      };
    case 255: 
      return Event_inotify_rm_watch
      {
      .fd = static_cast<int>(arg1),
      .wd = static_cast<__s32>(arg2),
      };
    case 256: 
      return Event_migrate_pages
      {
      .pid = static_cast<pid_t>(arg1),
      .maxnode = static_cast<unsigned long>(arg2),
      .from = reinterpret_cast<const unsigned long *>(arg3),
      .to = reinterpret_cast<const unsigned long *>(arg4),
      };
    case 257: 
      return Event_openat
      {
      .dfd = static_cast<int>(arg1),
      .filename = reinterpret_cast<const char *>(arg2),
      .flags = static_cast<int>(arg3),
      .mode = static_cast<mode_t>(arg4),
      };
    case 258: 
      return Event_mkdirat
      {
      .dfd = static_cast<int>(arg1),
      .pathname = reinterpret_cast<const char *>(arg2),
      .mode = static_cast<mode_t>(arg3),
      };
    case 259: 
      return Event_mknodat
      {
      .dfd = static_cast<int>(arg1),
      .filename = reinterpret_cast<const char *>(arg2),
      .mode = static_cast<mode_t>(arg3),
      .dev = static_cast<unsigned>(arg4),
      };
    case 260: 
      return Event_fchownat
      {
      .dfd = static_cast<int>(arg1),
      .filename = reinterpret_cast<const char *>(arg2),
      .user = static_cast<uid_t>(arg3),
      .group = static_cast<gid_t>(arg4),
      .flag = static_cast<int>(arg5),
      };
    case 262: 
      return Event_newfstatat
      {
      .dfd = static_cast<int>(arg1),
      .filename = reinterpret_cast<const char *>(arg2),
      .statbuf = reinterpret_cast<struct stat *>(arg3),
      .flag = static_cast<int>(arg4),
      };
    case 263: 
      return Event_unlinkat
      {
      .dfd = static_cast<int>(arg1),
      .pathname = reinterpret_cast<const char *>(arg2),
      .flag = static_cast<int>(arg3),
      };
    case 264: 
      return Event_renameat
      {
      .olddfd = static_cast<int>(arg1),
      .oldname = reinterpret_cast<const char *>(arg2),
      .newdfd = static_cast<int>(arg3),
      .newname = reinterpret_cast<const char *>(arg4),
      };
    case 265: 
      return Event_linkat
      {
      .olddfd = static_cast<int>(arg1),
      .oldname = reinterpret_cast<const char *>(arg2),
      .newdfd = static_cast<int>(arg3),
      .newname = reinterpret_cast<const char *>(arg4),
      .flags = static_cast<int>(arg5),
      };
    case 266: 
      return Event_symlinkat
      {
      .oldname = reinterpret_cast<const char *>(arg1),
      .newdfd = static_cast<int>(arg2),
      .newname = reinterpret_cast<const char *>(arg3),
      };
    case 267: 
      return Event_readlinkat
      {
      .dfd = static_cast<int>(arg1),
      .path = reinterpret_cast<const char *>(arg2),
      .buf = reinterpret_cast<char *>(arg3),
      .bufsiz = static_cast<int>(arg4),
      };
    case 268: 
      return Event_fchmodat
      {
      .dfd = static_cast<int>(arg1),
      .filename = reinterpret_cast<const char *>(arg2),
      .mode = static_cast<mode_t>(arg3),
      };
    case 269: 
      return Event_faccessat
      {
      .dfd = static_cast<int>(arg1),
      .filename = reinterpret_cast<const char *>(arg2),
      .mode = static_cast<int>(arg3),
      };
    case 270: 
      return Event_pselect6
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = reinterpret_cast<fd_set *>(arg2),
      .unnamed2 = reinterpret_cast<fd_set *>(arg3),
      .unnamed3 = reinterpret_cast<fd_set *>(arg4),
      .unnamed4 = reinterpret_cast<struct __kernel_timespec *>(arg5),
      .unnamed5 = reinterpret_cast<void *>(arg6),
      };
    case 275: 
      return Event_splice
      {
      .fd_in = static_cast<int>(arg1),
      .off_in = reinterpret_cast<loff_t *>(arg2),
      .fd_out = static_cast<int>(arg3),
      .off_out = reinterpret_cast<loff_t *>(arg4),
      .len = static_cast<size_t>(arg5),
      .flags = static_cast<unsigned int>(arg6),
      };
    case 276: 
      return Event_tee
      {
      .fdin = static_cast<int>(arg1),
      .fdout = static_cast<int>(arg2),
      .len = static_cast<size_t>(arg3),
      .flags = static_cast<unsigned int>(arg4),
      };
    case 277: 
      return Event_sync_file_range
      {
      .fd = static_cast<int>(arg1),
      .offset = static_cast<loff_t>(arg2),
      .nbytes = static_cast<loff_t>(arg3),
      .flags = static_cast<unsigned int>(arg4),
      };
    case 278: 
      return Event_vmsplice
      {
      .fd = static_cast<int>(arg1),
      .iov = reinterpret_cast<const struct iovec *>(arg2),
      .nr_segs = static_cast<unsigned long>(arg3),
      .flags = static_cast<unsigned int>(arg4),
      };
    case 279: 
      return Event_move_pages
      {
      .pid = static_cast<pid_t>(arg1),
      .nr_pages = static_cast<unsigned long>(arg2),
      .pages = reinterpret_cast<const void * *>(arg3),
      .nodes = reinterpret_cast<const int *>(arg4),
      .status = reinterpret_cast<int *>(arg5),
      .flags = static_cast<int>(arg6),
      };
    case 280: 
      return Event_utimensat
      {
      .dfd = static_cast<int>(arg1),
      .filename = reinterpret_cast<const char *>(arg2),
      .utimes = reinterpret_cast<struct __kernel_timespec *>(arg3),
      .flags = static_cast<int>(arg4),
      };
    case 281: 
      return Event_epoll_pwait
      {
      .epfd = static_cast<int>(arg1),
      .events = reinterpret_cast<struct epoll_event *>(arg2),
      .maxevents = static_cast<int>(arg3),
      .timeout = static_cast<int>(arg4),
      .SignMask = reinterpret_cast<const sigset_t *>(arg5),
      .sigsetsize = static_cast<size_t>(arg6),
      };
    case 282: 
      return Event_signalfd
      {
      .ufd = static_cast<int>(arg1),
      .user_mask = reinterpret_cast<sigset_t *>(arg2),
      .sizemask = static_cast<size_t>(arg3),
      };
    case 283: 
      return Event_timerfd_create
      {
      .clockid = static_cast<int>(arg1),
      .flags = static_cast<int>(arg2),
      };
    case 284: 
      return Event_eventfd
      {
      .count = static_cast<unsigned int>(arg1),
      };
    case 285: 
      return Event_fallocate
      {
      .fd = static_cast<int>(arg1),
      .mode = static_cast<int>(arg2),
      .offset = static_cast<loff_t>(arg3),
      .len = static_cast<loff_t>(arg4),
      };
    case 286: 
      return Event_timerfd_settime
      {
      .ufd = static_cast<int>(arg1),
      .flags = static_cast<int>(arg2),
      .utmr = reinterpret_cast<const struct __kernel_itimerspec *>(arg3),
      .otmr = reinterpret_cast<struct __kernel_itimerspec *>(arg4),
      };
    case 287: 
      return Event_timerfd_gettime
      {
      .ufd = static_cast<int>(arg1),
      .otmr = reinterpret_cast<struct __kernel_itimerspec *>(arg2),
      };
    case 288: 
      return Event_accept4
      {
      .unnamed0 = static_cast<int>(arg1),
      .unnamed1 = reinterpret_cast<struct sockaddr *>(arg2),
      .unnamed2 = reinterpret_cast<int *>(arg3),
      .unnamed3 = static_cast<int>(arg4),
      };
    case 289: 
      return Event_signalfd4
      {
      .ufd = static_cast<int>(arg1),
      .user_mask = reinterpret_cast<sigset_t *>(arg2),
      .sizemask = static_cast<size_t>(arg3),
      .flags = static_cast<int>(arg4),
      };
    case 290: 
      return Event_eventfd2
      {
      .count = static_cast<unsigned int>(arg1),
      .flags = static_cast<int>(arg2),
      };
    case 291: 
      return Event_epoll_create1
      {
      .flags = static_cast<int>(arg1),
      };
    case 292: 
      return Event_dup3
      {
      .oldfd = static_cast<unsigned int>(arg1),
      .newfd = static_cast<unsigned int>(arg2),
      .flags = static_cast<int>(arg3),
      };
    case 293: 
      return Event_pipe2
      {
      .fildes = reinterpret_cast<int *>(arg1),
      .flags = static_cast<int>(arg2),
      };
    case 294: 
      return Event_inotify_init1
      {
      .flags = static_cast<int>(arg1),
      };
    case 295: 
      return Event_preadv
      {
      .fd = static_cast<unsigned long>(arg1),
      .vec = reinterpret_cast<const struct iovec *>(arg2),
      .vlen = static_cast<unsigned long>(arg3),
      .pos_l = static_cast<unsigned long>(arg4),
      .pos_h = static_cast<unsigned long>(arg5),
      };
    case 296: 
      return Event_pwritev
      {
      .fd = static_cast<unsigned long>(arg1),
      .vec = reinterpret_cast<const struct iovec *>(arg2),
      .vlen = static_cast<unsigned long>(arg3),
      .pos_l = static_cast<unsigned long>(arg4),
      .pos_h = static_cast<unsigned long>(arg5),
      };
    case 297: 
      return Event_rt_tgsigqueueinfo
      {
      .tgid = static_cast<pid_t>(arg1),
      .pid = static_cast<pid_t>(arg2),
      .sig = static_cast<int>(arg3),
      .uinfo = reinterpret_cast<siginfo_t *>(arg4),
      };
    } // switch

    Event_Unsupported e;
    e.syscall_id = syscall_id;
    e.arg1 = arg1;
    e.arg2 = arg2;
    e.arg3 = arg3;
    e.arg4 = arg4;
    e.arg5 = arg5;
    e.arg6 = arg6;
    return e;
  } // function

} // namespace
