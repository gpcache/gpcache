#include <SyscallEvent.h>

namespace gpcache
{

  auto createEvent(SyscallDataType syscall_id, SyscallDataType arg1, SyscallDataType arg2, SyscallDataType arg3, SyscallDataType arg4, SyscallDataType arg5, SyscallDataType arg6) --> SyscallEvent
  {
    switch (syscall_id)
    {
    case 0: 
    {
      Event_read e{};
      return e;
    }
    case 1: 
    {
      Event_write e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.buf = reinterpret_cast<const char *>(arg2);
      e.count = static_cast<size_t>(arg3);
      return e;
    }
    case 2: 
    {
      Event_open e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      e.flags = static_cast<int>(arg2);
      e.mode = static_cast<mode_t>(arg3);
      return e;
    }
    case 3: 
    {
      Event_close e{};
      e.fd = static_cast<unsigned int>(arg1);
      return e;
    }
    case 4: 
    {
      Event_newstat e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      e.statbuf = reinterpret_cast< stat *>(arg2);
      return e;
    }
    case 5: 
    {
      Event_newfstat e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.statbuf = reinterpret_cast< stat *>(arg2);
      return e;
    }
    case 6: 
    {
      Event_newlstat e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      e.statbuf = reinterpret_cast< stat *>(arg2);
      return e;
    }
    case 7: 
    {
      Event_poll e{};
      e.ufds = reinterpret_cast< pollfd *>(arg1);
      e.nfds = static_cast<unsigned int>(arg2);
      e.timeout = static_cast<int>(arg3);
      return e;
    }
    case 8: 
    {
      Event_lseek e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.offset = static_cast<off_t>(arg2);
      e.whence = static_cast<unsigned int>(arg3);
      return e;
    }
    case 9: 
    {
      Event_mmap e{};
      e.addr = static_cast<unsigned long>(arg1);
      e.len = static_cast<unsigned long>(arg2);
      e.prot = static_cast<unsigned long>(arg3);
      e.flags = static_cast<unsigned long>(arg4);
      e.fd = static_cast<unsigned long>(arg5);
      e.pgoff = static_cast<unsigned long>(arg6);
      return e;
    }
    case 10: 
    {
      Event_mprotect e{};
      e.start = static_cast<unsigned long>(arg1);
      e.len = static_cast<size_t>(arg2);
      e.prot = static_cast<unsigned long>(arg3);
      return e;
    }
    case 11: 
    {
      Event_munmap e{};
      e.addr = static_cast<unsigned long>(arg1);
      e.len = static_cast<size_t>(arg2);
      return e;
    }
    case 12: 
    {
      Event_brk e{};
      e.brk = static_cast<unsigned long>(arg1);
      return e;
    }
    case 13: 
    {
      Event_rt_sigaction e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast<const sigaction *>(arg2);
      e.unnamed2 = reinterpret_cast< sigaction *>(arg3);
      e.unnamed3 = static_cast<size_t>(arg4);
      return e;
    }
    case 14: 
    {
      Event_rt_sigprocmask e{};
      e.how = static_cast<int>(arg1);
      e.set = reinterpret_cast<sigset_t *>(arg2);
      e.oset = reinterpret_cast<sigset_t *>(arg3);
      e.sigsetsize = static_cast<size_t>(arg4);
      return e;
    }
    case 16: 
    {
      Event_ioctl e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.cmd = static_cast<unsigned int>(arg2);
      e.arg = static_cast<unsigned long>(arg3);
      return e;
    }
    case 17: 
    {
      Event_pread64 e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.buf = reinterpret_cast<char *>(arg2);
      e.count = static_cast<size_t>(arg3);
      e.pos = static_cast<loff_t>(arg4);
      return e;
    }
    case 18: 
    {
      Event_pwrite64 e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.buf = reinterpret_cast<const char *>(arg2);
      e.count = static_cast<size_t>(arg3);
      e.pos = static_cast<loff_t>(arg4);
      return e;
    }
    case 19: 
    {
      Event_readv e{};
      e.fd = static_cast<unsigned long>(arg1);
      e.vec = reinterpret_cast<const iovec *>(arg2);
      e.vlen = static_cast<unsigned long>(arg3);
      return e;
    }
    case 20: 
    {
      Event_writev e{};
      e.fd = static_cast<unsigned long>(arg1);
      e.vec = reinterpret_cast<const iovec *>(arg2);
      e.vlen = static_cast<unsigned long>(arg3);
      return e;
    }
    case 21: 
    {
      Event_access e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      e.mode = static_cast<int>(arg2);
      return e;
    }
    case 22: 
    {
      Event_pipe e{};
      e.fildes = reinterpret_cast<int *>(arg1);
      return e;
    }
    case 23: 
    {
      Event_select e{};
      e.n = static_cast<int>(arg1);
      e.inp = reinterpret_cast<fd_set *>(arg2);
      e.outp = reinterpret_cast<fd_set *>(arg3);
      e.exp = reinterpret_cast<fd_set *>(arg4);
      e.tvp = reinterpret_cast< __kernel_timeval *>(arg5);
      return e;
    }
    case 24: 
    {
      Event_sched_yield e{};
      return e;
    }
    case 25: 
    {
      Event_mremap e{};
      e.addr = static_cast<unsigned long>(arg1);
      e.old_len = static_cast<unsigned long>(arg2);
      e.new_len = static_cast<unsigned long>(arg3);
      e.flags = static_cast<unsigned long>(arg4);
      e.new_addr = static_cast<unsigned long>(arg5);
      return e;
    }
    case 26: 
    {
      Event_msync e{};
      e.start = static_cast<unsigned long>(arg1);
      e.len = static_cast<size_t>(arg2);
      e.flags = static_cast<int>(arg3);
      return e;
    }
    case 27: 
    {
      Event_mincore e{};
      e.start = static_cast<unsigned long>(arg1);
      e.len = static_cast<size_t>(arg2);
      e.vec = reinterpret_cast<unsigned char *>(arg3);
      return e;
    }
    case 28: 
    {
      Event_madvise e{};
      e.start = static_cast<unsigned long>(arg1);
      e.len = static_cast<size_t>(arg2);
      e.behavior = static_cast<int>(arg3);
      return e;
    }
    case 29: 
    {
      Event_shmget e{};
      e.key = static_cast<key_t>(arg1);
      e.size = static_cast<size_t>(arg2);
      e.flag = static_cast<int>(arg3);
      return e;
    }
    case 30: 
    {
      Event_shmat e{};
      e.shmid = static_cast<int>(arg1);
      e.shmaddr = reinterpret_cast<char *>(arg2);
      e.shmflg = static_cast<int>(arg3);
      return e;
    }
    case 31: 
    {
      Event_shmctl e{};
      e.shmid = static_cast<int>(arg1);
      e.cmd = static_cast<int>(arg2);
      e.buf = reinterpret_cast< shmid_ds *>(arg3);
      return e;
    }
    case 32: 
    {
      Event_dup e{};
      e.fildes = static_cast<unsigned int>(arg1);
      return e;
    }
    case 33: 
    {
      Event_dup2 e{};
      e.oldfd = static_cast<unsigned int>(arg1);
      e.newfd = static_cast<unsigned int>(arg2);
      return e;
    }
    case 34: 
    {
      Event_pause e{};
      return e;
    }
    case 35: 
    {
      Event_nanosleep e{};
      e.rqtp = reinterpret_cast< __kernel_timespec *>(arg1);
      e.rmtp = reinterpret_cast< __kernel_timespec *>(arg2);
      return e;
    }
    case 36: 
    {
      Event_getitimer e{};
      e.which = static_cast<int>(arg1);
      e.value = reinterpret_cast< __kernel_itimerval *>(arg2);
      return e;
    }
    case 37: 
    {
      Event_alarm e{};
      e.seconds = static_cast<unsigned int>(arg1);
      return e;
    }
    case 38: 
    {
      Event_setitimer e{};
      e.which = static_cast<int>(arg1);
      e.value = reinterpret_cast< __kernel_itimerval *>(arg2);
      e.ovalue = reinterpret_cast< __kernel_itimerval *>(arg3);
      return e;
    }
    case 39: 
    {
      Event_getpid e{};
      return e;
    }
    case 40: 
    {
      Event_sendfile64 e{};
      e.out_fd = static_cast<int>(arg1);
      e.in_fd = static_cast<int>(arg2);
      e.offset = reinterpret_cast<loff_t *>(arg3);
      e.count = static_cast<size_t>(arg4);
      return e;
    }
    case 41: 
    {
      Event_socket e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = static_cast<int>(arg2);
      e.unnamed2 = static_cast<int>(arg3);
      return e;
    }
    case 42: 
    {
      Event_connect e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast< sockaddr *>(arg2);
      e.unnamed2 = static_cast<int>(arg3);
      return e;
    }
    case 43: 
    {
      Event_accept e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast< sockaddr *>(arg2);
      e.unnamed2 = reinterpret_cast<int *>(arg3);
      return e;
    }
    case 44: 
    {
      Event_sendto e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast<void *>(arg2);
      e.unnamed2 = static_cast<size_t>(arg3);
      e.unnamed3 = static_cast<unsigned>(arg4);
      e.unnamed4 = reinterpret_cast< sockaddr *>(arg5);
      e.unnamed5 = static_cast<int>(arg6);
      return e;
    }
    case 45: 
    {
      Event_recvfrom e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast<void *>(arg2);
      e.unnamed2 = static_cast<size_t>(arg3);
      e.unnamed3 = static_cast<unsigned>(arg4);
      e.unnamed4 = reinterpret_cast< sockaddr *>(arg5);
      e.unnamed5 = reinterpret_cast<int *>(arg6);
      return e;
    }
    case 46: 
    {
      Event_sendmsg e{};
      e.fd = static_cast<int>(arg1);
      e.msg = reinterpret_cast< user_msghdr *>(arg2);
      e.flags = static_cast<unsigned>(arg3);
      return e;
    }
    case 47: 
    {
      Event_recvmsg e{};
      e.fd = static_cast<int>(arg1);
      e.msg = reinterpret_cast< user_msghdr *>(arg2);
      e.flags = static_cast<unsigned>(arg3);
      return e;
    }
    case 48: 
    {
      Event_shutdown e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = static_cast<int>(arg2);
      return e;
    }
    case 49: 
    {
      Event_bind e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast< sockaddr *>(arg2);
      e.unnamed2 = static_cast<int>(arg3);
      return e;
    }
    case 50: 
    {
      Event_listen e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = static_cast<int>(arg2);
      return e;
    }
    case 51: 
    {
      Event_getsockname e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast< sockaddr *>(arg2);
      e.unnamed2 = reinterpret_cast<int *>(arg3);
      return e;
    }
    case 52: 
    {
      Event_getpeername e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast< sockaddr *>(arg2);
      e.unnamed2 = reinterpret_cast<int *>(arg3);
      return e;
    }
    case 53: 
    {
      Event_socketpair e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = static_cast<int>(arg2);
      e.unnamed2 = static_cast<int>(arg3);
      e.unnamed3 = reinterpret_cast<int *>(arg4);
      return e;
    }
    case 54: 
    {
      Event_setsockopt e{};
      e.fd = static_cast<int>(arg1);
      e.level = static_cast<int>(arg2);
      e.optname = static_cast<int>(arg3);
      e.optval = reinterpret_cast<char *>(arg4);
      e.optlen = static_cast<int>(arg5);
      return e;
    }
    case 55: 
    {
      Event_getsockopt e{};
      e.fd = static_cast<int>(arg1);
      e.level = static_cast<int>(arg2);
      e.optname = static_cast<int>(arg3);
      e.optval = reinterpret_cast<char *>(arg4);
      e.optlen = reinterpret_cast<int *>(arg5);
      return e;
    }
    case 60: 
    {
      Event_exit e{};
      e.error_code = static_cast<int>(arg1);
      return e;
    }
    case 61: 
    {
      Event_wait4 e{};
      e.pid = static_cast<pid_t>(arg1);
      e.stat_addr = reinterpret_cast<int *>(arg2);
      e.options = static_cast<int>(arg3);
      e.ru = reinterpret_cast< rusage *>(arg4);
      return e;
    }
    case 62: 
    {
      Event_kill e{};
      e.pid = static_cast<pid_t>(arg1);
      e.sig = static_cast<int>(arg2);
      return e;
    }
    case 63: 
    {
      Event_uname e{};
      e.unnamed0 = reinterpret_cast< utsname *>(arg1);
      return e;
    }
    case 64: 
    {
      Event_semget e{};
      e.key = static_cast<key_t>(arg1);
      e.nsems = static_cast<int>(arg2);
      e.semflg = static_cast<int>(arg3);
      return e;
    }
    case 65: 
    {
      Event_semop e{};
      e.semid = static_cast<int>(arg1);
      e.sops = reinterpret_cast< sembuf *>(arg2);
      e.nsops = static_cast<unsigned>(arg3);
      return e;
    }
    case 66: 
    {
      Event_semctl e{};
      e.semid = static_cast<int>(arg1);
      e.semnum = static_cast<int>(arg2);
      e.cmd = static_cast<int>(arg3);
      e.arg = static_cast<unsigned long>(arg4);
      return e;
    }
    case 67: 
    {
      Event_shmdt e{};
      e.shmaddr = reinterpret_cast<char *>(arg1);
      return e;
    }
    case 68: 
    {
      Event_msgget e{};
      e.key = static_cast<key_t>(arg1);
      e.msgflg = static_cast<int>(arg2);
      return e;
    }
    case 69: 
    {
      Event_msgsnd e{};
      e.msqid = static_cast<int>(arg1);
      e.msgp = reinterpret_cast< msgbuf *>(arg2);
      e.msgsz = static_cast<size_t>(arg3);
      e.msgflg = static_cast<int>(arg4);
      return e;
    }
    case 70: 
    {
      Event_msgrcv e{};
      e.msqid = static_cast<int>(arg1);
      e.msgp = reinterpret_cast< msgbuf *>(arg2);
      e.msgsz = static_cast<size_t>(arg3);
      e.msgtyp = static_cast<long>(arg4);
      e.msgflg = static_cast<int>(arg5);
      return e;
    }
    case 71: 
    {
      Event_msgctl e{};
      e.msqid = static_cast<int>(arg1);
      e.cmd = static_cast<int>(arg2);
      e.buf = reinterpret_cast< msqid_ds *>(arg3);
      return e;
    }
    case 72: 
    {
      Event_fcntl e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.cmd = static_cast<unsigned int>(arg2);
      e.arg = static_cast<unsigned long>(arg3);
      return e;
    }
    case 73: 
    {
      Event_flock e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.cmd = static_cast<unsigned int>(arg2);
      return e;
    }
    case 74: 
    {
      Event_fsync e{};
      e.fd = static_cast<unsigned int>(arg1);
      return e;
    }
    case 75: 
    {
      Event_fdatasync e{};
      e.fd = static_cast<unsigned int>(arg1);
      return e;
    }
    case 76: 
    {
      Event_truncate e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.length = static_cast<long>(arg2);
      return e;
    }
    case 77: 
    {
      Event_ftruncate e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.length = static_cast<unsigned long>(arg2);
      return e;
    }
    case 78: 
    {
      Event_getdents e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.dirent = reinterpret_cast< linux_dirent *>(arg2);
      e.count = static_cast<unsigned int>(arg3);
      return e;
    }
    case 79: 
    {
      Event_getcwd e{};
      e.buf = reinterpret_cast<char *>(arg1);
      e.size = static_cast<unsigned long>(arg2);
      return e;
    }
    case 80: 
    {
      Event_chdir e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      return e;
    }
    case 81: 
    {
      Event_fchdir e{};
      e.fd = static_cast<unsigned int>(arg1);
      return e;
    }
    case 82: 
    {
      Event_rename e{};
      e.oldname = reinterpret_cast<const char *>(arg1);
      e.newname = reinterpret_cast<const char *>(arg2);
      return e;
    }
    case 83: 
    {
      Event_mkdir e{};
      e.pathname = reinterpret_cast<const char *>(arg1);
      e.mode = static_cast<mode_t>(arg2);
      return e;
    }
    case 84: 
    {
      Event_rmdir e{};
      e.pathname = reinterpret_cast<const char *>(arg1);
      return e;
    }
    case 85: 
    {
      Event_creat e{};
      e.pathname = reinterpret_cast<const char *>(arg1);
      e.mode = static_cast<mode_t>(arg2);
      return e;
    }
    case 86: 
    {
      Event_link e{};
      e.oldname = reinterpret_cast<const char *>(arg1);
      e.newname = reinterpret_cast<const char *>(arg2);
      return e;
    }
    case 87: 
    {
      Event_unlink e{};
      e.pathname = reinterpret_cast<const char *>(arg1);
      return e;
    }
    case 88: 
    {
      Event_symlink e{};
      e.old = reinterpret_cast<const char *>(arg1);
      e.linkpath = reinterpret_cast<const char *>(arg2);
      return e;
    }
    case 89: 
    {
      Event_readlink e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.buf = reinterpret_cast<char *>(arg2);
      e.bufsiz = static_cast<int>(arg3);
      return e;
    }
    case 90: 
    {
      Event_chmod e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      e.mode = static_cast<mode_t>(arg2);
      return e;
    }
    case 91: 
    {
      Event_fchmod e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.mode = static_cast<mode_t>(arg2);
      return e;
    }
    case 92: 
    {
      Event_chown e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      e.user = static_cast<uid_t>(arg2);
      e.group = static_cast<gid_t>(arg3);
      return e;
    }
    case 93: 
    {
      Event_fchown e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.user = static_cast<uid_t>(arg2);
      e.group = static_cast<gid_t>(arg3);
      return e;
    }
    case 94: 
    {
      Event_lchown e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      e.user = static_cast<uid_t>(arg2);
      e.group = static_cast<gid_t>(arg3);
      return e;
    }
    case 95: 
    {
      Event_umask e{};
      e.mask = static_cast<int>(arg1);
      return e;
    }
    case 96: 
    {
      Event_gettimeofday e{};
      e.tv = reinterpret_cast< __kernel_timeval *>(arg1);
      e.tz = reinterpret_cast< timezone *>(arg2);
      return e;
    }
    case 97: 
    {
      Event_getrlimit e{};
      e.resource = static_cast<unsigned int>(arg1);
      e.rlim = reinterpret_cast< rlimit *>(arg2);
      return e;
    }
    case 98: 
    {
      Event_getrusage e{};
      e.who = static_cast<int>(arg1);
      e.ru = reinterpret_cast< rusage *>(arg2);
      return e;
    }
    case 99: 
    {
      Event_sysinfo e{};
      e.info = reinterpret_cast< sysinfo *>(arg1);
      return e;
    }
    case 100: 
    {
      Event_times e{};
      e.tbuf = reinterpret_cast< tms *>(arg1);
      return e;
    }
    case 101: 
    {
      Event_ptrace e{};
      e.request = static_cast<long>(arg1);
      e.pid = static_cast<long>(arg2);
      e.addr = static_cast<unsigned long>(arg3);
      e.data = static_cast<unsigned long>(arg4);
      return e;
    }
    case 102: 
    {
      Event_getuid e{};
      return e;
    }
    case 103: 
    {
      Event_syslog e{};
      e.type = static_cast<int>(arg1);
      e.buf = reinterpret_cast<char *>(arg2);
      e.len = static_cast<int>(arg3);
      return e;
    }
    case 104: 
    {
      Event_getgid e{};
      return e;
    }
    case 105: 
    {
      Event_setuid e{};
      e.uid = static_cast<uid_t>(arg1);
      return e;
    }
    case 106: 
    {
      Event_setgid e{};
      e.gid = static_cast<gid_t>(arg1);
      return e;
    }
    case 107: 
    {
      Event_geteuid e{};
      return e;
    }
    case 108: 
    {
      Event_getegid e{};
      return e;
    }
    case 109: 
    {
      Event_setpgid e{};
      e.pid = static_cast<pid_t>(arg1);
      e.pgid = static_cast<pid_t>(arg2);
      return e;
    }
    case 110: 
    {
      Event_getppid e{};
      return e;
    }
    case 111: 
    {
      Event_getpgrp e{};
      return e;
    }
    case 112: 
    {
      Event_setsid e{};
      return e;
    }
    case 113: 
    {
      Event_setreuid e{};
      e.ruid = static_cast<uid_t>(arg1);
      e.euid = static_cast<uid_t>(arg2);
      return e;
    }
    case 114: 
    {
      Event_setregid e{};
      e.rgid = static_cast<gid_t>(arg1);
      e.egid = static_cast<gid_t>(arg2);
      return e;
    }
    case 115: 
    {
      Event_getgroups e{};
      e.gidsetsize = static_cast<int>(arg1);
      e.grouplist = reinterpret_cast<gid_t *>(arg2);
      return e;
    }
    case 116: 
    {
      Event_setgroups e{};
      e.gidsetsize = static_cast<int>(arg1);
      e.grouplist = reinterpret_cast<gid_t *>(arg2);
      return e;
    }
    case 117: 
    {
      Event_setresuid e{};
      e.ruid = static_cast<uid_t>(arg1);
      e.euid = static_cast<uid_t>(arg2);
      e.suid = static_cast<uid_t>(arg3);
      return e;
    }
    case 118: 
    {
      Event_getresuid e{};
      e.ruid = reinterpret_cast<uid_t *>(arg1);
      e.euid = reinterpret_cast<uid_t *>(arg2);
      e.suid = reinterpret_cast<uid_t *>(arg3);
      return e;
    }
    case 119: 
    {
      Event_setresgid e{};
      e.rgid = static_cast<gid_t>(arg1);
      e.egid = static_cast<gid_t>(arg2);
      e.sgid = static_cast<gid_t>(arg3);
      return e;
    }
    case 120: 
    {
      Event_getresgid e{};
      e.rgid = reinterpret_cast<gid_t *>(arg1);
      e.egid = reinterpret_cast<gid_t *>(arg2);
      e.sgid = reinterpret_cast<gid_t *>(arg3);
      return e;
    }
    case 121: 
    {
      Event_getpgid e{};
      e.pid = static_cast<pid_t>(arg1);
      return e;
    }
    case 122: 
    {
      Event_setfsuid e{};
      e.uid = static_cast<uid_t>(arg1);
      return e;
    }
    case 123: 
    {
      Event_setfsgid e{};
      e.gid = static_cast<gid_t>(arg1);
      return e;
    }
    case 124: 
    {
      Event_getsid e{};
      e.pid = static_cast<pid_t>(arg1);
      return e;
    }
    case 127: 
    {
      Event_rt_sigpending e{};
      e.set = reinterpret_cast<sigset_t *>(arg1);
      e.sigsetsize = static_cast<size_t>(arg2);
      return e;
    }
    case 128: 
    {
      Event_rt_sigtimedwait e{};
      e.uthese = reinterpret_cast<const sigset_t *>(arg1);
      e.uinfo = reinterpret_cast<siginfo_t *>(arg2);
      e.uts = reinterpret_cast<const __kernel_timespec *>(arg3);
      e.sigsetsize = static_cast<size_t>(arg4);
      return e;
    }
    case 129: 
    {
      Event_rt_sigqueueinfo e{};
      e.pid = static_cast<pid_t>(arg1);
      e.sig = static_cast<int>(arg2);
      e.uinfo = reinterpret_cast<siginfo_t *>(arg3);
      return e;
    }
    case 130: 
    {
      Event_rt_sigsuspend e{};
      e.unewset = reinterpret_cast<sigset_t *>(arg1);
      e.sigsetsize = static_cast<size_t>(arg2);
      return e;
    }
    case 132: 
    {
      Event_utime e{};
      e.filename = reinterpret_cast<char *>(arg1);
      e.times = reinterpret_cast< utimbuf *>(arg2);
      return e;
    }
    case 133: 
    {
      Event_mknod e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      e.mode = static_cast<mode_t>(arg2);
      e.dev = static_cast<unsigned>(arg3);
      return e;
    }
    case 134: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 135: 
    {
      Event_personality e{};
      e.personality = static_cast<unsigned int>(arg1);
      return e;
    }
    case 136: 
    {
      Event_ustat e{};
      e.dev = static_cast<unsigned>(arg1);
      e.ubuf = reinterpret_cast< ustat *>(arg2);
      return e;
    }
    case 137: 
    {
      Event_statfs e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.buf = reinterpret_cast< statfs *>(arg2);
      return e;
    }
    case 138: 
    {
      Event_fstatfs e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.buf = reinterpret_cast< statfs *>(arg2);
      return e;
    }
    case 139: 
    {
      Event_sysfs e{};
      e.option = static_cast<int>(arg1);
      e.arg1 = static_cast<unsigned long>(arg2);
      e.arg2 = static_cast<unsigned long>(arg3);
      return e;
    }
    case 140: 
    {
      Event_getpriority e{};
      e.which = static_cast<int>(arg1);
      e.who = static_cast<int>(arg2);
      return e;
    }
    case 141: 
    {
      Event_setpriority e{};
      e.which = static_cast<int>(arg1);
      e.who = static_cast<int>(arg2);
      e.niceval = static_cast<int>(arg3);
      return e;
    }
    case 142: 
    {
      Event_sched_setparam e{};
      e.pid = static_cast<pid_t>(arg1);
      e.param = reinterpret_cast< sched_param *>(arg2);
      return e;
    }
    case 143: 
    {
      Event_sched_getparam e{};
      e.pid = static_cast<pid_t>(arg1);
      e.param = reinterpret_cast< sched_param *>(arg2);
      return e;
    }
    case 144: 
    {
      Event_sched_setscheduler e{};
      e.pid = static_cast<pid_t>(arg1);
      e.policy = static_cast<int>(arg2);
      e.param = reinterpret_cast< sched_param *>(arg3);
      return e;
    }
    case 145: 
    {
      Event_sched_getscheduler e{};
      e.pid = static_cast<pid_t>(arg1);
      return e;
    }
    case 146: 
    {
      Event_sched_get_priority_max e{};
      e.policy = static_cast<int>(arg1);
      return e;
    }
    case 147: 
    {
      Event_sched_get_priority_min e{};
      e.policy = static_cast<int>(arg1);
      return e;
    }
    case 148: 
    {
      Event_sched_rr_get_interval e{};
      e.pid = static_cast<pid_t>(arg1);
      e.interval = reinterpret_cast< __kernel_timespec *>(arg2);
      return e;
    }
    case 149: 
    {
      Event_mlock e{};
      e.start = static_cast<unsigned long>(arg1);
      e.len = static_cast<size_t>(arg2);
      return e;
    }
    case 150: 
    {
      Event_munlock e{};
      e.start = static_cast<unsigned long>(arg1);
      e.len = static_cast<size_t>(arg2);
      return e;
    }
    case 151: 
    {
      Event_mlockall e{};
      e.flags = static_cast<int>(arg1);
      return e;
    }
    case 152: 
    {
      Event_munlockall e{};
      return e;
    }
    case 153: 
    {
      Event_vhangup e{};
      return e;
    }
    case 154: 
    {
      Event_modify_ldt e{};
      return e;
    }
    case 155: 
    {
      Event_pivot_root e{};
      e.new_root = reinterpret_cast<const char *>(arg1);
      e.put_old = reinterpret_cast<const char *>(arg2);
      return e;
    }
    case 156: 
    {
      Event_sysctl e{};
      return e;
    }
    case 157: 
    {
      Event_prctl e{};
      e.option = static_cast<int>(arg1);
      e.arg2 = static_cast<unsigned long>(arg2);
      e.arg3 = static_cast<unsigned long>(arg3);
      e.arg4 = static_cast<unsigned long>(arg4);
      e.arg5 = static_cast<unsigned long>(arg5);
      return e;
    }
    case 158: 
    {
      Event_arch_prctl e{};
      return e;
    }
    case 159: 
    {
      Event_adjtimex e{};
      e.txc_p = reinterpret_cast< __kernel_timex *>(arg1);
      return e;
    }
    case 160: 
    {
      Event_setrlimit e{};
      e.resource = static_cast<unsigned int>(arg1);
      e.rlim = reinterpret_cast< rlimit *>(arg2);
      return e;
    }
    case 161: 
    {
      Event_chroot e{};
      e.filename = reinterpret_cast<const char *>(arg1);
      return e;
    }
    case 162: 
    {
      Event_sync e{};
      return e;
    }
    case 163: 
    {
      Event_acct e{};
      e.name = reinterpret_cast<const char *>(arg1);
      return e;
    }
    case 164: 
    {
      Event_settimeofday e{};
      e.tv = reinterpret_cast< __kernel_timeval *>(arg1);
      e.tz = reinterpret_cast< timezone *>(arg2);
      return e;
    }
    case 165: 
    {
      Event_mount e{};
      e.dev_name = reinterpret_cast<char *>(arg1);
      e.dir_name = reinterpret_cast<char *>(arg2);
      e.type = reinterpret_cast<char *>(arg3);
      e.flags = static_cast<unsigned long>(arg4);
      e.data = reinterpret_cast<void *>(arg5);
      return e;
    }
    case 166: 
    {
      Event_umount e{};
      e.name = reinterpret_cast<char *>(arg1);
      e.flags = static_cast<int>(arg2);
      return e;
    }
    case 167: 
    {
      Event_swapon e{};
      e.specialfile = reinterpret_cast<const char *>(arg1);
      e.swap_flags = static_cast<int>(arg2);
      return e;
    }
    case 168: 
    {
      Event_swapoff e{};
      e.specialfile = reinterpret_cast<const char *>(arg1);
      return e;
    }
    case 169: 
    {
      Event_reboot e{};
      e.magic1 = static_cast<int>(arg1);
      e.magic2 = static_cast<int>(arg2);
      e.cmd = static_cast<unsigned int>(arg3);
      e.arg = reinterpret_cast<void *>(arg4);
      return e;
    }
    case 170: 
    {
      Event_sethostname e{};
      e.name = reinterpret_cast<char *>(arg1);
      e.len = static_cast<int>(arg2);
      return e;
    }
    case 171: 
    {
      Event_setdomainname e{};
      e.name = reinterpret_cast<char *>(arg1);
      e.len = static_cast<int>(arg2);
      return e;
    }
    case 173: 
    {
      Event_ioperm e{};
      e.from = static_cast<unsigned long>(arg1);
      e.num = static_cast<unsigned long>(arg2);
      e.on = static_cast<int>(arg3);
      return e;
    }
    case 174: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 175: 
    {
      Event_init_module e{};
      e.umod = reinterpret_cast<void *>(arg1);
      e.len = static_cast<unsigned long>(arg2);
      e.uargs = reinterpret_cast<const char *>(arg3);
      return e;
    }
    case 176: 
    {
      Event_delete_module e{};
      e.name_user = reinterpret_cast<const char *>(arg1);
      e.flags = static_cast<unsigned int>(arg2);
      return e;
    }
    case 177: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 178: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 179: 
    {
      Event_quotactl e{};
      e.cmd = static_cast<unsigned int>(arg1);
      e.special = reinterpret_cast<const char *>(arg2);
      e.id = static_cast<int>(arg3);
      e.addr = reinterpret_cast<void *>(arg4);
      return e;
    }
    case 180: 
    {
      Event_nfsservctl e{};
      return e;
    }
    case 181: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 182: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 183: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 184: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 185: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 186: 
    {
      Event_gettid e{};
      return e;
    }
    case 187: 
    {
      Event_readahead e{};
      e.fd = static_cast<int>(arg1);
      e.offset = static_cast<loff_t>(arg2);
      e.count = static_cast<size_t>(arg3);
      return e;
    }
    case 188: 
    {
      Event_setxattr e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.name = reinterpret_cast<const char *>(arg2);
      e.value = reinterpret_cast<const void *>(arg3);
      e.size = static_cast<size_t>(arg4);
      e.flags = static_cast<int>(arg5);
      return e;
    }
    case 189: 
    {
      Event_lsetxattr e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.name = reinterpret_cast<const char *>(arg2);
      e.value = reinterpret_cast<const void *>(arg3);
      e.size = static_cast<size_t>(arg4);
      e.flags = static_cast<int>(arg5);
      return e;
    }
    case 190: 
    {
      Event_fsetxattr e{};
      e.fd = static_cast<int>(arg1);
      e.name = reinterpret_cast<const char *>(arg2);
      e.value = reinterpret_cast<const void *>(arg3);
      e.size = static_cast<size_t>(arg4);
      e.flags = static_cast<int>(arg5);
      return e;
    }
    case 191: 
    {
      Event_getxattr e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.name = reinterpret_cast<const char *>(arg2);
      e.value = reinterpret_cast<void *>(arg3);
      e.size = static_cast<size_t>(arg4);
      return e;
    }
    case 192: 
    {
      Event_lgetxattr e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.name = reinterpret_cast<const char *>(arg2);
      e.value = reinterpret_cast<void *>(arg3);
      e.size = static_cast<size_t>(arg4);
      return e;
    }
    case 193: 
    {
      Event_fgetxattr e{};
      e.fd = static_cast<int>(arg1);
      e.name = reinterpret_cast<const char *>(arg2);
      e.value = reinterpret_cast<void *>(arg3);
      e.size = static_cast<size_t>(arg4);
      return e;
    }
    case 194: 
    {
      Event_listxattr e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.list = reinterpret_cast<char *>(arg2);
      e.size = static_cast<size_t>(arg3);
      return e;
    }
    case 195: 
    {
      Event_llistxattr e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.list = reinterpret_cast<char *>(arg2);
      e.size = static_cast<size_t>(arg3);
      return e;
    }
    case 196: 
    {
      Event_flistxattr e{};
      e.fd = static_cast<int>(arg1);
      e.list = reinterpret_cast<char *>(arg2);
      e.size = static_cast<size_t>(arg3);
      return e;
    }
    case 197: 
    {
      Event_removexattr e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.name = reinterpret_cast<const char *>(arg2);
      return e;
    }
    case 198: 
    {
      Event_lremovexattr e{};
      e.path = reinterpret_cast<const char *>(arg1);
      e.name = reinterpret_cast<const char *>(arg2);
      return e;
    }
    case 199: 
    {
      Event_fremovexattr e{};
      e.fd = static_cast<int>(arg1);
      e.name = reinterpret_cast<const char *>(arg2);
      return e;
    }
    case 200: 
    {
      Event_tkill e{};
      e.pid = static_cast<pid_t>(arg1);
      e.sig = static_cast<int>(arg2);
      return e;
    }
    case 201: 
    {
      Event_time e{};
      e.tloc = reinterpret_cast<__kernel_time_t *>(arg1);
      return e;
    }
    case 202: 
    {
      Event_futex e{};
      e.uaddr = reinterpret_cast<uint32_t *>(arg1);
      e.op = static_cast<int>(arg2);
      e.val = static_cast<uint32_t>(arg3);
      e.utime = reinterpret_cast<const __kernel_timespec *>(arg4);
      e.uaddr2 = reinterpret_cast<uint32_t *>(arg5);
      e.val3 = static_cast<uint32_t>(arg6);
      return e;
    }
    case 203: 
    {
      Event_sched_setaffinity e{};
      e.pid = static_cast<pid_t>(arg1);
      e.len = static_cast<unsigned int>(arg2);
      e.user_mask_ptr = reinterpret_cast<unsigned long *>(arg3);
      return e;
    }
    case 204: 
    {
      Event_sched_getaffinity e{};
      e.pid = static_cast<pid_t>(arg1);
      e.len = static_cast<unsigned int>(arg2);
      e.user_mask_ptr = reinterpret_cast<unsigned long *>(arg3);
      return e;
    }
    case 205: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 206: 
    {
      Event_io_setup e{};
      e.nr_reqs = static_cast<unsigned>(arg1);
      e.ctx = reinterpret_cast<aio_context_t *>(arg2);
      return e;
    }
    case 207: 
    {
      Event_io_destroy e{};
      e.ctx = static_cast<aio_context_t>(arg1);
      return e;
    }
    case 208: 
    {
      Event_io_getevents e{};
      e.ctx_id = static_cast<aio_context_t>(arg1);
      e.min_nr = static_cast<long>(arg2);
      e.nr = static_cast<long>(arg3);
      e.events = reinterpret_cast< io_event *>(arg4);
      e.timeout = reinterpret_cast< __kernel_timespec *>(arg5);
      return e;
    }
    case 209: 
    {
      Event_io_submit e{};
      e.unnamed0 = static_cast<aio_context_t>(arg1);
      e.unnamed1 = static_cast<long>(arg2);
      e.unnamed2 = reinterpret_cast< iocb * *>(arg3);
      return e;
    }
    case 210: 
    {
      Event_io_cancel e{};
      e.ctx_id = static_cast<aio_context_t>(arg1);
      e.iocb = reinterpret_cast< iocb *>(arg2);
      e.result = reinterpret_cast< io_event *>(arg3);
      return e;
    }
    case 211: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 212: 
    {
      Event_lookup_dcookie e{};
      e.cookie64 = static_cast<uint64_t>(arg1);
      e.buf = reinterpret_cast<char *>(arg2);
      e.len = static_cast<size_t>(arg3);
      return e;
    }
    case 213: 
    {
      Event_epoll_create e{};
      e.size = static_cast<int>(arg1);
      return e;
    }
    case 214: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 215: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 216: 
    {
      Event_remap_file_pages e{};
      e.start = static_cast<unsigned long>(arg1);
      e.size = static_cast<unsigned long>(arg2);
      e.prot = static_cast<unsigned long>(arg3);
      e.pgoff = static_cast<unsigned long>(arg4);
      e.flags = static_cast<unsigned long>(arg5);
      return e;
    }
    case 217: 
    {
      Event_getdents64 e{};
      e.fd = static_cast<unsigned int>(arg1);
      e.dirent = reinterpret_cast< linux_dirent64 *>(arg2);
      e.count = static_cast<unsigned int>(arg3);
      return e;
    }
    case 218: 
    {
      Event_set_tid_address e{};
      e.tidptr = reinterpret_cast<int *>(arg1);
      return e;
    }
    case 219: 
    {
      Event_restart_syscall e{};
      return e;
    }
    case 220: 
    {
      Event_semtimedop e{};
      e.semid = static_cast<int>(arg1);
      e.sops = reinterpret_cast< sembuf *>(arg2);
      e.nsops = static_cast<unsigned>(arg3);
      e.timeout = reinterpret_cast<const __kernel_timespec *>(arg4);
      return e;
    }
    case 221: 
    {
      Event_fadvise64 e{};
      e.fd = static_cast<int>(arg1);
      e.offset = static_cast<loff_t>(arg2);
      e.len = static_cast<size_t>(arg3);
      e.advice = static_cast<int>(arg4);
      return e;
    }
    case 222: 
    {
      Event_timer_create e{};
      e.which_clock = static_cast<clockid_t>(arg1);
      e.timer_event_spec = reinterpret_cast< sigevent *>(arg2);
      e.created_timer_id = reinterpret_cast<timer_t *>(arg3);
      return e;
    }
    case 223: 
    {
      Event_timer_settime e{};
      e.timer_id = static_cast<timer_t>(arg1);
      e.flags = static_cast<int>(arg2);
      e.new_setting = reinterpret_cast<const __kernel_itimerspec *>(arg3);
      e.old_setting = reinterpret_cast< __kernel_itimerspec *>(arg4);
      return e;
    }
    case 224: 
    {
      Event_timer_gettime e{};
      e.timer_id = static_cast<timer_t>(arg1);
      e.setting = reinterpret_cast< __kernel_itimerspec *>(arg2);
      return e;
    }
    case 225: 
    {
      Event_timer_getoverrun e{};
      e.timer_id = static_cast<timer_t>(arg1);
      return e;
    }
    case 226: 
    {
      Event_timer_delete e{};
      e.timer_id = static_cast<timer_t>(arg1);
      return e;
    }
    case 227: 
    {
      Event_clock_settime e{};
      e.which_clock = static_cast<clockid_t>(arg1);
      e.tp = reinterpret_cast<const __kernel_timespec *>(arg2);
      return e;
    }
    case 228: 
    {
      Event_clock_gettime e{};
      e.which_clock = static_cast<clockid_t>(arg1);
      e.tp = reinterpret_cast< __kernel_timespec *>(arg2);
      return e;
    }
    case 229: 
    {
      Event_clock_getres e{};
      e.which_clock = static_cast<clockid_t>(arg1);
      e.tp = reinterpret_cast< __kernel_timespec *>(arg2);
      return e;
    }
    case 230: 
    {
      Event_clock_nanosleep e{};
      e.which_clock = static_cast<clockid_t>(arg1);
      e.flags = static_cast<int>(arg2);
      e.rqtp = reinterpret_cast<const __kernel_timespec *>(arg3);
      e.rmtp = reinterpret_cast< __kernel_timespec *>(arg4);
      return e;
    }
    case 231: 
    {
      Event_exit_group e{};
      e.error_code = static_cast<int>(arg1);
      return e;
    }
    case 232: 
    {
      Event_epoll_wait e{};
      e.epfd = static_cast<int>(arg1);
      e.events = reinterpret_cast< epoll_event *>(arg2);
      e.maxevents = static_cast<int>(arg3);
      e.timeout = static_cast<int>(arg4);
      return e;
    }
    case 233: 
    {
      Event_epoll_ctl e{};
      e.epfd = static_cast<int>(arg1);
      e.op = static_cast<int>(arg2);
      e.fd = static_cast<int>(arg3);
      e.event = reinterpret_cast< epoll_event *>(arg4);
      return e;
    }
    case 234: 
    {
      Event_tgkill e{};
      e.tgid = static_cast<pid_t>(arg1);
      e.pid = static_cast<pid_t>(arg2);
      e.sig = static_cast<int>(arg3);
      return e;
    }
    case 235: 
    {
      Event_utimes e{};
      e.filename = reinterpret_cast<char *>(arg1);
      e.utimes = reinterpret_cast< __kernel_timeval *>(arg2);
      return e;
    }
    case 236: 
    {
      Event_ni_syscall e{};
      return e;
    }
    case 237: 
    {
      Event_mbind e{};
      e.start = static_cast<unsigned long>(arg1);
      e.len = static_cast<unsigned long>(arg2);
      e.mode = static_cast<unsigned long>(arg3);
      e.nmask = reinterpret_cast<const unsigned long *>(arg4);
      e.maxnode = static_cast<unsigned long>(arg5);
      e.flags = static_cast<unsigned>(arg6);
      return e;
    }
    case 238: 
    {
      Event_set_mempolicy e{};
      e.mode = static_cast<int>(arg1);
      e.nmask = reinterpret_cast<const unsigned long *>(arg2);
      e.maxnode = static_cast<unsigned long>(arg3);
      return e;
    }
    case 239: 
    {
      Event_get_mempolicy e{};
      e.policy = reinterpret_cast<int *>(arg1);
      e.nmask = reinterpret_cast<unsigned long *>(arg2);
      e.maxnode = static_cast<unsigned long>(arg3);
      e.addr = static_cast<unsigned long>(arg4);
      e.flags = static_cast<unsigned long>(arg5);
      return e;
    }
    case 240: 
    {
      Event_mq_open e{};
      e.name = reinterpret_cast<const char *>(arg1);
      e.oflag = static_cast<int>(arg2);
      e.mode = static_cast<mode_t>(arg3);
      e.attr = reinterpret_cast< mq_attr *>(arg4);
      return e;
    }
    case 241: 
    {
      Event_mq_unlink e{};
      e.name = reinterpret_cast<const char *>(arg1);
      return e;
    }
    case 242: 
    {
      Event_mq_timedsend e{};
      e.mqdes = static_cast<mqd_t>(arg1);
      e.msg_ptr = reinterpret_cast<const char *>(arg2);
      e.msg_len = static_cast<size_t>(arg3);
      e.msg_prio = static_cast<unsigned int>(arg4);
      e.abs_timeout = reinterpret_cast<const __kernel_timespec *>(arg5);
      return e;
    }
    case 243: 
    {
      Event_mq_timedreceive e{};
      e.mqdes = static_cast<mqd_t>(arg1);
      e.msg_ptr = reinterpret_cast<char *>(arg2);
      e.msg_len = static_cast<size_t>(arg3);
      e.msg_prio = reinterpret_cast<unsigned int *>(arg4);
      e.abs_timeout = reinterpret_cast<const __kernel_timespec *>(arg5);
      return e;
    }
    case 244: 
    {
      Event_mq_notify e{};
      e.mqdes = static_cast<mqd_t>(arg1);
      e.notification = reinterpret_cast<const sigevent *>(arg2);
      return e;
    }
    case 245: 
    {
      Event_mq_getsetattr e{};
      e.mqdes = static_cast<mqd_t>(arg1);
      e.mqstat = reinterpret_cast<const mq_attr *>(arg2);
      e.omqstat = reinterpret_cast< mq_attr *>(arg3);
      return e;
    }
    case 246: 
    {
      Event_kexec_load e{};
      e.entry = static_cast<unsigned long>(arg1);
      e.nr_segments = static_cast<unsigned long>(arg2);
      e.segments = reinterpret_cast< kexec_segment *>(arg3);
      e.flags = static_cast<unsigned long>(arg4);
      return e;
    }
    case 247: 
    {
      Event_waitid e{};
      e.which = static_cast<int>(arg1);
      e.pid = static_cast<pid_t>(arg2);
      e.infop = reinterpret_cast< siginfo *>(arg3);
      e.options = static_cast<int>(arg4);
      e.ru = reinterpret_cast< rusage *>(arg5);
      return e;
    }
    case 250: 
    {
      Event_keyctl e{};
      e.cmd = static_cast<int>(arg1);
      e.arg2 = static_cast<unsigned long>(arg2);
      e.arg3 = static_cast<unsigned long>(arg3);
      e.arg4 = static_cast<unsigned long>(arg4);
      e.arg5 = static_cast<unsigned long>(arg5);
      return e;
    }
    case 251: 
    {
      Event_ioprio_set e{};
      e.which = static_cast<int>(arg1);
      e.who = static_cast<int>(arg2);
      e.ioprio = static_cast<int>(arg3);
      return e;
    }
    case 252: 
    {
      Event_ioprio_get e{};
      e.which = static_cast<int>(arg1);
      e.who = static_cast<int>(arg2);
      return e;
    }
    case 253: 
    {
      Event_inotify_init e{};
      return e;
    }
    case 254: 
    {
      Event_inotify_add_watch e{};
      e.fd = static_cast<int>(arg1);
      e.path = reinterpret_cast<const char *>(arg2);
      e.mask = static_cast<uint32_t>(arg3);
      return e;
    }
    case 255: 
    {
      Event_inotify_rm_watch e{};
      e.fd = static_cast<int>(arg1);
      e.wd = static_cast<__s32>(arg2);
      return e;
    }
    case 256: 
    {
      Event_migrate_pages e{};
      e.pid = static_cast<pid_t>(arg1);
      e.maxnode = static_cast<unsigned long>(arg2);
      e.from = reinterpret_cast<const unsigned long *>(arg3);
      e.to = reinterpret_cast<const unsigned long *>(arg4);
      return e;
    }
    case 257: 
    {
      Event_openat e{};
      e.dfd = static_cast<int>(arg1);
      e.filename = reinterpret_cast<const char *>(arg2);
      e.flags = static_cast<int>(arg3);
      e.mode = static_cast<mode_t>(arg4);
      return e;
    }
    case 258: 
    {
      Event_mkdirat e{};
      e.dfd = static_cast<int>(arg1);
      e.pathname = reinterpret_cast<const char *>(arg2);
      e.mode = static_cast<mode_t>(arg3);
      return e;
    }
    case 259: 
    {
      Event_mknodat e{};
      e.dfd = static_cast<int>(arg1);
      e.filename = reinterpret_cast<const char *>(arg2);
      e.mode = static_cast<mode_t>(arg3);
      e.dev = static_cast<unsigned>(arg4);
      return e;
    }
    case 260: 
    {
      Event_fchownat e{};
      e.dfd = static_cast<int>(arg1);
      e.filename = reinterpret_cast<const char *>(arg2);
      e.user = static_cast<uid_t>(arg3);
      e.group = static_cast<gid_t>(arg4);
      e.flag = static_cast<int>(arg5);
      return e;
    }
    case 261: 
    {
      Event_futimesat e{};
      e.dfd = static_cast<int>(arg1);
      e.filename = reinterpret_cast<const char *>(arg2);
      e.utimes = reinterpret_cast< __kernel_timeval *>(arg3);
      return e;
    }
    case 262: 
    {
      Event_newfstatat e{};
      e.dfd = static_cast<int>(arg1);
      e.filename = reinterpret_cast<const char *>(arg2);
      e.statbuf = reinterpret_cast< stat *>(arg3);
      e.flag = static_cast<int>(arg4);
      return e;
    }
    case 263: 
    {
      Event_unlinkat e{};
      e.dfd = static_cast<int>(arg1);
      e.pathname = reinterpret_cast<const char *>(arg2);
      e.flag = static_cast<int>(arg3);
      return e;
    }
    case 264: 
    {
      Event_renameat e{};
      e.olddfd = static_cast<int>(arg1);
      e.oldname = reinterpret_cast<const char *>(arg2);
      e.newdfd = static_cast<int>(arg3);
      e.newname = reinterpret_cast<const char *>(arg4);
      return e;
    }
    case 265: 
    {
      Event_linkat e{};
      e.olddfd = static_cast<int>(arg1);
      e.oldname = reinterpret_cast<const char *>(arg2);
      e.newdfd = static_cast<int>(arg3);
      e.newname = reinterpret_cast<const char *>(arg4);
      e.flags = static_cast<int>(arg5);
      return e;
    }
    case 266: 
    {
      Event_symlinkat e{};
      e.oldname = reinterpret_cast<const char *>(arg1);
      e.newdfd = static_cast<int>(arg2);
      e.newname = reinterpret_cast<const char *>(arg3);
      return e;
    }
    case 267: 
    {
      Event_readlinkat e{};
      e.dfd = static_cast<int>(arg1);
      e.path = reinterpret_cast<const char *>(arg2);
      e.buf = reinterpret_cast<char *>(arg3);
      e.bufsiz = static_cast<int>(arg4);
      return e;
    }
    case 268: 
    {
      Event_fchmodat e{};
      e.dfd = static_cast<int>(arg1);
      e.filename = reinterpret_cast<const char *>(arg2);
      e.mode = static_cast<mode_t>(arg3);
      return e;
    }
    case 269: 
    {
      Event_faccessat e{};
      e.dfd = static_cast<int>(arg1);
      e.filename = reinterpret_cast<const char *>(arg2);
      e.mode = static_cast<int>(arg3);
      return e;
    }
    case 270: 
    {
      Event_pselect6 e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast<fd_set *>(arg2);
      e.unnamed2 = reinterpret_cast<fd_set *>(arg3);
      e.unnamed3 = reinterpret_cast<fd_set *>(arg4);
      e.unnamed4 = reinterpret_cast< __kernel_timespec *>(arg5);
      e.unnamed5 = reinterpret_cast<void *>(arg6);
      return e;
    }
    case 273: 
    {
      Event_set_robust_list e{};
      e.head = reinterpret_cast< robust_list_head *>(arg1);
      e.len = static_cast<size_t>(arg2);
      return e;
    }
    case 274: 
    {
      Event_get_robust_list e{};
      e.pid = static_cast<int>(arg1);
      e.head_ptr = reinterpret_cast< robust_list_head * *>(arg2);
      e.len_ptr = reinterpret_cast<size_t *>(arg3);
      return e;
    }
    case 275: 
    {
      Event_splice e{};
      e.fd_in = static_cast<int>(arg1);
      e.off_in = reinterpret_cast<loff_t *>(arg2);
      e.fd_out = static_cast<int>(arg3);
      e.off_out = reinterpret_cast<loff_t *>(arg4);
      e.len = static_cast<size_t>(arg5);
      e.flags = static_cast<unsigned int>(arg6);
      return e;
    }
    case 276: 
    {
      Event_tee e{};
      e.fdin = static_cast<int>(arg1);
      e.fdout = static_cast<int>(arg2);
      e.len = static_cast<size_t>(arg3);
      e.flags = static_cast<unsigned int>(arg4);
      return e;
    }
    case 277: 
    {
      Event_sync_file_range e{};
      e.fd = static_cast<int>(arg1);
      e.offset = static_cast<loff_t>(arg2);
      e.nbytes = static_cast<loff_t>(arg3);
      e.flags = static_cast<unsigned int>(arg4);
      return e;
    }
    case 278: 
    {
      Event_vmsplice e{};
      e.fd = static_cast<int>(arg1);
      e.iov = reinterpret_cast<const iovec *>(arg2);
      e.nr_segs = static_cast<unsigned long>(arg3);
      e.flags = static_cast<unsigned int>(arg4);
      return e;
    }
    case 279: 
    {
      Event_move_pages e{};
      e.pid = static_cast<pid_t>(arg1);
      e.nr_pages = static_cast<unsigned long>(arg2);
      e.pages = reinterpret_cast<const void * *>(arg3);
      e.nodes = reinterpret_cast<const int *>(arg4);
      e.status = reinterpret_cast<int *>(arg5);
      e.flags = static_cast<int>(arg6);
      return e;
    }
    case 280: 
    {
      Event_utimensat e{};
      e.dfd = static_cast<int>(arg1);
      e.filename = reinterpret_cast<const char *>(arg2);
      e.utimes = reinterpret_cast< __kernel_timespec *>(arg3);
      e.flags = static_cast<int>(arg4);
      return e;
    }
    case 281: 
    {
      Event_epoll_pwait e{};
      e.epfd = static_cast<int>(arg1);
      e.events = reinterpret_cast< epoll_event *>(arg2);
      e.maxevents = static_cast<int>(arg3);
      e.timeout = static_cast<int>(arg4);
      e.sigmask = reinterpret_cast<const sigset_t *>(arg5);
      e.sigsetsize = static_cast<size_t>(arg6);
      return e;
    }
    case 282: 
    {
      Event_signalfd e{};
      e.ufd = static_cast<int>(arg1);
      e.user_mask = reinterpret_cast<sigset_t *>(arg2);
      e.sizemask = static_cast<size_t>(arg3);
      return e;
    }
    case 283: 
    {
      Event_timerfd_create e{};
      e.clockid = static_cast<int>(arg1);
      e.flags = static_cast<int>(arg2);
      return e;
    }
    case 284: 
    {
      Event_eventfd e{};
      e.count = static_cast<unsigned int>(arg1);
      return e;
    }
    case 285: 
    {
      Event_fallocate e{};
      e.fd = static_cast<int>(arg1);
      e.mode = static_cast<int>(arg2);
      e.offset = static_cast<loff_t>(arg3);
      e.len = static_cast<loff_t>(arg4);
      return e;
    }
    case 286: 
    {
      Event_timerfd_settime e{};
      e.ufd = static_cast<int>(arg1);
      e.flags = static_cast<int>(arg2);
      e.utmr = reinterpret_cast<const __kernel_itimerspec *>(arg3);
      e.otmr = reinterpret_cast< __kernel_itimerspec *>(arg4);
      return e;
    }
    case 287: 
    {
      Event_timerfd_gettime e{};
      e.ufd = static_cast<int>(arg1);
      e.otmr = reinterpret_cast< __kernel_itimerspec *>(arg2);
      return e;
    }
    case 288: 
    {
      Event_accept4 e{};
      e.unnamed0 = static_cast<int>(arg1);
      e.unnamed1 = reinterpret_cast< sockaddr *>(arg2);
      e.unnamed2 = reinterpret_cast<int *>(arg3);
      e.unnamed3 = static_cast<int>(arg4);
      return e;
    }
    case 289: 
    {
      Event_signalfd4 e{};
      e.ufd = static_cast<int>(arg1);
      e.user_mask = reinterpret_cast<sigset_t *>(arg2);
      e.sizemask = static_cast<size_t>(arg3);
      e.flags = static_cast<int>(arg4);
      return e;
    }
    case 290: 
    {
      Event_eventfd2 e{};
      e.count = static_cast<unsigned int>(arg1);
      e.flags = static_cast<int>(arg2);
      return e;
    }
    case 291: 
    {
      Event_epoll_create1 e{};
      e.flags = static_cast<int>(arg1);
      return e;
    }
    case 292: 
    {
      Event_dup3 e{};
      e.oldfd = static_cast<unsigned int>(arg1);
      e.newfd = static_cast<unsigned int>(arg2);
      e.flags = static_cast<int>(arg3);
      return e;
    }
    case 293: 
    {
      Event_pipe2 e{};
      e.fildes = reinterpret_cast<int *>(arg1);
      e.flags = static_cast<int>(arg2);
      return e;
    }
    case 294: 
    {
      Event_inotify_init1 e{};
      e.flags = static_cast<int>(arg1);
      return e;
    }
    case 295: 
    {
      Event_preadv e{};
      e.fd = static_cast<unsigned long>(arg1);
      e.vec = reinterpret_cast<const iovec *>(arg2);
      e.vlen = static_cast<unsigned long>(arg3);
      e.pos_l = static_cast<unsigned long>(arg4);
      e.pos_h = static_cast<unsigned long>(arg5);
      return e;
    }
    case 296: 
    {
      Event_pwritev e{};
      e.fd = static_cast<unsigned long>(arg1);
      e.vec = reinterpret_cast<const iovec *>(arg2);
      e.vlen = static_cast<unsigned long>(arg3);
      e.pos_l = static_cast<unsigned long>(arg4);
      e.pos_h = static_cast<unsigned long>(arg5);
      return e;
    }
    case 297: 
    {
      Event_rt_tgsigqueueinfo e{};
      e.tgid = static_cast<pid_t>(arg1);
      e.pid = static_cast<pid_t>(arg2);
      e.sig = static_cast<int>(arg3);
      e.uinfo = reinterpret_cast<siginfo_t *>(arg4);
      return e;
    }
    case 298: 
    {
      Event_perf_event_open e{};
      e.attr_uptr = reinterpret_cast< perf_event_attr *>(arg1);
      e.pid = static_cast<pid_t>(arg2);
      e.cpu = static_cast<int>(arg3);
      e.group_fd = static_cast<int>(arg4);
      e.flags = static_cast<unsigned long>(arg5);
      return e;
    }
  }

} // namespace
