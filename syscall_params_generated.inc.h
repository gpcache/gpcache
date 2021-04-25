syscall_params[0] = { "io_setup", {{"unsigned", "nr_reqs"}, {"aio_context_t __user *", "ctx"}}};
syscall_params[1] = { "io_destroy", {{"aio_context_t", "ctx"}}};
syscall_params[2] = { "io_submit", {{"", "aio_context_t"}, {"long", ""}, {"struct iocb __user * __user *", ""}}};
syscall_params[3] = { "io_cancel", {{"aio_context_t", "ctx_id"}, {"struct iocb __user *", "iocb"}, {"struct io_event __user *", "result"}}};
syscall_params[5] = { "setxattr", {{"const char __user *", "path"}, {"const char __user *", "name"}, {"const void __user *", "value"}, {"size_t", "size"}, {"int", "flags"}}};
syscall_params[6] = { "lsetxattr", {{"const char __user *", "path"}, {"const char __user *", "name"}, {"const void __user *", "value"}, {"size_t", "size"}, {"int", "flags"}}};
syscall_params[7] = { "fsetxattr", {{"int", "fd"}, {"const char __user *", "name"}, {"const void __user *", "value"}, {"size_t", "size"}, {"int", "flags"}}};
syscall_params[8] = { "getxattr", {{"const char __user *", "path"}, {"const char __user *", "name"}, {"void __user *", "value"}, {"size_t", "size"}}};
syscall_params[9] = { "lgetxattr", {{"const char __user *", "path"}, {"const char __user *", "name"}, {"void __user *", "value"}, {"size_t", "size"}}};
syscall_params[10] = { "fgetxattr", {{"int", "fd"}, {"const char __user *", "name"}, {"void __user *", "value"}, {"size_t", "size"}}};
syscall_params[11] = { "listxattr", {{"const char __user *", "path"}, {"char __user *", "list"}, {"size_t", "size"}}};
syscall_params[12] = { "llistxattr", {{"const char __user *", "path"}, {"char __user *", "list"}, {"size_t", "size"}}};
syscall_params[13] = { "flistxattr", {{"int", "fd"}, {"char __user *", "list"}, {"size_t", "size"}}};
syscall_params[14] = { "removexattr", {{"const char __user *", "path"}, {"const char __user *", "name"}}};
syscall_params[15] = { "lremovexattr", {{"const char __user *", "path"}, {"const char __user *", "name"}}};
syscall_params[16] = { "fremovexattr", {{"int", "fd"}, {"const char __user *", "name"}}};
syscall_params[17] = { "getcwd", {{"char __user *", "buf"}, {"unsigned long", "size"}}};
syscall_params[18] = { "lookup_dcookie", {{"u64", "cookie64"}, {"char __user *", "buf"}, {"size_t", "len"}}};
syscall_params[19] = { "eventfd2", {{"unsigned int", "count"}, {"int", "flags"}}};
syscall_params[20] = { "epoll_create1", {{"int", "flags"}}};
syscall_params[21] = { "epoll_ctl", {{"int", "epfd"}, {"int", "op"}, {"int", "fd"}, {"struct epoll_event __user *", "event"}}};
syscall_params[22] = { "epoll_pwait", {{"int", "epfd"}, {"struct epoll_event __user *", "events"}, {"int", "maxevents"}, {"int", "timeout"}, {"const sigset_t __user *", "sigmask"}, {"size_t", "sigsetsize"}}};
syscall_params[23] = { "dup", {{"unsigned int", "fildes"}}};
syscall_params[24] = { "dup3", {{"unsigned int", "oldfd"}, {"unsigned int", "newfd"}, {"int", "flags"}}};
syscall_params[26] = { "inotify_init1", {{"int", "flags"}}};
syscall_params[27] = { "inotify_add_watch", {{"int", "fd"}, {"const char __user *", "path"}, {"u32", "mask"}}};
syscall_params[28] = { "inotify_rm_watch", {{"int", "fd"}, {"__s32", "wd"}}};
syscall_params[29] = { "ioctl", {{"unsigned int", "fd"}, {"unsigned int", "cmd"}, {"unsigned long", "arg"}}};
syscall_params[30] = { "ioprio_set", {{"int", "which"}, {"int", "who"}, {"int", "ioprio"}}};
syscall_params[31] = { "ioprio_get", {{"int", "which"}, {"int", "who"}}};
syscall_params[32] = { "flock", {{"unsigned int", "fd"}, {"unsigned int", "cmd"}}};
syscall_params[33] = { "mknodat", {{"int", "dfd"}, {"const char __user *", "filename"}, {"umode_t", "mode"}, {"unsigned", "dev"}}};
syscall_params[34] = { "mkdirat", {{"int", "dfd"}, {"const char __user *", "pathname"}, {"umode_t", "mode"}}};
syscall_params[35] = { "unlinkat", {{"int", "dfd"}, {"const char __user *", "pathname"}, {"int", "flag"}}};
syscall_params[36] = { "symlinkat", {{"const char __user *", "oldname"}, {"int", "newdfd"}, {"const char __user *", "newname"}}};
syscall_params[37] = { "linkat", {{"int", "olddfd"}, {"const char __user *", "oldname"}, {"int", "newdfd"}, {"const char __user *", "newname"}, {"int", "flags"}}};
syscall_params[38] = { "renameat", {{"int", "olddfd"}, {"const char __user *", "oldname"}, {"int", "newdfd"}, {"const char __user *", "newname"}}};
syscall_params[39] = { "umount", {{"char __user *", "name"}, {"int", "flags"}}};
syscall_params[40] = { "mount", {{"char __user *", "dev_name"}, {"char __user *", "dir_name"}, {"char __user *", "type"}, {"unsigned long", "flags"}, {"void __user *", "data"}}};
syscall_params[41] = { "pivot_root", {{"const char __user *", "new_root"}, {"const char __user *", "put_old"}}};
syscall_params[42] = { "ni_syscall", {}};
syscall_params[47] = { "fallocate", {{"int", "fd"}, {"int", "mode"}, {"loff_t", "offset"}, {"loff_t", "len"}}};
syscall_params[48] = { "faccessat", {{"int", "dfd"}, {"const char __user *", "filename"}, {"int", "mode"}}};
syscall_params[49] = { "chdir", {{"const char __user *", "filename"}}};
syscall_params[50] = { "fchdir", {{"unsigned int", "fd"}}};
syscall_params[51] = { "chroot", {{"const char __user *", "filename"}}};
syscall_params[52] = { "fchmod", {{"unsigned int", "fd"}, {"umode_t", "mode"}}};
syscall_params[53] = { "fchmodat", {{"int", "dfd"}, {"const char __user *", "filename"}, {"umode_t", "mode"}}};
syscall_params[54] = { "fchownat", {{"int", "dfd"}, {"const char __user *", "filename"}, {"uid_t", "user"}, {"gid_t", "group"}, {"int", "flag"}}};
syscall_params[55] = { "fchown", {{"unsigned int", "fd"}, {"uid_t", "user"}, {"gid_t", "group"}}};
syscall_params[56] = { "openat", {{"int", "dfd"}, {"const char __user *", "filename"}, {"int", "flags"}, {"umode_t", "mode"}}};
syscall_params[57] = { "close", {{"unsigned int", "fd"}}};
syscall_params[58] = { "vhangup", {}};
syscall_params[59] = { "pipe2", {{"int __user *", "fildes"}, {"int", "flags"}}};
syscall_params[60] = { "quotactl", {{"unsigned int", "cmd"}, {"const char __user *", "special"}, {"qid_t", "id"}, {"void __user *", "addr"}}};
syscall_params[61] = { "getdents64", {{"unsigned int", "fd"}, {"struct linux_dirent64 __user *", "dirent"}, {"unsigned int", "count"}}};
syscall_params[63] = { "read", {{"unsigned int", "fd"}, {"char __user *", "buf"}, {"size_t", "count"}}};
syscall_params[64] = { "write", {{"unsigned int", "fd"}, {"const char __user *", "buf"}, {"size_t", "count"}}};
syscall_params[65] = { "readv", {{"unsigned long", "fd"}, {"const struct iovec __user *", "vec"}, {"unsigned long", "vlen"}}};
syscall_params[66] = { "writev", {{"unsigned long", "fd"}, {"const struct iovec __user *", "vec"}, {"unsigned long", "vlen"}}};
syscall_params[67] = { "pread64", {{"unsigned int", "fd"}, {"char __user *", "buf"}, {"size_t", "count"}, {"loff_t", "pos"}}};
syscall_params[68] = { "pwrite64", {{"unsigned int", "fd"}, {"const char __user *", "buf"}, {"size_t", "count"}, {"loff_t", "pos"}}};
syscall_params[69] = { "preadv", {{"unsigned long", "fd"}, {"const struct iovec __user *", "vec"}, {"unsigned long", "vlen"}, {"unsigned long", "pos_l"}, {"unsigned long", "pos_h"}}};
syscall_params[70] = { "pwritev", {{"unsigned long", "fd"}, {"const struct iovec __user *", "vec"}, {"unsigned long", "vlen"}, {"unsigned long", "pos_l"}, {"unsigned long", "pos_h"}}};
syscall_params[74] = { "signalfd4", {{"int", "ufd"}, {"sigset_t __user *", "user_mask"}, {"size_t", "sizemask"}, {"int", "flags"}}};
syscall_params[75] = { "vmsplice", {{"int", "fd"}, {"const struct iovec __user *", "iov"}, {"unsigned long", "nr_segs"}, {"unsigned int", "flags"}}};
syscall_params[76] = { "splice", {{"int", "fd_in"}, {"loff_t __user *", "off_in"}, {"int", "fd_out"}, {"loff_t __user *", "off_out"}, {"size_t", "len"}, {"unsigned int", "flags"}}};
syscall_params[77] = { "tee", {{"int", "fdin"}, {"int", "fdout"}, {"size_t", "len"}, {"unsigned int", "flags"}}};
syscall_params[78] = { "readlinkat", {{"int", "dfd"}, {"const char __user *", "path"}, {"char __user *", "buf"}, {"int", "bufsiz"}}};
syscall_params[81] = { "sync", {}};
syscall_params[82] = { "fsync", {{"unsigned int", "fd"}}};
syscall_params[83] = { "fdatasync", {{"unsigned int", "fd"}}};
syscall_params[84] = { "sync_file_range", {{"int", "fd"}, {"loff_t", "offset"}, {"loff_t", "nbytes"}, {"unsigned int", "flags"}}};
syscall_params[85] = { "timerfd_create", {{"int", "clockid"}, {"int", "flags"}}};
syscall_params[89] = { "acct", {{"const char __user *", "name"}}};
syscall_params[90] = { "capget", {{"cap_user_header_t", "header"}, {"cap_user_data_t", "dataptr"}}};
syscall_params[91] = { "capset", {{"cap_user_header_t", "header"}, {"const cap_user_data_t", "data"}}};
syscall_params[92] = { "personality", {{"unsigned int", "personality"}}};
syscall_params[93] = { "exit", {{"int", "error_code"}}};
syscall_params[94] = { "exit_group", {{"int", "error_code"}}};
syscall_params[95] = { "waitid", {{"int", "which"}, {"pid_t", "pid"}, {"struct siginfo __user *", "infop"}, {"int", "options"}, {"struct rusage __user *", "ru"}}};
syscall_params[96] = { "set_tid_address", {{"int __user *", "tidptr"}}};
syscall_params[97] = { "unshare", {{"unsigned long", "unshare_flags"}}};
syscall_params[99] = { "set_robust_list", {{"struct robust_list_head __user *", "head"}, {"size_t", "len"}}};
syscall_params[100] = { "get_robust_list", {{"int", "pid"}, {"struct robust_list_head __user * __user *", "head_ptr"}, {"size_t __user *", "len_ptr"}}};
syscall_params[102] = { "getitimer", {{"int", "which"}, {"struct __kernel_old_itimerval __user *", "value"}}};
syscall_params[103] = { "setitimer", {{"int", "which"}, {"struct __kernel_old_itimerval __user *", "value"}, {"struct __kernel_old_itimerval __user *", "ovalue"}}};
syscall_params[104] = { "kexec_load", {{"unsigned long", "entry"}, {"unsigned long", "nr_segments"}, {"struct kexec_segment __user *", "segments"}, {"unsigned long", "flags"}}};
syscall_params[105] = { "init_module", {{"void __user *", "umod"}, {"unsigned long", "len"}, {"const char __user *", "uargs"}}};
syscall_params[106] = { "delete_module", {{"const char __user *", "name_user"}, {"unsigned int", "flags"}}};
syscall_params[107] = { "timer_create", {{"clockid_t", "which_clock"}, {"struct sigevent __user *", "timer_event_spec"}, {"timer_t __user *", "created_timer_id"}}};
syscall_params[109] = { "timer_getoverrun", {{"timer_t", "timer_id"}}};
syscall_params[111] = { "timer_delete", {{"timer_t", "timer_id"}}};
syscall_params[116] = { "syslog", {{"int", "type"}, {"char __user *", "buf"}, {"int", "len"}}};
syscall_params[117] = { "ptrace", {{"long", "request"}, {"long", "pid"}, {"unsigned long", "addr"}, {"unsigned long", "data"}}};
syscall_params[118] = { "sched_setparam", {{"pid_t", "pid"}, {"struct sched_param __user *", "param"}}};
syscall_params[119] = { "sched_setscheduler", {{"pid_t", "pid"}, {"int", "policy"}, {"struct sched_param __user *", "param"}}};
syscall_params[120] = { "sched_getscheduler", {{"pid_t", "pid"}}};
syscall_params[121] = { "sched_getparam", {{"pid_t", "pid"}, {"struct sched_param __user *", "param"}}};
syscall_params[122] = { "sched_setaffinity", {{"pid_t", "pid"}, {"unsigned int", "len"}, {"unsigned long __user *", "user_mask_ptr"}}};
syscall_params[123] = { "sched_getaffinity", {{"pid_t", "pid"}, {"unsigned int", "len"}, {"unsigned long __user *", "user_mask_ptr"}}};
syscall_params[124] = { "sched_yield", {}};
syscall_params[125] = { "sched_get_priority_max", {{"int", "policy"}}};
syscall_params[126] = { "sched_get_priority_min", {{"int", "policy"}}};
syscall_params[128] = { "restart_syscall", {}};
syscall_params[129] = { "kill", {{"pid_t", "pid"}, {"int", "sig"}}};
syscall_params[130] = { "tkill", {{"pid_t", "pid"}, {"int", "sig"}}};
syscall_params[131] = { "tgkill", {{"pid_t", "tgid"}, {"pid_t", "pid"}, {"int", "sig"}}};
syscall_params[132] = { "sigaltstack", {{"const struct sigaltstack __user *", "uss"}, {"struct sigaltstack __user *", "uoss"}}};
syscall_params[133] = { "rt_sigsuspend", {{"sigset_t __user *", "unewset"}, {"size_t", "sigsetsize"}}};
syscall_params[134] = { "rt_sigaction", {{"int", ""}, {"const struct sigaction __user *", ""}, {"struct sigaction __user *", ""}, {"size_t", ""}}};
syscall_params[135] = { "rt_sigprocmask", {{"int", "how"}, {"sigset_t __user *", "set"}, {"sigset_t __user *", "oset"}, {"size_t", "sigsetsize"}}};
syscall_params[136] = { "rt_sigpending", {{"sigset_t __user *", "set"}, {"size_t", "sigsetsize"}}};
syscall_params[138] = { "rt_sigqueueinfo", {{"pid_t", "pid"}, {"int", "sig"}, {"siginfo_t __user *", "uinfo"}}};
syscall_params[139] = { "rt_sigreturn", {}};
syscall_params[140] = { "setpriority", {{"int", "which"}, {"int", "who"}, {"int", "niceval"}}};
syscall_params[141] = { "getpriority", {{"int", "which"}, {"int", "who"}}};
syscall_params[142] = { "reboot", {{"int", "magic1"}, {"int", "magic2"}, {"unsigned int", "cmd"}, {"void __user *", "arg"}}};
syscall_params[143] = { "setregid", {{"gid_t", "rgid"}, {"gid_t", "egid"}}};
syscall_params[144] = { "setgid", {{"gid_t", "gid"}}};
syscall_params[145] = { "setreuid", {{"uid_t", "ruid"}, {"uid_t", "euid"}}};
syscall_params[146] = { "setuid", {{"uid_t", "uid"}}};
syscall_params[147] = { "setresuid", {{"uid_t", "ruid"}, {"uid_t", "euid"}, {"uid_t", "suid"}}};
syscall_params[148] = { "getresuid", {{"uid_t __user *", "ruid"}, {"uid_t __user *", "euid"}, {"uid_t __user *", "suid"}}};
syscall_params[149] = { "setresgid", {{"gid_t", "rgid"}, {"gid_t", "egid"}, {"gid_t", "sgid"}}};
syscall_params[150] = { "getresgid", {{"gid_t __user *", "rgid"}, {"gid_t __user *", "egid"}, {"gid_t __user *", "sgid"}}};
syscall_params[151] = { "setfsuid", {{"uid_t", "uid"}}};
syscall_params[152] = { "setfsgid", {{"gid_t", "gid"}}};
syscall_params[153] = { "times", {{"struct tms __user *", "tbuf"}}};
syscall_params[154] = { "setpgid", {{"pid_t", "pid"}, {"pid_t", "pgid"}}};
syscall_params[155] = { "getpgid", {{"pid_t", "pid"}}};
syscall_params[156] = { "getsid", {{"pid_t", "pid"}}};
syscall_params[157] = { "setsid", {}};
syscall_params[158] = { "getgroups", {{"int", "gidsetsize"}, {"gid_t __user *", "grouplist"}}};
syscall_params[159] = { "setgroups", {{"int", "gidsetsize"}, {"gid_t __user *", "grouplist"}}};
syscall_params[160] = { "newuname", {{"struct new_utsname __user *", "name"}}};
syscall_params[161] = { "sethostname", {{"char __user *", "name"}, {"int", "len"}}};
syscall_params[162] = { "setdomainname", {{"char __user *", "name"}, {"int", "len"}}};
syscall_params[163] = { "getrlimit", {{"unsigned int", "resource"}, {"struct rlimit __user *", "rlim"}}};
syscall_params[164] = { "setrlimit", {{"unsigned int", "resource"}, {"struct rlimit __user *", "rlim"}}};
syscall_params[165] = { "getrusage", {{"int", "who"}, {"struct rusage __user *", "ru"}}};
syscall_params[166] = { "umask", {{"int", "mask"}}};
syscall_params[167] = { "prctl", {{"int", "option"}, {"unsigned long", "arg2"}, {"unsigned long", "arg3"}, {"unsigned long", "arg4"}, {"unsigned long", "arg5"}}};
syscall_params[168] = { "getcpu", {{"unsigned __user *", "cpu"}, {"unsigned __user *", "node"}, {"struct getcpu_cache __user *", "cache"}}};
syscall_params[169] = { "gettimeofday", {{"struct __kernel_old_timeval __user *", "tv"}, {"struct timezone __user *", "tz"}}};
syscall_params[170] = { "settimeofday", {{"struct __kernel_old_timeval __user *", "tv"}, {"struct timezone __user *", "tz"}}};
syscall_params[172] = { "getpid", {}};
syscall_params[173] = { "getppid", {}};
syscall_params[174] = { "getuid", {}};
syscall_params[175] = { "geteuid", {}};
syscall_params[176] = { "getgid", {}};
syscall_params[177] = { "getegid", {}};
syscall_params[178] = { "gettid", {}};
syscall_params[179] = { "sysinfo", {{"struct sysinfo __user *", "info"}}};
syscall_params[180] = { "mq_open", {{"const char __user *", "name"}, {"int", "oflag"}, {"umode_t", "mode"}, {"struct mq_attr __user *", "attr"}}};
syscall_params[181] = { "mq_unlink", {{"const char __user *", "name"}}};
syscall_params[184] = { "mq_notify", {{"mqd_t", "mqdes"}, {"const struct sigevent __user *", "notification"}}};
syscall_params[185] = { "mq_getsetattr", {{"mqd_t", "mqdes"}, {"const struct mq_attr __user *", "mqstat"}, {"struct mq_attr __user *", "omqstat"}}};
syscall_params[186] = { "msgget", {{"key_t", "key"}, {"int", "msgflg"}}};
syscall_params[187] = { "msgctl", {{"int", "msqid"}, {"int", "cmd"}, {"struct msqid_ds __user *", "buf"}}};
syscall_params[188] = { "msgrcv", {{"int", "msqid"}, {"struct msgbuf __user *", "msgp"}, {"size_t", "msgsz"}, {"long", "msgtyp"}, {"int", "msgflg"}}};
syscall_params[189] = { "msgsnd", {{"int", "msqid"}, {"struct msgbuf __user *", "msgp"}, {"size_t", "msgsz"}, {"int", "msgflg"}}};
syscall_params[190] = { "semget", {{"key_t", "key"}, {"int", "nsems"}, {"int", "semflg"}}};
syscall_params[191] = { "semctl", {{"int", "semid"}, {"int", "semnum"}, {"int", "cmd"}, {"unsigned long", "arg"}}};
syscall_params[193] = { "semop", {{"int", "semid"}, {"struct sembuf __user *", "sops"}, {"unsigned", "nsops"}}};
syscall_params[194] = { "shmget", {{"key_t", "key"}, {"size_t", "size"}, {"int", "flag"}}};
syscall_params[195] = { "shmctl", {{"int", "shmid"}, {"int", "cmd"}, {"struct shmid_ds __user *", "buf"}}};
syscall_params[196] = { "shmat", {{"int", "shmid"}, {"char __user *", "shmaddr"}, {"int", "shmflg"}}};
syscall_params[197] = { "shmdt", {{"char __user *", "shmaddr"}}};
syscall_params[198] = { "socket", {{"int", ""}, {"int", ""}, {"int", ""}}};
syscall_params[199] = { "socketpair", {{"int", ""}, {"int", ""}, {"int", ""}, {"int __user *", ""}}};
syscall_params[200] = { "bind", {{"int", ""}, {"struct sockaddr __user *", ""}, {"int", ""}}};
syscall_params[201] = { "listen", {{"int", ""}, {"int", ""}}};
syscall_params[202] = { "accept", {{"int", ""}, {"struct sockaddr __user *", ""}, {"int __user *", ""}}};
syscall_params[203] = { "connect", {{"int", ""}, {"struct sockaddr __user *", ""}, {"int", ""}}};
syscall_params[204] = { "getsockname", {{"int", ""}, {"struct sockaddr __user *", ""}, {"int __user *", ""}}};
syscall_params[205] = { "getpeername", {{"int", ""}, {"struct sockaddr __user *", ""}, {"int __user *", ""}}};
syscall_params[206] = { "sendto", {{"int", ""}, {"void __user *", ""}, {"size_t", ""}, {"", "unsigned"}, {"struct sockaddr __user *", ""}, {"int", ""}}};
syscall_params[207] = { "recvfrom", {{"int", ""}, {"void __user *", ""}, {"size_t", ""}, {"", "unsigned"}, {"struct sockaddr __user *", ""}, {"int __user *", ""}}};
syscall_params[208] = { "setsockopt", {{"int", "fd"}, {"int", "level"}, {"int", "optname"}, {"char __user *", "optval"}, {"int", "optlen"}}};
syscall_params[209] = { "getsockopt", {{"int", "fd"}, {"int", "level"}, {"int", "optname"}, {"char __user *", "optval"}, {"int __user *", "optlen"}}};
syscall_params[210] = { "shutdown", {{"int", ""}, {"int", ""}}};
syscall_params[211] = { "sendmsg", {{"int", "fd"}, {"struct user_msghdr __user *", "msg"}, {"unsigned", "flags"}}};
syscall_params[212] = { "recvmsg", {{"int", "fd"}, {"struct user_msghdr __user *", "msg"}, {"unsigned", "flags"}}};
syscall_params[213] = { "readahead", {{"int", "fd"}, {"loff_t", "offset"}, {"size_t", "count"}}};
syscall_params[214] = { "brk", {{"unsigned long", "brk"}}};
syscall_params[215] = { "munmap", {{"unsigned long", "addr"}, {"size_t", "len"}}};
syscall_params[216] = { "mremap", {{"unsigned long", "addr"}, {"unsigned long", "old_len"}, {"unsigned long", "new_len"}, {"unsigned long", "flags"}, {"unsigned long", "new_addr"}}};
syscall_params[217] = { "add_key", {{"const char __user *", "_type"}, {"const char __user *", "_description"}, {"const void __user *", "_payload"}, {"size_t", "plen"}, {"key_serial_t", "destringid"}}};
syscall_params[218] = { "request_key", {{"const char __user *", "_type"}, {"const char __user *", "_description"}, {"const char __user *", "_callout_info"}, {"key_serial_t", "destringid"}}};
syscall_params[219] = { "keyctl", {{"int", "cmd"}, {"unsigned long", "arg2"}, {"unsigned long", "arg3"}, {"unsigned long", "arg4"}, {"unsigned long", "arg5"}}};
syscall_params[220] = { "clone", {{"unsigned long", ""}, {"unsigned long", ""}, {"int __user *", ""}, {"int __user *", ""}, {"unsigned long", ""}}};
syscall_params[221] = { "execve", {{"const char __user *", "filename"}, {"const char __user *const __user *", "argv"}, {"const char __user *const __user *", "envp"}}};
syscall_params[224] = { "swapon", {{"const char __user *", "specialfile"}, {"int", "swap_flags"}}};
syscall_params[225] = { "swapoff", {{"const char __user *", "specialfile"}}};
syscall_params[226] = { "mprotect", {{"unsigned long", "start"}, {"size_t", "len"}, {"unsigned long", "prot"}}};
syscall_params[227] = { "msync", {{"unsigned long", "start"}, {"size_t", "len"}, {"int", "flags"}}};
syscall_params[228] = { "mlock", {{"unsigned long", "start"}, {"size_t", "len"}}};
syscall_params[229] = { "munlock", {{"unsigned long", "start"}, {"size_t", "len"}}};
syscall_params[230] = { "mlockall", {{"int", "flags"}}};
syscall_params[231] = { "munlockall", {}};
syscall_params[232] = { "mincore", {{"unsigned long", "start"}, {"size_t", "len"}, {"unsigned char __user *", "vec"}}};
syscall_params[233] = { "madvise", {{"unsigned long", "start"}, {"size_t", "len"}, {"int", "behavior"}}};
syscall_params[234] = { "remap_file_pages", {{"unsigned long", "start"}, {"unsigned long", "size"}, {"unsigned long", "prot"}, {"unsigned long", "pgoff"}, {"unsigned long", "flags"}}};
syscall_params[235] = { "mbind", {{"unsigned long", "start"}, {"unsigned long", "len"}, {"unsigned long", "mode"}, {"const unsigned long __user *", "nmask"}, {"unsigned long", "maxnode"}, {"unsigned", "flags"}}};
syscall_params[236] = { "get_mempolicy", {{"int __user *", "policy"}, {"unsigned long __user *", "nmask"}, {"unsigned long", "maxnode"}, {"unsigned long", "addr"}, {"unsigned long", "flags"}}};
syscall_params[237] = { "set_mempolicy", {{"int", "mode"}, {"const unsigned long __user *", "nmask"}, {"unsigned long", "maxnode"}}};
syscall_params[238] = { "migrate_pages", {{"pid_t", "pid"}, {"unsigned long", "maxnode"}, {"const unsigned long __user *", "from"}, {"const unsigned long __user *", "to"}}};
syscall_params[239] = { "move_pages", {{"pid_t", "pid"}, {"unsigned long", "nr_pages"}, {"const void __user * __user *", "pages"}, {"const int __user *", "nodes"}, {"int __user *", "status"}, {"int", "flags"}}};
syscall_params[240] = { "rt_tgsigqueueinfo", {{"pid_t", "tgid"}, {"pid_t", "pid"}, {"int", "sig"}, {"siginfo_t __user *", "uinfo"}}};
syscall_params[241] = { "perf_event_open", {{"struct perf_event_attr __user *", "attr_uptr"}, {"pid_t", "pid"}, {"int", "cpu"}, {"int", "group_fd"}, {"unsigned long", "flags"}}};
syscall_params[242] = { "accept4", {{"int", ""}, {"struct sockaddr __user *", ""}, {"int __user *", ""}, {"int", ""}}};
syscall_params[260] = { "wait4", {{"pid_t", "pid"}, {"int __user *", "stat_addr"}, {"int", "options"}, {"struct rusage __user *", "ru"}}};
syscall_params[261] = { "prlimit64", {{"pid_t", "pid"}, {"unsigned int", "resource"}, {"const struct rlimit64 __user *", "new_rlim"}, {"struct rlimit64 __user *", "old_rlim"}}};
syscall_params[262] = { "fanotify_init", {{"unsigned int", "flags"}, {"unsigned int", "event_f_flags"}}};
syscall_params[263] = { "fanotify_mark", {{"int", "fanotify_fd"}, {"unsigned int", "flags"}, {"u64", "mask"}, {"int", "fd"}, {"const char  __user *", "pathname"}}};
syscall_params[264] = { "name_to_handle_at", {{"int", "dfd"}, {"const char __user *", "name"}, {"struct file_handle __user *", "handle"}, {"int __user *", "mnt_id"}, {"int", "flag"}}};
syscall_params[265] = { "open_by_handle_at", {{"int", "mountdirfd"}, {"struct file_handle __user *", "handle"}, {"int", "flags"}}};
syscall_params[267] = { "syncfs", {{"int", "fd"}}};
syscall_params[268] = { "setns", {{"int", "fd"}, {"int", "nstype"}}};
syscall_params[269] = { "sendmmsg", {{"int", "fd"}, {"struct mmsghdr __user *", "msg"}, {"unsigned int", "vlen"}, {"unsigned", "flags"}}};
syscall_params[270] = { "process_vm_readv", {{"pid_t", "pid"}, {"const struct iovec __user *", "lvec"}, {"unsigned long", "liovcnt"}, {"const struct iovec __user *", "rvec"}, {"unsigned long", "riovcnt"}, {"unsigned long", "flags"}}};
syscall_params[271] = { "process_vm_writev", {{"pid_t", "pid"}, {"const struct iovec __user *", "lvec"}, {"unsigned long", "liovcnt"}, {"const struct iovec __user *", "rvec"}, {"unsigned long", "riovcnt"}, {"unsigned long", "flags"}}};
syscall_params[272] = { "kcmp", {{"pid_t", "pid1"}, {"pid_t", "pid2"}, {"int", "type"}, {"unsigned long", "idx1"}, {"unsigned long", "idx2"}}};
syscall_params[273] = { "finit_module", {{"int", "fd"}, {"const char __user *", "uargs"}, {"int", "flags"}}};
syscall_params[274] = { "sched_setattr", {{"pid_t", "pid"}, {"struct sched_attr __user *", "attr"}, {"unsigned int", "flags"}}};
syscall_params[275] = { "sched_getattr", {{"pid_t", "pid"}, {"struct sched_attr __user *", "attr"}, {"unsigned int", "size"}, {"unsigned int", "flags"}}};
syscall_params[276] = { "renameat2", {{"int", "olddfd"}, {"const char __user *", "oldname"}, {"int", "newdfd"}, {"const char __user *", "newname"}, {"unsigned int", "flags"}}};
syscall_params[277] = { "seccomp", {{"unsigned int", "op"}, {"unsigned int", "flags"}, {"void __user *", "uargs"}}};
syscall_params[278] = { "getrandom", {{"char __user *", "buf"}, {"size_t", "count"}, {"unsigned int", "flags"}}};
syscall_params[279] = { "memfd_create", {{"const char __user *", "uname_ptr"}, {"unsigned int", "flags"}}};
syscall_params[280] = { "bpf", {{"int", "cmd"}, {"union bpf_attr *", "attr"}, {"unsigned int", "size"}}};
syscall_params[281] = { "execveat", {{"int", "dfd"}, {"const char __user *", "filename"}, {"const char __user *const __user *", "argv"}, {"const char __user *const __user *", "envp"}, {"int", "flags"}}};
syscall_params[282] = { "userfaultfd", {{"int", "flags"}}};
syscall_params[283] = { "membarrier", {{"int", "cmd"}, {"unsigned int", "flags"}, {"int", "cpu_id"}}};
syscall_params[284] = { "mlock2", {{"unsigned long", "start"}, {"size_t", "len"}, {"int", "flags"}}};
syscall_params[285] = { "copy_file_range", {{"int", "fd_in"}, {"loff_t __user *", "off_in"}, {"int", "fd_out"}, {"loff_t __user *", "off_out"}, {"size_t", "len"}, {"unsigned int", "flags"}}};
syscall_params[286] = { "preadv2", {{"unsigned long", "fd"}, {"const struct iovec __user *", "vec"}, {"unsigned long", "vlen"}, {"unsigned long", "pos_l"}, {"unsigned long", "pos_h"}, {"rwf_t", "flags"}}};
syscall_params[287] = { "pwritev2", {{"unsigned long", "fd"}, {"const struct iovec __user *", "vec"}, {"unsigned long", "vlen"}, {"unsigned long", "pos_l"}, {"unsigned long", "pos_h"}, {"rwf_t", "flags"}}};
syscall_params[288] = { "pkey_mprotect", {{"unsigned long", "start"}, {"size_t", "len"}, {"unsigned long", "prot"}, {"int", "pkey"}}};
syscall_params[293] = { "rseq", {{"struct rseq __user *", "rseq"}, {"uint32_t", "rseq_len"}, {"int", "flags"}, {"uint32_t", "sig"}}};
syscall_params[403] = { "clock_gettime", {{"clockid_t", "which_clock"}, {"struct __kernel_timespec __user *", "tp"}}};
syscall_params[404] = { "clock_settime", {{"clockid_t", "which_clock"}, {"const struct __kernel_timespec __user *", "tp"}}};
syscall_params[405] = { "clock_adjtime", {{"clockid_t", "which_clock"}, {"struct __kernel_timex __user *", "tx"}}};
syscall_params[406] = { "clock_getres", {{"clockid_t", "which_clock"}, {"struct __kernel_timespec __user *", "tp"}}};
syscall_params[407] = { "clock_nanosleep", {{"clockid_t", "which_clock"}, {"int", "flags"}, {"const struct __kernel_timespec __user *", "rqtp"}, {"struct __kernel_timespec __user *", "rmtp"}}};
syscall_params[408] = { "timer_gettime", {{"timer_t", "timer_id"}, {"struct __kernel_itimerspec __user *", "setting"}}};
syscall_params[409] = { "timer_settime", {{"timer_t", "timer_id"}, {"int", "flags"}, {"const struct __kernel_itimerspec __user *", "new_setting"}, {"struct __kernel_itimerspec __user *", "old_setting"}}};
syscall_params[410] = { "timerfd_gettime", {{"int", "ufd"}, {"struct __kernel_itimerspec __user *", "otmr"}}};
syscall_params[411] = { "timerfd_settime", {{"int", "ufd"}, {"int", "flags"}, {"const struct __kernel_itimerspec __user *", "utmr"}, {"struct __kernel_itimerspec __user *", "otmr"}}};
syscall_params[412] = { "utimensat", {{"int", "dfd"}, {"const char __user *", "filename"}, {"struct __kernel_timespec __user *", "utimes"}, {"int", "flags"}}};
syscall_params[413] = { "pselect6", {{"int", ""}, {"fd_set __user *", ""}, {"fd_set __user *", ""}, {"fd_set __user *", ""}, {"struct __kernel_timespec __user *", ""}, {"void __user *", ""}}};
syscall_params[414] = { "ppoll", {{"struct pollfd __user *", ""}, {"unsigned int", ""}, {"struct __kernel_timespec __user *", ""}, {"const sigset_t __user *", ""}, {"size_t", ""}}};
syscall_params[416] = { "io_pgetevents", {{"aio_context_t", "ctx_id"}, {"long", "min_nr"}, {"long", "nr"}, {"struct io_event __user *", "events"}, {"struct __kernel_timespec __user *", "timeout"}, {"const struct __aio_sigset *", "sig"}}};
syscall_params[417] = { "recvmmsg", {{"int", "fd"}, {"struct mmsghdr __user *", "msg"}, {"unsigned int", "vlen"}, {"unsigned", "flags"}, {"struct __kernel_timespec __user *", "timeout"}}};
syscall_params[418] = { "mq_timedsend", {{"mqd_t", "mqdes"}, {"const char __user *", "msg_ptr"}, {"size_t", "msg_len"}, {"unsigned int", "msg_prio"}, {"const struct __kernel_timespec __user *", "abs_timeout"}}};
syscall_params[419] = { "mq_timedreceive", {{"mqd_t", "mqdes"}, {"char __user *", "msg_ptr"}, {"size_t", "msg_len"}, {"unsigned int __user *", "msg_prio"}, {"const struct __kernel_timespec __user *", "abs_timeout"}}};
syscall_params[420] = { "semtimedop", {{"int", "semid"}, {"struct sembuf __user *", "sops"}, {"unsigned", "nsops"}, {"const struct __kernel_timespec __user *", "timeout"}}};
syscall_params[421] = { "rt_sigtimedwait", {{"const sigset_t __user *", "uthese"}, {"siginfo_t __user *", "uinfo"}, {"const struct __kernel_timespec __user *", "uts"}, {"size_t", "sigsetsize"}}};
syscall_params[422] = { "futex", {{"u32 __user *", "uaddr"}, {"int", "op"}, {"u32", "val"}, {"const struct __kernel_timespec __user *", "utime"}, {"u32 __user *", "uaddr2"}, {"u32", "val3"}}};
syscall_params[423] = { "sched_rr_get_interval", {{"pid_t", "pid"}, {"struct __kernel_timespec __user *", "interval"}}};
syscall_params[424] = { "pidfd_send_signal", {{"int", "pidfd"}, {"int", "sig"}, {"siginfo_t __user *", "info"}, {"unsigned int", "flags"}}};
syscall_params[425] = { "io_uring_setup", {{"u32", "entries"}, {"struct io_uring_params __user *", "p"}}};
syscall_params[426] = { "io_uring_enter", {{"unsigned int", "fd"}, {"u32", "to_submit"}, {"u32", "min_complete"}, {"u32", "flags"}, {"const void __user *", "argp"}, {"size_t", "argsz"}}};
syscall_params[427] = { "io_uring_register", {{"unsigned int", "fd"}, {"unsigned int", "op"}, {"void __user *", "arg"}, {"unsigned int", "nr_args"}}};
syscall_params[428] = { "open_tree", {{"int", "dfd"}, {"const char __user *", "path"}, {"unsigned", "flags"}}};
syscall_params[429] = { "move_mount", {{"int", "from_dfd"}, {"const char __user *", "from_path"}, {"int", "to_dfd"}, {"const char __user *", "to_path"}, {"unsigned int", "ms_flags"}}};
syscall_params[430] = { "fsopen", {{"const char __user *", "fs_name"}, {"unsigned int", "flags"}}};
syscall_params[431] = { "fsconfig", {{"int", "fs_fd"}, {"unsigned int", "cmd"}, {"const char __user *", "key"}, {"const void __user *", "value"}, {"int", "aux"}}};
syscall_params[432] = { "fsmount", {{"int", "fs_fd"}, {"unsigned int", "flags"}, {"unsigned int", "ms_flags"}}};
syscall_params[433] = { "fspick", {{"int", "dfd"}, {"const char __user *", "path"}, {"unsigned int", "flags"}}};
syscall_params[434] = { "pidfd_open", {{"pid_t", "pid"}, {"unsigned int", "flags"}}};
syscall_params[435] = { "clone3", {{"struct clone_args __user *", "uargs"}, {"size_t", "size"}}};
syscall_params[436] = { "close_range", {{"unsigned int", "fd"}, {"unsigned int", "max_fd"}, {"unsigned int", "flags"}}};
syscall_params[437] = { "openat2", {{"int", "dfd"}, {"const char __user *", "filename"}, {"struct open_how *", "how"}, {"size_t", "size"}}};
syscall_params[438] = { "pidfd_getfd", {{"int", "pidfd"}, {"int", "fd"}, {"unsigned int", "flags"}}};
syscall_params[439] = { "faccessat2", {{"int", "dfd"}, {"const char __user *", "filename"}, {"int", "mode"}, {"int", "flags"}}};
syscall_params[440] = { "process_madvise", {{"int", "pidfd"}, {"const struct iovec __user *", "vec"}, {"size_t", "vlen"}, {"int", "behavior"}, {"unsigned int", "flags"}}};
syscall_params[441] = { "epoll_pwait2", {{"int", "epfd"}, {"struct epoll_event __user *", "events"}, {"int", "maxevents"}, {"const struct __kernel_timespec __user *", "timeout"}, {"const sigset_t __user *", "sigmask"}, {"size_t", "sigsetsize"}}};
syscall_params[442] = { "mount_setattr", {{"int", "dfd"}, {"const char __user *", "path"}, {"unsigned int", "flags"}, {"struct mount_attr __user *", "uattr"}, {"size_t", "usize"}}};
