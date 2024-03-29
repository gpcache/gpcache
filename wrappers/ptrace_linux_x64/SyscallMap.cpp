#include "../ptrace.h"

namespace Ptrace {

auto create_syscall_map() -> std::map<SyscallDataType, SyscallInfo> const {
  thread_local static auto map = std::map<SyscallDataType, SyscallInfo>();
  if (map.empty()) {

    map[0] = SyscallInfo{.syscall_id = 0,
                         .name = "read",
                         .params = {{"unsigned int", "fd"},
                                    {"char *", "buf"},
                                    {"size_t", "count"}}};
    map[1] = SyscallInfo{.syscall_id = 1,
                         .name = "write",
                         .params = {{"unsigned int", "fd"},
                                    {"const char *", "buf"},
                                    {"size_t", "count"}}};
    map[2] = SyscallInfo{.syscall_id = 2,
                         .name = "open",
                         .params = {{"const char *", "filename"},
                                    {"int", "flags"},
                                    {"mode_t", "mode"}}};
    map[3] = SyscallInfo{
        .syscall_id = 3, .name = "close", .params = {{"unsigned int", "fd"}}};
    map[4] = SyscallInfo{
        .syscall_id = 4,
        .name = "stat",
        .params = {{"const char *", "filename"}, {"struct stat *", "statbuf"}}};
    map[5] = SyscallInfo{
        .syscall_id = 5,
        .name = "fstat",
        .params = {{"unsigned int", "fd"}, {"struct stat *", "statbuf"}}};
    map[6] = SyscallInfo{
        .syscall_id = 6,
        .name = "lstat",
        .params = {{"const char *", "filename"}, {"struct stat *", "statbuf"}}};
    map[7] = SyscallInfo{.syscall_id = 7,
                         .name = "poll",
                         .params = {{"struct pollfd *", "ufds"},
                                    {"unsigned int", "nfds"},
                                    {"int", "timeout"}}};
    map[8] = SyscallInfo{.syscall_id = 8,
                         .name = "lseek",
                         .params = {{"unsigned int", "fd"},
                                    {"off_t", "offset"},
                                    {"unsigned int", "whence"}}};
    map[9] = SyscallInfo{.syscall_id = 9,
                         .name = "mmap",
                         .params = {{"unsigned long", "addr"},
                                    {"unsigned long", "len"},
                                    {"unsigned long", "prot"},
                                    {"unsigned long", "flags"},
                                    {"unsigned long", "fd"},
                                    {"off_t", "pgoff"}}};
    map[10] = SyscallInfo{.syscall_id = 10,
                          .name = "mprotect",
                          .params = {{"unsigned long", "start"},
                                     {"size_t", "len"},
                                     {"unsigned long", "prot"}}};
    map[11] =
        SyscallInfo{.syscall_id = 11,
                    .name = "munmap",
                    .params = {{"unsigned long", "addr"}, {"size_t", "len"}}};
    map[12] = SyscallInfo{
        .syscall_id = 12, .name = "brk", .params = {{"unsigned long", "brk"}}};
    map[13] = SyscallInfo{.syscall_id = 13,
                          .name = "rt_sigaction",
                          .params = {{"int", "unnamed0"},
                                     {"const struct sigaction *", "unnamed1"},
                                     {"struct sigaction *", "unnamed2"},
                                     {"size_t", "unnamed3"}}};
    map[14] = SyscallInfo{.syscall_id = 14,
                          .name = "rt_sigprocmask",
                          .params = {{"int", "how"},
                                     {"sigset_t *", "set"},
                                     {"sigset_t *", "oset"},
                                     {"size_t", "sigsetsize"}}};
    map[15] = SyscallInfo{.syscall_id = 15,
                          .name = "rt_sigreturn",
                          .params = {{"struct pt_regs *", "regs"}}};
    map[16] = SyscallInfo{.syscall_id = 16,
                          .name = "ioctl",
                          .params = {{"unsigned int", "fd"},
                                     {"unsigned int", "cmd"},
                                     {"unsigned long", "arg"}}};
    map[17] = SyscallInfo{.syscall_id = 17,
                          .name = "pread64",
                          .params = {{"unsigned int", "fd"},
                                     {"char *", "buf"},
                                     {"size_t", "count"},
                                     {"loff_t", "pos"}}};
    map[18] = SyscallInfo{.syscall_id = 18,
                          .name = "pwrite64",
                          .params = {{"unsigned int", "fd"},
                                     {"const char *", "buf"},
                                     {"size_t", "count"},
                                     {"loff_t", "pos"}}};
    map[19] = SyscallInfo{.syscall_id = 19,
                          .name = "readv",
                          .params = {{"unsigned long", "fd"},
                                     {"const struct iovec *", "vec"},
                                     {"unsigned long", "vlen"}}};
    map[20] = SyscallInfo{.syscall_id = 20,
                          .name = "writev",
                          .params = {{"unsigned long", "fd"},
                                     {"const struct iovec *", "vec"},
                                     {"unsigned long", "vlen"}}};
    map[21] =
        SyscallInfo{.syscall_id = 21,
                    .name = "access",
                    .params = {{"const char *", "filename"}, {"int", "mode"}}};
    map[22] = SyscallInfo{
        .syscall_id = 22, .name = "pipe", .params = {{"int *", "fildes"}}};
    map[23] = SyscallInfo{.syscall_id = 23,
                          .name = "select",
                          .params = {{"int", "n"},
                                     {"fd_set *", "inp"},
                                     {"fd_set *", "outp"},
                                     {"fd_set *", "exp"},
                                     {"struct __kernel_timeval *", "tvp"}}};
    map[24] =
        SyscallInfo{.syscall_id = 24, .name = "sched_yield", .params = {}};
    map[25] = SyscallInfo{.syscall_id = 25,
                          .name = "mremap",
                          .params = {{"unsigned long", "addr"},
                                     {"unsigned long", "old_len"},
                                     {"unsigned long", "new_len"},
                                     {"unsigned long", "flags"},
                                     {"unsigned long", "new_addr"}}};
    map[26] = SyscallInfo{.syscall_id = 26,
                          .name = "msync",
                          .params = {{"unsigned long", "start"},
                                     {"size_t", "len"},
                                     {"int", "flags"}}};
    map[27] = SyscallInfo{.syscall_id = 27,
                          .name = "mincore",
                          .params = {{"unsigned long", "start"},
                                     {"size_t", "len"},
                                     {"unsigned char *", "vec"}}};
    map[28] = SyscallInfo{.syscall_id = 28,
                          .name = "madvise",
                          .params = {{"unsigned long", "start"},
                                     {"size_t", "len"},
                                     {"int", "behavior"}}};
    map[29] = SyscallInfo{
        .syscall_id = 29,
        .name = "shmget",
        .params = {{"key_t", "key"}, {"size_t", "size"}, {"int", "flag"}}};
    map[30] = SyscallInfo{
        .syscall_id = 30,
        .name = "shmat",
        .params = {{"int", "shmid"}, {"char *", "shmaddr"}, {"int", "shmflg"}}};
    map[31] = SyscallInfo{.syscall_id = 31,
                          .name = "shmctl",
                          .params = {{"int", "shmid"},
                                     {"int", "cmd"},
                                     {"struct shmid_ds *", "buf"}}};
    map[32] = SyscallInfo{.syscall_id = 32,
                          .name = "dup",
                          .params = {{"unsigned int", "fildes"}}};
    map[33] = SyscallInfo{
        .syscall_id = 33,
        .name = "dup2",
        .params = {{"unsigned int", "oldfd"}, {"unsigned int", "newfd"}}};
    map[34] = SyscallInfo{.syscall_id = 34, .name = "pause", .params = {}};
    map[35] = SyscallInfo{.syscall_id = 35,
                          .name = "nanosleep",
                          .params = {{"struct __kernel_timespec *", "rqtp"},
                                     {"struct __kernel_timespec *", "rmtp"}}};
    map[36] = SyscallInfo{
        .syscall_id = 36,
        .name = "getitimer",
        .params = {{"int", "which"}, {"struct __kernel_itimerval *", "value"}}};
    map[37] = SyscallInfo{.syscall_id = 37,
                          .name = "alarm",
                          .params = {{"unsigned int", "seconds"}}};
    map[38] =
        SyscallInfo{.syscall_id = 38,
                    .name = "setitimer",
                    .params = {{"int", "which"},
                               {"struct __kernel_itimerval *", "value"},
                               {"struct __kernel_itimerval *", "ovalue"}}};
    map[39] = SyscallInfo{.syscall_id = 39, .name = "getpid", .params = {}};
    map[40] = SyscallInfo{.syscall_id = 40,
                          .name = "sendfile",
                          .params = {{"int", "out_fd"},
                                     {"int", "in_fd"},
                                     {"loff_t *", "offset"},
                                     {"size_t", "count"}}};
    map[41] = SyscallInfo{.syscall_id = 41,
                          .name = "socket",
                          .params = {{"int", "unnamed0"},
                                     {"int", "unnamed1"},
                                     {"int", "unnamed2"}}};
    map[42] = SyscallInfo{.syscall_id = 42,
                          .name = "connect",
                          .params = {{"int", "unnamed0"},
                                     {"struct sockaddr *", "unnamed1"},
                                     {"int", "unnamed2"}}};
    map[43] = SyscallInfo{.syscall_id = 43,
                          .name = "accept",
                          .params = {{"int", "unnamed0"},
                                     {"struct sockaddr *", "unnamed1"},
                                     {"int *", "unnamed2"}}};
    map[44] = SyscallInfo{.syscall_id = 44,
                          .name = "sendto",
                          .params = {{"int", "unnamed0"},
                                     {"void *", "unnamed1"},
                                     {"size_t", "unnamed2"},
                                     {"unsigned", "unnamed3"},
                                     {"struct sockaddr *", "unnamed4"},
                                     {"int", "unnamed5"}}};
    map[45] = SyscallInfo{.syscall_id = 45,
                          .name = "recvfrom",
                          .params = {{"int", "unnamed0"},
                                     {"void *", "unnamed1"},
                                     {"size_t", "unnamed2"},
                                     {"unsigned", "unnamed3"},
                                     {"struct sockaddr *", "unnamed4"},
                                     {"int *", "unnamed5"}}};
    map[46] = SyscallInfo{.syscall_id = 46,
                          .name = "sendmsg",
                          .params = {{"int", "fd"},
                                     {"struct user_msghdr *", "msg"},
                                     {"unsigned", "flags"}}};
    map[47] = SyscallInfo{.syscall_id = 47,
                          .name = "recvmsg",
                          .params = {{"int", "fd"},
                                     {"struct user_msghdr *", "msg"},
                                     {"unsigned", "flags"}}};
    map[48] = SyscallInfo{.syscall_id = 48,
                          .name = "shutdown",
                          .params = {{"int", "unnamed0"}, {"int", "unnamed1"}}};
    map[49] = SyscallInfo{.syscall_id = 49,
                          .name = "bind",
                          .params = {{"int", "unnamed0"},
                                     {"struct sockaddr *", "unnamed1"},
                                     {"int", "unnamed2"}}};
    map[50] = SyscallInfo{.syscall_id = 50,
                          .name = "listen",
                          .params = {{"int", "unnamed0"}, {"int", "unnamed1"}}};
    map[51] = SyscallInfo{.syscall_id = 51,
                          .name = "getsockname",
                          .params = {{"int", "unnamed0"},
                                     {"struct sockaddr *", "unnamed1"},
                                     {"int *", "unnamed2"}}};
    map[52] = SyscallInfo{.syscall_id = 52,
                          .name = "getpeername",
                          .params = {{"int", "unnamed0"},
                                     {"struct sockaddr *", "unnamed1"},
                                     {"int *", "unnamed2"}}};
    map[53] = SyscallInfo{.syscall_id = 53,
                          .name = "socketpair",
                          .params = {{"int", "unnamed0"},
                                     {"int", "unnamed1"},
                                     {"int", "unnamed2"},
                                     {"int *", "unnamed3"}}};
    map[54] = SyscallInfo{.syscall_id = 54,
                          .name = "setsockopt",
                          .params = {{"int", "fd"},
                                     {"int", "level"},
                                     {"int", "optname"},
                                     {"char *", "optval"},
                                     {"int", "optlen"}}};
    map[55] = SyscallInfo{.syscall_id = 55,
                          .name = "getsockopt",
                          .params = {{"int", "fd"},
                                     {"int", "level"},
                                     {"int", "optname"},
                                     {"char *", "optval"},
                                     {"int *", "optlen"}}};
    map[56] = SyscallInfo{.syscall_id = 56,
                          .name = "clone",
                          .params = {{"unsigned long", "unnamed0"},
                                     {"unsigned long", "unnamed1"},
                                     {"int *", "unnamed2"},
                                     {"unsigned long", "unnamed3"},
                                     {"int *", "unnamed4"},
                                     {"unsigned long", "unnamed5"},
                                     {"unsigned long", "unnamed6"},
                                     {"int", "unnamed7"},
                                     {"int *", "unnamed8"},
                                     {"int *", "unnamed9"},
                                     {"unsigned long", "unnamed10"},
                                     {"unsigned long", "unnamed11"},
                                     {"unsigned long", "unnamed12"},
                                     {"int *", "unnamed13"},
                                     {"int *", "unnamed14"},
                                     {"unsigned long", "unnamed15"}}};
    map[57] = SyscallInfo{.syscall_id = 57, .name = "fork", .params = {}};
    map[58] = SyscallInfo{.syscall_id = 58, .name = "vfork", .params = {}};
    map[59] = SyscallInfo{.syscall_id = 59,
                          .name = "execve",
                          .params = {{"const char *", "filename"},
                                     {"const char *const *", "argv"},
                                     {"const char *const *", "envp"}}};
    map[60] = SyscallInfo{
        .syscall_id = 60, .name = "exit", .params = {{"int", "error_code"}}};
    map[61] = SyscallInfo{.syscall_id = 61,
                          .name = "wait4",
                          .params = {{"pid_t", "pid"},
                                     {"int *", "stat_addr"},
                                     {"int", "options"},
                                     {"struct rusage *", "ru"}}};
    map[62] = SyscallInfo{.syscall_id = 62,
                          .name = "kill",
                          .params = {{"pid_t", "pid"}, {"int", "sig"}}};
    map[63] = SyscallInfo{.syscall_id = 63,
                          .name = "uname",
                          .params = {{"struct new_utsname *", "name"}}};
    map[64] = SyscallInfo{
        .syscall_id = 64,
        .name = "semget",
        .params = {{"key_t", "key"}, {"int", "nsems"}, {"int", "semflg"}}};
    map[65] = SyscallInfo{.syscall_id = 65,
                          .name = "semop",
                          .params = {{"int", "semid"},
                                     {"struct sembuf *", "sops"},
                                     {"unsigned", "nsops"}}};
    map[66] = SyscallInfo{.syscall_id = 66,
                          .name = "semctl",
                          .params = {{"int", "semid"},
                                     {"int", "semnum"},
                                     {"int", "cmd"},
                                     {"unsigned long", "arg"}}};
    map[67] = SyscallInfo{
        .syscall_id = 67, .name = "shmdt", .params = {{"char *", "shmaddr"}}};
    map[68] = SyscallInfo{.syscall_id = 68,
                          .name = "msgget",
                          .params = {{"key_t", "key"}, {"int", "msgflg"}}};
    map[69] = SyscallInfo{.syscall_id = 69,
                          .name = "msgsnd",
                          .params = {{"int", "msqid"},
                                     {"struct msgbuf *", "msgp"},
                                     {"size_t", "msgsz"},
                                     {"int", "msgflg"}}};
    map[70] = SyscallInfo{.syscall_id = 70,
                          .name = "msgrcv",
                          .params = {{"int", "msqid"},
                                     {"struct msgbuf *", "msgp"},
                                     {"size_t", "msgsz"},
                                     {"long", "msgtyp"},
                                     {"int", "msgflg"}}};
    map[71] = SyscallInfo{.syscall_id = 71,
                          .name = "msgctl",
                          .params = {{"int", "msqid"},
                                     {"int", "cmd"},
                                     {"struct msqid_ds *", "buf"}}};
    map[72] = SyscallInfo{.syscall_id = 72,
                          .name = "fcntl",
                          .params = {{"unsigned int", "fd"},
                                     {"unsigned int", "cmd"},
                                     {"unsigned long", "arg"}}};
    map[73] = SyscallInfo{
        .syscall_id = 73,
        .name = "flock",
        .params = {{"unsigned int", "fd"}, {"unsigned int", "cmd"}}};
    map[74] = SyscallInfo{
        .syscall_id = 74, .name = "fsync", .params = {{"unsigned int", "fd"}}};
    map[75] = SyscallInfo{.syscall_id = 75,
                          .name = "fdatasync",
                          .params = {{"unsigned int", "fd"}}};
    map[76] =
        SyscallInfo{.syscall_id = 76,
                    .name = "truncate",
                    .params = {{"const char *", "path"}, {"long", "length"}}};
    map[77] = SyscallInfo{
        .syscall_id = 77,
        .name = "ftruncate",
        .params = {{"unsigned int", "fd"}, {"unsigned long", "length"}}};
    map[78] = SyscallInfo{.syscall_id = 78,
                          .name = "getdents",
                          .params = {{"unsigned int", "fd"},
                                     {"struct linux_dirent *", "dirent"},
                                     {"unsigned int", "count"}}};
    map[79] =
        SyscallInfo{.syscall_id = 79,
                    .name = "getcwd",
                    .params = {{"char *", "buf"}, {"unsigned long", "size"}}};
    map[80] = SyscallInfo{.syscall_id = 80,
                          .name = "chdir",
                          .params = {{"const char *", "filename"}}};
    map[81] = SyscallInfo{
        .syscall_id = 81, .name = "fchdir", .params = {{"unsigned int", "fd"}}};
    map[82] = SyscallInfo{
        .syscall_id = 82,
        .name = "rename",
        .params = {{"const char *", "oldname"}, {"const char *", "newname"}}};
    map[83] = SyscallInfo{
        .syscall_id = 83,
        .name = "mkdir",
        .params = {{"const char *", "pathname"}, {"mode_t", "mode"}}};
    map[84] = SyscallInfo{.syscall_id = 84,
                          .name = "rmdir",
                          .params = {{"const char *", "pathname"}}};
    map[85] = SyscallInfo{
        .syscall_id = 85,
        .name = "creat",
        .params = {{"const char *", "pathname"}, {"mode_t", "mode"}}};
    map[86] = SyscallInfo{
        .syscall_id = 86,
        .name = "link",
        .params = {{"const char *", "oldname"}, {"const char *", "newname"}}};
    map[87] = SyscallInfo{.syscall_id = 87,
                          .name = "unlink",
                          .params = {{"const char *", "pathname"}}};
    map[88] = SyscallInfo{
        .syscall_id = 88,
        .name = "symlink",
        .params = {{"const char *", "old"}, {"const char *", "new__"}}};
    map[89] = SyscallInfo{.syscall_id = 89,
                          .name = "readlink",
                          .params = {{"const char *", "path"},
                                     {"char *", "buf"},
                                     {"int", "bufsiz"}}};
    map[90] = SyscallInfo{
        .syscall_id = 90,
        .name = "chmod",
        .params = {{"const char *", "filename"}, {"mode_t", "mode"}}};
    map[91] =
        SyscallInfo{.syscall_id = 91,
                    .name = "fchmod",
                    .params = {{"unsigned int", "fd"}, {"mode_t", "mode"}}};
    map[92] = SyscallInfo{.syscall_id = 92,
                          .name = "chown",
                          .params = {{"const char *", "filename"},
                                     {"uid_t", "user"},
                                     {"gid_t", "group"}}};
    map[93] = SyscallInfo{.syscall_id = 93,
                          .name = "fchown",
                          .params = {{"unsigned int", "fd"},
                                     {"uid_t", "user"},
                                     {"gid_t", "group"}}};
    map[94] = SyscallInfo{.syscall_id = 94,
                          .name = "lchown",
                          .params = {{"const char *", "filename"},
                                     {"uid_t", "user"},
                                     {"gid_t", "group"}}};
    map[95] = SyscallInfo{
        .syscall_id = 95, .name = "umask", .params = {{"int", "mask"}}};
    map[96] = SyscallInfo{.syscall_id = 96,
                          .name = "gettimeofday",
                          .params = {{"struct __kernel_timeval *", "tv"},
                                     {"struct timezone *", "tz"}}};
    map[97] = SyscallInfo{
        .syscall_id = 97,
        .name = "getrlimit",
        .params = {{"unsigned int", "resource"}, {"struct rlimit *", "rlim"}}};
    map[98] =
        SyscallInfo{.syscall_id = 98,
                    .name = "getrusage",
                    .params = {{"int", "who"}, {"struct rusage *", "ru"}}};
    map[99] = SyscallInfo{.syscall_id = 99,
                          .name = "sysinfo",
                          .params = {{"struct sysinfo *", "info"}}};
    map[100] = SyscallInfo{.syscall_id = 100,
                           .name = "times",
                           .params = {{"struct tms *", "tbuf"}}};
    map[101] = SyscallInfo{.syscall_id = 101,
                           .name = "ptrace",
                           .params = {{"long", "request"},
                                      {"long", "pid"},
                                      {"unsigned long", "addr"},
                                      {"unsigned long", "data"}}};
    map[102] = SyscallInfo{.syscall_id = 102, .name = "getuid", .params = {}};
    map[103] = SyscallInfo{
        .syscall_id = 103,
        .name = "syslog",
        .params = {{"int", "type"}, {"char *", "buf"}, {"int", "len"}}};
    map[104] = SyscallInfo{.syscall_id = 104, .name = "getgid", .params = {}};
    map[105] = SyscallInfo{
        .syscall_id = 105, .name = "setuid", .params = {{"uid_t", "uid"}}};
    map[106] = SyscallInfo{
        .syscall_id = 106, .name = "setgid", .params = {{"gid_t", "gid"}}};
    map[107] = SyscallInfo{.syscall_id = 107, .name = "geteuid", .params = {}};
    map[108] = SyscallInfo{.syscall_id = 108, .name = "getegid", .params = {}};
    map[109] = SyscallInfo{.syscall_id = 109,
                           .name = "setpgid",
                           .params = {{"pid_t", "pid"}, {"pid_t", "pgid"}}};
    map[110] = SyscallInfo{.syscall_id = 110, .name = "getppid", .params = {}};
    map[111] = SyscallInfo{.syscall_id = 111, .name = "getpgrp", .params = {}};
    map[112] = SyscallInfo{.syscall_id = 112, .name = "setsid", .params = {}};
    map[113] = SyscallInfo{.syscall_id = 113,
                           .name = "setreuid",
                           .params = {{"uid_t", "ruid"}, {"uid_t", "euid"}}};
    map[114] = SyscallInfo{.syscall_id = 114,
                           .name = "setregid",
                           .params = {{"gid_t", "rgid"}, {"gid_t", "egid"}}};
    map[115] = SyscallInfo{
        .syscall_id = 115,
        .name = "getgroups",
        .params = {{"int", "gidsetsize"}, {"gid_t *", "grouplist"}}};
    map[116] = SyscallInfo{
        .syscall_id = 116,
        .name = "setgroups",
        .params = {{"int", "gidsetsize"}, {"gid_t *", "grouplist"}}};
    map[117] = SyscallInfo{
        .syscall_id = 117,
        .name = "setresuid",
        .params = {{"uid_t", "ruid"}, {"uid_t", "euid"}, {"uid_t", "suid"}}};
    map[118] = SyscallInfo{.syscall_id = 118,
                           .name = "getresuid",
                           .params = {{"uid_t *", "ruid"},
                                      {"uid_t *", "euid"},
                                      {"uid_t *", "suid"}}};
    map[119] = SyscallInfo{
        .syscall_id = 119,
        .name = "setresgid",
        .params = {{"gid_t", "rgid"}, {"gid_t", "egid"}, {"gid_t", "sgid"}}};
    map[120] = SyscallInfo{.syscall_id = 120,
                           .name = "getresgid",
                           .params = {{"gid_t *", "rgid"},
                                      {"gid_t *", "egid"},
                                      {"gid_t *", "sgid"}}};
    map[121] = SyscallInfo{
        .syscall_id = 121, .name = "getpgid", .params = {{"pid_t", "pid"}}};
    map[122] = SyscallInfo{
        .syscall_id = 122, .name = "setfsuid", .params = {{"uid_t", "uid"}}};
    map[123] = SyscallInfo{
        .syscall_id = 123, .name = "setfsgid", .params = {{"gid_t", "gid"}}};
    map[124] = SyscallInfo{
        .syscall_id = 124, .name = "getsid", .params = {{"pid_t", "pid"}}};
    map[125] = SyscallInfo{.syscall_id = 125,
                           .name = "capget",
                           .params = {{"cap_user_header_t", "header"},
                                      {"cap_user_data_t", "dataptr"}}};
    map[126] = SyscallInfo{.syscall_id = 126,
                           .name = "capset",
                           .params = {{"cap_user_header_t", "header"},
                                      {"const cap_user_data_t", "data"}}};
    map[127] = SyscallInfo{
        .syscall_id = 127,
        .name = "rt_sigpending",
        .params = {{"sigset_t *", "set"}, {"size_t", "sigsetsize"}}};
    map[128] =
        SyscallInfo{.syscall_id = 128,
                    .name = "rt_sigtimedwait",
                    .params = {{"const sigset_t *", "uthese"},
                               {"siginfo_t *", "uinfo"},
                               {"const struct __kernel_timespec *", "uts"},
                               {"size_t", "sigsetsize"}}};
    map[129] = SyscallInfo{
        .syscall_id = 129,
        .name = "rt_sigqueueinfo",
        .params = {{"pid_t", "pid"}, {"int", "sig"}, {"siginfo_t *", "uinfo"}}};
    map[130] = SyscallInfo{
        .syscall_id = 130,
        .name = "rt_sigsuspend",
        .params = {{"sigset_t *", "unewset"}, {"size_t", "sigsetsize"}}};
    map[131] = SyscallInfo{.syscall_id = 131,
                           .name = "sigaltstack",
                           .params = {{"const struct sigaltstack *", "uss"},
                                      {"struct sigaltstack *", "uoss"}}};
    map[132] = SyscallInfo{
        .syscall_id = 132,
        .name = "utime",
        .params = {{"char *", "filename"}, {"struct utimbuf *", "times"}}};
    map[133] = SyscallInfo{.syscall_id = 133,
                           .name = "mknod",
                           .params = {{"const char *", "filename"},
                                      {"mode_t", "mode"},
                                      {"unsigned", "dev"}}};
    map[134] = SyscallInfo{.syscall_id = 134, .name = "uselib", .params = {}};
    map[135] = SyscallInfo{.syscall_id = 135,
                           .name = "personality",
                           .params = {{"unsigned int", "personality"}}};
    map[136] = SyscallInfo{
        .syscall_id = 136,
        .name = "ustat",
        .params = {{"unsigned", "dev"}, {"struct ustat *", "ubuf"}}};
    map[137] = SyscallInfo{
        .syscall_id = 137,
        .name = "statfs",
        .params = {{"const char *", "path"}, {"struct statfs *", "buf"}}};
    map[138] = SyscallInfo{
        .syscall_id = 138,
        .name = "fstatfs",
        .params = {{"unsigned int", "fd"}, {"struct statfs *", "buf"}}};
    map[139] = SyscallInfo{.syscall_id = 139,
                           .name = "sysfs",
                           .params = {{"int", "option"},
                                      {"unsigned long", "arg1"},
                                      {"unsigned long", "arg2"}}};
    map[140] = SyscallInfo{.syscall_id = 140,
                           .name = "getpriority",
                           .params = {{"int", "which"}, {"int", "who"}}};
    map[141] = SyscallInfo{
        .syscall_id = 141,
        .name = "setpriority",
        .params = {{"int", "which"}, {"int", "who"}, {"int", "niceval"}}};
    map[142] = SyscallInfo{
        .syscall_id = 142,
        .name = "sched_setparam",
        .params = {{"pid_t", "pid"}, {"struct sched_param *", "param"}}};
    map[143] = SyscallInfo{
        .syscall_id = 143,
        .name = "sched_getparam",
        .params = {{"pid_t", "pid"}, {"struct sched_param *", "param"}}};
    map[144] = SyscallInfo{.syscall_id = 144,
                           .name = "sched_setscheduler",
                           .params = {{"pid_t", "pid"},
                                      {"int", "policy"},
                                      {"struct sched_param *", "param"}}};
    map[145] = SyscallInfo{.syscall_id = 145,
                           .name = "sched_getscheduler",
                           .params = {{"pid_t", "pid"}}};
    map[146] = SyscallInfo{.syscall_id = 146,
                           .name = "sched_get_priority_max",
                           .params = {{"int", "policy"}}};
    map[147] = SyscallInfo{.syscall_id = 147,
                           .name = "sched_get_priority_min",
                           .params = {{"int", "policy"}}};
    map[148] =
        SyscallInfo{.syscall_id = 148,
                    .name = "sched_rr_get_interval",
                    .params = {{"pid_t", "pid"},
                               {"struct __kernel_timespec *", "interval"}}};
    map[149] =
        SyscallInfo{.syscall_id = 149,
                    .name = "mlock",
                    .params = {{"unsigned long", "start"}, {"size_t", "len"}}};
    map[150] =
        SyscallInfo{.syscall_id = 150,
                    .name = "munlock",
                    .params = {{"unsigned long", "start"}, {"size_t", "len"}}};
    map[151] = SyscallInfo{
        .syscall_id = 151, .name = "mlockall", .params = {{"int", "flags"}}};
    map[152] =
        SyscallInfo{.syscall_id = 152, .name = "munlockall", .params = {}};
    map[153] = SyscallInfo{.syscall_id = 153, .name = "vhangup", .params = {}};
    map[154] =
        SyscallInfo{.syscall_id = 154, .name = "modify_ldt", .params = {}};
    map[155] = SyscallInfo{
        .syscall_id = 155,
        .name = "pivot_root",
        .params = {{"const char *", "new_root"}, {"const char *", "put_old"}}};
    map[156] = SyscallInfo{.syscall_id = 156, .name = "_sysctl", .params = {}};
    map[157] = SyscallInfo{.syscall_id = 157,
                           .name = "prctl",
                           .params = {{"int", "option"},
                                      {"unsigned long", "arg2"},
                                      {"unsigned long", "arg3"},
                                      {"unsigned long", "arg4"},
                                      {"unsigned long", "arg5"}}};
    map[158] =
        SyscallInfo{.syscall_id = 158, .name = "arch_prctl", .params = {}};
    map[159] = SyscallInfo{.syscall_id = 159,
                           .name = "adjtimex",
                           .params = {{"struct __kernel_timex *", "txc_p"}}};
    map[160] = SyscallInfo{
        .syscall_id = 160,
        .name = "setrlimit",
        .params = {{"unsigned int", "resource"}, {"struct rlimit *", "rlim"}}};
    map[161] = SyscallInfo{.syscall_id = 161,
                           .name = "chroot",
                           .params = {{"const char *", "filename"}}};
    map[162] = SyscallInfo{.syscall_id = 162, .name = "sync", .params = {}};
    map[163] = SyscallInfo{.syscall_id = 163,
                           .name = "acct",
                           .params = {{"const char *", "name"}}};
    map[164] = SyscallInfo{.syscall_id = 164,
                           .name = "settimeofday",
                           .params = {{"struct __kernel_timeval *", "tv"},
                                      {"struct timezone *", "tz"}}};
    map[165] = SyscallInfo{.syscall_id = 165,
                           .name = "mount",
                           .params = {{"char *", "dev_name"},
                                      {"char *", "dir_name"},
                                      {"char *", "type"},
                                      {"unsigned long", "flags"},
                                      {"void *", "data"}}};
    map[166] = SyscallInfo{.syscall_id = 166,
                           .name = "umount2",
                           .params = {{"char *", "name"}, {"int", "flags"}}};
    map[167] = SyscallInfo{
        .syscall_id = 167,
        .name = "swapon",
        .params = {{"const char *", "specialfile"}, {"int", "swap_flags"}}};
    map[168] = SyscallInfo{.syscall_id = 168,
                           .name = "swapoff",
                           .params = {{"const char *", "specialfile"}}};
    map[169] = SyscallInfo{.syscall_id = 169,
                           .name = "reboot",
                           .params = {{"int", "magic1"},
                                      {"int", "magic2"},
                                      {"unsigned int", "cmd"},
                                      {"void *", "arg"}}};
    map[170] = SyscallInfo{.syscall_id = 170,
                           .name = "sethostname",
                           .params = {{"char *", "name"}, {"int", "len"}}};
    map[171] = SyscallInfo{.syscall_id = 171,
                           .name = "setdomainname",
                           .params = {{"char *", "name"}, {"int", "len"}}};
    map[172] = SyscallInfo{.syscall_id = 172, .name = "iopl", .params = {}};
    map[173] = SyscallInfo{.syscall_id = 173,
                           .name = "ioperm",
                           .params = {{"unsigned long", "from"},
                                      {"unsigned long", "num"},
                                      {"int", "on"}}};
    map[174] =
        SyscallInfo{.syscall_id = 174, .name = "create_module", .params = {}};
    map[175] = SyscallInfo{.syscall_id = 175,
                           .name = "init_module",
                           .params = {{"void *", "umod"},
                                      {"unsigned long", "len"},
                                      {"const char *", "uargs"}}};
    map[176] = SyscallInfo{
        .syscall_id = 176,
        .name = "delete_module",
        .params = {{"const char *", "name_user"}, {"unsigned int", "flags"}}};
    map[177] =
        SyscallInfo{.syscall_id = 177, .name = "get_kernel_syms", .params = {}};
    map[178] =
        SyscallInfo{.syscall_id = 178, .name = "query_module", .params = {}};
    map[179] = SyscallInfo{.syscall_id = 179,
                           .name = "quotactl",
                           .params = {{"unsigned int", "cmd"},
                                      {"const char *", "special"},
                                      {"int", "id"},
                                      {"void *", "addr"}}};
    map[180] =
        SyscallInfo{.syscall_id = 180, .name = "nfsservctl", .params = {}};
    map[181] = SyscallInfo{.syscall_id = 181, .name = "getpmsg", .params = {}};
    map[182] = SyscallInfo{.syscall_id = 182, .name = "putpmsg", .params = {}};
    map[183] =
        SyscallInfo{.syscall_id = 183, .name = "afs_syscall", .params = {}};
    map[184] = SyscallInfo{.syscall_id = 184, .name = "tuxcall", .params = {}};
    map[185] = SyscallInfo{.syscall_id = 185, .name = "security", .params = {}};
    map[186] = SyscallInfo{.syscall_id = 186, .name = "gettid", .params = {}};
    map[187] = SyscallInfo{
        .syscall_id = 187,
        .name = "readahead",
        .params = {{"int", "fd"}, {"loff_t", "offset"}, {"size_t", "count"}}};
    map[188] = SyscallInfo{.syscall_id = 188,
                           .name = "setxattr",
                           .params = {{"const char *", "path"},
                                      {"const char *", "name"},
                                      {"const void *", "value"},
                                      {"size_t", "size"},
                                      {"int", "flags"}}};
    map[189] = SyscallInfo{.syscall_id = 189,
                           .name = "lsetxattr",
                           .params = {{"const char *", "path"},
                                      {"const char *", "name"},
                                      {"const void *", "value"},
                                      {"size_t", "size"},
                                      {"int", "flags"}}};
    map[190] = SyscallInfo{.syscall_id = 190,
                           .name = "fsetxattr",
                           .params = {{"int", "fd"},
                                      {"const char *", "name"},
                                      {"const void *", "value"},
                                      {"size_t", "size"},
                                      {"int", "flags"}}};
    map[191] = SyscallInfo{.syscall_id = 191,
                           .name = "getxattr",
                           .params = {{"const char *", "path"},
                                      {"const char *", "name"},
                                      {"void *", "value"},
                                      {"size_t", "size"}}};
    map[192] = SyscallInfo{.syscall_id = 192,
                           .name = "lgetxattr",
                           .params = {{"const char *", "path"},
                                      {"const char *", "name"},
                                      {"void *", "value"},
                                      {"size_t", "size"}}};
    map[193] = SyscallInfo{.syscall_id = 193,
                           .name = "fgetxattr",
                           .params = {{"int", "fd"},
                                      {"const char *", "name"},
                                      {"void *", "value"},
                                      {"size_t", "size"}}};
    map[194] = SyscallInfo{.syscall_id = 194,
                           .name = "listxattr",
                           .params = {{"const char *", "path"},
                                      {"char *", "list"},
                                      {"size_t", "size"}}};
    map[195] = SyscallInfo{.syscall_id = 195,
                           .name = "llistxattr",
                           .params = {{"const char *", "path"},
                                      {"char *", "list"},
                                      {"size_t", "size"}}};
    map[196] = SyscallInfo{
        .syscall_id = 196,
        .name = "flistxattr",
        .params = {{"int", "fd"}, {"char *", "list"}, {"size_t", "size"}}};
    map[197] = SyscallInfo{
        .syscall_id = 197,
        .name = "removexattr",
        .params = {{"const char *", "path"}, {"const char *", "name"}}};
    map[198] = SyscallInfo{
        .syscall_id = 198,
        .name = "lremovexattr",
        .params = {{"const char *", "path"}, {"const char *", "name"}}};
    map[199] = SyscallInfo{.syscall_id = 199,
                           .name = "fremovexattr",
                           .params = {{"int", "fd"}, {"const char *", "name"}}};
    map[200] = SyscallInfo{.syscall_id = 200,
                           .name = "tkill",
                           .params = {{"pid_t", "pid"}, {"int", "sig"}}};
    map[201] = SyscallInfo{.syscall_id = 201,
                           .name = "time",
                           .params = {{"__kernel_time_t *", "tloc"}}};
    map[202] =
        SyscallInfo{.syscall_id = 202,
                    .name = "futex",
                    .params = {{"uint32_t *", "uaddr"},
                               {"int", "op"},
                               {"uint32_t", "val"},
                               {"const struct __kernel_timespec *", "utime"},
                               {"uint32_t *", "uaddr2"},
                               {"uint32_t", "val3"}}};
    map[203] = SyscallInfo{.syscall_id = 203,
                           .name = "sched_setaffinity",
                           .params = {{"pid_t", "pid"},
                                      {"unsigned int", "len"},
                                      {"unsigned long *", "user_mask_ptr"}}};
    map[204] = SyscallInfo{.syscall_id = 204,
                           .name = "sched_getaffinity",
                           .params = {{"pid_t", "pid"},
                                      {"unsigned int", "len"},
                                      {"unsigned long *", "user_mask_ptr"}}};
    map[205] =
        SyscallInfo{.syscall_id = 205, .name = "set_thread_area", .params = {}};
    map[206] = SyscallInfo{
        .syscall_id = 206,
        .name = "io_setup",
        .params = {{"unsigned", "nr_reqs"}, {"aio_context_t *", "ctx"}}};
    map[207] = SyscallInfo{.syscall_id = 207,
                           .name = "io_destroy",
                           .params = {{"aio_context_t", "ctx"}}};
    map[208] =
        SyscallInfo{.syscall_id = 208,
                    .name = "io_getevents",
                    .params = {{"aio_context_t", "ctx_id"},
                               {"long", "min_nr"},
                               {"long", "nr"},
                               {"struct io_event *", "events"},
                               {"struct __kernel_timespec *", "timeout"}}};
    map[209] = SyscallInfo{.syscall_id = 209,
                           .name = "io_submit",
                           .params = {{"aio_context_t", "unnamed0"},
                                      {"long", "unnamed1"},
                                      {"struct iocb * *", "unnamed2"}}};
    map[210] = SyscallInfo{.syscall_id = 210,
                           .name = "io_cancel",
                           .params = {{"aio_context_t", "ctx_id"},
                                      {"struct iocb *", "iocb"},
                                      {"struct io_event *", "result"}}};
    map[211] =
        SyscallInfo{.syscall_id = 211, .name = "get_thread_area", .params = {}};
    map[212] = SyscallInfo{.syscall_id = 212,
                           .name = "lookup_dcookie",
                           .params = {{"uint64_t", "cookie64"},
                                      {"char *", "buf"},
                                      {"size_t", "len"}}};
    map[213] = SyscallInfo{
        .syscall_id = 213, .name = "epoll_create", .params = {{"int", "size"}}};
    map[214] =
        SyscallInfo{.syscall_id = 214, .name = "epoll_ctl_old", .params = {}};
    map[215] =
        SyscallInfo{.syscall_id = 215, .name = "epoll_wait_old", .params = {}};
    map[216] = SyscallInfo{.syscall_id = 216,
                           .name = "remap_file_pages",
                           .params = {{"unsigned long", "start"},
                                      {"unsigned long", "size"},
                                      {"unsigned long", "prot"},
                                      {"unsigned long", "pgoff"},
                                      {"unsigned long", "flags"}}};
    map[217] = SyscallInfo{.syscall_id = 217,
                           .name = "getdents64",
                           .params = {{"unsigned int", "fd"},
                                      {"struct linux_dirent64 *", "dirent"},
                                      {"unsigned int", "count"}}};
    map[218] = SyscallInfo{.syscall_id = 218,
                           .name = "set_tid_address",
                           .params = {{"int *", "tidptr"}}};
    map[219] =
        SyscallInfo{.syscall_id = 219, .name = "restart_syscall", .params = {}};
    map[220] = SyscallInfo{
        .syscall_id = 220,
        .name = "semtimedop",
        .params = {{"int", "semid"},
                   {"struct sembuf *", "sops"},
                   {"unsigned", "nsops"},
                   {"const struct __kernel_timespec *", "timeout"}}};
    map[221] = SyscallInfo{.syscall_id = 221,
                           .name = "fadvise64",
                           .params = {{"int", "fd"},
                                      {"loff_t", "offset"},
                                      {"size_t", "len"},
                                      {"int", "advice"}}};
    map[222] = SyscallInfo{.syscall_id = 222,
                           .name = "timer_create",
                           .params = {{"clockid_t", "which_clock"},
                                      {"struct sigevent *", "timer_event_spec"},
                                      {"timer_t *", "created_timer_id"}}};
    map[223] = SyscallInfo{
        .syscall_id = 223,
        .name = "timer_settime",
        .params = {{"timer_t", "timer_id"},
                   {"int", "flags"},
                   {"const struct __kernel_itimerspec *", "new_setting"},
                   {"struct __kernel_itimerspec *", "old_setting"}}};
    map[224] =
        SyscallInfo{.syscall_id = 224,
                    .name = "timer_gettime",
                    .params = {{"timer_t", "timer_id"},
                               {"struct __kernel_itimerspec *", "setting"}}};
    map[225] = SyscallInfo{.syscall_id = 225,
                           .name = "timer_getoverrun",
                           .params = {{"timer_t", "timer_id"}}};
    map[226] = SyscallInfo{.syscall_id = 226,
                           .name = "timer_delete",
                           .params = {{"timer_t", "timer_id"}}};
    map[227] =
        SyscallInfo{.syscall_id = 227,
                    .name = "clock_settime",
                    .params = {{"clockid_t", "which_clock"},
                               {"const struct __kernel_timespec *", "tp"}}};
    map[228] = SyscallInfo{.syscall_id = 228,
                           .name = "clock_gettime",
                           .params = {{"clockid_t", "which_clock"},
                                      {"struct __kernel_timespec *", "tp"}}};
    map[229] = SyscallInfo{.syscall_id = 229,
                           .name = "clock_getres",
                           .params = {{"clockid_t", "which_clock"},
                                      {"struct __kernel_timespec *", "tp"}}};
    map[230] =
        SyscallInfo{.syscall_id = 230,
                    .name = "clock_nanosleep",
                    .params = {{"clockid_t", "which_clock"},
                               {"int", "flags"},
                               {"const struct __kernel_timespec *", "rqtp"},
                               {"struct __kernel_timespec *", "rmtp"}}};
    map[231] = SyscallInfo{.syscall_id = 231,
                           .name = "exit_group",
                           .params = {{"int", "error_code"}}};
    map[232] = SyscallInfo{.syscall_id = 232,
                           .name = "epoll_wait",
                           .params = {{"int", "epfd"},
                                      {"struct epoll_event *", "events"},
                                      {"int", "maxevents"},
                                      {"int", "timeout"}}};
    map[233] = SyscallInfo{.syscall_id = 233,
                           .name = "epoll_ctl",
                           .params = {{"int", "epfd"},
                                      {"int", "op"},
                                      {"int", "fd"},
                                      {"struct epoll_event *", "event"}}};
    map[234] = SyscallInfo{
        .syscall_id = 234,
        .name = "tgkill",
        .params = {{"pid_t", "tgid"}, {"pid_t", "pid"}, {"int", "sig"}}};
    map[235] = SyscallInfo{.syscall_id = 235,
                           .name = "utimes",
                           .params = {{"char *", "filename"},
                                      {"struct __kernel_timeval *", "utimes"}}};
    map[236] = SyscallInfo{.syscall_id = 236, .name = "vserver", .params = {}};
    map[237] = SyscallInfo{.syscall_id = 237,
                           .name = "mbind",
                           .params = {{"unsigned long", "start"},
                                      {"unsigned long", "len"},
                                      {"unsigned long", "mode"},
                                      {"const unsigned long *", "nmask"},
                                      {"unsigned long", "maxnode"},
                                      {"unsigned", "flags"}}};
    map[238] = SyscallInfo{.syscall_id = 238,
                           .name = "set_mempolicy",
                           .params = {{"int", "mode"},
                                      {"const unsigned long *", "nmask"},
                                      {"unsigned long", "maxnode"}}};
    map[239] = SyscallInfo{.syscall_id = 239,
                           .name = "get_mempolicy",
                           .params = {{"int *", "policy"},
                                      {"unsigned long *", "nmask"},
                                      {"unsigned long", "maxnode"},
                                      {"unsigned long", "addr"},
                                      {"unsigned long", "flags"}}};
    map[240] = SyscallInfo{.syscall_id = 240,
                           .name = "mq_open",
                           .params = {{"const char *", "name"},
                                      {"int", "oflag"},
                                      {"mode_t", "mode"},
                                      {"struct mq_attr *", "attr"}}};
    map[241] = SyscallInfo{.syscall_id = 241,
                           .name = "mq_unlink",
                           .params = {{"const char *", "name"}}};
    map[242] = SyscallInfo{
        .syscall_id = 242,
        .name = "mq_timedsend",
        .params = {{"mqd_t", "mqdes"},
                   {"const char *", "msg_ptr"},
                   {"size_t", "msg_len"},
                   {"unsigned int", "msg_prio"},
                   {"const struct __kernel_timespec *", "abs_timeout"}}};
    map[243] = SyscallInfo{
        .syscall_id = 243,
        .name = "mq_timedreceive",
        .params = {{"mqd_t", "mqdes"},
                   {"char *", "msg_ptr"},
                   {"size_t", "msg_len"},
                   {"unsigned int *", "msg_prio"},
                   {"const struct __kernel_timespec *", "abs_timeout"}}};
    map[244] =
        SyscallInfo{.syscall_id = 244,
                    .name = "mq_notify",
                    .params = {{"mqd_t", "mqdes"},
                               {"const struct sigevent *", "notification"}}};
    map[245] = SyscallInfo{.syscall_id = 245,
                           .name = "mq_getsetattr",
                           .params = {{"mqd_t", "mqdes"},
                                      {"const struct mq_attr *", "mqstat"},
                                      {"struct mq_attr *", "omqstat"}}};
    map[246] = SyscallInfo{.syscall_id = 246,
                           .name = "kexec_load",
                           .params = {{"unsigned long", "entry"},
                                      {"unsigned long", "nr_segments"},
                                      {"struct kexec_segment *", "segments"},
                                      {"unsigned long", "flags"}}};
    map[247] = SyscallInfo{.syscall_id = 247,
                           .name = "waitid",
                           .params = {{"int", "which"},
                                      {"pid_t", "pid"},
                                      {"struct siginfo *", "infop"},
                                      {"int", "options"},
                                      {"struct rusage *", "ru"}}};
    map[248] = SyscallInfo{.syscall_id = 248,
                           .name = "add_key",
                           .params = {{"const char *", "_type"},
                                      {"const char *", "_description"},
                                      {"const void *", "_payload"},
                                      {"size_t", "plen"},
                                      {"key_serial_t", "destringid"}}};
    map[249] = SyscallInfo{.syscall_id = 249,
                           .name = "request_key",
                           .params = {{"const char *", "_type"},
                                      {"const char *", "_description"},
                                      {"const char *", "_callout_info"},
                                      {"key_serial_t", "destringid"}}};
    map[250] = SyscallInfo{.syscall_id = 250,
                           .name = "keyctl",
                           .params = {{"int", "cmd"},
                                      {"unsigned long", "arg2"},
                                      {"unsigned long", "arg3"},
                                      {"unsigned long", "arg4"},
                                      {"unsigned long", "arg5"}}};
    map[251] = SyscallInfo{
        .syscall_id = 251,
        .name = "ioprio_set",
        .params = {{"int", "which"}, {"int", "who"}, {"int", "ioprio"}}};
    map[252] = SyscallInfo{.syscall_id = 252,
                           .name = "ioprio_get",
                           .params = {{"int", "which"}, {"int", "who"}}};
    map[253] =
        SyscallInfo{.syscall_id = 253, .name = "inotify_init", .params = {}};
    map[254] = SyscallInfo{.syscall_id = 254,
                           .name = "inotify_add_watch",
                           .params = {{"int", "fd"},
                                      {"const char *", "path"},
                                      {"uint32_t", "mask"}}};
    map[255] = SyscallInfo{.syscall_id = 255,
                           .name = "inotify_rm_watch",
                           .params = {{"int", "fd"}, {"__s32", "wd"}}};
    map[256] = SyscallInfo{.syscall_id = 256,
                           .name = "migrate_pages",
                           .params = {{"pid_t", "pid"},
                                      {"unsigned long", "maxnode"},
                                      {"const unsigned long *", "from"},
                                      {"const unsigned long *", "to"}}};
    map[257] = SyscallInfo{.syscall_id = 257,
                           .name = "openat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"int", "flags"},
                                      {"mode_t", "mode"}}};
    map[258] = SyscallInfo{.syscall_id = 258,
                           .name = "mkdirat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "pathname"},
                                      {"mode_t", "mode"}}};
    map[259] = SyscallInfo{.syscall_id = 259,
                           .name = "mknodat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"mode_t", "mode"},
                                      {"unsigned", "dev"}}};
    map[260] = SyscallInfo{.syscall_id = 260,
                           .name = "fchownat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"uid_t", "user"},
                                      {"gid_t", "group"},
                                      {"int", "flag"}}};
    map[261] = SyscallInfo{.syscall_id = 261,
                           .name = "futimesat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"struct __kernel_timeval *", "utimes"}}};
    map[262] = SyscallInfo{.syscall_id = 262,
                           .name = "newfstatat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"struct stat *", "statbuf"},
                                      {"int", "flag"}}};
    map[263] = SyscallInfo{.syscall_id = 263,
                           .name = "unlinkat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "pathname"},
                                      {"int", "flag"}}};
    map[264] = SyscallInfo{.syscall_id = 264,
                           .name = "renameat",
                           .params = {{"int", "olddfd"},
                                      {"const char *", "oldname"},
                                      {"int", "newdfd"},
                                      {"const char *", "newname"}}};
    map[265] = SyscallInfo{.syscall_id = 265,
                           .name = "linkat",
                           .params = {{"int", "olddfd"},
                                      {"const char *", "oldname"},
                                      {"int", "newdfd"},
                                      {"const char *", "newname"},
                                      {"int", "flags"}}};
    map[266] = SyscallInfo{.syscall_id = 266,
                           .name = "symlinkat",
                           .params = {{"const char *", "oldname"},
                                      {"int", "newdfd"},
                                      {"const char *", "newname"}}};
    map[267] = SyscallInfo{.syscall_id = 267,
                           .name = "readlinkat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "path"},
                                      {"char *", "buf"},
                                      {"int", "bufsiz"}}};
    map[268] = SyscallInfo{.syscall_id = 268,
                           .name = "fchmodat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"mode_t", "mode"}}};
    map[269] = SyscallInfo{.syscall_id = 269,
                           .name = "faccessat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"int", "mode"}}};
    map[270] =
        SyscallInfo{.syscall_id = 270,
                    .name = "pselect6",
                    .params = {{"int", "unnamed0"},
                               {"fd_set *", "unnamed1"},
                               {"fd_set *", "unnamed2"},
                               {"fd_set *", "unnamed3"},
                               {"struct __kernel_timespec *", "unnamed4"},
                               {"void *", "unnamed5"}}};
    map[271] =
        SyscallInfo{.syscall_id = 271,
                    .name = "ppoll",
                    .params = {{"struct pollfd *", "unnamed0"},
                               {"unsigned int", "unnamed1"},
                               {"struct __kernel_timespec *", "unnamed2"},
                               {"const sigset_t *", "unnamed3"},
                               {"size_t", "unnamed4"}}};
    map[272] = SyscallInfo{.syscall_id = 272,
                           .name = "unshare",
                           .params = {{"unsigned long", "unshare_flags"}}};
    map[273] = SyscallInfo{
        .syscall_id = 273,
        .name = "set_robust_list",
        .params = {{"struct robust_list_head *", "head"}, {"size_t", "len"}}};
    map[274] =
        SyscallInfo{.syscall_id = 274,
                    .name = "get_robust_list",
                    .params = {{"int", "pid"},
                               {"struct robust_list_head * *", "head_ptr"},
                               {"size_t *", "len_ptr"}}};
    map[275] = SyscallInfo{.syscall_id = 275,
                           .name = "splice",
                           .params = {{"int", "fd_in"},
                                      {"loff_t *", "off_in"},
                                      {"int", "fd_out"},
                                      {"loff_t *", "off_out"},
                                      {"size_t", "len"},
                                      {"unsigned int", "flags"}}};
    map[276] = SyscallInfo{.syscall_id = 276,
                           .name = "tee",
                           .params = {{"int", "fdin"},
                                      {"int", "fdout"},
                                      {"size_t", "len"},
                                      {"unsigned int", "flags"}}};
    map[277] = SyscallInfo{.syscall_id = 277,
                           .name = "sync_file_range",
                           .params = {{"int", "fd"},
                                      {"loff_t", "offset"},
                                      {"loff_t", "nbytes"},
                                      {"unsigned int", "flags"}}};
    map[278] = SyscallInfo{.syscall_id = 278,
                           .name = "vmsplice",
                           .params = {{"int", "fd"},
                                      {"const struct iovec *", "iov"},
                                      {"unsigned long", "nr_segs"},
                                      {"unsigned int", "flags"}}};
    map[279] = SyscallInfo{.syscall_id = 279,
                           .name = "move_pages",
                           .params = {{"pid_t", "pid"},
                                      {"unsigned long", "nr_pages"},
                                      {"const void * *", "pages"},
                                      {"const int *", "nodes"},
                                      {"int *", "status"},
                                      {"int", "flags"}}};
    map[280] = SyscallInfo{.syscall_id = 280,
                           .name = "utimensat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"struct __kernel_timespec *", "utimes"},
                                      {"int", "flags"}}};
    map[281] = SyscallInfo{.syscall_id = 281,
                           .name = "epoll_pwait",
                           .params = {{"int", "epfd"},
                                      {"struct epoll_event *", "events"},
                                      {"int", "maxevents"},
                                      {"int", "timeout"},
                                      {"const sigset_t *", "SignMask"},
                                      {"size_t", "sigsetsize"}}};
    map[282] = SyscallInfo{.syscall_id = 282,
                           .name = "signalfd",
                           .params = {{"int", "ufd"},
                                      {"sigset_t *", "user_mask"},
                                      {"size_t", "sizemask"}}};
    map[283] = SyscallInfo{.syscall_id = 283,
                           .name = "timerfd_create",
                           .params = {{"int", "clockid"}, {"int", "flags"}}};
    map[284] = SyscallInfo{.syscall_id = 284,
                           .name = "eventfd",
                           .params = {{"unsigned int", "count"}}};
    map[285] = SyscallInfo{.syscall_id = 285,
                           .name = "fallocate",
                           .params = {{"int", "fd"},
                                      {"int", "mode"},
                                      {"loff_t", "offset"},
                                      {"loff_t", "len"}}};
    map[286] =
        SyscallInfo{.syscall_id = 286,
                    .name = "timerfd_settime",
                    .params = {{"int", "ufd"},
                               {"int", "flags"},
                               {"const struct __kernel_itimerspec *", "utmr"},
                               {"struct __kernel_itimerspec *", "otmr"}}};
    map[287] = SyscallInfo{
        .syscall_id = 287,
        .name = "timerfd_gettime",
        .params = {{"int", "ufd"}, {"struct __kernel_itimerspec *", "otmr"}}};
    map[288] = SyscallInfo{.syscall_id = 288,
                           .name = "accept4",
                           .params = {{"int", "unnamed0"},
                                      {"struct sockaddr *", "unnamed1"},
                                      {"int *", "unnamed2"},
                                      {"int", "unnamed3"}}};
    map[289] = SyscallInfo{.syscall_id = 289,
                           .name = "signalfd4",
                           .params = {{"int", "ufd"},
                                      {"sigset_t *", "user_mask"},
                                      {"size_t", "sizemask"},
                                      {"int", "flags"}}};
    map[290] =
        SyscallInfo{.syscall_id = 290,
                    .name = "eventfd2",
                    .params = {{"unsigned int", "count"}, {"int", "flags"}}};
    map[291] = SyscallInfo{.syscall_id = 291,
                           .name = "epoll_create1",
                           .params = {{"int", "flags"}}};
    map[292] = SyscallInfo{.syscall_id = 292,
                           .name = "dup3",
                           .params = {{"unsigned int", "oldfd"},
                                      {"unsigned int", "newfd"},
                                      {"int", "flags"}}};
    map[293] = SyscallInfo{.syscall_id = 293,
                           .name = "pipe2",
                           .params = {{"int *", "fildes"}, {"int", "flags"}}};
    map[294] = SyscallInfo{.syscall_id = 294,
                           .name = "inotify_init1",
                           .params = {{"int", "flags"}}};
    map[295] = SyscallInfo{.syscall_id = 295,
                           .name = "preadv",
                           .params = {{"unsigned long", "fd"},
                                      {"const struct iovec *", "vec"},
                                      {"unsigned long", "vlen"},
                                      {"unsigned long", "pos_l"},
                                      {"unsigned long", "pos_h"}}};
    map[296] = SyscallInfo{.syscall_id = 296,
                           .name = "pwritev",
                           .params = {{"unsigned long", "fd"},
                                      {"const struct iovec *", "vec"},
                                      {"unsigned long", "vlen"},
                                      {"unsigned long", "pos_l"},
                                      {"unsigned long", "pos_h"}}};
    map[297] = SyscallInfo{.syscall_id = 297,
                           .name = "rt_tgsigqueueinfo",
                           .params = {{"pid_t", "tgid"},
                                      {"pid_t", "pid"},
                                      {"int", "sig"},
                                      {"siginfo_t *", "uinfo"}}};
    map[298] = SyscallInfo{.syscall_id = 298,
                           .name = "perf_event_open",
                           .params = {{"struct perf_event_attr *", "attr_uptr"},
                                      {"pid_t", "pid"},
                                      {"int", "cpu"},
                                      {"int", "group_fd"},
                                      {"unsigned long", "flags"}}};
    map[299] =
        SyscallInfo{.syscall_id = 299,
                    .name = "recvmmsg",
                    .params = {{"int", "fd"},
                               {"struct mmsghdr *", "msg"},
                               {"unsigned int", "vlen"},
                               {"unsigned", "flags"},
                               {"struct __kernel_timespec *", "timeout"}}};
    map[300] = SyscallInfo{.syscall_id = 300,
                           .name = "fanotify_init",
                           .params = {{"unsigned int", "flags"},
                                      {"unsigned int", "event_f_flags"}}};
    map[301] = SyscallInfo{.syscall_id = 301,
                           .name = "fanotify_mark",
                           .params = {{"int", "fanotify_fd"},
                                      {"unsigned int", "flags"},
                                      {"uint64_t", "mask"},
                                      {"int", "fd"},
                                      {"const char  *", "pathname"}}};
    map[302] = SyscallInfo{.syscall_id = 302,
                           .name = "prlimit64",
                           .params = {{"pid_t", "pid"},
                                      {"unsigned int", "resource"},
                                      {"const struct rlimit64 *", "new_rlim"},
                                      {"struct rlimit64 *", "old_rlim"}}};
    map[303] = SyscallInfo{.syscall_id = 303,
                           .name = "name_to_handle_at",
                           .params = {{"int", "dfd"},
                                      {"const char *", "name"},
                                      {"struct file_handle *", "handle"},
                                      {"int *", "mnt_id"},
                                      {"int", "flag"}}};
    map[304] = SyscallInfo{.syscall_id = 304,
                           .name = "open_by_handle_at",
                           .params = {{"int", "mountdirfd"},
                                      {"struct file_handle *", "handle"},
                                      {"int", "flags"}}};
    map[305] = SyscallInfo{.syscall_id = 305,
                           .name = "clock_adjtime",
                           .params = {{"clockid_t", "which_clock"},
                                      {"struct __kernel_timex *", "tx"}}};
    map[306] = SyscallInfo{
        .syscall_id = 306, .name = "syncfs", .params = {{"int", "fd"}}};
    map[307] = SyscallInfo{.syscall_id = 307,
                           .name = "sendmmsg",
                           .params = {{"int", "fd"},
                                      {"struct mmsghdr *", "msg"},
                                      {"unsigned int", "vlen"},
                                      {"unsigned", "flags"}}};
    map[308] = SyscallInfo{.syscall_id = 308,
                           .name = "setns",
                           .params = {{"int", "fd"}, {"int", "nstype"}}};
    map[309] = SyscallInfo{.syscall_id = 309,
                           .name = "getcpu",
                           .params = {{"unsigned *", "cpu"},
                                      {"unsigned *", "node"},
                                      {"struct getcpu_cache *", "cache"}}};
    map[310] = SyscallInfo{.syscall_id = 310,
                           .name = "process_vm_readv",
                           .params = {{"pid_t", "pid"},
                                      {"const struct iovec *", "lvec"},
                                      {"unsigned long", "liovcnt"},
                                      {"const struct iovec *", "rvec"},
                                      {"unsigned long", "riovcnt"},
                                      {"unsigned long", "flags"}}};
    map[311] = SyscallInfo{.syscall_id = 311,
                           .name = "process_vm_writev",
                           .params = {{"pid_t", "pid"},
                                      {"const struct iovec *", "lvec"},
                                      {"unsigned long", "liovcnt"},
                                      {"const struct iovec *", "rvec"},
                                      {"unsigned long", "riovcnt"},
                                      {"unsigned long", "flags"}}};
    map[312] = SyscallInfo{.syscall_id = 312,
                           .name = "kcmp",
                           .params = {{"pid_t", "pid1"},
                                      {"pid_t", "pid2"},
                                      {"int", "type"},
                                      {"unsigned long", "idx1"},
                                      {"unsigned long", "idx2"}}};
    map[313] = SyscallInfo{
        .syscall_id = 313,
        .name = "finit_module",
        .params = {{"int", "fd"}, {"const char *", "uargs"}, {"int", "flags"}}};
    map[314] = SyscallInfo{.syscall_id = 314,
                           .name = "sched_setattr",
                           .params = {{"pid_t", "pid"},
                                      {"struct sched_attr *", "attr"},
                                      {"unsigned int", "flags"}}};
    map[315] = SyscallInfo{.syscall_id = 315,
                           .name = "sched_getattr",
                           .params = {{"pid_t", "pid"},
                                      {"struct sched_attr *", "attr"},
                                      {"unsigned int", "size"},
                                      {"unsigned int", "flags"}}};
    map[316] = SyscallInfo{.syscall_id = 316,
                           .name = "renameat2",
                           .params = {{"int", "olddfd"},
                                      {"const char *", "oldname"},
                                      {"int", "newdfd"},
                                      {"const char *", "newname"},
                                      {"unsigned int", "flags"}}};
    map[317] = SyscallInfo{.syscall_id = 317,
                           .name = "seccomp",
                           .params = {{"unsigned int", "op"},
                                      {"unsigned int", "flags"},
                                      {"void *", "uargs"}}};
    map[318] = SyscallInfo{.syscall_id = 318,
                           .name = "getrandom",
                           .params = {{"char *", "buf"},
                                      {"size_t", "count"},
                                      {"unsigned int", "flags"}}};
    map[319] = SyscallInfo{
        .syscall_id = 319,
        .name = "memfd_create",
        .params = {{"const char *", "uname_ptr"}, {"unsigned int", "flags"}}};
    map[320] = SyscallInfo{.syscall_id = 320,
                           .name = "kexec_file_load",
                           .params = {{"int", "kernel_fd"},
                                      {"int", "initrd_fd"},
                                      {"unsigned long", "cmdline_len"},
                                      {"const char *", "cmdline_ptr"},
                                      {"unsigned long", "flags"}}};
    map[321] = SyscallInfo{.syscall_id = 321,
                           .name = "bpf",
                           .params = {{"int", "cmd"},
                                      {"union bpf_attr *", "attr"},
                                      {"unsigned int", "size"}}};
    map[322] = SyscallInfo{.syscall_id = 322,
                           .name = "execveat",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"const char *const *", "argv"},
                                      {"const char *const *", "envp"},
                                      {"int", "flags"}}};
    map[323] = SyscallInfo{
        .syscall_id = 323, .name = "userfaultfd", .params = {{"int", "flags"}}};
    map[324] = SyscallInfo{.syscall_id = 324,
                           .name = "membarrier",
                           .params = {{"int", "cmd"},
                                      {"unsigned int", "flags"},
                                      {"int", "cpu_id"}}};
    map[325] = SyscallInfo{.syscall_id = 325,
                           .name = "mlock2",
                           .params = {{"unsigned long", "start"},
                                      {"size_t", "len"},
                                      {"int", "flags"}}};
    map[326] = SyscallInfo{.syscall_id = 326,
                           .name = "copy_file_range",
                           .params = {{"int", "fd_in"},
                                      {"loff_t *", "off_in"},
                                      {"int", "fd_out"},
                                      {"loff_t *", "off_out"},
                                      {"size_t", "len"},
                                      {"unsigned int", "flags"}}};
    map[327] = SyscallInfo{.syscall_id = 327,
                           .name = "preadv2",
                           .params = {{"unsigned long", "fd"},
                                      {"const struct iovec *", "vec"},
                                      {"unsigned long", "vlen"},
                                      {"unsigned long", "pos_l"},
                                      {"unsigned long", "pos_h"},
                                      {"int", "flags"}}};
    map[328] = SyscallInfo{.syscall_id = 328,
                           .name = "pwritev2",
                           .params = {{"unsigned long", "fd"},
                                      {"const struct iovec *", "vec"},
                                      {"unsigned long", "vlen"},
                                      {"unsigned long", "pos_l"},
                                      {"unsigned long", "pos_h"},
                                      {"int", "flags"}}};
    map[329] = SyscallInfo{.syscall_id = 329,
                           .name = "pkey_mprotect",
                           .params = {{"unsigned long", "start"},
                                      {"size_t", "len"},
                                      {"unsigned long", "prot"},
                                      {"int", "pkey"}}};
    map[330] = SyscallInfo{
        .syscall_id = 330,
        .name = "pkey_alloc",
        .params = {{"unsigned long", "flags"}, {"unsigned long", "init_val"}}};
    map[331] = SyscallInfo{
        .syscall_id = 331, .name = "pkey_free", .params = {{"int", "pkey"}}};
    map[332] = SyscallInfo{.syscall_id = 332,
                           .name = "statx",
                           .params = {{"int", "dfd"},
                                      {"const char *", "path"},
                                      {"unsigned", "flags"},
                                      {"unsigned", "mask"},
                                      {"struct statx *", "buffer"}}};
    map[333] = SyscallInfo{.syscall_id = 333,
                           .name = "io_pgetevents",
                           .params = {{"aio_context_t", "ctx_id"},
                                      {"long", "min_nr"},
                                      {"long", "nr"},
                                      {"struct io_event *", "events"},
                                      {"struct __kernel_timespec *", "timeout"},
                                      {"const struct __aio_sigset *", "sig"}}};
    map[334] = SyscallInfo{.syscall_id = 334,
                           .name = "rseq",
                           .params = {{"struct rseq *", "rseq"},
                                      {"uint32_t", "rseq_len"},
                                      {"int", "flags"},
                                      {"uint32_t", "sig"}}};
    map[424] = SyscallInfo{.syscall_id = 424,
                           .name = "pidfd_send_signal",
                           .params = {{"int", "pidfd"},
                                      {"int", "sig"},
                                      {"siginfo_t *", "info"},
                                      {"unsigned int", "flags"}}};
    map[425] = SyscallInfo{
        .syscall_id = 425,
        .name = "io_uring_setup",
        .params = {{"uint32_t", "entries"}, {"struct io_uring_params *", "p"}}};
    map[426] = SyscallInfo{.syscall_id = 426,
                           .name = "io_uring_enter",
                           .params = {{"unsigned int", "fd"},
                                      {"uint32_t", "to_submit"},
                                      {"uint32_t", "min_complete"},
                                      {"uint32_t", "flags"},
                                      {"const void *", "argp"},
                                      {"size_t", "argsz"}}};
    map[427] = SyscallInfo{.syscall_id = 427,
                           .name = "io_uring_register",
                           .params = {{"unsigned int", "fd"},
                                      {"unsigned int", "op"},
                                      {"void *", "arg"},
                                      {"unsigned int", "nr_args"}}};
    map[428] = SyscallInfo{.syscall_id = 428,
                           .name = "open_tree",
                           .params = {{"int", "dfd"},
                                      {"const char *", "path"},
                                      {"unsigned", "flags"}}};
    map[429] = SyscallInfo{.syscall_id = 429,
                           .name = "move_mount",
                           .params = {{"int", "from_dfd"},
                                      {"const char *", "from_path"},
                                      {"int", "to_dfd"},
                                      {"const char *", "to_path"},
                                      {"unsigned int", "ms_flags"}}};
    map[430] = SyscallInfo{
        .syscall_id = 430,
        .name = "fsopen",
        .params = {{"const char *", "fs_name"}, {"unsigned int", "flags"}}};
    map[431] = SyscallInfo{.syscall_id = 431,
                           .name = "fsconfig",
                           .params = {{"int", "fs_fd"},
                                      {"unsigned int", "cmd"},
                                      {"const char *", "key"},
                                      {"const void *", "value"},
                                      {"int", "aux"}}};
    map[432] = SyscallInfo{.syscall_id = 432,
                           .name = "fsmount",
                           .params = {{"int", "fs_fd"},
                                      {"unsigned int", "flags"},
                                      {"unsigned int", "ms_flags"}}};
    map[433] = SyscallInfo{.syscall_id = 433,
                           .name = "fspick",
                           .params = {{"int", "dfd"},
                                      {"const char *", "path"},
                                      {"unsigned int", "flags"}}};
    map[434] =
        SyscallInfo{.syscall_id = 434,
                    .name = "pidfd_open",
                    .params = {{"pid_t", "pid"}, {"unsigned int", "flags"}}};
    map[435] = SyscallInfo{
        .syscall_id = 435,
        .name = "clone3",
        .params = {{"struct clone_args *", "uargs"}, {"size_t", "size"}}};
    map[436] = SyscallInfo{.syscall_id = 436,
                           .name = "close_range",
                           .params = {{"unsigned int", "fd"},
                                      {"unsigned int", "max_fd"},
                                      {"unsigned int", "flags"}}};
    map[437] = SyscallInfo{.syscall_id = 437,
                           .name = "openat2",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"struct open_how *", "how"},
                                      {"size_t", "size"}}};
    map[438] = SyscallInfo{
        .syscall_id = 438,
        .name = "pidfd_getfd",
        .params = {{"int", "pidfd"}, {"int", "fd"}, {"unsigned int", "flags"}}};
    map[439] = SyscallInfo{.syscall_id = 439,
                           .name = "faccessat2",
                           .params = {{"int", "dfd"},
                                      {"const char *", "filename"},
                                      {"int", "mode"},
                                      {"int", "flags"}}};
    map[440] = SyscallInfo{.syscall_id = 440,
                           .name = "process_madvise",
                           .params = {{"int", "pidfd"},
                                      {"const struct iovec *", "vec"},
                                      {"size_t", "vlen"},
                                      {"int", "behavior"},
                                      {"unsigned int", "flags"}}};
    map[441] =
        SyscallInfo{.syscall_id = 441,
                    .name = "epoll_pwait2",
                    .params = {{"int", "epfd"},
                               {"struct epoll_event *", "events"},
                               {"int", "maxevents"},
                               {"const struct __kernel_timespec *", "timeout"},
                               {"const sigset_t *", "SignMask"},
                               {"size_t", "sigsetsize"}}};
    map[442] = SyscallInfo{.syscall_id = 442,
                           .name = "mount_setattr",
                           .params = {{"int", "dfd"},
                                      {"const char *", "path"},
                                      {"unsigned int", "flags"},
                                      {"struct mount_attr *", "uattr"},
                                      {"size_t", "usize"}}};
    map[444] =
        SyscallInfo{.syscall_id = 444,
                    .name = "landlock_create_ruleset",
                    .params = {{"const struct landlock_ruleset_attr *", "attr"},
                               {"size_t", "size"},
                               {"__uint32_t", "flags"}}};
    map[445] = SyscallInfo{.syscall_id = 445,
                           .name = "landlock_add_rule",
                           .params = {{"int", "ruleset_fd"},
                                      {"enum landlock_rule_type", "rule_type"},
                                      {"const void *", "rule_attr"},
                                      {"__uint32_t", "flags"}}};
    map[446] =
        SyscallInfo{.syscall_id = 446,
                    .name = "landlock_restrict_self",
                    .params = {{"int", "ruleset_fd"}, {"__uint32_t", "flags"}}};
  } // map.empty
  return map;
} // create_syscall_map

} // namespace Ptrace
