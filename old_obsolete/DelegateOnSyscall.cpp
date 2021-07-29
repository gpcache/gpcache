#include <OnSyscall.h>
auto createSyscallEvent(OnSyscall &handler, SyscallDataType syscall_id)
    -> SyscallEvent {
  switch (syscall_id) {
  case 0:
    unsigned int fd = {}; // value of 0
    char *buf = {};       // value of 1
    size_t count = {};    // value of 2
    handler.read(fd, buf, count);
    break;
  case 1:
    unsigned int fd = {}; // value of 0
    const char *buf = {}; // value of 1
    size_t count = {};    // value of 2
    handler.write(fd, buf, count);
    break;
  case 2:
    const char *filename = {}; // value of 0
    int flags = {};            // value of 1
    mode_t mode = {};          // value of 2
    handler.open(filename, flags, mode);
    break;
  case 3:
    unsigned int fd = {}; // value of 0
    handler.close(fd);
    break;
  case 4:
    const char *filename = {}; // value of 0
    struct stat *statbuf = {}; // value of 1
    handler.newstat(filename, statbuf);
    break;
  case 5:
    unsigned int fd = {};      // value of 0
    struct stat *statbuf = {}; // value of 1
    handler.newfstat(fd, statbuf);
    break;
  case 6:
    const char *filename = {}; // value of 0
    struct stat *statbuf = {}; // value of 1
    handler.newlstat(filename, statbuf);
    break;
  case 7:
    struct pollfd *ufds = {}; // value of 0
    unsigned int nfds = {};   // value of 1
    int timeout = {};         // value of 2
    handler.poll(ufds, nfds, timeout);
    break;
  case 8:
    unsigned int fd = {};     // value of 0
    off_t offset = {};        // value of 1
    unsigned int whence = {}; // value of 2
    handler.lseek(fd, offset, whence);
    break;
  case 9:
    unsigned long addr = {};  // value of 0
    unsigned long len = {};   // value of 1
    unsigned long prot = {};  // value of 2
    unsigned long flags = {}; // value of 3
    unsigned long fd = {};    // value of 4
    unsigned long pgoff = {}; // value of 5
    handler.mmap(addr, len, prot, flags, fd, pgoff);
    break;
  case 10:
    unsigned long start = {}; // value of 0
    size_t len = {};          // value of 1
    unsigned long prot = {};  // value of 2
    handler.mprotect(start, len, prot);
    break;
  case 11:
    unsigned long addr = {}; // value of 0
    size_t len = {};         // value of 1
    handler.munmap(addr, len);
    break;
  case 12:
    unsigned long brk = {}; // value of 0
    handler.brk(brk);
    break;
  case 13:
    int = {};                      // value of 0
    const struct sigaction * = {}; // value of 1
    struct sigaction * = {};       // value of 2
    size_t = {};                   // value of 3
    handler.rt_sigaction(, , , );
    break;
  case 14:
    int how = {};           // value of 0
    sigset_t *set = {};     // value of 1
    sigset_t *oset = {};    // value of 2
    size_t sigsetsize = {}; // value of 3
    handler.rt_sigprocmask(how, set, oset, sigsetsize);
    break;
  case 16:
    unsigned int fd = {};   // value of 0
    unsigned int cmd = {};  // value of 1
    unsigned long arg = {}; // value of 2
    handler.ioctl(fd, cmd, arg);
    break;
  case 17:
    unsigned int fd = {}; // value of 0
    char *buf = {};       // value of 1
    size_t count = {};    // value of 2
    loff_t pos = {};      // value of 3
    handler.pread64(fd, buf, count, pos);
    break;
  case 18:
    unsigned int fd = {}; // value of 0
    const char *buf = {}; // value of 1
    size_t count = {};    // value of 2
    loff_t pos = {};      // value of 3
    handler.pwrite64(fd, buf, count, pos);
    break;
  case 19:
    unsigned long fd = {};        // value of 0
    const struct iovec *vec = {}; // value of 1
    unsigned long vlen = {};      // value of 2
    handler.readv(fd, vec, vlen);
    break;
  case 20:
    unsigned long fd = {};        // value of 0
    const struct iovec *vec = {}; // value of 1
    unsigned long vlen = {};      // value of 2
    handler.writev(fd, vec, vlen);
    break;
  case 21:
    const char *filename = {}; // value of 0
    int mode = {};             // value of 1
    handler.access(filename, mode);
    break;
  case 22:
    int *fildes = {}; // value of 0
    handler.pipe(fildes);
    break;
  case 23:
    int n = {};                        // value of 0
    fd_set *inp = {};                  // value of 1
    fd_set *outp = {};                 // value of 2
    fd_set *exp = {};                  // value of 3
    struct __kernel_timeval *tvp = {}; // value of 4
    handler.select(n, inp, outp, exp, tvp);
    break;
  case 24:
    handler.sched_yield();
    break;
  case 25:
    unsigned long addr = {};     // value of 0
    unsigned long old_len = {};  // value of 1
    unsigned long new_len = {};  // value of 2
    unsigned long flags = {};    // value of 3
    unsigned long new_addr = {}; // value of 4
    handler.mremap(addr, old_len, new_len, flags, new_addr);
    break;
  case 26:
    unsigned long start = {}; // value of 0
    size_t len = {};          // value of 1
    int flags = {};           // value of 2
    handler.msync(start, len, flags);
    break;
  case 27:
    unsigned long start = {}; // value of 0
    size_t len = {};          // value of 1
    unsigned char *vec = {};  // value of 2
    handler.mincore(start, len, vec);
    break;
  case 28:
    unsigned long start = {}; // value of 0
    size_t len = {};          // value of 1
    int behavior = {};        // value of 2
    handler.madvise(start, len, behavior);
    break;
  case 29:
    key_t key = {};   // value of 0
    size_t size = {}; // value of 1
    int flag = {};    // value of 2
    handler.shmget(key, size, flag);
    break;
  case 30:
    int shmid = {};     // value of 0
    char *shmaddr = {}; // value of 1
    int shmflg = {};    // value of 2
    handler.shmat(shmid, shmaddr, shmflg);
    break;
  case 31:
    int shmid = {};            // value of 0
    int cmd = {};              // value of 1
    struct shmid_ds *buf = {}; // value of 2
    handler.shmctl(shmid, cmd, buf);
    break;
  case 32:
    unsigned int fildes = {}; // value of 0
    handler.dup(fildes);
    break;
  case 33:
    unsigned int oldfd = {}; // value of 0
    unsigned int newfd = {}; // value of 1
    handler.dup2(oldfd, newfd);
    break;
  case 34:
    handler.pause();
    break;
  case 35:
    struct __kernel_timespec *rqtp = {}; // value of 0
    struct __kernel_timespec *rmtp = {}; // value of 1
    handler.nanosleep(rqtp, rmtp);
    break;
  case 36:
    int which = {};                        // value of 0
    struct __kernel_itimerval *value = {}; // value of 1
    handler.getitimer(which, value);
    break;
  case 37:
    unsigned int seconds = {}; // value of 0
    handler.alarm(seconds);
    break;
  case 38:
    int which = {};                         // value of 0
    struct __kernel_itimerval *value = {};  // value of 1
    struct __kernel_itimerval *ovalue = {}; // value of 2
    handler.setitimer(which, value, ovalue);
    break;
  case 39:
    handler.getpid();
    break;
  case 40:
    int out_fd = {};     // value of 0
    int in_fd = {};      // value of 1
    loff_t *offset = {}; // value of 2
    size_t count = {};   // value of 3
    handler.sendfile64(out_fd, in_fd, offset, count);
    break;
  case 41:
    int = {}; // value of 0
    int = {}; // value of 1
    int = {}; // value of 2
    handler.socket(, , );
    break;
  case 42:
    int = {};               // value of 0
    struct sockaddr * = {}; // value of 1
    int = {};               // value of 2
    handler.connect(, , );
    break;
  case 43:
    int = {};               // value of 0
    struct sockaddr * = {}; // value of 1
    int * = {};             // value of 2
    handler.accept(, , );
    break;
  case 44:
    int = {};               // value of 0
    void * = {};            // value of 1
    size_t = {};            // value of 2
    unsigned = {};          // value of 3
    struct sockaddr * = {}; // value of 4
    int = {};               // value of 5
    handler.sendto(, , , unsigned, , );
    break;
  case 45:
    int = {};               // value of 0
    void * = {};            // value of 1
    size_t = {};            // value of 2
    unsigned = {};          // value of 3
    struct sockaddr * = {}; // value of 4
    int * = {};             // value of 5
    handler.recvfrom(, , , unsigned, , );
    break;
  case 46:
    int fd = {};                  // value of 0
    struct user_msghdr *msg = {}; // value of 1
    unsigned flags = {};          // value of 2
    handler.sendmsg(fd, msg, flags);
    break;
  case 47:
    int fd = {};                  // value of 0
    struct user_msghdr *msg = {}; // value of 1
    unsigned flags = {};          // value of 2
    handler.recvmsg(fd, msg, flags);
    break;
  case 48:
    int = {}; // value of 0
    int = {}; // value of 1
    handler.shutdown(, );
    break;
  case 49:
    int = {};               // value of 0
    struct sockaddr * = {}; // value of 1
    int = {};               // value of 2
    handler.bind(, , );
    break;
  case 50:
    int = {}; // value of 0
    int = {}; // value of 1
    handler.listen(, );
    break;
  case 51:
    int = {};               // value of 0
    struct sockaddr * = {}; // value of 1
    int * = {};             // value of 2
    handler.getsockname(, , );
    break;
  case 52:
    int = {};               // value of 0
    struct sockaddr * = {}; // value of 1
    int * = {};             // value of 2
    handler.getpeername(, , );
    break;
  case 53:
    int = {};   // value of 0
    int = {};   // value of 1
    int = {};   // value of 2
    int * = {}; // value of 3
    handler.socketpair(, , , );
    break;
  case 54:
    int fd = {};       // value of 0
    int level = {};    // value of 1
    int optname = {};  // value of 2
    char *optval = {}; // value of 3
    int optlen = {};   // value of 4
    handler.setsockopt(fd, level, optname, optval, optlen);
    break;
  case 55:
    int fd = {};       // value of 0
    int level = {};    // value of 1
    int optname = {};  // value of 2
    char *optval = {}; // value of 3
    int *optlen = {};  // value of 4
    handler.getsockopt(fd, level, optname, optval, optlen);
    break;
  case 60:
    int error_code = {}; // value of 0
    handler.exit(error_code);
    break;
  case 61:
    pid_t pid = {};         // value of 0
    int *stat_addr = {};    // value of 1
    int options = {};       // value of 2
    struct rusage *ru = {}; // value of 3
    handler.wait4(pid, stat_addr, options, ru);
    break;
  case 62:
    pid_t pid = {}; // value of 0
    int sig = {};   // value of 1
    handler.kill(pid, sig);
    break;
  case 63:
    struct utsname * = {}; // value of 0
    handler.uname();
    break;
  case 64:
    key_t key = {};  // value of 0
    int nsems = {};  // value of 1
    int semflg = {}; // value of 2
    handler.semget(key, nsems, semflg);
    break;
  case 65:
    int semid = {};           // value of 0
    struct sembuf *sops = {}; // value of 1
    unsigned nsops = {};      // value of 2
    handler.semop(semid, sops, nsops);
    break;
  case 66:
    int semid = {};         // value of 0
    int semnum = {};        // value of 1
    int cmd = {};           // value of 2
    unsigned long arg = {}; // value of 3
    handler.semctl(semid, semnum, cmd, arg);
    break;
  case 67:
    char *shmaddr = {}; // value of 0
    handler.shmdt(shmaddr);
    break;
  case 68:
    key_t key = {};  // value of 0
    int msgflg = {}; // value of 1
    handler.msgget(key, msgflg);
    break;
  case 69:
    int msqid = {};           // value of 0
    struct msgbuf *msgp = {}; // value of 1
    size_t msgsz = {};        // value of 2
    int msgflg = {};          // value of 3
    handler.msgsnd(msqid, msgp, msgsz, msgflg);
    break;
  case 70:
    int msqid = {};           // value of 0
    struct msgbuf *msgp = {}; // value of 1
    size_t msgsz = {};        // value of 2
    long msgtyp = {};         // value of 3
    int msgflg = {};          // value of 4
    handler.msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
    break;
  case 71:
    int msqid = {};            // value of 0
    int cmd = {};              // value of 1
    struct msqid_ds *buf = {}; // value of 2
    handler.msgctl(msqid, cmd, buf);
    break;
  case 72:
    unsigned int fd = {};   // value of 0
    unsigned int cmd = {};  // value of 1
    unsigned long arg = {}; // value of 2
    handler.fcntl(fd, cmd, arg);
    break;
  case 73:
    unsigned int fd = {};  // value of 0
    unsigned int cmd = {}; // value of 1
    handler.flock(fd, cmd);
    break;
  case 74:
    unsigned int fd = {}; // value of 0
    handler.fsync(fd);
    break;
  case 75:
    unsigned int fd = {}; // value of 0
    handler.fdatasync(fd);
    break;
  case 76:
    const char *path = {}; // value of 0
    long length = {};      // value of 1
    handler.truncate(path, length);
    break;
  case 77:
    unsigned int fd = {};      // value of 0
    unsigned long length = {}; // value of 1
    handler.ftruncate(fd, length);
    break;
  case 78:
    unsigned int fd = {};             // value of 0
    struct linux_dirent *dirent = {}; // value of 1
    unsigned int count = {};          // value of 2
    handler.getdents(fd, dirent, count);
    break;
  case 79:
    char *buf = {};          // value of 0
    unsigned long size = {}; // value of 1
    handler.getcwd(buf, size);
    break;
  case 80:
    const char *filename = {}; // value of 0
    handler.chdir(filename);
    break;
  case 81:
    unsigned int fd = {}; // value of 0
    handler.fchdir(fd);
    break;
  case 82:
    const char *oldname = {}; // value of 0
    const char *newname = {}; // value of 1
    handler.rename(oldname, newname);
    break;
  case 83:
    const char *pathname = {}; // value of 0
    mode_t mode = {};          // value of 1
    handler.mkdir(pathname, mode);
    break;
  case 84:
    const char *pathname = {}; // value of 0
    handler.rmdir(pathname);
    break;
  case 85:
    const char *pathname = {}; // value of 0
    mode_t mode = {};          // value of 1
    handler.creat(pathname, mode);
    break;
  case 86:
    const char *oldname = {}; // value of 0
    const char *newname = {}; // value of 1
    handler.link(oldname, newname);
    break;
  case 87:
    const char *pathname = {}; // value of 0
    handler.unlink(pathname);
    break;
  case 88:
    const char *old = {};      // value of 0
    const char *linkpath = {}; // value of 1
    handler.symlink(old, linkpath);
    break;
  case 89:
    const char *path = {}; // value of 0
    char *buf = {};        // value of 1
    int bufsiz = {};       // value of 2
    handler.readlink(path, buf, bufsiz);
    break;
  case 90:
    const char *filename = {}; // value of 0
    mode_t mode = {};          // value of 1
    handler.chmod(filename, mode);
    break;
  case 91:
    unsigned int fd = {}; // value of 0
    mode_t mode = {};     // value of 1
    handler.fchmod(fd, mode);
    break;
  case 92:
    const char *filename = {}; // value of 0
    uid_t user = {};           // value of 1
    gid_t group = {};          // value of 2
    handler.chown(filename, user, group);
    break;
  case 93:
    unsigned int fd = {}; // value of 0
    uid_t user = {};      // value of 1
    gid_t group = {};     // value of 2
    handler.fchown(fd, user, group);
    break;
  case 94:
    const char *filename = {}; // value of 0
    uid_t user = {};           // value of 1
    gid_t group = {};          // value of 2
    handler.lchown(filename, user, group);
    break;
  case 95:
    int mask = {}; // value of 0
    handler.umask(mask);
    break;
  case 96:
    struct __kernel_timeval *tv = {}; // value of 0
    struct timezone *tz = {};         // value of 1
    handler.gettimeofday(tv, tz);
    break;
  case 97:
    unsigned int resource = {}; // value of 0
    struct rlimit *rlim = {};   // value of 1
    handler.getrlimit(resource, rlim);
    break;
  case 98:
    int who = {};           // value of 0
    struct rusage *ru = {}; // value of 1
    handler.getrusage(who, ru);
    break;
  case 99:
    struct sysinfo *info = {}; // value of 0
    handler.sysinfo(info);
    break;
  case 100:
    struct tms *tbuf = {}; // value of 0
    handler.times(tbuf);
    break;
  case 101:
    long request = {};       // value of 0
    long pid = {};           // value of 1
    unsigned long addr = {}; // value of 2
    unsigned long data = {}; // value of 3
    handler.ptrace(request, pid, addr, data);
    break;
  case 102:
    handler.getuid();
    break;
  case 103:
    int type = {};  // value of 0
    char *buf = {}; // value of 1
    int len = {};   // value of 2
    handler.syslog(type, buf, len);
    break;
  case 104:
    handler.getgid();
    break;
  case 105:
    uid_t uid = {}; // value of 0
    handler.setuid(uid);
    break;
  case 106:
    gid_t gid = {}; // value of 0
    handler.setgid(gid);
    break;
  case 107:
    handler.geteuid();
    break;
  case 108:
    handler.getegid();
    break;
  case 109:
    pid_t pid = {};  // value of 0
    pid_t pgid = {}; // value of 1
    handler.setpgid(pid, pgid);
    break;
  case 110:
    handler.getppid();
    break;
  case 111:
    handler.getpgrp();
    break;
  case 112:
    handler.setsid();
    break;
  case 113:
    uid_t ruid = {}; // value of 0
    uid_t euid = {}; // value of 1
    handler.setreuid(ruid, euid);
    break;
  case 114:
    gid_t rgid = {}; // value of 0
    gid_t egid = {}; // value of 1
    handler.setregid(rgid, egid);
    break;
  case 115:
    int gidsetsize = {};   // value of 0
    gid_t *grouplist = {}; // value of 1
    handler.getgroups(gidsetsize, grouplist);
    break;
  case 116:
    int gidsetsize = {};   // value of 0
    gid_t *grouplist = {}; // value of 1
    handler.setgroups(gidsetsize, grouplist);
    break;
  case 117:
    uid_t ruid = {}; // value of 0
    uid_t euid = {}; // value of 1
    uid_t suid = {}; // value of 2
    handler.setresuid(ruid, euid, suid);
    break;
  case 118:
    uid_t *ruid = {}; // value of 0
    uid_t *euid = {}; // value of 1
    uid_t *suid = {}; // value of 2
    handler.getresuid(ruid, euid, suid);
    break;
  case 119:
    gid_t rgid = {}; // value of 0
    gid_t egid = {}; // value of 1
    gid_t sgid = {}; // value of 2
    handler.setresgid(rgid, egid, sgid);
    break;
  case 120:
    gid_t *rgid = {}; // value of 0
    gid_t *egid = {}; // value of 1
    gid_t *sgid = {}; // value of 2
    handler.getresgid(rgid, egid, sgid);
    break;
  case 121:
    pid_t pid = {}; // value of 0
    handler.getpgid(pid);
    break;
  case 122:
    uid_t uid = {}; // value of 0
    handler.setfsuid(uid);
    break;
  case 123:
    gid_t gid = {}; // value of 0
    handler.setfsgid(gid);
    break;
  case 124:
    pid_t pid = {}; // value of 0
    handler.getsid(pid);
    break;
  case 125:
    int header = {};  // value of 0
    int dataptr = {}; // value of 1
    handler.capget(header, dataptr);
    break;
  case 126:
    int header = {};     // value of 0
    const int data = {}; // value of 1
    handler.capset(header, data);
    break;
  case 127:
    sigset_t *set = {};     // value of 0
    size_t sigsetsize = {}; // value of 1
    handler.rt_sigpending(set, sigsetsize);
    break;
  case 128:
    const sigset_t *uthese = {};              // value of 0
    siginfo_t *uinfo = {};                    // value of 1
    const struct __kernel_timespec *uts = {}; // value of 2
    size_t sigsetsize = {};                   // value of 3
    handler.rt_sigtimedwait(uthese, uinfo, uts, sigsetsize);
    break;
  case 129:
    pid_t pid = {};        // value of 0
    int sig = {};          // value of 1
    siginfo_t *uinfo = {}; // value of 2
    handler.rt_sigqueueinfo(pid, sig, uinfo);
    break;
  case 130:
    sigset_t *unewset = {}; // value of 0
    size_t sigsetsize = {}; // value of 1
    handler.rt_sigsuspend(unewset, sigsetsize);
    break;
  case 132:
    char *filename = {};        // value of 0
    struct utimbuf *times = {}; // value of 1
    handler.utime(filename, times);
    break;
  case 133:
    const char *filename = {}; // value of 0
    mode_t mode = {};          // value of 1
    unsigned dev = {};         // value of 2
    handler.mknod(filename, mode, dev);
    break;
  case 134:
    handler.ni_syscall();
    break;
  case 135:
    unsigned int personality = {}; // value of 0
    handler.personality(personality);
    break;
  case 136:
    unsigned dev = {};       // value of 0
    struct ustat *ubuf = {}; // value of 1
    handler.ustat(dev, ubuf);
    break;
  case 137:
    const char *path = {};   // value of 0
    struct statfs *buf = {}; // value of 1
    handler.statfs(path, buf);
    break;
  case 138:
    unsigned int fd = {};    // value of 0
    struct statfs *buf = {}; // value of 1
    handler.fstatfs(fd, buf);
    break;
  case 139:
    int option = {};         // value of 0
    unsigned long arg1 = {}; // value of 1
    unsigned long arg2 = {}; // value of 2
    handler.sysfs(option, arg1, arg2);
    break;
  case 140:
    int which = {}; // value of 0
    int who = {};   // value of 1
    handler.getpriority(which, who);
    break;
  case 141:
    int which = {};   // value of 0
    int who = {};     // value of 1
    int niceval = {}; // value of 2
    handler.setpriority(which, who, niceval);
    break;
  case 142:
    pid_t pid = {};                 // value of 0
    struct sched_param *param = {}; // value of 1
    handler.sched_setparam(pid, param);
    break;
  case 143:
    pid_t pid = {};                 // value of 0
    struct sched_param *param = {}; // value of 1
    handler.sched_getparam(pid, param);
    break;
  case 144:
    pid_t pid = {};                 // value of 0
    int policy = {};                // value of 1
    struct sched_param *param = {}; // value of 2
    handler.sched_setscheduler(pid, policy, param);
    break;
  case 145:
    pid_t pid = {}; // value of 0
    handler.sched_getscheduler(pid);
    break;
  case 146:
    int policy = {}; // value of 0
    handler.sched_get_priority_max(policy);
    break;
  case 147:
    int policy = {}; // value of 0
    handler.sched_get_priority_min(policy);
    break;
  case 148:
    pid_t pid = {};                          // value of 0
    struct __kernel_timespec *interval = {}; // value of 1
    handler.sched_rr_get_interval(pid, interval);
    break;
  case 149:
    unsigned long start = {}; // value of 0
    size_t len = {};          // value of 1
    handler.mlock(start, len);
    break;
  case 150:
    unsigned long start = {}; // value of 0
    size_t len = {};          // value of 1
    handler.munlock(start, len);
    break;
  case 151:
    int flags = {}; // value of 0
    handler.mlockall(flags);
    break;
  case 152:
    handler.munlockall();
    break;
  case 153:
    handler.vhangup();
    break;
  case 154:
    handler.modify_ldt();
    break;
  case 155:
    const char *new_root = {}; // value of 0
    const char *put_old = {};  // value of 1
    handler.pivot_root(new_root, put_old);
    break;
  case 156:
    handler.sysctl();
    break;
  case 157:
    int option = {};         // value of 0
    unsigned long arg2 = {}; // value of 1
    unsigned long arg3 = {}; // value of 2
    unsigned long arg4 = {}; // value of 3
    unsigned long arg5 = {}; // value of 4
    handler.prctl(option, arg2, arg3, arg4, arg5);
    break;
  case 158:
    int code = {};           // value of 0
    unsigned long addr = {}; // value of 1
    handler.arch_prctl(code, addr);
    break;
  case 159:
    struct __kernel_timex *txc_p = {}; // value of 0
    handler.adjtimex(txc_p);
    break;
  case 160:
    unsigned int resource = {}; // value of 0
    struct rlimit *rlim = {};   // value of 1
    handler.setrlimit(resource, rlim);
    break;
  case 161:
    const char *filename = {}; // value of 0
    handler.chroot(filename);
    break;
  case 162:
    handler.sync();
    break;
  case 163:
    const char *name = {}; // value of 0
    handler.acct(name);
    break;
  case 164:
    struct __kernel_timeval *tv = {}; // value of 0
    struct timezone *tz = {};         // value of 1
    handler.settimeofday(tv, tz);
    break;
  case 165:
    char *dev_name = {};      // value of 0
    char *dir_name = {};      // value of 1
    char *type = {};          // value of 2
    unsigned long flags = {}; // value of 3
    void *data = {};          // value of 4
    handler.mount(dev_name, dir_name, type, flags, data);
    break;
  case 166:
    char *name = {}; // value of 0
    int flags = {};  // value of 1
    handler.umount(name, flags);
    break;
  case 167:
    const char *specialfile = {}; // value of 0
    int swap_flags = {};          // value of 1
    handler.swapon(specialfile, swap_flags);
    break;
  case 168:
    const char *specialfile = {}; // value of 0
    handler.swapoff(specialfile);
    break;
  case 169:
    int magic1 = {};       // value of 0
    int magic2 = {};       // value of 1
    unsigned int cmd = {}; // value of 2
    void *arg = {};        // value of 3
    handler.reboot(magic1, magic2, cmd, arg);
    break;
  case 170:
    char *name = {}; // value of 0
    int len = {};    // value of 1
    handler.sethostname(name, len);
    break;
  case 171:
    char *name = {}; // value of 0
    int len = {};    // value of 1
    handler.setdomainname(name, len);
    break;
  case 173:
    unsigned long from = {}; // value of 0
    unsigned long num = {};  // value of 1
    int on = {};             // value of 2
    handler.ioperm(from, num, on);
    break;
  case 174:
    handler.ni_syscall();
    break;
  case 175:
    void *umod = {};        // value of 0
    unsigned long len = {}; // value of 1
    const char *uargs = {}; // value of 2
    handler.init_module(umod, len, uargs);
    break;
  case 176:
    const char *name_user = {}; // value of 0
    unsigned int flags = {};    // value of 1
    handler.delete_module(name_user, flags);
    break;
  case 177:
    handler.ni_syscall();
    break;
  case 178:
    handler.ni_syscall();
    break;
  case 179:
    unsigned int cmd = {};    // value of 0
    const char *special = {}; // value of 1
    int id = {};              // value of 2
    void *addr = {};          // value of 3
    handler.quotactl(cmd, special, id, addr);
    break;
  case 180:
    handler.nfsservctl();
    break;
  case 181:
    handler.ni_syscall();
    break;
  case 182:
    handler.ni_syscall();
    break;
  case 183:
    handler.ni_syscall();
    break;
  case 184:
    handler.ni_syscall();
    break;
  case 185:
    handler.ni_syscall();
    break;
  case 186:
    handler.gettid();
    break;
  case 187:
    int fd = {};        // value of 0
    loff_t offset = {}; // value of 1
    size_t count = {};  // value of 2
    handler.readahead(fd, offset, count);
    break;
  case 188:
    const char *path = {};  // value of 0
    const char *name = {};  // value of 1
    const void *value = {}; // value of 2
    size_t size = {};       // value of 3
    int flags = {};         // value of 4
    handler.setxattr(path, name, value, size, flags);
    break;
  case 189:
    const char *path = {};  // value of 0
    const char *name = {};  // value of 1
    const void *value = {}; // value of 2
    size_t size = {};       // value of 3
    int flags = {};         // value of 4
    handler.lsetxattr(path, name, value, size, flags);
    break;
  case 190:
    int fd = {};            // value of 0
    const char *name = {};  // value of 1
    const void *value = {}; // value of 2
    size_t size = {};       // value of 3
    int flags = {};         // value of 4
    handler.fsetxattr(fd, name, value, size, flags);
    break;
  case 191:
    const char *path = {}; // value of 0
    const char *name = {}; // value of 1
    void *value = {};      // value of 2
    size_t size = {};      // value of 3
    handler.getxattr(path, name, value, size);
    break;
  case 192:
    const char *path = {}; // value of 0
    const char *name = {}; // value of 1
    void *value = {};      // value of 2
    size_t size = {};      // value of 3
    handler.lgetxattr(path, name, value, size);
    break;
  case 193:
    int fd = {};           // value of 0
    const char *name = {}; // value of 1
    void *value = {};      // value of 2
    size_t size = {};      // value of 3
    handler.fgetxattr(fd, name, value, size);
    break;
  case 194:
    const char *path = {}; // value of 0
    char *list = {};       // value of 1
    size_t size = {};      // value of 2
    handler.listxattr(path, list, size);
    break;
  case 195:
    const char *path = {}; // value of 0
    char *list = {};       // value of 1
    size_t size = {};      // value of 2
    handler.llistxattr(path, list, size);
    break;
  case 196:
    int fd = {};      // value of 0
    char *list = {};  // value of 1
    size_t size = {}; // value of 2
    handler.flistxattr(fd, list, size);
    break;
  case 197:
    const char *path = {}; // value of 0
    const char *name = {}; // value of 1
    handler.removexattr(path, name);
    break;
  case 198:
    const char *path = {}; // value of 0
    const char *name = {}; // value of 1
    handler.lremovexattr(path, name);
    break;
  case 199:
    int fd = {};           // value of 0
    const char *name = {}; // value of 1
    handler.fremovexattr(fd, name);
    break;
  case 200:
    pid_t pid = {}; // value of 0
    int sig = {};   // value of 1
    handler.tkill(pid, sig);
    break;
  case 201:
    __kernel_time_t *tloc = {}; // value of 0
    handler.time(tloc);
    break;
  case 202:
    uint32_t *uaddr = {};                       // value of 0
    int op = {};                                // value of 1
    uint32_t val = {};                          // value of 2
    const struct __kernel_timespec *utime = {}; // value of 3
    uint32_t *uaddr2 = {};                      // value of 4
    uint32_t val3 = {};                         // value of 5
    handler.futex(uaddr, op, val, utime, uaddr2, val3);
    break;
  case 203:
    pid_t pid = {};                    // value of 0
    unsigned int len = {};             // value of 1
    unsigned long *user_mask_ptr = {}; // value of 2
    handler.sched_setaffinity(pid, len, user_mask_ptr);
    break;
  case 204:
    pid_t pid = {};                    // value of 0
    unsigned int len = {};             // value of 1
    unsigned long *user_mask_ptr = {}; // value of 2
    handler.sched_getaffinity(pid, len, user_mask_ptr);
    break;
  case 205:
    handler.ni_syscall();
    break;
  case 206:
    unsigned nr_reqs = {};   // value of 0
    aio_context_t *ctx = {}; // value of 1
    handler.io_setup(nr_reqs, ctx);
    break;
  case 207:
    aio_context_t ctx = {}; // value of 0
    handler.io_destroy(ctx);
    break;
  case 208:
    aio_context_t ctx_id = {};              // value of 0
    long min_nr = {};                       // value of 1
    long nr = {};                           // value of 2
    struct io_event *events = {};           // value of 3
    struct __kernel_timespec *timeout = {}; // value of 4
    handler.io_getevents(ctx_id, min_nr, nr, events, timeout);
    break;
  case 209:
    aio_context_t = {};  // value of 0
    long = {};           // value of 1
    struct iocb ** = {}; // value of 2
    handler.io_submit(aio_context_t, , );
    break;
  case 210:
    aio_context_t ctx_id = {};    // value of 0
    struct iocb *iocb = {};       // value of 1
    struct io_event *result = {}; // value of 2
    handler.io_cancel(ctx_id, iocb, result);
    break;
  case 211:
    handler.ni_syscall();
    break;
  case 212:
    uint64_t cookie64 = {}; // value of 0
    char *buf = {};         // value of 1
    size_t len = {};        // value of 2
    handler.lookup_dcookie(cookie64, buf, len);
    break;
  case 213:
    int size = {}; // value of 0
    handler.epoll_create(size);
    break;
  case 214:
    handler.ni_syscall();
    break;
  case 215:
    handler.ni_syscall();
    break;
  case 216:
    unsigned long start = {}; // value of 0
    unsigned long size = {};  // value of 1
    unsigned long prot = {};  // value of 2
    unsigned long pgoff = {}; // value of 3
    unsigned long flags = {}; // value of 4
    handler.remap_file_pages(start, size, prot, pgoff, flags);
    break;
  case 217:
    unsigned int fd = {};               // value of 0
    struct linux_dirent64 *dirent = {}; // value of 1
    unsigned int count = {};            // value of 2
    handler.getdents64(fd, dirent, count);
    break;
  case 218:
    int *tidptr = {}; // value of 0
    handler.set_tid_address(tidptr);
    break;
  case 219:
    handler.restart_syscall();
    break;
  case 220:
    int semid = {};                               // value of 0
    struct sembuf *sops = {};                     // value of 1
    unsigned nsops = {};                          // value of 2
    const struct __kernel_timespec *timeout = {}; // value of 3
    handler.semtimedop(semid, sops, nsops, timeout);
    break;
  case 221:
    int fd = {};        // value of 0
    loff_t offset = {}; // value of 1
    size_t len = {};    // value of 2
    int advice = {};    // value of 3
    handler.fadvise64(fd, offset, len, advice);
    break;
  case 222:
    clockid_t which_clock = {};             // value of 0
    struct sigevent *timer_event_spec = {}; // value of 1
    timer_t *created_timer_id = {};         // value of 2
    handler.timer_create(which_clock, timer_event_spec, created_timer_id);
    break;
  case 223:
    timer_t timer_id = {};                              // value of 0
    int flags = {};                                     // value of 1
    const struct __kernel_itimerspec *new_setting = {}; // value of 2
    struct __kernel_itimerspec *old_setting = {};       // value of 3
    handler.timer_settime(timer_id, flags, new_setting, old_setting);
    break;
  case 224:
    timer_t timer_id = {};                    // value of 0
    struct __kernel_itimerspec *setting = {}; // value of 1
    handler.timer_gettime(timer_id, setting);
    break;
  case 225:
    timer_t timer_id = {}; // value of 0
    handler.timer_getoverrun(timer_id);
    break;
  case 226:
    timer_t timer_id = {}; // value of 0
    handler.timer_delete(timer_id);
    break;
  case 227:
    clockid_t which_clock = {};              // value of 0
    const struct __kernel_timespec *tp = {}; // value of 1
    handler.clock_settime(which_clock, tp);
    break;
  case 228:
    clockid_t which_clock = {};        // value of 0
    struct __kernel_timespec *tp = {}; // value of 1
    handler.clock_gettime(which_clock, tp);
    break;
  case 229:
    clockid_t which_clock = {};        // value of 0
    struct __kernel_timespec *tp = {}; // value of 1
    handler.clock_getres(which_clock, tp);
    break;
  case 230:
    clockid_t which_clock = {};                // value of 0
    int flags = {};                            // value of 1
    const struct __kernel_timespec *rqtp = {}; // value of 2
    struct __kernel_timespec *rmtp = {};       // value of 3
    handler.clock_nanosleep(which_clock, flags, rqtp, rmtp);
    break;
  case 231:
    int error_code = {}; // value of 0
    handler.exit_group(error_code);
    break;
  case 232:
    int epfd = {};                   // value of 0
    struct epoll_event *events = {}; // value of 1
    int maxevents = {};              // value of 2
    int timeout = {};                // value of 3
    handler.epoll_wait(epfd, events, maxevents, timeout);
    break;
  case 233:
    int epfd = {};                  // value of 0
    int op = {};                    // value of 1
    int fd = {};                    // value of 2
    struct epoll_event *event = {}; // value of 3
    handler.epoll_ctl(epfd, op, fd, event);
    break;
  case 234:
    pid_t tgid = {}; // value of 0
    pid_t pid = {};  // value of 1
    int sig = {};    // value of 2
    handler.tgkill(tgid, pid, sig);
    break;
  case 235:
    char *filename = {};                  // value of 0
    struct __kernel_timeval *utimes = {}; // value of 1
    handler.utimes(filename, utimes);
    break;
  case 236:
    handler.ni_syscall();
    break;
  case 237:
    unsigned long start = {};        // value of 0
    unsigned long len = {};          // value of 1
    unsigned long mode = {};         // value of 2
    const unsigned long *nmask = {}; // value of 3
    unsigned long maxnode = {};      // value of 4
    unsigned flags = {};             // value of 5
    handler.mbind(start, len, mode, nmask, maxnode, flags);
    break;
  case 238:
    int mode = {};                   // value of 0
    const unsigned long *nmask = {}; // value of 1
    unsigned long maxnode = {};      // value of 2
    handler.set_mempolicy(mode, nmask, maxnode);
    break;
  case 239:
    int *policy = {};           // value of 0
    unsigned long *nmask = {};  // value of 1
    unsigned long maxnode = {}; // value of 2
    unsigned long addr = {};    // value of 3
    unsigned long flags = {};   // value of 4
    handler.get_mempolicy(policy, nmask, maxnode, addr, flags);
    break;
  case 240:
    const char *name = {};     // value of 0
    int oflag = {};            // value of 1
    mode_t mode = {};          // value of 2
    struct mq_attr *attr = {}; // value of 3
    handler.mq_open(name, oflag, mode, attr);
    break;
  case 241:
    const char *name = {}; // value of 0
    handler.mq_unlink(name);
    break;
  case 242:
    mqd_t mqdes = {};                                 // value of 0
    const char *msg_ptr = {};                         // value of 1
    size_t msg_len = {};                              // value of 2
    unsigned int msg_prio = {};                       // value of 3
    const struct __kernel_timespec *abs_timeout = {}; // value of 4
    handler.mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
    break;
  case 243:
    mqd_t mqdes = {};                                 // value of 0
    char *msg_ptr = {};                               // value of 1
    size_t msg_len = {};                              // value of 2
    unsigned int *msg_prio = {};                      // value of 3
    const struct __kernel_timespec *abs_timeout = {}; // value of 4
    handler.mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
    break;
  case 244:
    mqd_t mqdes = {};                         // value of 0
    const struct sigevent *notification = {}; // value of 1
    handler.mq_notify(mqdes, notification);
    break;
  case 245:
    mqd_t mqdes = {};                  // value of 0
    const struct mq_attr *mqstat = {}; // value of 1
    struct mq_attr *omqstat = {};      // value of 2
    handler.mq_getsetattr(mqdes, mqstat, omqstat);
    break;
  case 246:
    unsigned long entry = {};            // value of 0
    unsigned long nr_segments = {};      // value of 1
    struct kexec_segment *segments = {}; // value of 2
    unsigned long flags = {};            // value of 3
    handler.kexec_load(entry, nr_segments, segments, flags);
    break;
  case 247:
    int which = {};             // value of 0
    pid_t pid = {};             // value of 1
    struct siginfo *infop = {}; // value of 2
    int options = {};           // value of 3
    struct rusage *ru = {};     // value of 4
    handler.waitid(which, pid, infop, options, ru);
    break;
  case 248:
    const char *_type = {};        // value of 0
    const char *_description = {}; // value of 1
    const void *_payload = {};     // value of 2
    size_t plen = {};              // value of 3
    int destringid = {};           // value of 4
    handler.add_key(_type, _description, _payload, plen, destringid);
    break;
  case 249:
    const char *_type = {};         // value of 0
    const char *_description = {};  // value of 1
    const char *_callout_info = {}; // value of 2
    int destringid = {};            // value of 3
    handler.request_key(_type, _description, _callout_info, destringid);
    break;
  case 250:
    int cmd = {};            // value of 0
    unsigned long arg2 = {}; // value of 1
    unsigned long arg3 = {}; // value of 2
    unsigned long arg4 = {}; // value of 3
    unsigned long arg5 = {}; // value of 4
    handler.keyctl(cmd, arg2, arg3, arg4, arg5);
    break;
  case 251:
    int which = {};  // value of 0
    int who = {};    // value of 1
    int ioprio = {}; // value of 2
    handler.ioprio_set(which, who, ioprio);
    break;
  case 252:
    int which = {}; // value of 0
    int who = {};   // value of 1
    handler.ioprio_get(which, who);
    break;
  case 253:
    handler.inotify_init();
    break;
  case 254:
    int fd = {};           // value of 0
    const char *path = {}; // value of 1
    uint32_t mask = {};    // value of 2
    handler.inotify_add_watch(fd, path, mask);
    break;
  case 255:
    int fd = {};   // value of 0
    __s32 wd = {}; // value of 1
    handler.inotify_rm_watch(fd, wd);
    break;
  case 256:
    pid_t pid = {};                 // value of 0
    unsigned long maxnode = {};     // value of 1
    const unsigned long *from = {}; // value of 2
    const unsigned long *to = {};   // value of 3
    handler.migrate_pages(pid, maxnode, from, to);
    break;
  case 257:
    int dfd = {};              // value of 0
    const char *filename = {}; // value of 1
    int flags = {};            // value of 2
    mode_t mode = {};          // value of 3
    handler.openat(dfd, filename, flags, mode);
    break;
  case 258:
    int dfd = {};              // value of 0
    const char *pathname = {}; // value of 1
    mode_t mode = {};          // value of 2
    handler.mkdirat(dfd, pathname, mode);
    break;
  case 259:
    int dfd = {};              // value of 0
    const char *filename = {}; // value of 1
    mode_t mode = {};          // value of 2
    unsigned dev = {};         // value of 3
    handler.mknodat(dfd, filename, mode, dev);
    break;
  case 260:
    int dfd = {};              // value of 0
    const char *filename = {}; // value of 1
    uid_t user = {};           // value of 2
    gid_t group = {};          // value of 3
    int flag = {};             // value of 4
    handler.fchownat(dfd, filename, user, group, flag);
    break;
  case 261:
    int dfd = {};                         // value of 0
    const char *filename = {};            // value of 1
    struct __kernel_timeval *utimes = {}; // value of 2
    handler.futimesat(dfd, filename, utimes);
    break;
  case 262:
    int dfd = {};              // value of 0
    const char *filename = {}; // value of 1
    struct stat *statbuf = {}; // value of 2
    int flag = {};             // value of 3
    handler.newfstatat(dfd, filename, statbuf, flag);
    break;
  case 263:
    int dfd = {};              // value of 0
    const char *pathname = {}; // value of 1
    int flag = {};             // value of 2
    handler.unlinkat(dfd, pathname, flag);
    break;
  case 264:
    int olddfd = {};          // value of 0
    const char *oldname = {}; // value of 1
    int newdfd = {};          // value of 2
    const char *newname = {}; // value of 3
    handler.renameat(olddfd, oldname, newdfd, newname);
    break;
  case 265:
    int olddfd = {};          // value of 0
    const char *oldname = {}; // value of 1
    int newdfd = {};          // value of 2
    const char *newname = {}; // value of 3
    int flags = {};           // value of 4
    handler.linkat(olddfd, oldname, newdfd, newname, flags);
    break;
  case 266:
    const char *oldname = {}; // value of 0
    int newdfd = {};          // value of 1
    const char *newname = {}; // value of 2
    handler.symlinkat(oldname, newdfd, newname);
    break;
  case 267:
    int dfd = {};          // value of 0
    const char *path = {}; // value of 1
    char *buf = {};        // value of 2
    int bufsiz = {};       // value of 3
    handler.readlinkat(dfd, path, buf, bufsiz);
    break;
  case 268:
    int dfd = {};              // value of 0
    const char *filename = {}; // value of 1
    mode_t mode = {};          // value of 2
    handler.fchmodat(dfd, filename, mode);
    break;
  case 269:
    int dfd = {};              // value of 0
    const char *filename = {}; // value of 1
    int mode = {};             // value of 2
    handler.faccessat(dfd, filename, mode);
    break;
  case 270:
    int = {};                        // value of 0
    fd_set * = {};                   // value of 1
    fd_set * = {};                   // value of 2
    fd_set * = {};                   // value of 3
    struct __kernel_timespec * = {}; // value of 4
    void * = {};                     // value of 5
    handler.pselect6(, , , , , );
    break;
  case 273:
    struct robust_list_head *head = {}; // value of 0
    size_t len = {};                    // value of 1
    handler.set_robust_list(head, len);
    break;
  case 274:
    int pid = {};                            // value of 0
    struct robust_list_head **head_ptr = {}; // value of 1
    size_t *len_ptr = {};                    // value of 2
    handler.get_robust_list(pid, head_ptr, len_ptr);
    break;
  case 275:
    int fd_in = {};          // value of 0
    loff_t *off_in = {};     // value of 1
    int fd_out = {};         // value of 2
    loff_t *off_out = {};    // value of 3
    size_t len = {};         // value of 4
    unsigned int flags = {}; // value of 5
    handler.splice(fd_in, off_in, fd_out, off_out, len, flags);
    break;
  case 276:
    int fdin = {};           // value of 0
    int fdout = {};          // value of 1
    size_t len = {};         // value of 2
    unsigned int flags = {}; // value of 3
    handler.tee(fdin, fdout, len, flags);
    break;
  case 277:
    int fd = {};             // value of 0
    loff_t offset = {};      // value of 1
    loff_t nbytes = {};      // value of 2
    unsigned int flags = {}; // value of 3
    handler.sync_file_range(fd, offset, nbytes, flags);
    break;
  case 278:
    int fd = {};                  // value of 0
    const struct iovec *iov = {}; // value of 1
    unsigned long nr_segs = {};   // value of 2
    unsigned int flags = {};      // value of 3
    handler.vmsplice(fd, iov, nr_segs, flags);
    break;
  case 279:
    pid_t pid = {};              // value of 0
    unsigned long nr_pages = {}; // value of 1
    const void **pages = {};     // value of 2
    const int *nodes = {};       // value of 3
    int *status = {};            // value of 4
    int flags = {};              // value of 5
    handler.move_pages(pid, nr_pages, pages, nodes, status, flags);
    break;
  case 280:
    int dfd = {};                          // value of 0
    const char *filename = {};             // value of 1
    struct __kernel_timespec *utimes = {}; // value of 2
    int flags = {};                        // value of 3
    handler.utimensat(dfd, filename, utimes, flags);
    break;
  case 281:
    int epfd = {};                   // value of 0
    struct epoll_event *events = {}; // value of 1
    int maxevents = {};              // value of 2
    int timeout = {};                // value of 3
    const sigset_t *sigmask = {};    // value of 4
    size_t sigsetsize = {};          // value of 5
    handler.epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize);
    break;
  case 282:
    int ufd = {};             // value of 0
    sigset_t *user_mask = {}; // value of 1
    size_t sizemask = {};     // value of 2
    handler.signalfd(ufd, user_mask, sizemask);
    break;
  case 283:
    int clockid = {}; // value of 0
    int flags = {};   // value of 1
    handler.timerfd_create(clockid, flags);
    break;
  case 284:
    unsigned int count = {}; // value of 0
    handler.eventfd(count);
    break;
  case 285:
    int fd = {};        // value of 0
    int mode = {};      // value of 1
    loff_t offset = {}; // value of 2
    loff_t len = {};    // value of 3
    handler.fallocate(fd, mode, offset, len);
    break;
  case 286:
    int ufd = {};                                // value of 0
    int flags = {};                              // value of 1
    const struct __kernel_itimerspec *utmr = {}; // value of 2
    struct __kernel_itimerspec *otmr = {};       // value of 3
    handler.timerfd_settime(ufd, flags, utmr, otmr);
    break;
  case 287:
    int ufd = {};                          // value of 0
    struct __kernel_itimerspec *otmr = {}; // value of 1
    handler.timerfd_gettime(ufd, otmr);
    break;
  case 288:
    int = {};               // value of 0
    struct sockaddr * = {}; // value of 1
    int * = {};             // value of 2
    int = {};               // value of 3
    handler.accept4(, , , );
    break;
  case 289:
    int ufd = {};             // value of 0
    sigset_t *user_mask = {}; // value of 1
    size_t sizemask = {};     // value of 2
    int flags = {};           // value of 3
    handler.signalfd4(ufd, user_mask, sizemask, flags);
    break;
  case 290:
    unsigned int count = {}; // value of 0
    int flags = {};          // value of 1
    handler.eventfd2(count, flags);
    break;
  case 291:
    int flags = {}; // value of 0
    handler.epoll_create1(flags);
    break;
  case 292:
    unsigned int oldfd = {}; // value of 0
    unsigned int newfd = {}; // value of 1
    int flags = {};          // value of 2
    handler.dup3(oldfd, newfd, flags);
    break;
  case 293:
    int *fildes = {}; // value of 0
    int flags = {};   // value of 1
    handler.pipe2(fildes, flags);
    break;
  case 294:
    int flags = {}; // value of 0
    handler.inotify_init1(flags);
    break;
  case 295:
    unsigned long fd = {};        // value of 0
    const struct iovec *vec = {}; // value of 1
    unsigned long vlen = {};      // value of 2
    unsigned long pos_l = {};     // value of 3
    unsigned long pos_h = {};     // value of 4
    handler.preadv(fd, vec, vlen, pos_l, pos_h);
    break;
  case 296:
    unsigned long fd = {};        // value of 0
    const struct iovec *vec = {}; // value of 1
    unsigned long vlen = {};      // value of 2
    unsigned long pos_l = {};     // value of 3
    unsigned long pos_h = {};     // value of 4
    handler.pwritev(fd, vec, vlen, pos_l, pos_h);
    break;
  case 297:
    pid_t tgid = {};       // value of 0
    pid_t pid = {};        // value of 1
    int sig = {};          // value of 2
    siginfo_t *uinfo = {}; // value of 3
    handler.rt_tgsigqueueinfo(tgid, pid, sig, uinfo);
    break;
  case 298:
    struct perf_event_attr *attr_uptr = {}; // value of 0
    pid_t pid = {};                         // value of 1
    int cpu = {};                           // value of 2
    int group_fd = {};                      // value of 3
    unsigned long flags = {};               // value of 4
    handler.perf_event_open(attr_uptr, pid, cpu, group_fd, flags);
    break;
  }
}
