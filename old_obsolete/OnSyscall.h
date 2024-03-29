// Generated via code_generator/generate_syscalls.py
#include <cstdint>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <mqueue.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <unistd.h>
using SyscallDataType = decltype(user_regs_struct{}.rax);

class OnSyscall {
  virtual auto io_setup(unsigned nr_reqs, aio_context_t *ctx,
                        SyscallDataType return_value) -> void = 0;
  virtual auto io_destroy(aio_context_t ctx, SyscallDataType return_value)
      -> void = 0;
  virtual auto io_submit(aio_context_t, long, iocb **,
                         SyscallDataType return_value) -> void = 0;
  virtual auto io_cancel(aio_context_t ctx_id, iocb *iocb, io_event *result,
                         SyscallDataType return_value) -> void = 0;
  virtual auto io_getevents(aio_context_t ctx_id, long min_nr, long nr,
                            io_event *events, __kernel_timespec *timeout,
                            SyscallDataType return_value) -> void = 0;
  virtual auto io_pgetevents(aio_context_t ctx_id, long min_nr, long nr,
                             io_event *events, __kernel_timespec *timeout,
                             const __aio_sigset *sig,
                             SyscallDataType return_value) -> void = 0;
  virtual auto io_uring_setup(uint32_t entries, io_uring_params *p,
                              SyscallDataType return_value) -> void = 0;
  virtual auto io_uring_enter(unsigned int fd, uint32_t to_submit,
                              uint32_t min_complete, uint32_t flags,
                              const void *argp, size_t argsz,
                              SyscallDataType return_value) -> void = 0;
  virtual auto io_uring_register(unsigned int fd, unsigned int op, void *arg,
                                 unsigned int nr_args,
                                 SyscallDataType return_value) -> void = 0;
  virtual auto setxattr(const char *path, const char *name, const void *value,
                        size_t size, int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto lsetxattr(const char *path, const char *name, const void *value,
                         size_t size, int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto fsetxattr(int fd, const char *name, const void *value,
                         size_t size, int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto getxattr(const char *path, const char *name, void *value,
                        size_t size, SyscallDataType return_value) -> void = 0;
  virtual auto lgetxattr(const char *path, const char *name, void *value,
                         size_t size, SyscallDataType return_value) -> void = 0;
  virtual auto fgetxattr(int fd, const char *name, void *value, size_t size,
                         SyscallDataType return_value) -> void = 0;
  virtual auto listxattr(const char *path, char *list, size_t size,
                         SyscallDataType return_value) -> void = 0;
  virtual auto llistxattr(const char *path, char *list, size_t size,
                          SyscallDataType return_value) -> void = 0;
  virtual auto flistxattr(int fd, char *list, size_t size,
                          SyscallDataType return_value) -> void = 0;
  virtual auto removexattr(const char *path, const char *name,
                           SyscallDataType return_value) -> void = 0;
  virtual auto lremovexattr(const char *path, const char *name,
                            SyscallDataType return_value) -> void = 0;
  virtual auto fremovexattr(int fd, const char *name,
                            SyscallDataType return_value) -> void = 0;
  virtual auto getcwd(char *buf, unsigned long size,
                      SyscallDataType return_value) -> void = 0;
  virtual auto lookup_dcookie(uint64_t cookie64, char *buf, size_t len,
                              SyscallDataType return_value) -> void = 0;
  virtual auto eventfd2(unsigned int count, int flags,
                        SyscallDataType return_value) -> void = 0;
  virtual auto epoll_create1(int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto epoll_ctl(int epfd, int op, int fd, epoll_event *event,
                         SyscallDataType return_value) -> void = 0;
  virtual auto epoll_pwait(int epfd, epoll_event *events, int maxevents,
                           int timeout, const sigset_t *sigmask,
                           size_t sigsetsize, SyscallDataType return_value)
      -> void = 0;
  virtual auto epoll_pwait2(int epfd, epoll_event *events, int maxevents,
                            const __kernel_timespec *timeout,
                            const sigset_t *sigmask, size_t sigsetsize,
                            SyscallDataType return_value) -> void = 0;
  virtual auto dup(unsigned int fildes, SyscallDataType return_value)
      -> void = 0;
  virtual auto dup3(unsigned int oldfd, unsigned int newfd, int flags,
                    SyscallDataType return_value) -> void = 0;
  virtual auto fcntl(unsigned int fd, unsigned int cmd, unsigned long arg,
                     SyscallDataType return_value) -> void = 0;
  virtual auto fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg,
                       SyscallDataType return_value) -> void = 0;
  virtual auto inotify_init1(int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto inotify_add_watch(int fd, const char *path, uint32_t mask,
                                 SyscallDataType return_value) -> void = 0;
  virtual auto inotify_rm_watch(int fd, __s32 wd, SyscallDataType return_value)
      -> void = 0;
  virtual auto ioctl(unsigned int fd, unsigned int cmd, unsigned long arg,
                     SyscallDataType return_value) -> void = 0;
  virtual auto ioprio_set(int which, int who, int ioprio,
                          SyscallDataType return_value) -> void = 0;
  virtual auto ioprio_get(int which, int who, SyscallDataType return_value)
      -> void = 0;
  virtual auto flock(unsigned int fd, unsigned int cmd,
                     SyscallDataType return_value) -> void = 0;
  virtual auto mknodat(int dfd, const char *filename, mode_t mode, unsigned dev,
                       SyscallDataType return_value) -> void = 0;
  virtual auto mkdirat(int dfd, const char *pathname, mode_t mode,
                       SyscallDataType return_value) -> void = 0;
  virtual auto unlinkat(int dfd, const char *pathname, int flag,
                        SyscallDataType return_value) -> void = 0;
  virtual auto symlinkat(const char *oldname, int newdfd, const char *newname,
                         SyscallDataType return_value) -> void = 0;
  virtual auto linkat(int olddfd, const char *oldname, int newdfd,
                      const char *newname, int flags,
                      SyscallDataType return_value) -> void = 0;
  virtual auto renameat(int olddfd, const char *oldname, int newdfd,
                        const char *newname, SyscallDataType return_value)
      -> void = 0;
  virtual auto umount(char *name, int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto mount(char *dev_name, char *dir_name, char *type,
                     unsigned long flags, void *data,
                     SyscallDataType return_value) -> void = 0;
  virtual auto pivot_root(const char *new_root, const char *put_old,
                          SyscallDataType return_value) -> void = 0;
  virtual auto statfs(const char *path, statfs *buf,
                      SyscallDataType return_value) -> void = 0;
  virtual auto statfs64(const char *path, size_t sz, statfs64 *buf,
                        SyscallDataType return_value) -> void = 0;
  virtual auto fstatfs(unsigned int fd, statfs *buf,
                       SyscallDataType return_value) -> void = 0;
  virtual auto fstatfs64(unsigned int fd, size_t sz, statfs64 *buf,
                         SyscallDataType return_value) -> void = 0;
  virtual auto truncate(const char *path, long length,
                        SyscallDataType return_value) -> void = 0;
  virtual auto ftruncate(unsigned int fd, unsigned long length,
                         SyscallDataType return_value) -> void = 0;
  virtual auto truncate64(const char *path, loff_t length,
                          SyscallDataType return_value) -> void = 0;
  virtual auto ftruncate64(unsigned int fd, loff_t length,
                           SyscallDataType return_value) -> void = 0;
  virtual auto fallocate(int fd, int mode, loff_t offset, loff_t len,
                         SyscallDataType return_value) -> void = 0;
  virtual auto faccessat(int dfd, const char *filename, int mode,
                         SyscallDataType return_value) -> void = 0;
  virtual auto faccessat2(int dfd, const char *filename, int mode, int flags,
                          SyscallDataType return_value) -> void = 0;
  virtual auto chdir(const char *filename, SyscallDataType return_value)
      -> void = 0;
  virtual auto fchdir(unsigned int fd, SyscallDataType return_value)
      -> void = 0;
  virtual auto chroot(const char *filename, SyscallDataType return_value)
      -> void = 0;
  virtual auto fchmod(unsigned int fd, mode_t mode,
                      SyscallDataType return_value) -> void = 0;
  virtual auto fchmodat(int dfd, const char *filename, mode_t mode,
                        SyscallDataType return_value) -> void = 0;
  virtual auto fchownat(int dfd, const char *filename, uid_t user, gid_t group,
                        int flag, SyscallDataType return_value) -> void = 0;
  virtual auto fchown(unsigned int fd, uid_t user, gid_t group,
                      SyscallDataType return_value) -> void = 0;
  virtual auto openat(int dfd, const char *filename, int flags, mode_t mode,
                      SyscallDataType return_value) -> void = 0;
  virtual auto openat2(int dfd, const char *filename, open_how *how,
                       size_t size, SyscallDataType return_value) -> void = 0;
  virtual auto close(unsigned int fd, SyscallDataType return_value) -> void = 0;
  virtual auto close_range(unsigned int fd, unsigned int max_fd,
                           unsigned int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto vhangup(SyscallDataType return_value) -> void = 0;
  virtual auto pipe2(int *fildes, int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto quotactl(unsigned int cmd, const char *special, int id,
                        void *addr, SyscallDataType return_value) -> void = 0;
  virtual auto quotactl_path(unsigned int cmd, const char * /* unsupported */,
                             int id, void *addr, SyscallDataType return_value)
      -> void = 0;
  virtual auto getdents64(unsigned int fd, linux_dirent64 *dirent,
                          unsigned int count, SyscallDataType return_value)
      -> void = 0;
  virtual auto llseek(unsigned int fd, unsigned long offset_high,
                      unsigned long offset_low, loff_t *result,
                      unsigned int whence, SyscallDataType return_value)
      -> void = 0;
  virtual auto lseek(unsigned int fd, off_t offset, unsigned int whence,
                     SyscallDataType return_value) -> void = 0;
  virtual auto read(unsigned int fd, char *buf, size_t count,
                    SyscallDataType return_value) -> void = 0;
  virtual auto write(unsigned int fd, const char *buf, size_t count,
                     SyscallDataType return_value) -> void = 0;
  virtual auto readv(unsigned long fd, const iovec *vec, unsigned long vlen,
                     SyscallDataType return_value) -> void = 0;
  virtual auto writev(unsigned long fd, const iovec *vec, unsigned long vlen,
                      SyscallDataType return_value) -> void = 0;
  virtual auto pread64(unsigned int fd, char *buf, size_t count, loff_t pos,
                       SyscallDataType return_value) -> void = 0;
  virtual auto pwrite64(unsigned int fd, const char *buf, size_t count,
                        loff_t pos, SyscallDataType return_value) -> void = 0;
  virtual auto preadv(unsigned long fd, const iovec *vec, unsigned long vlen,
                      unsigned long pos_l, unsigned long pos_h,
                      SyscallDataType return_value) -> void = 0;
  virtual auto pwritev(unsigned long fd, const iovec *vec, unsigned long vlen,
                       unsigned long pos_l, unsigned long pos_h,
                       SyscallDataType return_value) -> void = 0;
  virtual auto sendfile64(int out_fd, int in_fd, loff_t *offset, size_t count,
                          SyscallDataType return_value) -> void = 0;
  virtual auto pselect6(int, fd_set *, fd_set *, fd_set *, __kernel_timespec *,
                        void *, SyscallDataType return_value) -> void = 0;
  virtual auto ppoll(pollfd *, unsigned int, __kernel_timespec *,
                     const sigset_t *, size_t, SyscallDataType return_value)
      -> void = 0;
  virtual auto signalfd4(int ufd, sigset_t *user_mask, size_t sizemask,
                         int flags, SyscallDataType return_value) -> void = 0;
  virtual auto vmsplice(int fd, const iovec *iov, unsigned long nr_segs,
                        unsigned int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                      size_t len, unsigned int flags,
                      SyscallDataType return_value) -> void = 0;
  virtual auto tee(int fdin, int fdout, size_t len, unsigned int flags,
                   SyscallDataType return_value) -> void = 0;
  virtual auto readlinkat(int dfd, const char *path, char *buf, int bufsiz,
                          SyscallDataType return_value) -> void = 0;
  virtual auto newfstatat(int dfd, const char *filename, stat *statbuf,
                          int flag, SyscallDataType return_value) -> void = 0;
  virtual auto newfstat(unsigned int fd, stat *statbuf,
                        SyscallDataType return_value) -> void = 0;
  virtual auto fstat64(unsigned long fd, stat64 *statbuf,
                       SyscallDataType return_value) -> void = 0;
  virtual auto fstatat64(int dfd, const char *filename, stat64 *statbuf,
                         int flag, SyscallDataType return_value) -> void = 0;
  virtual auto sync(SyscallDataType return_value) -> void = 0;
  virtual auto fsync(unsigned int fd, SyscallDataType return_value) -> void = 0;
  virtual auto fdatasync(unsigned int fd, SyscallDataType return_value)
      -> void = 0;
  virtual auto sync_file_range2(int fd, unsigned int flags, loff_t offset,
                                loff_t nbytes, SyscallDataType return_value)
      -> void = 0;
  virtual auto sync_file_range(int fd, loff_t offset, loff_t nbytes,
                               unsigned int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto timerfd_create(int clockid, int flags,
                              SyscallDataType return_value) -> void = 0;
  virtual auto timerfd_settime(int ufd, int flags,
                               const __kernel_itimerspec *utmr,
                               __kernel_itimerspec *otmr,
                               SyscallDataType return_value) -> void = 0;
  virtual auto timerfd_gettime(int ufd, __kernel_itimerspec *otmr,
                               SyscallDataType return_value) -> void = 0;
  virtual auto utimensat(int dfd, const char *filename,
                         __kernel_timespec *utimes, int flags,
                         SyscallDataType return_value) -> void = 0;
  virtual auto acct(const char *name, SyscallDataType return_value) -> void = 0;
  virtual auto capget(int /* unsupported */ header,
                      int /* unsupported */ dataptr,
                      SyscallDataType return_value) -> void = 0;
  virtual auto capset(int /* unsupported */ header,
                      const int /* unsupported */ data,
                      SyscallDataType return_value) -> void = 0;
  virtual auto personality(unsigned int personality,
                           SyscallDataType return_value) -> void = 0;
  virtual auto exit(int error_code, SyscallDataType return_value) -> void = 0;
  virtual auto exit_group(int error_code, SyscallDataType return_value)
      -> void = 0;
  virtual auto waitid(int which, pid_t pid, siginfo *infop, int options,
                      rusage *ru, SyscallDataType return_value) -> void = 0;
  virtual auto set_tid_address(int *tidptr, SyscallDataType return_value)
      -> void = 0;
  virtual auto unshare(unsigned long unshare_flags,
                       SyscallDataType return_value) -> void = 0;
  virtual auto futex(uint32_t *uaddr, int op, uint32_t val,
                     const __kernel_timespec *utime, uint32_t *uaddr2,
                     uint32_t val3, SyscallDataType return_value) -> void = 0;
  virtual auto get_robust_list(int pid, robust_list_head **head_ptr,
                               size_t *len_ptr, SyscallDataType return_value)
      -> void = 0;
  virtual auto set_robust_list(robust_list_head *head, size_t len,
                               SyscallDataType return_value) -> void = 0;
  virtual auto nanosleep(__kernel_timespec *rqtp, __kernel_timespec *rmtp,
                         SyscallDataType return_value) -> void = 0;
  virtual auto getitimer(int which, __kernel_itimerval *value,
                         SyscallDataType return_value) -> void = 0;
  virtual auto setitimer(int which, __kernel_itimerval *value,
                         __kernel_itimerval *ovalue,
                         SyscallDataType return_value) -> void = 0;
  virtual auto kexec_load(unsigned long entry, unsigned long nr_segments,
                          kexec_segment *segments, unsigned long flags,
                          SyscallDataType return_value) -> void = 0;
  virtual auto init_module(void *umod, unsigned long len, const char *uargs,
                           SyscallDataType return_value) -> void = 0;
  virtual auto delete_module(const char *name_user, unsigned int flags,
                             SyscallDataType return_value) -> void = 0;
  virtual auto timer_create(clockid_t which_clock, sigevent *timer_event_spec,
                            timer_t *created_timer_id,
                            SyscallDataType return_value) -> void = 0;
  virtual auto timer_gettime(timer_t timer_id, __kernel_itimerspec *setting,
                             SyscallDataType return_value) -> void = 0;
  virtual auto timer_getoverrun(timer_t timer_id, SyscallDataType return_value)
      -> void = 0;
  virtual auto timer_settime(timer_t timer_id, int flags,
                             const __kernel_itimerspec *new_setting,
                             __kernel_itimerspec *old_setting,
                             SyscallDataType return_value) -> void = 0;
  virtual auto timer_delete(timer_t timer_id, SyscallDataType return_value)
      -> void = 0;
  virtual auto clock_settime(clockid_t which_clock, const __kernel_timespec *tp,
                             SyscallDataType return_value) -> void = 0;
  virtual auto clock_gettime(clockid_t which_clock, __kernel_timespec *tp,
                             SyscallDataType return_value) -> void = 0;
  virtual auto clock_getres(clockid_t which_clock, __kernel_timespec *tp,
                            SyscallDataType return_value) -> void = 0;
  virtual auto clock_nanosleep(clockid_t which_clock, int flags,
                               const __kernel_timespec *rqtp,
                               __kernel_timespec *rmtp,
                               SyscallDataType return_value) -> void = 0;
  virtual auto syslog(int type, char *buf, int len,
                      SyscallDataType return_value) -> void = 0;
  virtual auto ptrace(long request, long pid, unsigned long addr,
                      unsigned long data, SyscallDataType return_value)
      -> void = 0;
  virtual auto sched_setparam(pid_t pid, sched_param *param,
                              SyscallDataType return_value) -> void = 0;
  virtual auto sched_setscheduler(pid_t pid, int policy, sched_param *param,
                                  SyscallDataType return_value) -> void = 0;
  virtual auto sched_getscheduler(pid_t pid, SyscallDataType return_value)
      -> void = 0;
  virtual auto sched_getparam(pid_t pid, sched_param *param,
                              SyscallDataType return_value) -> void = 0;
  virtual auto sched_setaffinity(pid_t pid, unsigned int len,
                                 unsigned long *user_mask_ptr,
                                 SyscallDataType return_value) -> void = 0;
  virtual auto sched_getaffinity(pid_t pid, unsigned int len,
                                 unsigned long *user_mask_ptr,
                                 SyscallDataType return_value) -> void = 0;
  virtual auto sched_yield(SyscallDataType return_value) -> void = 0;
  virtual auto sched_get_priority_max(int policy, SyscallDataType return_value)
      -> void = 0;
  virtual auto sched_get_priority_min(int policy, SyscallDataType return_value)
      -> void = 0;
  virtual auto sched_rr_get_interval(pid_t pid, __kernel_timespec *interval,
                                     SyscallDataType return_value) -> void = 0;
  virtual auto restart_syscall(SyscallDataType return_value) -> void = 0;
  virtual auto kill(pid_t pid, int sig, SyscallDataType return_value)
      -> void = 0;
  virtual auto tkill(pid_t pid, int sig, SyscallDataType return_value)
      -> void = 0;
  virtual auto tgkill(pid_t tgid, pid_t pid, int sig,
                      SyscallDataType return_value) -> void = 0;
  virtual auto sigaltstack(const sigaltstack *uss, sigaltstack *uoss,
                           SyscallDataType return_value) -> void = 0;
  virtual auto rt_sigsuspend(sigset_t *unewset, size_t sigsetsize,
                             SyscallDataType return_value) -> void = 0;
  virtual auto rt_sigaction(int, const sigaction *, sigaction *, size_t,
                            SyscallDataType return_value) -> void = 0;
  virtual auto rt_sigprocmask(int how, sigset_t *set, sigset_t *oset,
                              size_t sigsetsize, SyscallDataType return_value)
      -> void = 0;
  virtual auto rt_sigpending(sigset_t *set, size_t sigsetsize,
                             SyscallDataType return_value) -> void = 0;
  virtual auto rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
                               const __kernel_timespec *uts, size_t sigsetsize,
                               SyscallDataType return_value) -> void = 0;
  virtual auto rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *uinfo,
                               SyscallDataType return_value) -> void = 0;
  virtual auto setpriority(int which, int who, int niceval,
                           SyscallDataType return_value) -> void = 0;
  virtual auto getpriority(int which, int who, SyscallDataType return_value)
      -> void = 0;
  virtual auto reboot(int magic1, int magic2, unsigned int cmd, void *arg,
                      SyscallDataType return_value) -> void = 0;
  virtual auto setregid(gid_t rgid, gid_t egid, SyscallDataType return_value)
      -> void = 0;
  virtual auto setgid(gid_t gid, SyscallDataType return_value) -> void = 0;
  virtual auto setreuid(uid_t ruid, uid_t euid, SyscallDataType return_value)
      -> void = 0;
  virtual auto setuid(uid_t uid, SyscallDataType return_value) -> void = 0;
  virtual auto setresuid(uid_t ruid, uid_t euid, uid_t suid,
                         SyscallDataType return_value) -> void = 0;
  virtual auto getresuid(uid_t *ruid, uid_t *euid, uid_t *suid,
                         SyscallDataType return_value) -> void = 0;
  virtual auto setresgid(gid_t rgid, gid_t egid, gid_t sgid,
                         SyscallDataType return_value) -> void = 0;
  virtual auto getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid,
                         SyscallDataType return_value) -> void = 0;
  virtual auto setfsuid(uid_t uid, SyscallDataType return_value) -> void = 0;
  virtual auto setfsgid(gid_t gid, SyscallDataType return_value) -> void = 0;
  virtual auto times(tms *tbuf, SyscallDataType return_value) -> void = 0;
  virtual auto setpgid(pid_t pid, pid_t pgid, SyscallDataType return_value)
      -> void = 0;
  virtual auto getpgid(pid_t pid, SyscallDataType return_value) -> void = 0;
  virtual auto getsid(pid_t pid, SyscallDataType return_value) -> void = 0;
  virtual auto setsid(SyscallDataType return_value) -> void = 0;
  virtual auto getgroups(int gidsetsize, gid_t *grouplist,
                         SyscallDataType return_value) -> void = 0;
  virtual auto setgroups(int gidsetsize, gid_t *grouplist,
                         SyscallDataType return_value) -> void = 0;
  virtual auto newuname(new_utsname *name, SyscallDataType return_value)
      -> void = 0;
  virtual auto sethostname(char *name, int len, SyscallDataType return_value)
      -> void = 0;
  virtual auto setdomainname(char *name, int len, SyscallDataType return_value)
      -> void = 0;
  virtual auto getrlimit(unsigned int resource, rlimit *rlim,
                         SyscallDataType return_value) -> void = 0;
  virtual auto setrlimit(unsigned int resource, rlimit *rlim,
                         SyscallDataType return_value) -> void = 0;
  virtual auto getrusage(int who, rusage *ru, SyscallDataType return_value)
      -> void = 0;
  virtual auto umask(int mask, SyscallDataType return_value) -> void = 0;
  virtual auto prctl(int option, unsigned long arg2, unsigned long arg3,
                     unsigned long arg4, unsigned long arg5,
                     SyscallDataType return_value) -> void = 0;
  virtual auto getcpu(unsigned *cpu, unsigned *node, getcpu_cache *cache,
                      SyscallDataType return_value) -> void = 0;
  virtual auto gettimeofday(__kernel_timeval *tv, timezone *tz,
                            SyscallDataType return_value) -> void = 0;
  virtual auto settimeofday(__kernel_timeval *tv, timezone *tz,
                            SyscallDataType return_value) -> void = 0;
  virtual auto adjtimex(__kernel_timex *txc_p, SyscallDataType return_value)
      -> void = 0;
  virtual auto getpid(SyscallDataType return_value) -> void = 0;
  virtual auto getppid(SyscallDataType return_value) -> void = 0;
  virtual auto getuid(SyscallDataType return_value) -> void = 0;
  virtual auto geteuid(SyscallDataType return_value) -> void = 0;
  virtual auto getgid(SyscallDataType return_value) -> void = 0;
  virtual auto getegid(SyscallDataType return_value) -> void = 0;
  virtual auto gettid(SyscallDataType return_value) -> void = 0;
  virtual auto sysinfo(sysinfo *info, SyscallDataType return_value) -> void = 0;
  virtual auto mq_open(const char *name, int oflag, mode_t mode, mq_attr *attr,
                       SyscallDataType return_value) -> void = 0;
  virtual auto mq_unlink(const char *name, SyscallDataType return_value)
      -> void = 0;
  virtual auto mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
                            unsigned int msg_prio,
                            const __kernel_timespec *abs_timeout,
                            SyscallDataType return_value) -> void = 0;
  virtual auto mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
                               unsigned int *msg_prio,
                               const __kernel_timespec *abs_timeout,
                               SyscallDataType return_value) -> void = 0;
  virtual auto mq_notify(mqd_t mqdes, const sigevent *notification,
                         SyscallDataType return_value) -> void = 0;
  virtual auto mq_getsetattr(mqd_t mqdes, const mq_attr *mqstat,
                             mq_attr *omqstat, SyscallDataType return_value)
      -> void = 0;
  virtual auto msgget(key_t key, int msgflg, SyscallDataType return_value)
      -> void = 0;
  virtual auto old_msgctl(int msqid, int cmd, msqid_ds *buf,
                          SyscallDataType return_value) -> void = 0;
  virtual auto msgctl(int msqid, int cmd, msqid_ds *buf,
                      SyscallDataType return_value) -> void = 0;
  virtual auto msgrcv(int msqid, msgbuf *msgp, size_t msgsz, long msgtyp,
                      int msgflg, SyscallDataType return_value) -> void = 0;
  virtual auto msgsnd(int msqid, msgbuf *msgp, size_t msgsz, int msgflg,
                      SyscallDataType return_value) -> void = 0;
  virtual auto semget(key_t key, int nsems, int semflg,
                      SyscallDataType return_value) -> void = 0;
  virtual auto semctl(int semid, int semnum, int cmd, unsigned long arg,
                      SyscallDataType return_value) -> void = 0;
  virtual auto old_semctl(int semid, int semnum, int cmd, unsigned long arg,
                          SyscallDataType return_value) -> void = 0;
  virtual auto semtimedop(int semid, sembuf *sops, unsigned nsops,
                          const __kernel_timespec *timeout,
                          SyscallDataType return_value) -> void = 0;
  virtual auto semop(int semid, sembuf *sops, unsigned nsops,
                     SyscallDataType return_value) -> void = 0;
  virtual auto shmget(key_t key, size_t size, int flag,
                      SyscallDataType return_value) -> void = 0;
  virtual auto old_shmctl(int shmid, int cmd, shmid_ds *buf,
                          SyscallDataType return_value) -> void = 0;
  virtual auto shmctl(int shmid, int cmd, shmid_ds *buf,
                      SyscallDataType return_value) -> void = 0;
  virtual auto shmat(int shmid, char *shmaddr, int shmflg,
                     SyscallDataType return_value) -> void = 0;
  virtual auto shmdt(char *shmaddr, SyscallDataType return_value) -> void = 0;
  virtual auto socket(int, int, int, SyscallDataType return_value) -> void = 0;
  virtual auto socketpair(int, int, int, int *, SyscallDataType return_value)
      -> void = 0;
  virtual auto bind(int, sockaddr *, int, SyscallDataType return_value)
      -> void = 0;
  virtual auto listen(int, int, SyscallDataType return_value) -> void = 0;
  virtual auto accept(int, sockaddr *, int *, SyscallDataType return_value)
      -> void = 0;
  virtual auto connect(int, sockaddr *, int, SyscallDataType return_value)
      -> void = 0;
  virtual auto getsockname(int, sockaddr *, int *, SyscallDataType return_value)
      -> void = 0;
  virtual auto getpeername(int, sockaddr *, int *, SyscallDataType return_value)
      -> void = 0;
  virtual auto sendto(int, void *, size_t, unsigned, sockaddr *, int,
                      SyscallDataType return_value) -> void = 0;
  virtual auto recvfrom(int, void *, size_t, unsigned, sockaddr *, int *,
                        SyscallDataType return_value) -> void = 0;
  virtual auto setsockopt(int fd, int level, int optname, char *optval,
                          int optlen, SyscallDataType return_value) -> void = 0;
  virtual auto getsockopt(int fd, int level, int optname, char *optval,
                          int *optlen, SyscallDataType return_value)
      -> void = 0;
  virtual auto shutdown(int, int, SyscallDataType return_value) -> void = 0;
  virtual auto sendmsg(int fd, user_msghdr *msg, unsigned flags,
                       SyscallDataType return_value) -> void = 0;
  virtual auto recvmsg(int fd, user_msghdr *msg, unsigned flags,
                       SyscallDataType return_value) -> void = 0;
  virtual auto readahead(int fd, loff_t offset, size_t count,
                         SyscallDataType return_value) -> void = 0;
  virtual auto brk(unsigned long brk, SyscallDataType return_value) -> void = 0;
  virtual auto munmap(unsigned long addr, size_t len,
                      SyscallDataType return_value) -> void = 0;
  virtual auto mremap(unsigned long addr, unsigned long old_len,
                      unsigned long new_len, unsigned long flags,
                      unsigned long new_addr, SyscallDataType return_value)
      -> void = 0;
  virtual auto add_key(const char *_type, const char *_description,
                       const void *_payload, size_t plen,
                       int /* unsupported */ destringid,
                       SyscallDataType return_value) -> void = 0;
  virtual auto request_key(const char *_type, const char *_description,
                           const char *_callout_info,
                           int /* unsupported */ destringid,
                           SyscallDataType return_value) -> void = 0;
  virtual auto keyctl(int cmd, unsigned long arg2, unsigned long arg3,
                      unsigned long arg4, unsigned long arg5,
                      SyscallDataType return_value) -> void = 0;
  virtual auto clone(unsigned long, unsigned long, int *, int *, unsigned long,
                     SyscallDataType return_value) -> void = 0;
  virtual auto clone3(clone_args *uargs, size_t size,
                      SyscallDataType return_value) -> void = 0;
  virtual auto execve(const char *filename, const char *const *argv,
                      const char *const *envp, SyscallDataType return_value)
      -> void = 0;
  virtual auto fadvise64_64(int fd, loff_t offset, loff_t len, int advice,
                            SyscallDataType return_value) -> void = 0;
  virtual auto swapon(const char *specialfile, int swap_flags,
                      SyscallDataType return_value) -> void = 0;
  virtual auto swapoff(const char *specialfile, SyscallDataType return_value)
      -> void = 0;
  virtual auto mprotect(unsigned long start, size_t len, unsigned long prot,
                        SyscallDataType return_value) -> void = 0;
  virtual auto msync(unsigned long start, size_t len, int flags,
                     SyscallDataType return_value) -> void = 0;
  virtual auto mlock(unsigned long start, size_t len,
                     SyscallDataType return_value) -> void = 0;
  virtual auto munlock(unsigned long start, size_t len,
                       SyscallDataType return_value) -> void = 0;
  virtual auto mlockall(int flags, SyscallDataType return_value) -> void = 0;
  virtual auto munlockall(SyscallDataType return_value) -> void = 0;
  virtual auto mincore(unsigned long start, size_t len, unsigned char *vec,
                       SyscallDataType return_value) -> void = 0;
  virtual auto madvise(unsigned long start, size_t len, int behavior,
                       SyscallDataType return_value) -> void = 0;
  virtual auto process_madvise(int pidfd, const iovec *vec, size_t vlen,
                               int behavior, unsigned int flags,
                               SyscallDataType return_value) -> void = 0;
  virtual auto remap_file_pages(unsigned long start, unsigned long size,
                                unsigned long prot, unsigned long pgoff,
                                unsigned long flags,
                                SyscallDataType return_value) -> void = 0;
  virtual auto mbind(unsigned long start, unsigned long len, unsigned long mode,
                     const unsigned long *nmask, unsigned long maxnode,
                     unsigned flags, SyscallDataType return_value) -> void = 0;
  virtual auto get_mempolicy(int *policy, unsigned long *nmask,
                             unsigned long maxnode, unsigned long addr,
                             unsigned long flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto set_mempolicy(int mode, const unsigned long *nmask,
                             unsigned long maxnode,
                             SyscallDataType return_value) -> void = 0;
  virtual auto migrate_pages(pid_t pid, unsigned long maxnode,
                             const unsigned long *from, const unsigned long *to,
                             SyscallDataType return_value) -> void = 0;
  virtual auto move_pages(pid_t pid, unsigned long nr_pages, const void **pages,
                          const int *nodes, int *status, int flags,
                          SyscallDataType return_value) -> void = 0;
  virtual auto rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig,
                                 siginfo_t *uinfo, SyscallDataType return_value)
      -> void = 0;
  virtual auto perf_event_open(perf_event_attr *attr_uptr, pid_t pid, int cpu,
                               int group_fd, unsigned long flags,
                               SyscallDataType return_value) -> void = 0;
  virtual auto accept4(int, sockaddr *, int *, int,
                       SyscallDataType return_value) -> void = 0;
  virtual auto recvmmsg(int fd, mmsghdr *msg, unsigned int vlen, unsigned flags,
                        __kernel_timespec *timeout,
                        SyscallDataType return_value) -> void = 0;
  virtual auto wait4(pid_t pid, int *stat_addr, int options, rusage *ru,
                     SyscallDataType return_value) -> void = 0;
  virtual auto prlimit64(pid_t pid, unsigned int resource,
                         const rlimit64 *new_rlim, rlimit64 *old_rlim,
                         SyscallDataType return_value) -> void = 0;
  virtual auto fanotify_init(unsigned int flags, unsigned int event_f_flags,
                             SyscallDataType return_value) -> void = 0;
  virtual auto fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask,
                             int fd, const char *pathname,
                             SyscallDataType return_value) -> void = 0;
  virtual auto name_to_handle_at(int dfd, const char *name, file_handle *handle,
                                 int *mnt_id, int flag,
                                 SyscallDataType return_value) -> void = 0;
  virtual auto open_by_handle_at(int mountdirfd, file_handle *handle, int flags,
                                 SyscallDataType return_value) -> void = 0;
  virtual auto clock_adjtime(clockid_t which_clock, __kernel_timex *tx,
                             SyscallDataType return_value) -> void = 0;
  virtual auto syncfs(int fd, SyscallDataType return_value) -> void = 0;
  virtual auto setns(int fd, int nstype, SyscallDataType return_value)
      -> void = 0;
  virtual auto pidfd_open(pid_t pid, unsigned int flags,
                          SyscallDataType return_value) -> void = 0;
  virtual auto sendmmsg(int fd, mmsghdr *msg, unsigned int vlen, unsigned flags,
                        SyscallDataType return_value) -> void = 0;
  virtual auto process_vm_readv(pid_t pid, const iovec *lvec,
                                unsigned long liovcnt, const iovec *rvec,
                                unsigned long riovcnt, unsigned long flags,
                                SyscallDataType return_value) -> void = 0;
  virtual auto process_vm_writev(pid_t pid, const iovec *lvec,
                                 unsigned long liovcnt, const iovec *rvec,
                                 unsigned long riovcnt, unsigned long flags,
                                 SyscallDataType return_value) -> void = 0;
  virtual auto kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1,
                    unsigned long idx2, SyscallDataType return_value)
      -> void = 0;
  virtual auto finit_module(int fd, const char *uargs, int flags,
                            SyscallDataType return_value) -> void = 0;
  virtual auto sched_setattr(pid_t pid, sched_attr *attr, unsigned int flags,
                             SyscallDataType return_value) -> void = 0;
  virtual auto sched_getattr(pid_t pid, sched_attr *attr, unsigned int size,
                             unsigned int flags, SyscallDataType return_value)
      -> void = 0;
  virtual auto renameat2(int olddfd, const char *oldname, int newdfd,
                         const char *newname, unsigned int flags,
                         SyscallDataType return_value) -> void = 0;
  virtual auto seccomp(unsigned int op, unsigned int flags, void *uargs,
                       SyscallDataType return_value) -> void = 0;
  virtual auto getrandom(char *buf, size_t count, unsigned int flags,
                         SyscallDataType return_value) -> void = 0;
  virtual auto memfd_create(const char *uname_ptr, unsigned int flags,
                            SyscallDataType return_value) -> void = 0;
  virtual auto bpf(int cmd, union bpf_attr *attr, unsigned int size,
                   SyscallDataType return_value) -> void = 0;
  virtual auto execveat(int dfd, const char *filename, const char *const *argv,
                        const char *const *envp, int flags,
                        SyscallDataType return_value) -> void = 0;
  virtual auto userfaultfd(int flags, SyscallDataType return_value) -> void = 0;
  virtual auto membarrier(int cmd, unsigned int flags, int cpu_id,
                          SyscallDataType return_value) -> void = 0;
  virtual auto mlock2(unsigned long start, size_t len, int flags,
                      SyscallDataType return_value) -> void = 0;
  virtual auto copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                               loff_t *off_out, size_t len, unsigned int flags,
                               SyscallDataType return_value) -> void = 0;
  virtual auto preadv2(unsigned long fd, const iovec *vec, unsigned long vlen,
                       unsigned long pos_l, unsigned long pos_h, int flags,
                       SyscallDataType return_value) -> void = 0;
  virtual auto pwritev2(unsigned long fd, const iovec *vec, unsigned long vlen,
                        unsigned long pos_l, unsigned long pos_h, int flags,
                        SyscallDataType return_value) -> void = 0;
  virtual auto pkey_mprotect(unsigned long start, size_t len,
                             unsigned long prot, int pkey,
                             SyscallDataType return_value) -> void = 0;
  virtual auto pkey_alloc(unsigned long flags, unsigned long init_val,
                          SyscallDataType return_value) -> void = 0;
  virtual auto pkey_free(int pkey, SyscallDataType return_value) -> void = 0;
  virtual auto statx(int dfd, const char *path, unsigned flags, unsigned mask,
                     statx *buffer, SyscallDataType return_value) -> void = 0;
  virtual auto rseq(rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig,
                    SyscallDataType return_value) -> void = 0;
  virtual auto open_tree(int dfd, const char *path, unsigned flags,
                         SyscallDataType return_value) -> void = 0;
  virtual auto move_mount(int from_dfd, const char *from_path, int to_dfd,
                          const char *to_path, unsigned int ms_flags,
                          SyscallDataType return_value) -> void = 0;
  virtual auto mount_setattr(int dfd, const char *path, unsigned int flags,
                             mount_attr *uattr, size_t usize,
                             SyscallDataType return_value) -> void = 0;
  virtual auto fsopen(const char *fs_name, unsigned int flags,
                      SyscallDataType return_value) -> void = 0;
  virtual auto fsconfig(int fs_fd, unsigned int cmd, const char *key,
                        const void *value, int aux,
                        SyscallDataType return_value) -> void = 0;
  virtual auto fsmount(int fs_fd, unsigned int flags, unsigned int ms_flags,
                       SyscallDataType return_value) -> void = 0;
  virtual auto fspick(int dfd, const char *path, unsigned int flags,
                      SyscallDataType return_value) -> void = 0;
  virtual auto pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
                                 unsigned int flags,
                                 SyscallDataType return_value) -> void = 0;
  virtual auto pidfd_getfd(int pidfd, int fd, unsigned int flags,
                           SyscallDataType return_value) -> void = 0;
  virtual auto landlock_create_ruleset(const landlock_ruleset_attr *attr,
                                       size_t size, __uint32_t flags,
                                       SyscallDataType return_value)
      -> void = 0;
  virtual auto landlock_add_rule(int ruleset_fd,
                                 int /* unsupported */ rule_type,
                                 const void *rule_attr, __uint32_t flags,
                                 SyscallDataType return_value) -> void = 0;
  virtual auto landlock_restrict_self(int ruleset_fd, __uint32_t flags,
                                      SyscallDataType return_value) -> void = 0;
  virtual auto ioperm(unsigned long from, unsigned long num, int on,
                      SyscallDataType return_value) -> void = 0;
  virtual auto pciconfig_read(unsigned long bus, unsigned long dfn,
                              unsigned long off, unsigned long len, void *buf,
                              SyscallDataType return_value) -> void = 0;
  virtual auto pciconfig_write(unsigned long bus, unsigned long dfn,
                               unsigned long off, unsigned long len, void *buf,
                               SyscallDataType return_value) -> void = 0;
  virtual auto pciconfig_iobase(long which, unsigned long bus,
                                unsigned long devfn,
                                SyscallDataType return_value) -> void = 0;
  virtual auto spu_run(int fd, __uint32_t *unpc, __uint32_t *ustatus,
                       SyscallDataType return_value) -> void = 0;
  virtual auto spu_create(const char *name, unsigned int flags, mode_t mode,
                          int fd, SyscallDataType return_value) -> void = 0;
  virtual auto open(const char *filename, int flags, mode_t mode,
                    SyscallDataType return_value) -> void = 0;
  virtual auto link(const char *oldname, const char *newname,
                    SyscallDataType return_value) -> void = 0;
  virtual auto unlink(const char *pathname, SyscallDataType return_value)
      -> void = 0;
  virtual auto mknod(const char *filename, mode_t mode, unsigned dev,
                     SyscallDataType return_value) -> void = 0;
  virtual auto chmod(const char *filename, mode_t mode,
                     SyscallDataType return_value) -> void = 0;
  virtual auto chown(const char *filename, uid_t user, gid_t group,
                     SyscallDataType return_value) -> void = 0;
  virtual auto mkdir(const char *pathname, mode_t mode,
                     SyscallDataType return_value) -> void = 0;
  virtual auto rmdir(const char *pathname, SyscallDataType return_value)
      -> void = 0;
  virtual auto lchown(const char *filename, uid_t user, gid_t group,
                      SyscallDataType return_value) -> void = 0;
  virtual auto access(const char *filename, int mode,
                      SyscallDataType return_value) -> void = 0;
  virtual auto rename(const char *oldname, const char *newname,
                      SyscallDataType return_value) -> void = 0;
  virtual auto symlink(const char *old, const char *linkpath,
                       SyscallDataType return_value) -> void = 0;
  virtual auto stat64(const char *filename, stat64 *statbuf,
                      SyscallDataType return_value) -> void = 0;
  virtual auto lstat64(const char *filename, stat64 *statbuf,
                       SyscallDataType return_value) -> void = 0;
  virtual auto pipe(int *fildes, SyscallDataType return_value) -> void = 0;
  virtual auto dup2(unsigned int oldfd, unsigned int newfd,
                    SyscallDataType return_value) -> void = 0;
  virtual auto epoll_create(int size, SyscallDataType return_value) -> void = 0;
  virtual auto inotify_init(SyscallDataType return_value) -> void = 0;
  virtual auto eventfd(unsigned int count, SyscallDataType return_value)
      -> void = 0;
  virtual auto signalfd(int ufd, sigset_t *user_mask, size_t sizemask,
                        SyscallDataType return_value) -> void = 0;
  virtual auto sendfile(int out_fd, int in_fd, off_t *offset, size_t count,
                        SyscallDataType return_value) -> void = 0;
  virtual auto newstat(const char *filename, stat *statbuf,
                       SyscallDataType return_value) -> void = 0;
  virtual auto newlstat(const char *filename, stat *statbuf,
                        SyscallDataType return_value) -> void = 0;
  virtual auto fadvise64(int fd, loff_t offset, size_t len, int advice,
                         SyscallDataType return_value) -> void = 0;
  virtual auto alarm(unsigned int seconds, SyscallDataType return_value)
      -> void = 0;
  virtual auto getpgrp(SyscallDataType return_value) -> void = 0;
  virtual auto pause(SyscallDataType return_value) -> void = 0;
  virtual auto time(__kernel_time_t *tloc, SyscallDataType return_value)
      -> void = 0;
  virtual auto utime(char *filename, utimbuf *times,
                     SyscallDataType return_value) -> void = 0;
  virtual auto utimes(char *filename, __kernel_timeval *utimes,
                      SyscallDataType return_value) -> void = 0;
  virtual auto futimesat(int dfd, const char *filename,
                         __kernel_timeval *utimes, SyscallDataType return_value)
      -> void = 0;
  virtual auto creat(const char *pathname, mode_t mode,
                     SyscallDataType return_value) -> void = 0;
  virtual auto getdents(unsigned int fd, linux_dirent *dirent,
                        unsigned int count, SyscallDataType return_value)
      -> void = 0;
  virtual auto select(int n, fd_set *inp, fd_set *outp, fd_set *exp,
                      __kernel_timeval *tvp, SyscallDataType return_value)
      -> void = 0;
  virtual auto poll(pollfd *ufds, unsigned int nfds, int timeout,
                    SyscallDataType return_value) -> void = 0;
  virtual auto epoll_wait(int epfd, epoll_event *events, int maxevents,
                          int timeout, SyscallDataType return_value)
      -> void = 0;
  virtual auto ustat(unsigned dev, ustat *ubuf, SyscallDataType return_value)
      -> void = 0;
  virtual auto vfork(SyscallDataType return_value) -> void = 0;
  virtual auto recv(int, void *, size_t, unsigned, SyscallDataType return_value)
      -> void = 0;
  virtual auto send(int, void *, size_t, unsigned, SyscallDataType return_value)
      -> void = 0;
  virtual auto bdflush(int func, long data, SyscallDataType return_value)
      -> void = 0;
  virtual auto oldumount(char *name, SyscallDataType return_value) -> void = 0;
  virtual auto uselib(const char *library, SyscallDataType return_value)
      -> void = 0;
  virtual auto sysfs(int option, unsigned long arg1, unsigned long arg2,
                     SyscallDataType return_value) -> void = 0;
  virtual auto fork(SyscallDataType return_value) -> void = 0;
  virtual auto stime(__kernel_time_t *tptr, SyscallDataType return_value)
      -> void = 0;
  virtual auto sigpending(sigset_t *uset, SyscallDataType return_value)
      -> void = 0;
  virtual auto sigprocmask(int how, sigset_t *set, sigset_t *oset,
                           SyscallDataType return_value) -> void = 0;
  virtual auto sigsuspend(int unused1, int unused2, sigset_t mask,
                          SyscallDataType return_value) -> void = 0;
  virtual auto sigaction(int, const sigaction *, sigaction *,
                         SyscallDataType return_value) -> void = 0;
  virtual auto sgetmask(SyscallDataType return_value) -> void = 0;
  virtual auto ssetmask(int newmask, SyscallDataType return_value) -> void = 0;
  virtual auto signal(int sig, __sighandler_t handler,
                      SyscallDataType return_value) -> void = 0;
  virtual auto nice(int increment, SyscallDataType return_value) -> void = 0;
  virtual auto kexec_file_load(int kernel_fd, int initrd_fd,
                               unsigned long cmdline_len,
                               const char *cmdline_ptr, unsigned long flags,
                               SyscallDataType return_value) -> void = 0;
  virtual auto waitpid(pid_t pid, int *stat_addr, int options,
                       SyscallDataType return_value) -> void = 0;
  virtual auto socketcall(int call, unsigned long *args,
                          SyscallDataType return_value) -> void = 0;
  virtual auto stat(const char *filename, __kernel_stat *statbuf,
                    SyscallDataType return_value) -> void = 0;
  virtual auto lstat(const char *filename, __kernel_stat *statbuf,
                     SyscallDataType return_value) -> void = 0;
  virtual auto fstat(unsigned int fd, __kernel_stat *statbuf,
                     SyscallDataType return_value) -> void = 0;
  virtual auto readlink(const char *path, char *buf, int bufsiz,
                        SyscallDataType return_value) -> void = 0;
  virtual auto old_select(sel_arg_ *arg, SyscallDataType return_value)
      -> void = 0;
  virtual auto old_readdir(unsigned int, linux_dirent *, unsigned int,
                           SyscallDataType return_value) -> void = 0;
  virtual auto gethostname(char *name, int len, SyscallDataType return_value)
      -> void = 0;
  virtual auto uname(utsname *, SyscallDataType return_value) -> void = 0;
  virtual auto olduname(oldutsname *, SyscallDataType return_value) -> void = 0;
  virtual auto old_getrlimit(unsigned int resource, rlimit *rlim,
                             SyscallDataType return_value) -> void = 0;
  virtual auto ipc(unsigned int call, int first, unsigned long second,
                   unsigned long third, void *ptr, long fifth,
                   SyscallDataType return_value) -> void = 0;
  virtual auto mmap(unsigned long addr, unsigned long len, unsigned long prot,
                    unsigned long flags, unsigned long fd, unsigned long pgoff,
                    SyscallDataType return_value) -> void = 0;
  virtual auto old_mmap(mmap_arg_ *arg, SyscallDataType return_value)
      -> void = 0;
  virtual auto ni_syscall(SyscallDataType return_value) -> void = 0;
  virtual auto arch_prctl(int code, unsigned long addr,
                          SyscallDataType return_value) -> void = 0;
};
