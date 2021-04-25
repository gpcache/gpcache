#include <sys/user.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <iostream>

#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <optional>

auto debugger()
{
  const pid_t child = fork();
  if (child == -1)
    throw "forking failed";

  if (child == 0)
  {
    ptrace(PTRACE_TRACEME);
    execl("/bin/ls", "ls", NULL);
    // execvp or any other way of exec

    throw "unreachable code";
  }
  else
  {
    bool enter_syscall = true;

    while (true)
    {
      ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE);
      int status = 0;
      waitpid(child, &status, 0);
      if (WIFEXITED(status))
        throw "Child has already exited";

      if (!WIFSTOPPED(status))
        throw "stopped something";

      if ((WSTOPSIG(status) & 0x80) != 0)
        throw "Stop reason is not syscall.";

      struct user_regs_struct user_regs;
      ptrace(PTRACE_GETREGS, child, 0, &user_regs);

      if (user_regs.orig_rax == 231 /* gotta love magic numbers */)
        fprintf(stderr, "+++ exited with %lld +++\n", user_regs.rdi);

      if (enter_syscall)
      {
        std::cout << syscall_name[user_regs.orig_rax] << "() = ";
        enter_syscall = false;
      }
      else
      {
        std::cout << static_cast<long long>(user_regs.rax);
        std::cout << std::endl;
        enter_syscall = true;
      }

      if (ptrace(PTRACE_CONT, child, NULL, NULL))
        throw "Continue failed";
    }
  }
  return 0;
}