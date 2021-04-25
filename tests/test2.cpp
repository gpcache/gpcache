#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdio>
#include <sys/reg.h>
#include <cstdint>

int main()
{
  pid_t child = fork();
  if (child == 0)
  {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execl("/bin/ls", "ls", NULL);
  }
  else
  {
    wait(NULL);
    uint64_t orig_eax = ptrace(PTRACE_PEEKUSER,
                               child, 8 * ORIG_RAX,
                               NULL);
    printf("\n\nThe child made a "
           "system call %ld\n\n\n",
           orig_eax);
    ptrace(PTRACE_CONT, child, NULL, NULL);
  }
  return 0;
}
