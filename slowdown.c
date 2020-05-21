/* Slowdown programs based on syscalls.
 *
 * This is independent of tinolib (subdir tino/)
 *
 * This Works is placed under the terms of the Copyright Less License,
 * see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>

#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "slowdown_version.h"

static const char	*arg0;
static int		verbose;
#if 0
static int		jail, quiet, recursive;
#endif
static pid_t		mypid;

#define	FATAL(X)	do { if (X) OOPS("%s:%d:%s: FATAL INTERNAL ERROR: %s", __FILE__, __LINE__, __FUNCTION__, #X); } while (0)

static void
OOPS(const char *s, ...)
{
  va_list	list;
  int		e;

  e	= errno;
  fprintf(stderr, "[%ld] %s error: ", (long)mypid, arg0);
  va_start(list, s);
  vfprintf(stderr, s, list);
  va_end(list);
  fprintf(stderr, ": %s\n", strerror(e));
  exit(23);
}

static void
warn(const char *s, ...)
{
  va_list	list;

  fprintf(stderr, "[%ld] %s warn: ", (long)mypid, arg0);
  va_start(list, s);
  vfprintf(stderr, s, list);
  va_end(list);
  fprintf(stderr, "\n");
}

static void
status(pid_t pid, const char *s, ...)
{
  va_list	list;

  if (!verbose)
    return;

  fprintf(stderr, "[%ld] %s status: ", (long)mypid, arg0);
  if (pid)
    fprintf(stderr, "[%ld] ", (long)pid);
  va_start(list, s);
  vfprintf(stderr, s, list);
  va_end(list);
  fprintf(stderr, "\n");
}

#if 0
/* Switch of slowdown, send SIGTERM to child and terminate.
 *
 * This allows the child to react on SIGTERM, too.
 */
static void
sig_kill(void)
{
  000;
}

/* Set slowdown value to 0 (no slowdown)
 *
 * This allows the child to react on SIGHUP, too.  This sends no
 * SIGHUP to the child!
 */
static void
sig_hup(void)
{
  000;
}

/* Increment slowdown by 1 ms
 *
 * With SIGUSR1 and SIGUSR2 you can "pulse in" arbitrary values to
 * slowdown.  Just give a SIGHUP first.
 */
static void
sig_usr1(void)
{
  000;
}

/* Double slowdown,
 *
 * If value is 0 this presets to the user given value
 */
static void
sig_usr2(void)
{
  000;
}
#endif

static int			is_delay;
static struct timespec		delay;
static unsigned long long	delay_us;
static long			sleeps;

/* This obviously isn't precise.
 *
 * When I call it with 1ms it runs with 10ms, as this is the best
 * resolution of my kernel (my impression).  Sadly it does not return
 * the real time which elapsed.
 *
 * This can be repaied using explicite systemcalls, but I will not
 * implement this today.
 */
static int
do_delay(void)
{
#if 0
  struct timespec	elapsed;
#endif
  int			ret;
  struct timeval	a, b;
  static long long	miss_us;

  if (!is_delay)
    return 0;
  if ((miss_us+=delay_us)<0)
    return 0;
  sleeps++;
  if (gettimeofday(&a, NULL))
    OOPS("gettimeofday");
  ret	= nanosleep(&delay, NULL);
  if (gettimeofday(&b, NULL))
    OOPS("gettimeofday");
  miss_us	-= (b.tv_sec-a.tv_sec)*1000000ull+b.tv_usec-a.tv_usec;
#if 0
  if (!ret)
    {
      if (elapsed.tv_sec>delay.tv_sec ||
          (elapsed.tv_sec==delay.tv_sec &&
           elapsed.tv_nsec>delay.tv_nsec)
          )
        fprintf(stderr, ">\n");
    }
#endif
  return ret;
}

/* Attach to a given PID.
 *
 * Note: According to manual, ptrace() never delivers EINTR
 */
static void
ptrace__attach(pid_t pid)
{
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
    OOPS("cannot attach to %ld", (long)pid);
  status(pid, "attached");
}

/* Like ptrace__attach, but for children
 */
static void
ptrace__traceme(void)
{
  if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
  OOPS("ptrace(PTRACE_TRACEME)");
}

/* We use PTRACE_SYSCALL to stop the child each time it does
 * a syscall().  (This only happens if ptrace() is active.)
 */
static void
ptrace__syscall(pid_t pid, int sig)
{
  if (ptrace(PTRACE_SYSCALL, pid, NULL, sig))
    OOPS("ptrace(PTRACE_SYSCALL)");
}

#define	PTRACE__WSTOPSIG(sta)	(WSTOPSIG(sta) & ~0x80)
#define	PTRACE__WIFPTRACED(sta)	(WSTOPSIG(sta) & 0x80)		/* WIFPTRACED() is missing	*/

/* ptrace() delivers SIGTRAP each time the process is stopped.
 *
 * To be able to distinguish ptrace()'s SIGTRAP from other
 * SIGTRAP, we need to set an option, so ptrace()'s SIGTRAP
 * will be delivered as PTRACE__WSTOPSIG
 */
static void
ptrace__setoptions(pid_t pid)
{
  if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD))
    OOPS("ptrace(PTRACE_SETOPTIONS)");
  status(pid, "options");
}

/* Detach from a child.
 *
 * AFAICS this must be done in the right situation
 */
static void
ptrace__detach(pid_t pid)
{
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
    OOPS("ptrace(PTRACE_DETACH)");
  status(pid, "detached");
}

/* This routine is too long
 */
static int
delay_trace(char **argv)
{
  pid_t	pid;
  int	sta;
  long	loops;
  int	retval, retval_set;
  char	*end;
  int	detach;

  /* Detaching is not so easy as one might think.
   * As we are doing asynchronous things, we just cannot detach,
   * as there may be a signal which then is spuriously delivered
   * to the old parent if we detach.  So we must wait until we
   * got the process stopped such that we can detach cleanly.
   */
  detach	= 0;

  /* If program is a PID and there are no args attach to the process.
   */
  if (isdigit(argv[0][0]) && !argv[1] && (pid=strtol(argv[0], &end, 0))!=0 && end && !*end)
    {
      ptrace__attach(pid);
      ptrace__setoptions(pid);

#if 0
      /* Just in case, revive process
       */
      ptrace__syscall(pid, 0);
#endif

      /* Try to detach cleanly in case we had a stopped process
       */
      detach	= !is_delay;
    }
  else if ((pid=fork())==0)
    {
      /* Fork a child and start tracing.
       *
       * I observed, that this creates a SIGTRAP, so this process is
       * stopped for the wait below.
       *
       * If delay is set to 0 no trace is done.
       */
      if (is_delay)
        ptrace__traceme();
      /* Wait for the process
       */
      kill(getpid(), SIGSTOP);
      /* Fork off the new process
       */
      execvp(argv[0], argv);
      OOPS("fork failed: %s", argv[0]);
    }
  else if (pid==(pid_t)-1)
    OOPS("fork");
  else
    status(pid, "started");

  /* Start the wait loop
   */
  retval	= 129;	/* default in case of termsig/exitsig	*/
  retval_set	= 0;
  for (loops=1;;loops++)
    {
      pid_t	pid2;

      errno	= 0;
      pid2	= waitpid((pid_t)-1, &sta, WUNTRACED);
      if (pid2==(pid_t)-1)
        {
          if (!errno || errno==EINTR || errno==EAGAIN)
            continue;
          /* Wait terminates with ECHILD in case there are no more
           * childs left.
           */
          if (errno==ECHILD)
            break;		/* We do not have any more child processes	*/
          /* Some undetermined error occurred.
           * Bail out is best here, I hope.
           */
          OOPS("waitpid");
        }
      if (WIFEXITED(sta))
        {
          /* Process terminated.
           *
           * If it's our child then remember the retval.  As more
           * childs might be traced (future!) we continue here.  The
           * wait above terminates anyways.
           */
          status(pid2, "exit %d", WEXITSTATUS(sta));
          if (pid2==pid)
            {
              retval		= WEXITSTATUS(sta);
              retval_set++;
            }
        }
      else if (WIFSIGNALED(sta))
        {
          /* Process terminated due to signal.
           *
           * Usually you will see a warn "return value not set", as
           * the process is terminated without return value.
           */
          status(pid2, "exit by signal %d", WTERMSIG(sta));
          /* WIFEXITED() from pid will follow	*/
        }
      else if (WIFSTOPPED(sta))
        {
          /* Process stopped due to ptrace() or signal
           *
           * If it's SIGTRAP it's ptrace() in our case, so do not
           * report in this case.  There shall be some way to
           * distinguish between ptrace() and "kill -TRAP", but I do
           * not know any.
           *
           * For other signals you will see that it's delivered, which
           * is not a bad "debugging sideeffect", I think ;)
           */
          if (!PTRACE__WIFPTRACED(sta))
            status(pid2, "signal %d", WSTOPSIG(sta));

          /* Do we want to detach cleanly?
           */
          else if (detach)
            {
              ptrace__detach(pid2);
              if (pid == pid2)
                break;
            }

          /* Now delay the processing
           */
          do_delay();
          ptrace__syscall(pid2, (PTRACE__WIFPTRACED(sta) ? 0 : WSTOPSIG(sta)));
          continue;
        }
#ifdef WCOREDUMP
      /* There are some systems which tell about cores
       *
       * Implemented according to the manual.
       */
      else if (WCOREDUMP(sta))
        status(pid2, "coredump");
#endif
      /* Well, hit me, but sometimes things happen, which I want to
       * know about.
       */
      else
        warn("unknown wait status 0x%x", sta);
    }
  /* Warn if we came here without seeing a proper return value.
   */
  if (!retval_set)
    warn("return value not set");
  /* Report closing status
   */
  status((pid_t)0, "%ld loops, %ld sleeps, retval %d", loops, sleeps, retval);
  /* Terminate with the return value of the forked process
   *
   * Well, this is true in the attached case, so we are stealing the
   * return value in this case ;)
   */
  return retval;
}

static int
delay_copy(void)
{
  int	got;
  char	buf[BUFSIZ];
  long	loops, bytes;

  /* Read the input blocks
   */
  bytes	= 0;
  for (loops=1; (got=read(0, buf, sizeof buf))!=0; loops++)
    {
      int	max, i;

      if (got<0)
        {
          if (errno==EINTR || errno==EAGAIN)
            {
              do_delay();
              continue;
            }
          OOPS("stdin");
        }
      bytes	+= got;

      /* output lines delayed
       *
       * If is_delay is not set, output full blocks
       */
      max	= is_delay ? 0 : got;
      for (i=0; i<got; )
        {
          int	put;

          while (max<got && buf[max++]!='\n');
          put	= write(1, buf+i, max-i);
          /* Delay after the write.
           *
           * I hate it to wait on the first round ;)
           */
          do_delay();
          if (put<0)
            {
              if (errno==EINTR || errno==EAGAIN)
                continue;
              OOPS("stdout");
            }
          if (!put)
            OOPS("EOF on stdout (broken pipe?)");
          i	+= put;
        }
    }
  status((pid_t)0, "%ld loops, %ld sleeps, bytes %ld", loops, sleeps, bytes);
  return 0;
}

static void
usage(void)
{
  fprintf(stderr,
          "Usage: %s [-options] delay [pid|program [args..]]\n"
          "\t\tVersion " SLOWDOWN_VERSION " compiled " __DATE__ "\n"
#if 0
          "\t-s\tjail\n"	/* I forgot why I introduced this	*/
          "\t-q\tquiet (suppress errors)\n"
          "\t-r\trecursive (follow forks etc.)\n"
#endif
          "\t-v\tverbose status output\n"
          "\tdelay is in milliseconds.  delays below system counter\n"
          "\tresolution are compensated (through left out delays).\n"
          "\tIf program is missing it copies stdin to stdout\n"
          "\tand delays each line or read() (max. 4096 bytes).\n"
          "\tElse program is fork()ed, ptrace()d and each syscall of it\n"
          "\tis delayed as given.\n"
          "\tIf program has no args and is a PID the PID is attached.\n"
          "\tIf you terminate slowdown with an attached PID\n"
          "\tand the program hangs, try 'slowdown 0 PID'.\n"
          "\treturns 23=error 42=usage, program return code or 0=EOF\n"
          , arg0
          );
  exit(42);
}

/* Parse options
 */
static void
setargs(int *argc, char ***argv)
{
  char	*tmp;

  mypid		= getpid();

  arg0		= **argv;
  if ((tmp=strrchr(arg0, '/'))!=0)
    arg0	= tmp+1;

#if 0
  jail		= 0;
  quiet		= 0;
  recursive	= 0;
#endif
  verbose	= 0;

  for (; *argc>1 && (tmp=argv[0][1])!=0 && *tmp++=='-' && *tmp; (*argc)--, (*argv)++)
    for (;;)
      {
        switch (*tmp++)
          {
#if 0
          case 'j':	jail++; continue;
          case 'q':	quiet++; continue;
          case 'r':	recursive++; continue;
#endif
          case 'v':	verbose++; continue;
          default:	usage();
          case 0:	break;
          }
        break;
      }

  if (*argc<2)
    usage();
}

/* Calculate delay from given string argument
 */
static void
set_delay(const char *arg)
{
  char	*end;

  delay_us	= strtoul(arg, &end, 0);
  is_delay	= delay_us!=0;

  delay.tv_sec	= delay_us/1000;
  delay.tv_nsec	= (delay_us%1000)*1000000ul;

  delay_us	*= 1000;

  if (!end || *end)
    OOPS("please give a positive milliseconds for delay");

  FATAL((delay.tv_sec*1000000ull+delay.tv_nsec/1000ul) != delay_us);
}

/* slowdown [options] ms
 * slowdown [options] ms PID
 * slowdown [options] ms cmd [args..]
 *
 * return:
 */
int
main(int argc, char **argv)
{
  setargs(&argc, &argv);

  set_delay(argv[1]);
  if (argc>2)
    return delay_trace(argv+2);
  return delay_copy();
}

