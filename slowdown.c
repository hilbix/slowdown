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
static int		mypid;

static void
ex(int ret, const char *s, ...)
{
  va_list	list;
  int		e;

  e	= errno;
  fprintf(stderr, "[%d] %s error: ", mypid, arg0);
  va_start(list, s);
  vfprintf(stderr, s, list);
  va_end(list);
  fprintf(stderr, ": %s\n", strerror(e));
  exit(ret);
}

static void
warn(const char *s, ...)
{
  va_list	list;

  fprintf(stderr, "[%d] %s warn: ", mypid, arg0);
  va_start(list, s);
  vfprintf(stderr, s, list);
  va_end(list);
  fprintf(stderr, "\n");
}

static void
status(const char *s, ...)
{
  va_list	list;

  if (!verbose)
    return;

  fprintf(stderr, "[%d] %s status: ", mypid, arg0);
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
    ex(-1, "gettimeofday");
  ret	= nanosleep(&delay, NULL);
  if (gettimeofday(&b, NULL))
    ex(-1, "gettimeofday");
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

static int
set_delay(const char *arg)
{
  char	*end;

  errno		= EOVERFLOW;
  delay_us	= strtoul(arg, &end, 0);
  delay.tv_sec	= delay_us/1000;
  delay.tv_nsec	= (delay_us%1000)*1000000ul;
  is_delay	= delay_us!=0;
  delay_us	*= 1000;
  return !end || *end || (delay.tv_sec*1000000ull+delay.tv_nsec/1000ul)!=delay_us || delay.tv_sec>3600;
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
      if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
	ex(-1, "cannot attach to %ld", (long)pid);
      status("%ld attached", (long)pid);
      /* Just in case, revive process
       */
      ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

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
      if (is_delay &&
	  ptrace(PTRACE_TRACEME, 0, NULL, NULL))
	ex(-1, "ptrace(PTRACE_TRACEME)");
      /* Fork off the new process
       */
      execvp(argv[0], argv);
      ex(-1, "fork failed: %s", argv[0]);
    }
  else if (pid==(pid_t)-1)
    ex(-1, "fork");
  else
    status("%ld started", (long)pid);

  /* Start the wait loop
   *
   * The ptrace() delivers SIGTRAP each time the process is stopped.
   * We use PTRACE_SYSCALL below to stop the process each time it does
   * a syscall().  (This only happens if ptrace() is active.)
   */
  retval	= 129;	/* default in case of termsig/exitsig	*/
  retval_set	= 0;
  if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD))
    ex(-1, "ptrace(PTRACE_SETOPTIONS)");
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
	  ex(-1, "waitpid");
	}
      if (WIFEXITED(sta))
	{
	  /* Process terminated.
	   *
	   * If it's our child then remember the retval.  As more
	   * childs might be traced (future!) we continue here.  The
	   * wait above terminates anyways.
	   */
	  status("%ld exit %d", (long)pid2, WEXITSTATUS(sta));
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
	  status("%ld exitsig %d", (long)pid2, WTERMSIG(sta));
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
	  if (WSTOPSIG(sta)!=(SIGTRAP|0x80))
	    status("%ld signal %d", (long)pid2, WSTOPSIG(sta));

	  /* Do we want to detach cleanly?
	   */
	  else if (detach)
	    {
	      if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
		ex(-1, "ptrace(PTRACE_DETACH)");
	      status("%ld detached", (long)pid);
	      break;
	    }

	  /* Now delay the processing
	   */
	  do_delay();
	  /* EINTR is not defined according to the manual
	   */
	  if (ptrace(PTRACE_SYSCALL, pid2, NULL, ((WSTOPSIG(sta) & 0x80) ? 0 : WSTOPSIG(sta))))
	    ex(-1, "ptrace(PTRACE_SYSCALL)");
	  continue;
	}
#ifdef WCOREDUMP
      /* There are some systems which tell about cores
       *
       * Implemented according to the manual.
       */
      else if (WCOREDUMP(sta))
	status("%ld core", (long)pid2);
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
  status("%ld loops, %ld sleeps, retval %d", loops, sleeps, retval);
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
	  ex(-1, "stdin");
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
	      ex(-1, "stdout");
	    }
	  if (!put)
	    ex(-2, "EOF on stdout (broken pipe)");
	  i	+= put;
	}
    }
  status("%ld loops, %ld sleeps, bytes %ld", loops, sleeps, bytes);
  return 0;
}

static void
usage(const char *arg0)
{
  fprintf(stderr,
	  "Usage: %s [-v] delay [pid|program [args..]]\n"
	  "\t\tVersion " SLOWDOWN_VERSION " compiled " __DATE__ "\n"
	  "\t-v\tverbose status output\n"
	  "\t\tto suppress errors use 2>/dev/null\n"
	  "\tdelay is in milliseconds.  delays below system counter\n"
	  "\tresolution are compensated (through left out delays).\n"
	  "\tIf program is missing it copies stdin to stdout\n"
	  "\tand delays each line or read() (max. 4096 bytes).\n"
	  "\tElse program is fork()ed, ptrace()d and each syscall of it\n"
	  "\tis delayed as given.\n"
	  "\tIf program has no args and is a PID the PID is attached.\n"
	  "\tIf you terminate slowdown with an attached PID\n"
	  "\tand the program hangs, try 'slowdown 0 PID'.\n"
	  , arg0
	  );
}

static void
setarg0(const char *s)
{
  char	*tmp;

  mypid	= getpid();
  arg0	= s;
  if ((tmp=strrchr(arg0, '/'))!=0)
    arg0	= tmp+1;
}

int
main(int argc, char **argv)
{
  setarg0(argv[0]);
  verbose	= 0;
  if (argc>1 && !strcmp(argv[1], "-v"))
    {
      verbose	= 1;
      argc--;
      argv++;
    }
  if (argc<2)
    {
      usage(arg0);
      return 1;
    }
  if (set_delay(argv[1]))
    {
      perror(argv[1]);
      return 2;
    }
  if (argc>2)
    return delay_trace(argv+2);
  return delay_copy();
}
