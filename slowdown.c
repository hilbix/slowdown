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
static int		debug;
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

struct delay_info
  {
    int			is_delay;
    long long		sleeps;
    struct timespec	delay;
    unsigned long long	delay_us;
    long long		miss_us;
  };

struct trace_info
  {
    pid_t	pid;
    int		sta, sig, evt;
    int		detach, firststop;
    int		retval, retval_set;
    int		options;
    siginfo_t	si;
    struct delay_info	*delay;
    long long		loops;
  };

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
do_delay(struct delay_info *delay)
{
#if 0
  struct timespec	elapsed;
#endif
  int			ret;
  struct timeval	a, b;

  if (!delay->is_delay)
    return 0;
  if ((delay->miss_us += delay->delay_us)<0)
    return 0;
  delay->sleeps++;

  if (gettimeofday(&a, NULL))
    OOPS("gettimeofday");
  ret	= nanosleep(&delay->delay, NULL);
  if (gettimeofday(&b, NULL))
    OOPS("gettimeofday");
  delay->miss_us	-= (b.tv_sec-a.tv_sec)*1000000ull+b.tv_usec-a.tv_usec;
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
ptrace__attach(struct trace_info *inf)
{
  if (ptrace(PTRACE_ATTACH, inf->pid, NULL, NULL))
    OOPS("cannot attach to %ld", (long)inf->pid);
  status(inf->pid, "attached");
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
ptrace__syscall(struct trace_info *inf)
{
  if (ptrace(PTRACE_SYSCALL, inf->pid, NULL, inf->sig))
    OOPS("ptrace(PTRACE_SYSCALL)");
}

/* We need PTRACE_LISTEN in case the child is in groupstop
 * to avoid it being started when it is not supposed to.
 */
static void
ptrace__listen(struct trace_info *inf)
{
  if (ptrace(PTRACE_LISTEN, inf->pid, NULL, inf->sig))
    OOPS("ptrace(PTRACE_LISTEN)");
}

/* ptrace() delivers SIGTRAP each time the process is stopped.
 *
 * To be able to distinguish ptrace()'s SIGTRAP from other
 * SIGTRAP, we need to set an option, so ptrace()'s SIGTRAP
 * will be delivered as PTRACE__WSTOPSIG
 */
static void
ptrace__setoptions(struct trace_info *inf)
{
  if (ptrace(PTRACE_SETOPTIONS, inf->pid, NULL, inf->options))
    OOPS("ptrace(PTRACE_SETOPTIONS)");
  status(inf->pid, "options");
}

/* Detach from a child.
 *
 * AFAICS this must be done in the right situation
 */
static void
ptrace__detach(struct trace_info *inf)
{
  if (ptrace(PTRACE_DETACH, inf->pid, NULL, NULL))
    OOPS("ptrace(PTRACE_DETACH)");
  status(inf->pid, "detached");
}

static int
ptrace__getsiginfo(struct trace_info *inf)
{
  return ptrace(PTRACE_GETSIGINFO, inf->pid, 0, &inf->si);
}

enum ptrace__stops
  {
  PTRACE__SIGNAL,
  PTRACE__OPTIONS_MISSING,
  PTRACE__SYSCALL,
  PTRACE__GROUPSTOP,
  PTRACE__EVENTSTOP,
  PTRACE__TRAP,		/* I can observe spurious TRAPs, sigh	*/
  };

static enum ptrace__stops
ptrace__event(struct trace_info *inf)
{
  inf->sig	= inf->sta>>8;
  if (inf->sig & 0x80)
    {
      inf->sig	= 0;
      return PTRACE__SYSCALL;	/* options already applied	*/
    }

  if (inf->sig & ~0xff)
    switch (inf->evt = inf->sig >> 8)
      {
      default:
        warn("unknown extended status 0x%x", inf->sta);
        /* intended fall though	*/
      case PTRACE_EVENT_VFORK:
      case PTRACE_EVENT_FORK:
      case PTRACE_EVENT_CLONE:
      case PTRACE_EVENT_VFORK_DONE:
      case PTRACE_EVENT_EXEC:
      case PTRACE_EVENT_EXIT:
      case PTRACE_EVENT_SECCOMP:
        inf->sig	&= 0xff;
        return PTRACE__EVENTSTOP;

      /* PTRACE_EVENT_STOP is the only event stop which can be group stop either.
       * Isn't this name a little bit ironic, perhaps?
       */
      case PTRACE_EVENT_STOP:
        /* According to documentation, which sucks a lot BTW,
         * PTRACE_EVENT_STOP actually is a group stop condition.
         * Isn't the name a bit ironic then?
         */
        inf->sig	&= 0xff;
        return PTRACE__GROUPSTOP;
      }

  /* So we just have a 7 bit signal number.
   *
   * If it is SIGTRAP it might be a ptrace() signal.
   * If it is some other, it might be a event or group stop.
   * Else it is just a signal.
   *
   * This is all according to documentation which might
   * have changed incompatible in the last -1 us, of course.
   */
  switch (inf->sig)
    {
    default:		/* signal by sure	*/
      return PTRACE__SIGNAL;

    case SIGSTOP:	/* might be group stop or signal	*/
      if (inf->firststop)
        {
          inf->firststop = 0;
          inf->sig	= 0;
          return PTRACE__OPTIONS_MISSING;
        }
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU:
      if (!ptrace__getsiginfo(inf) || errno!=EINVAL)
        return PTRACE__SIGNAL;
      return PTRACE__GROUPSTOP;

    case SIGTRAP:	/* might be ptrace() or signal	*/
      if (ptrace__getsiginfo(inf))
        return PTRACE__OPTIONS_MISSING;
      break;
    }

  inf->sig	= 0;
  if (inf->si.si_code != SIGTRAP &&
      inf->si.si_code != (SIGTRAP | 0x80))
    return PTRACE__TRAP;
  return PTRACE__OPTIONS_MISSING;
}

static void
ptrace__loop(struct trace_info *inf)
{
  pid_t	mainpid;
  char	c;

  mainpid	= inf->pid;

  inf->pid		= 0;
  inf->retval		= 129;	/* default in case of termsig/exitsig	*/
  inf->retval_set	= 0;
  inf->firststop	= 1;

  c			= 0;
  for (;;)
    {
      inf->loops++;
      if (debug && c)
        fputc(c, stderr);
      c		= '*';
      errno	= 0;
      inf->pid	= waitpid((pid_t)-1, &inf->sta, WUNTRACED);
      if (inf->pid == (pid_t)-1)
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
      if (WIFEXITED(inf->sta))
        {
          /* Process terminated.
           *
           * If it's our child then remember the retval.  As more
           * childs might be traced (future!) we continue here.  The
           * wait above terminates anyways.
           */
          status(inf->pid, "exit %d", WEXITSTATUS(inf->sta));
          if (inf->pid == mainpid)
            {
              inf->retval	= WEXITSTATUS(inf->sta);
              inf->retval_set++;
            }
          continue;
        }
      if (WIFSIGNALED(inf->sta))
        {
          /* Process terminated due to signal.
           *
           * Usually you will see a warn "return value not set", as
           * the process is terminated without return value.
           */
          status(inf->pid, "exit by signal %d", WTERMSIG(inf->sta));
          /* WIFEXITED() from pid will follow	*/
          continue;
        }
#ifdef WCOREDUMP
      /* There are some systems which tell about cores
       *
       * Implemented according to the manual.
       */
      if (WCOREDUMP(inf->sta))
        {
          status(inf->pid, "coredump");
          continue;
        }
#endif
      if (!WIFSTOPPED(inf->sta))
        {
          /* Well, hit me, but sometimes things happen, which I want to
           * know about.
           */
          warn("unknown wait status 0x%x", inf->sta);
          continue;
        }

      /* Process stopped due to a signal.
       *
       * This can be SIGTRAP (from ptrace()) or not.
       */

      switch (ptrace__event(inf))
        {
        case PTRACE__GROUPSTOP:
          status(inf->pid, "groupstop");
          ptrace__listen(inf);	/* in this case we must listen	*/
          continue;

        case PTRACE__SIGNAL:	/* signal	*/
          status(inf->pid, "signal %d", inf->sig);
          break;

        case PTRACE__OPTIONS_MISSING:
          ptrace__setoptions(inf);
        case PTRACE__SYSCALL:	/* syscall()	*/
          /* Do we want to detach cleanly?
           */
          if (inf->detach)
            {
              ptrace__detach(inf);
              if (inf->pid == mainpid)
                return;
            }
          break;

        case PTRACE__EVENTSTOP:
          status(inf->pid, "Event %x", inf->evt);
          break;

        case PTRACE__TRAP:
          /* I really have no idea why I get spurious TRAPs
           * which must be suppresed to not make the child fail.
           */
          status(inf->pid, "TRAP ignored");
          break;
        }

      /* Now delay the processing
       */
      do_delay(inf->delay);
      if (inf->sig)
        status(inf->pid, "deliver sig %d", inf->sig);
      ptrace__syscall(inf);
      c	= '#';
    }
  /* Warn if we came here without seeing a proper return value.
   */
}


/* This routine is too long
 */
static int
delay_trace(struct delay_info *delay, char **argv)
{
  struct trace_info	inf = { 0 };
  char			*end;

  inf.delay	= delay;
  inf.options	= PTRACE_O_TRACESYSGOOD;

  /* Detaching is not so easy as one might think.
   * As we are doing asynchronous things, we just cannot detach,
   * as there may be a signal which then is spuriously delivered
   * to the old parent if we detach.  So we must wait until we
   * got the process stopped such that we can detach cleanly.
   */

  /* If program is a PID and there are no args attach to the process.
   */
  if (isdigit(argv[0][0]) && !argv[1] && (inf.pid=strtol(argv[0], &end, 0))!=0 && end && !*end)
    {
      ptrace__attach(&inf);

#if 0
      /* Just in case, revive process
       */
      ptrace__syscall(pid, 0);
#endif

      /* Try to detach cleanly in case we had a stopped process
       */
      inf.detach	= !inf.delay->is_delay;
    }
  else if ((inf.pid=fork())==0)
    {
      /* Fork a child and start tracing.
       *
       * I observed, that this creates a SIGTRAP, so this process is
       * stopped for the wait below.
       *
       * If delay is set to 0 no trace is done.
       */
      if (inf.delay->is_delay)
        ptrace__traceme();
      /* Wait for the process
       */
      raise(SIGSTOP);
      /* Fork off the new process
       */
      execvp(argv[0], argv);
      OOPS("fork failed: %s", argv[0]);
    }
  else if (inf.pid==(pid_t)-1)
    OOPS("fork");
  else
    status(inf.pid, "started");

  /* run it	*/
  ptrace__loop(&inf);

  if (!inf.retval_set)
    warn("return value not set");

  /* Report closing status
   */
  status((pid_t)0, "%lld loops, %lld sleeps, retval %d", inf.loops, inf.delay->sleeps, inf.retval);

  /* Terminate with the return value of the forked process
   *
   * Well, this is true in the attached case, so we are stealing the
   * return value in this case ;)
   */
  return inf.retval;
}

static int
delay_copy(struct delay_info *delay)
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
              do_delay(delay);
              continue;
            }
          OOPS("stdin");
        }
      bytes	+= got;

      /* output lines delayed
       *
       * If is_delay is not set, output full blocks
       */
      max	= delay->is_delay ? 0 : got;
      for (i=0; i<got; )
        {
          int	put;

          while (max<got && buf[max++]!='\n');
          put	= write(1, buf+i, max-i);
          /* Delay after the write.
           *
           * I hate it to wait on the first round ;)
           */
          do_delay(delay);
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
  status((pid_t)0, "%ld loops, %lld sleeps, bytes %ld", loops, delay->sleeps, bytes);
  return 0;
}

static void
usage(void)
{
  fprintf(stderr,
          "Usage: %s [-options] delay [pid|program [args..]]\n"
          "\t\tVersion " SLOWDOWN_VERSION " compiled " __DATE__ "\n"
          "\t-d\tdebug.  Print a # for each delay and * for other loops.\n"
#if 0
          "\t-j\tjail.  Kill program if slowdown terminates\n"	/* PTRACE_O_EXITKILL */
          "\t-q\tquiet (suppress errors)\n"
          "\t-r\trecursive (follow forks etc.)\n"		/* PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK */
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

  debug		= 0;
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
          case 'd':	debug++; continue;
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
set_delay(struct delay_info *delay, const char *arg)
{
  char	*end;

  delay->delay_us	= strtoul(arg, &end, 0);
  delay->is_delay	= delay->delay_us!=0;

  delay->delay.tv_sec	= delay->delay_us/1000;
  delay->delay.tv_nsec	= (delay->delay_us%1000)*1000000ul;

  delay->delay_us	*= 1000;

  if (!end || *end)
    OOPS("please give a positive milliseconds for delay");

  FATAL((delay->delay.tv_sec*1000000ull+delay->delay.tv_nsec/1000ul) != delay->delay_us);
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
  static struct delay_info	delay = { 0 };

  setargs(&argc, &argv);
  set_delay(&delay, argv[1]);
  if (argc>2)
    return delay_trace(&delay, argv+2);
  return delay_copy(&delay);
}

