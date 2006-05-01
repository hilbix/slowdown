/* $Header$
 *
 * Copyright (C)2006 Valentin Hilbig, webmaster@scylla-charybdis.com
 * This shall be independent of tinolib.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Log$
 * Revision 1.1  2006-05-01 01:52:30  tino
 * A first version which works
 *
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
  fprintf(stderr, "[%ld] %s error: ", (long)mypid, arg0);
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

  fprintf(stderr, "[%ld] %s warn: ", (long)mypid, arg0);
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

  fprintf(stderr, "[%ld] %s status: ", (long)mypid, arg0);
  va_start(list, s);
  vfprintf(stderr, s, list);
  va_end(list);
  fprintf(stderr, "\n");
}

static int		is_delay;
static struct timespec	delay;
static long		sleeps;

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
  struct timespec	elapsed;
  int			ret;

  if (!is_delay)
    return 0;
  sleeps++;
  ret	= nanosleep(&delay, &elapsed);
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
  char			*end;
  unsigned long long	ms;

  ms		= strtoull(arg, &end, 0);
  delay.tv_sec	= ms/1000;
  delay.tv_nsec	= (ms%1000)*1000000ul;
  is_delay	= delay.tv_sec!=0 || delay.tv_nsec!=0;
  return !end || *end || (delay.tv_sec*1000+delay.tv_nsec/1000000ul)!=ms;
}

static int
delay_trace(char **argv)
{
  pid_t	pid;
  int	sta;
  long	loops;
  int	retval, retval_set;
  char	*end;

  if (isdigit(argv[0][0]) && !argv[1] && (pid=strtol(argv[0], &end, 0))!=0 && end && !*end)
    {
      if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
	ex(-1, "cannot attach to %ld", (long)pid);
      status("%ld attached", (long)pid);
      /* Just in case, revive process
       */
      ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }
  else if ((pid=fork())==0)
    {
      if (is_delay &&
	  ptrace(PTRACE_TRACEME, 0, NULL, NULL))
	ex(-1, "ptrace(PTRACE_TRACEME)");
      execvp(argv[0], argv);
      ex(-1, argv[0]);
    }
  else
    status("%ld started", (long)pid);
  retval	= -1;
  retval_set	= 0;
  for (loops=0;;loops++)
    {
      pid_t	pid2;

      errno	= 0;
      pid2	= waitpid((pid_t)-1, &sta, WUNTRACED);
      if (pid2==(pid_t)-1)
	{
	  if (!errno || errno==EINTR || errno==EAGAIN)
	    continue;
	  if (errno==ECHILD)
	    break;		/* We do not have any more child processes	*/
	  ex(-1, "waitpid");
	}
      if (WIFEXITED(sta))
	{
	  status("%ld exit %d", (long)pid2, WEXITSTATUS(sta));
	  if (pid2==pid)
	    {
	      retval		= WEXITSTATUS(sta);
	      retval_set++;
	    }
	}
      else if (WIFSIGNALED(sta))
	{
	  status("%ld exitsig %d", (long)pid2, WTERMSIG(sta));
	}
      else if (WIFSTOPPED(sta))
	{
	  if (WSTOPSIG(sta)!=SIGTRAP)
	    status("%ld signal %d", (long)pid2, WSTOPSIG(sta));
	  if (ptrace(PTRACE_SYSCALL, pid2, NULL, (void *)(WSTOPSIG(sta)==SIGTRAP ? 0 : WSTOPSIG(sta))))
	    ex(-1, "ptrace(PTRACE_SYSCALL)");
	  do_delay();
	  continue;
	}
#ifdef WCOREDUMP
      else if (WCOREDUMP(sta))
	status("%ld core", (long)pid2);
#endif
    }
  if (!retval_set)
    warn("return value not set");
  status("%ld loops, %ld sleeps, retval %d\n", loops, sleeps, retval);
#if 0
  ex(-1, "not yet");
#endif
  return retval;
}

static int
delay_copy(void)
{
  int	got;
  char	buf[BUFSIZ];
  
  while ((got=read(0, buf, sizeof buf))!=0)
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
      max	= is_delay ? 0 : got;
      for (i=0; i<got; )
	{
	  int	put;

	  while (max<got && buf[max++]!='\n');
	  put	= write(1, buf+i, max-i);
	  do_delay();
	  if (put<0)
	    {
	      if (errno==EINTR || errno==EAGAIN)
		continue;
	      ex(-1, "stdout");
	    }
	  if (!put)
	    ex(-2, "EOF on stdout");
	  i	+= put;
	}
    }
  return 0;
}

static void
usage(const char *arg0)
{
  fprintf(stderr,
	  "Usage: %s [-v] delay [pid|program [args..]]\n"
	  "\t\tVersion " SLOWDOWN_VERSION " compiled " __DATE__ "\n"
	  "\t-v\tverbose\n"
	  "\tdelay is in milliseconds.\n"
	  "\tIf program is missing it copies stdin to stdout\n"
	  "\tand delays each line or read() (max. 4096 bytes).\n"
	  "\tElse program is fork()ed, ptrace()d and each syscall of it\n"
	  "\tis delayed as given.\n"
	  "\tIf program has no args and is a PID the PID is attached.\n"
	  , arg0
	  );
}

static void
setarg0(const char *s)
{
  char	*tmp;

  arg0	= s;
  if ((tmp=strrchr(arg0, '/'))!=0)
    arg0	= tmp+1;
}

int
main(int argc, char **argv)
{
  mypid	= getpid();
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
