# Usage

```
git clone https://github.com/hilbix/slowdown.git
cd slowdown
make
```

Then

```
slowdown 10 process args..
```


# Why?

Often things are just too fast.  For example

```
find / -type f -ls | awk -f process.awk
```

might eat up so much system IO that the system becomes unresponsive.
This is where slowdown comes into place.  In this case you can write:

```
find / -type f -ls | slowdown 50 | awk -f process.awk
```

which means, only process 20 lines per second.  Also it can be used to
slowdown processes like my `md5backup` which often tears down the system
too hard.  Slowdown shall be the solution to it.

```
Usage: slowdown [-v] delay [process [args..]]
```

- `-v` switches on some verbose reporting
- `delay` is in milliseconds

There is a special "detach feature" to revive hung processes:

```
slowdown [-v] 0 PID
```

This let the traced PID continue and then tries to detach without
sending spurious signals to the orignal parent (which apparently does
not work in all cases now).  For now you have to ignore the return
value (in future this shall return 0 or whatever, I'm undecided).

If the process is missing it acts as a filter from stdin to stdout
such that it delays the IO the given delay each line or BLKSIZ (4096)
bytes, whatever comes first.  Also it runs unbuffered, such that it
writes lines to stdout in a flushed mode.  Always as you expect it.

If process is given, it is started "traced", that is, it is delayed
each time it does a SYSCALL.  Except from this it just behaves as if
it is not there and sends all the signals it receives to the child, so
it's like it isn't there.

Also you can attach to other processes by giving the PID as the
process name in case you do not give any args.

That's just the complete idea behind slowdown.

Note that there is a similar project at freshmeat:
- http://freshmeat.net/projects/slowdown/
So if my version does not help you, perhaps the other can.

# Notes

- If delay is below the resolution of the system timer, the waits are
  over-estimated by the OS, so the delays are measured and some delay
  calls are left out to compensate which results in a lower delay
  count than one would expect.

# Bugs

- fork()s of the child processes are not followed.  This is the new
  child processes are not traced as well.  This shall be the default
  behavior, though.

- If slowdown terminates, the traced process may stay in the traced
  state, so it does stop running.  There shall be an automatic detach
  somehow.  There is a detach feature for this now: `slowdown 0 PID`

- On detach sometimes the original parent still sees the child
  stopped.  So the signals are not completely cleaned up.  Perhaps we
  must first loop to catch all outstanding signals and then, if there
  is no more signal, then detach on the latest waited TRAP.

- SIGTSTP does not work correctly.  So if you attach to some process
  in a shell and try to stop it (CTRL-Z), then this does not work, as
  the SIGTSTP is no more delivered to the parent shell any more due to
  the reparenting.

# License

This Works is placed under the terms of the Copyright Less License,
see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.

This means it is free as in free speech, free beer and free baby.
Do you copyright babies?

-Tino
webmaster@scylla-charybdis.com
http://www.scylla-charybdis.com/