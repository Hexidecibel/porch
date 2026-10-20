#!/usr/bin/env python3
"""Daemonize a command: detach from terminal, run as session leader.

Usage: daemonize.py <logfile> <cmd> [args...]

The command's stdout+stderr go to <logfile>. Parent exits 0 after the
first fork succeeds; the grandchild execs <cmd> with PPID=1.

Portable replacement for setsid(1), which is not available on stock macOS.
"""
import os
import sys
import resource


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: daemonize.py <logfile> <cmd> [args...]\n")
        sys.exit(2)

    logfile = sys.argv[1]
    cmd = sys.argv[2:]

    # Resolve relative paths to absolute BEFORE we chdir("/"). The command
    # itself (argv[0]) and the logfile may have been passed as relative
    # paths by the caller.
    logfile = os.path.abspath(logfile)
    if os.sep in cmd[0] or (os.altsep and os.altsep in cmd[0]):
        # Path-like (contains a slash): resolve relative to current CWD.
        cmd[0] = os.path.abspath(cmd[0])
    # else: bare command name — let execvp search PATH.

    # First fork: parent exits so the shell returns immediately.
    if os.fork() > 0:
        os._exit(0)

    # Become session leader so we have no controlling terminal.
    os.setsid()

    # Second fork: ensures the daemon cannot reacquire a controlling
    # terminal (since only a session leader can, and we won't be one).
    if os.fork() > 0:
        os._exit(0)

    # Make the final daemon process its own process group leader so that
    # `kill -- -$PID` (used by bin/status) terminates the whole tree.
    # After the second fork we are NOT a session leader, so setpgrp() just
    # creates a new process group with us as the leader.
    try:
        os.setpgrp()
    except OSError:
        pass

    os.chdir("/")

    # Redirect std streams.
    with open("/dev/null", "rb") as dn:
        os.dup2(dn.fileno(), 0)
    try:
        # Owner-only: these logs carry whatever the daemonized tool prints, and
        # for bin/secure-entry / bin/inject that can include secret-shaped
        # material. The default umask left them group- and world-readable.
        fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        # O_CREAT's mode only applies to a new file; tighten a log left over
        # from before (they used to be created 0664).
        os.fchmod(fd, 0o600)
        lf = os.fdopen(fd, "ab", 0)
    except Exception as e:
        sys.stderr.write("daemonize: cannot open logfile %s: %s\n" % (logfile, e))
        os._exit(1)
    os.dup2(lf.fileno(), 1)
    os.dup2(lf.fileno(), 2)

    # Close any other inherited fds so we don't hold the parent's open files.
    try:
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if maxfd == resource.RLIM_INFINITY or maxfd > 1024:
            maxfd = 1024
        os.closerange(3, maxfd)
    except Exception:
        pass

    try:
        os.execvp(cmd[0], cmd)
    except Exception as e:
        sys.stderr.write("daemonize: execvp failed: %s\n" % e)
        os._exit(127)


if __name__ == "__main__":
    main()
