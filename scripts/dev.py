#!/usr/bin/env python3
"""
Cross-platform launcher for `cargo tauri dev` that GUARANTEES the whole build/app
process tree (cargo -> rustc -> olympus-desktop -> embedded postgres) is torn down
when this launcher exits by ANY means: Ctrl-C, terminal close (SIGHUP / window X),
or a hard crash / kill of the launcher itself. No orphaned builds, no stale
postgres holding the embedded-DB lock.

Because every launch cleans up after itself, builds stop piling up — the pileup
only happens when `cargo tauri dev` is run *without* a tree-killer.

Per-OS mechanism:
  Windows  : a Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. The job handle is
             owned only by THIS process; when this process dies by any means, the OS
             closes the handle and kills every process in the job. OS-guaranteed,
             including a hard crash of the launcher.
  Linux /  : the child runs in its own session/process-group. Signal traps + an
  macOS      atexit hook kill the group on Ctrl-C / TERM / HUP / normal exit; a
             detached watchdog polls this launcher's PID and SIGKILLs the group if
             the launcher vanishes without running its handlers (crash / SIGKILL).

Usage:
    python scripts/dev.py [extra args forwarded to `cargo tauri dev`]
"""
from __future__ import annotations

import atexit
import os
import platform
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)  # scripts/.. == repo root
IS_WINDOWS = platform.system() == "Windows"


def main() -> int:
    # Internal watchdog mode (Unix): poll a PID; kill a process group when it dies.
    if len(sys.argv) >= 4 and sys.argv[1] == "--watch":
        return _watch(int(sys.argv[2]), int(sys.argv[3]))
    cmd = ["cargo", "tauri", "dev", *sys.argv[1:]]
    return _run_windows(cmd) if IS_WINDOWS else _run_unix(cmd)


# ---------------------------------------------------------------- Windows ------
def _run_windows(cmd) -> int:
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IOCNT(ctypes.Structure):
        _fields_ = [
            (n, ctypes.c_uint64)
            for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )
        ]

    class EXT(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC),
            ("IoInfo", IOCNT),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9

    # argtypes matter on 64-bit: without them ctypes truncates HANDLEs to 32 bits.
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    k32.SetInformationJobObject.restype = wintypes.BOOL
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    k32.AssignProcessToJobObject.restype = wintypes.BOOL
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    hjob = k32.CreateJobObjectW(None, None)
    if not hjob:
        raise ctypes.WinError(ctypes.get_last_error())

    info = EXT()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not k32.SetInformationJobObject(
        hjob, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    proc = subprocess.Popen(cmd, cwd=REPO)

    # Assign the just-started process; all its descendants inherit job membership.
    if not k32.AssignProcessToJobObject(hjob, int(proc._handle)):
        err = ctypes.get_last_error()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        k32.CloseHandle(hjob)
        raise RuntimeError(
            "AssignProcessToJobObject failed "
            f"(err {err}); refusing to run without Windows tree-kill protection"
        )

    try:
        return proc.wait()
    except KeyboardInterrupt:
        return 130
    finally:
        # Closing the last job handle triggers KILL_ON_JOB_CLOSE on a clean exit;
        # on a crash the OS closes it for us and the kill still fires.
        k32.CloseHandle(hjob)


# -------------------------------------------------------- Linux & macOS --------
def _run_unix(cmd) -> int:
    # start_new_session=True puts the child in its own session => pgid == child pid.
    proc = subprocess.Popen(cmd, cwd=REPO, start_new_session=True)
    pgid = proc.pid
    done = {"v": False}

    def reap(*_):
        if done["v"]:
            return
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(s, signal.SIG_IGN)
        try:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(pgid, sig)
                except ProcessLookupError:
                    break
                time.sleep(1.0)
        finally:
            done["v"] = True

    atexit.register(reap)

    def handle_signal(*_):
        reap()
        raise SystemExit(130)

    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, handle_signal)

    # Crash insurance: a detached poller that kills the group if WE die without
    # running the handlers above (SIGKILL of this shell, power loss, etc.).
    try:
        subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "--watch", str(os.getpid()), str(pgid)],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        reap()
        raise RuntimeError("failed to start dev.py watchdog; refusing to run without crash cleanup") from exc

    try:
        return proc.wait()
    except KeyboardInterrupt:
        return 130
    finally:
        reap()


def _watch(parent_pid: int, pgid: int) -> int:
    while True:
        try:
            os.kill(parent_pid, 0)  # signal 0 == liveness probe
        except OSError:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return 0
        time.sleep(2)


if __name__ == "__main__":
    raise SystemExit(main())
