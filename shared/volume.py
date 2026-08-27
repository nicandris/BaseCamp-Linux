"""System volume, read from the default PipeWire sink.

Two callers need it: the monitor loop in emax_controller, which pushes the
level to the keyboard's wheel display over `11 83`, and the Everest panel,
which mirrors what the keyboard is being sent.

`@DEFAULT_AUDIO_SINK@` re-resolves on every read, so switching output device is
followed with no extra work.

Why a watcher and not a poll: the loop pushes the level several times a second.
Any staleness in the cached value is pushed *over* the level the firmware just
set from a wheel turn, so the display visibly snaps back to the old number
until the next poll. `pactl subscribe` makes the update immediate instead of
merely frequent. If it is unavailable the code falls back to a rate-limited
poll, which still works — it just flickers on wheel turns.
"""
import ctypes
import signal
import subprocess
import threading
import time

POLL_INTERVAL = 0.5          # fallback only, when the watcher is not running

_lock = threading.Lock()
_level = None                # last known level, from watcher or poll
_last_poll = 0.0
_watcher = None


def parse_wpctl_volume(text):
    """Level 0-100 from `wpctl get-volume` output, 0 when muted, None if the
    line is not one we understand. Levels above 1.0 are legal and clamp to 100.
    """
    if not text or not text.startswith("Volume:"):
        return None
    if "[MUTED]" in text:
        return 0
    parts = text.split()
    if len(parts) < 2:
        return None
    try:
        return max(0, min(100, round(float(parts[1]) * 100)))
    except ValueError:
        return None


def is_volume_event(line):
    """True for a `pactl subscribe` line that can change the level we show.

    Sink events cover volume and mute; server events cover the default sink
    being switched to another device, which changes whose level we report.
    """
    if not line or "Event" not in line:
        return False
    return " on sink " in line or " on server " in line


def _read():
    try:
        out = subprocess.run(["wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@"],
                             capture_output=True, text=True, timeout=1).stdout
    except Exception:
        return None
    return parse_wpctl_volume(out.strip())


try:
    _libc = ctypes.CDLL("libc.so.6", use_errno=True)
except Exception:                         # not Linux, or no glibc
    _libc = None

PR_SET_PDEATHSIG = 1


def _die_with_parent():
    """Ask the kernel to signal this child when its parent dies.

    The watcher thread is a daemon, so it is killed outright when the monitor
    process ends and its `finally` never runs. Without this every start and
    stop of Monitor Mode would strand a `pactl subscribe` process.

    This runs in the forked child, between fork and exec, where almost nothing
    is safe to do: another thread may have held the dynamic loader's lock at
    the moment of the fork, and loading a library here would then deadlock a
    child that can never be reaped. `libc` is therefore resolved above, in the
    parent, and this only calls through the pointer.
    """
    if _libc is not None:
        _libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM)


def _watch_loop():
    global _level
    try:
        proc = subprocess.Popen(["pactl", "subscribe"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True,
                                preexec_fn=_die_with_parent)
    except Exception:
        return
    try:
        for line in proc.stdout:
            if is_volume_event(line):
                value = _read()
                if value is not None:
                    with _lock:
                        _level = value
    except Exception:
        pass
    finally:
        try:
            proc.kill()
        except Exception:
            pass


def start_watch():
    """Begin following volume changes as they happen. Safe to call twice."""
    global _watcher, _level
    if _watcher is not None and _watcher.is_alive():
        return
    seed = _read()                        # outside the lock: this forks a process
    if seed is not None:
        with _lock:
            _level = seed
    _watcher = threading.Thread(target=_watch_loop, daemon=True)
    _watcher.start()


def system_volume():
    """Volume of the currently selected output, 0-100, or None if unreadable.

    Free to call every loop iteration: with the watcher running this is a
    variable read, and without it the poll is rate limited.
    """
    global _level, _last_poll
    if _watcher is not None and _watcher.is_alive():
        with _lock:
            return _level
    now = time.monotonic()
    if now - _last_poll >= POLL_INTERVAL:
        _last_poll = now
        value = _read()
        if value is not None:             # a failed read keeps the last good
            with _lock:                   # level rather than blanking the
                _level = value            # display
    with _lock:
        return _level
