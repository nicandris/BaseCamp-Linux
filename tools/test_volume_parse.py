#!/usr/bin/env python3
"""Check the wpctl volume parsing behind the wheel display's volume sync.

Run: python3 tools/test_volume_parse.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.volume import (parse_wpctl_volume as parse, is_volume_event,
                           parse_pactl_volume, parse_pactl_mute)


def test():
    assert parse("Volume: 0.50") == 50
    assert parse("Volume: 0.00") == 0
    assert parse("Volume: 1.00") == 100
    assert parse("Volume: 0.005") == 0          # rounds down, stays in range
    assert parse("Volume: 1.40") == 100         # over-amplified clamps
    assert parse("Volume: 0.45 [MUTED]") == 0   # muted reads as silent
    assert parse("Volume: 0.00 [MUTED]") == 0
    assert parse("Volume: 0.333") == 33
    # Anything we do not understand must be None, never a wrong number: the
    # loop skips the push on None and leaves the last good value on screen.
    assert parse("") is None
    assert parse(None) is None
    assert parse("Sink not found") is None
    assert parse("Volume:") is None
    assert parse("Volume: loud") is None
    # `pactl subscribe` lines. sink and server matter; sink-input is a single
    # app's stream and source is a microphone, neither of which we display.
    assert is_volume_event("Event 'change' on sink #72")
    assert is_volume_event("Event 'change' on server #0")     # default sink swap
    assert is_volume_event("Event 'new' on sink #55")
    assert not is_volume_event("Event 'change' on sink-input #431")
    assert not is_volume_event("Event 'change' on source #50")
    assert not is_volume_event("Event 'remove' on client #12")
    assert not is_volume_event("")
    assert not is_volume_event(None)
    # pactl prints one reading per channel; the first percentage is the level.
    assert parse_pactl_volume(
        "Volume: front-left: 32768 /  50% / -18.06 dB,   front-right: 32768 /  50% / -18.06 dB") == 50
    assert parse_pactl_volume("Volume: mono: 0 /   0% / -inf dB") == 0
    assert parse_pactl_volume("Volume: mono: 65536 / 100% / 0.00 dB") == 100
    assert parse_pactl_volume("Volume: mono: 98304 / 150% / 7.06 dB") == 100   # clamps
    assert parse_pactl_volume("Sink not found") is None
    assert parse_pactl_volume("Volume: mono: no percentage here") is None
    assert parse_pactl_volume("") is None
    assert parse_pactl_volume(None) is None

    assert parse_pactl_mute("Mute: yes") is True
    assert parse_pactl_mute("Mute: no") is False
    assert parse_pactl_mute("Mute:") is None
    assert parse_pactl_mute("Sink not found") is None
    assert parse_pactl_mute(None) is None

    print("volume parse ok")


if __name__ == "__main__":
    test()
