#!/usr/bin/env python3
"""
Checks the Everest probe's decoding without an Everest.

    python3 tools/test_everest_probe.py

The interesting part of that script is one struct read out of one reply, and
getting it wrong would tell an Everest Core owner they own a Max. The reply
below was recorded from a real Everest Max with both the numpad and the media
dock attached, which is the ground truth this pins against.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import everest_probe as probe   # noqa: E402

failures = []


def check(name, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + "%-46s %s" % (name, detail))
    if not ok:
        failures.append("%s: %s" % (name, detail))


def reply(body):
    """A `11 14` answer carrying this 29 byte struct."""
    return bytes([0x11, 0x14, 0x00, 0x00]) + bytes(body) + bytes(
        probe.PAYLOAD_LEN - 4 - len(body))


# Recorded from an Everest Max on this desk, both parts attached.
MAX_REPLY = bytes.fromhex(
    "111400000 1ff15f3cc23111e001e00011213141501003200000000000000"
    .replace(" ", "")) + bytes(probe.PAYLOAD_LEN - 33)

info = probe.decode_extend_info(MAX_REPLY)
check("a complete Max: numpad reported attached", info["numpad_plugged"] is True)
check("and the media dock too", info["mm_dock_plugged"] is True)
check("which reads as a Max", "Everest Max" in probe.describe(info),
      probe.describe(info))
check("the dock colour comes out of the middle",
      info["mm_dock_color"] == [243, 204, 35], info["mm_dock_color"])
check("the two timeouts are 16 bit, little endian",
      (info["mm_dock_screensaver_s"], info["mm_dock_turn_off_s"]) == (30, 30),
      (info["mm_dock_screensaver_s"], info["mm_dock_turn_off_s"]))
check("five profile slots, five brightness pairs",
      len(info["mm_dock_show_profile"]) == 5 and len(info["brightness"]) == 5)

# The case the probe exists for, which nobody here can produce: a keyboard
# with neither part attached.
core = probe.decode_extend_info(reply([0] * 29))
check("neither attached: not a Max",
      core["numpad_plugged"] is False and core["mm_dock_plugged"] is False)
check("and it says so in words", "Core" in probe.describe(core),
      probe.describe(core))

# The two flags are independent, and each is read from its own byte. Reading
# one of them off the wrong offset would still pass a both-attached reply.
only_numpad = bytearray(29)
only_numpad[16] = 1
info = probe.decode_extend_info(reply(only_numpad))
check("numpad alone is numpad alone",
      info["numpad_plugged"] and not info["mm_dock_plugged"],
      probe.describe(info))
only_dock = bytearray(29)
only_dock[0] = 1
info = probe.decode_extend_info(reply(only_dock))
check("dock alone is dock alone",
      info["mm_dock_plugged"] and not info["numpad_plugged"],
      probe.describe(info))

# Nothing here may raise on a short or missing answer: the point of the file
# it writes is that it arrives even when the keyboard says something odd.
check("a truncated reply decodes to nothing",
      probe.decode_extend_info(bytes([0x11, 0x14, 0, 0, 1])) is None)
check("no reply at all decodes to nothing",
      probe.decode_extend_info(None) is None)
check("and that is said in words rather than crashing",
      "did not answer" in probe.describe(None), probe.describe(None))

# The probe must not be able to write to the keyboard by accident.
for name, packet in (("init", probe.INIT_PACKET),
                     ("extend info", probe.EXTEND_PACKET),
                     ("firmware info", probe.FW_INFO_PACKET),
                     ("firmware layout", probe.FW_LAYOUT_PACKET)):
    check("%s is a query and the right length" % name,
          len(packet) == probe.PAYLOAD_LEN and packet[0] == 0x11,
          packet[:3].hex(" "))

source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "everest_probe.py"), encoding="utf-8").read()
check("it never detaches a kernel driver",
      "detach_kernel_driver" not in source)
check("and never opens the device through libusb",
      "usb.core" not in source)

print()
if failures:
    print("%d check(s) failed:" % len(failures))
    for failure in failures:
        print("  - %s" % failure)
    sys.exit(1)
print("all checks passed")
