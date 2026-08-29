#!/usr/bin/env python3
"""
Mountain Everest probe for BaseCamp-Linux.

    curl -O https://raw.githubusercontent.com/ramisotti13-eng/BaseCamp-Linux/main/tools/everest_probe.py
    python3 everest_probe.py

Nothing to install: on Linux this talks to /dev/hidraw itself and needs no
Python packages. If it says it has no permission, run it once with sudo.

It reads and does not write. No flash, no key bindings, no firmware, no
lighting: every command it sends is a query. It goes through /dev/hidraw and
never detaches a kernel driver, so it cannot leave the keyboard in a state a
replug is needed to fix.

## What it is for

The Everest Max and the Everest Core are the same keyboard. The Max is the
Core with a numpad and a media dock attached, and both report the same USB
product id, so from the outside they are indistinguishable. BaseCamp-Linux has
only ever been used with a Max, and it shows the numpad and main display
controls to everybody, whether those parts are there or not.

The keyboard itself knows. `11 14` answers with FW_EXTEND_INFO, which carries
byMMDockPlug and byNumpadPlug, and the application already sends that command
several times a second as a keepalive and throws the answer away.

If you own an Everest Core, or a Max with the numpad or the dock unplugged,
the file this writes says what the keyboard reports about itself, and that is
what the application needs in order to stop offering controls for parts that
are not attached.

Reverse engineered from Mountain Base Camp for Windows (SDKDLL.dll,
GetExtendInfo) and checked against an Everest Max with both parts attached.
"""
import argparse
import datetime
import json
import os
import platform
import select
import sys

VID = 0x3282
PID = 0x0001              # Everest Max and Everest Core alike
PAYLOAD_LEN = 64
HIDRAW_CLASS = "/sys/class/hidraw"

INIT_PACKET = bytes([0x11, 0x80, 0x00, 0x00, 0x01]) + bytes(PAYLOAD_LEN - 5)
EXTEND_PACKET = bytes([0x11, 0x14]) + bytes(PAYLOAD_LEN - 2)
FW_INFO_PACKET = bytes([0x11, 0x00]) + bytes(PAYLOAD_LEN - 2)
FW_LAYOUT_PACKET = bytes([0x11, 0x12]) + bytes(PAYLOAD_LEN - 2)

report = {
    "probe_version": 1,
    "device": "everest",
    "created": datetime.datetime.now().isoformat(timespec="seconds"),
    "environment": {},
    "interfaces": [],
    "firmware": {},
    "extend_info": {},
    "notes": [],
}


def section(title):
    print("\n%s\n%s" % (title, "-" * len(title)))


def hexs(data):
    return " ".join("%02x" % b for b in data) if data else ""


# ── Finding the keyboard ─────────────────────────────────────────────────────

def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def hidraw_entries(vid, pid, base=None):
    """The vendor's HID interfaces, straight out of sysfs.

    No Python binding involved: /sys/class/hidraw/*/device/uevent carries the
    vendor and product, and the interface number sits on the USB interface a
    few directories up.
    """
    entries = []
    root = base or HIDRAW_CLASS
    for name in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        uevent = read_text(os.path.join(root, name, "device", "uevent"))
        ids = ""
        for line in uevent.splitlines():
            if line.startswith("HID_ID="):
                ids = line.split("=", 1)[1]
        parts = ids.split(":")
        if len(parts) != 3:
            continue
        try:
            if int(parts[1], 16) != vid or int(parts[2], 16) != pid:
                continue
        except ValueError:
            continue

        path = os.path.realpath(os.path.join(root, name, "device"))
        interface, product = None, ""
        for _ in range(4):
            path = os.path.dirname(path)
            if interface is None:
                value = read_text(os.path.join(path, "bInterfaceNumber"))
                if value:
                    try:
                        interface = int(value, 16)
                    except ValueError:
                        pass
            if not product:
                product = read_text(os.path.join(path, "product"))
        entries.append({
            "interface_number": interface,
            "path": "/dev/%s" % name,
            "product_string": product,
            "descriptor": read_text(
                os.path.join(root, name, "device", "report_descriptor")) or "",
        })
    entries.sort(key=lambda e: e["interface_number"]
                 if e["interface_number"] is not None else 99)
    return entries


def usage_page(node):
    """Usage page and usage out of the report descriptor, or (None, None)."""
    try:
        with open(os.path.join(HIDRAW_CLASS, os.path.basename(node),
                               "device", "report_descriptor"), "rb") as handle:
            data = handle.read()
    except OSError:
        return None, None
    page = use = None
    index = 0
    while index < len(data):
        prefix = data[index]
        size = prefix & 0x03
        size = 4 if size == 3 else size
        value = int.from_bytes(data[index + 1:index + 1 + size], "little")
        tag = prefix & 0xFC
        if tag == 0x04 and page is None:
            page = value
        elif tag == 0x08 and use is None:
            use = value
        index += 1 + size
    return page, use


class Link:
    """A /dev/hidraw node, opened directly."""

    def __init__(self, entry):
        self.path = entry["path"]
        self.fd = os.open(self.path, os.O_RDWR)
        self.poller = select.poll()
        self.poller.register(self.fd, select.POLLIN)

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass

    def write(self, payload):
        os.write(self.fd, b"\x00" + bytes(payload))

    def read(self, timeout_ms=400):
        if not self.poller.poll(max(0, int(timeout_ms))):
            return None
        data = os.read(self.fd, PAYLOAD_LEN + 1)
        return bytes(data) if data else None

    def ask(self, payload, timeout_ms=400, tries=4):
        """Send, then read until the matching answer turns up.

        Key state reports arrive on the same interface and start with 0x01;
        they are not the answer to a command, so they are skipped rather than
        mistaken for one.
        """
        self.write(payload)
        wanted = (payload[0], payload[1])
        for _ in range(tries):
            data = self.read(timeout_ms)
            if data is None:
                return None
            if len(data) >= 2 and (data[0], data[1]) == wanted:
                return data
        return None


# ── FW_EXTEND_INFO ───────────────────────────────────────────────────────────
#
# From SDKDLL.dll: GetExtendInfo sends `11 14` and keeps 29 bytes of the
# answer. On the wire those 29 bytes start at offset 4, after the echoed
# command. The field order is the struct in the Windows service.

def decode_extend_info(data):
    """The keyboard's own account of what is attached to it."""
    if not data or len(data) < 4 + 29:
        return None
    body = data[4:4 + 29]
    return {
        "mm_dock_plugged": bool(body[0]),
        "mm_dock_show_menu": body[1],
        "mm_dock_menu_index": body[2],
        "mm_dock_color": list(body[3:6]),
        "mm_dock_screen_setup": body[6],
        "mm_dock_screensaver_s": int.from_bytes(body[7:9], "little"),
        "mm_dock_turn_off_s": int.from_bytes(body[9:11], "little"),
        "mm_dock_show_profile": list(body[11:16]),
        "numpad_plugged": bool(body[16]),
        "pixel_shift_time": body[17],
        "mm_dock_double_click": body[18],
        "brightness": [{"dock": body[19 + i * 2], "numpad": body[20 + i * 2]}
                       for i in range(5)],
        "raw": hexs(body),
    }


def describe(info):
    """What the answer means for someone reading the output."""
    if info is None:
        return "the keyboard did not answer 11 14"
    dock, numpad = info["mm_dock_plugged"], info["numpad_plugged"]
    if dock and numpad:
        return "numpad and media dock both attached: an Everest Max, complete"
    if numpad and not dock:
        return "numpad attached, no media dock"
    if dock and not numpad:
        return "media dock attached, no numpad"
    return ("neither attached: an Everest Core, or a Max with both parts "
            "unplugged")


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--vid", type=lambda v: int(v, 0), default=VID)
    parser.add_argument("--pid", type=lambda v: int(v, 0), default=PID,
                        help="0x0001 for Everest Max and Core")
    parser.add_argument("--out", default=None, help="where to write the report")
    args = parser.parse_args()

    print("Mountain Everest probe for BaseCamp-Linux.")
    report["environment"] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "vid": "0x%04X" % args.vid,
        "pid": "0x%04X" % args.pid,
        "euid": os.geteuid(),
    }

    section("Keyboard")
    entries = hidraw_entries(args.vid, args.pid)
    if not entries:
        print("  no Everest found (VID 0x%04X PID 0x%04X)." % (args.vid, args.pid))
        print("  Plug it in and try again. If it is plugged in, run this once")
        print("  with sudo to rule out permissions.")
        return 1

    vendor = None
    for entry in entries:
        page, use = usage_page(entry["path"])
        entry["usage_page"] = "0x%04X" % page if page is not None else None
        entry["usage"] = "0x%02X" % use if use is not None else None
        print("  interface %-2s  usage page %-8s %s"
              % (entry["interface_number"], entry["usage_page"] or "?",
                 entry["path"]))
        if page == 0xFF00:
            vendor = entry
    report["interfaces"] = entries

    if vendor is None:
        # Older kernels and odd enumerations do not always give a usage page;
        # the vendor collection is the last interface on this keyboard.
        vendor = sorted(entries, key=lambda e: e["interface_number"] or 0)[-1]
        report["notes"].append("no 0xFF00 collection found, guessed the last "
                               "interface")

    print("\n  talking to interface %s (%s)"
          % (vendor["interface_number"], vendor["path"]))

    try:
        link = Link(vendor)
    except PermissionError:
        print("\n  no permission for %s." % vendor["path"])
        print("  Run this once as: sudo python3 %s"
              % os.path.basename(sys.argv[0]))
        print("  Or install 99-mountain.rules from the repository and replug.")
        return 1
    except OSError as exc:
        print("\n  cannot open %s: %s" % (vendor["path"], exc))
        return 1

    try:
        link.ask(INIT_PACKET)

        section("Firmware")
        for label, packet, key in (("info", FW_INFO_PACKET, "info"),
                                   ("layout", FW_LAYOUT_PACKET, "layout")):
            answer = link.ask(packet)
            report["firmware"][key] = hexs(answer) if answer else None
            print("  %-8s %s" % (label, hexs(answer[:16]) if answer else "(no answer)"))

        section("What is attached")
        answer = link.ask(EXTEND_PACKET)
        report["extend_info"]["raw_reply"] = hexs(answer) if answer else None
        info = decode_extend_info(answer)
        report["extend_info"]["decoded"] = info
        if info is None:
            print("  the keyboard did not answer 11 14.")
            print("  Please send the file anyway, the raw reply is in it.")
        else:
            print("  numpad      %s" % ("attached" if info["numpad_plugged"]
                                        else "not attached"))
            print("  media dock  %s" % ("attached" if info["mm_dock_plugged"]
                                        else "not attached"))
            print("\n  %s" % describe(info))
            print("\n  the rest of what it reports:")
            print("    dock colour            %s" % info["mm_dock_color"])
            print("    dock screensaver       %s s" % info["mm_dock_screensaver_s"])
            print("    dock turns off after   %s s" % info["mm_dock_turn_off_s"])
            print("    brightness per profile %s"
                  % [(b["dock"], b["numpad"]) for b in info["brightness"]])
    finally:
        link.close()

    out = args.out or ("everest-probe-%s.json"
                       % datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1)
    print("\nWritten: %s" % os.path.abspath(out))
    print("Please attach that file to the issue you were asked to.")
    print("It contains device identifiers and the keyboard's own settings,")
    print("nothing else.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
