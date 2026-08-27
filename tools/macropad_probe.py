#!/usr/bin/env python3
"""
Mountain MacroPad probe for BaseCamp-Linux.

We reverse-engineered the MacroPad (VID 0x3282, PID 0x0008) from the Windows
software, but nobody on the project owns one. This script collects the last
missing piece from someone who does: the exact shape of the report the pad
sends when a key is pressed. Everything else about the protocol is already
known and does not need your hardware.

    python3 macropad_probe.py

It writes macropad-probe-<timestamp>.json next to itself. Attach that file to
https://github.com/ramisotti13-eng/BaseCamp-Linux/issues and we can finish the
driver.

What it does:
  * lists the USB/HID interfaces of the pad and dumps its report descriptors
  * sends the vendor handshake (11 80 00 00 01) and asks for firmware info
  * records the raw reports while you press each key M1 to M12 in turn
  * with --lighting, tries a few colours so you can see whether they land

What it never does: write to flash, change your key bindings, touch firmware,
or save anything on the device. The lighting test is opt-in and is not
persisted, so unplugging the pad restores it.

This file is standalone on purpose. Copy it anywhere, no other project files
needed, and on Linux no Python packages either: it talks to /dev/hidraw
directly. Python 3.8 or newer.
"""
import argparse
import binascii
import json
import os
import platform
import select
import sys
import time

VID = 0x3282
PID = 0x0008
PAYLOAD_LEN = 64
NUM_KEYS = 12

INIT_PACKET = bytes([0x11, 0x80, 0x00, 0x00, 0x01]) + bytes(PAYLOAD_LEN - 5)
FW_INFO_PACKET = bytes([0x11, 0x00]) + bytes(PAYLOAD_LEN - 2)
FW_LAYOUT_PACKET = bytes([0x11, 0x12]) + bytes(PAYLOAD_LEN - 2)

KNOWN_MOUNTAIN_PIDS = {
    0x0001: "Everest Keyboard",
    0x0002: "Makalu mouse",
    0x0003: "Makalu 67 mouse",
    0x0005: "Everest 60 (ANSI)",
    0x0006: "Everest 60 (ISO)",
    0x0008: "MacroPad",
    0x0009: "DisplayPad",
}

report = {
    "probe_version": 2,
    "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "environment": {},
    "mountain_devices": [],
    "interfaces": [],
    "handshake": [],
    "firmware": {},
    "key_capture": {},
    "lighting": {},
    "notes": [],
}


# ── output helpers ────────────────────────────────────────────────────────────

def section(title):
    print()
    print(title)
    print("-" * len(title))


def note(text):
    report["notes"].append(text)
    print("  note: %s" % text)


def hexs(data):
    if data is None:
        return None
    return binascii.hexlify(bytes(data), " ").decode()


# ── HID report descriptor ─────────────────────────────────────────────────────

HIDRAW_CLASS = "/sys/class/hidraw"


def read_report_descriptor(hid_path, base=None):
    """Read the raw report descriptor from sysfs. Linux and hidraw only.

    Node paths look like /dev/hidraw3; the descriptor sits next to the device
    node in sysfs. `base` exists so the tests can point this at a fake tree."""
    if isinstance(hid_path, bytes):
        hid_path = hid_path.decode(errors="replace")
    name = os.path.basename(hid_path)
    if not name.startswith("hidraw"):
        return None
    sysfs = os.path.join(base or HIDRAW_CLASS, name, "device", "report_descriptor")
    try:
        with open(sysfs, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def walk_descriptor(data):
    """Minimal HID item walker. Enough to see usage pages and report sizes."""
    items = []
    index = 0
    while index < len(data):
        prefix = data[index]
        index += 1
        if prefix == 0xFE:                       # long item, skip it
            if index >= len(data):
                break
            size = data[index]
            index += 2 + size
            continue
        size = prefix & 0x03
        size = 4 if size == 3 else size
        item_type = (prefix >> 2) & 0x03         # 0 main, 1 global, 2 local
        tag = (prefix >> 4) & 0x0F
        value = int.from_bytes(data[index:index + size], "little")
        index += size
        items.append((item_type, tag, value))
    return items


def summarise_descriptor(data):
    """Report IDs with their input/output/feature payload sizes, in bytes."""
    usage_page = usage = report_id = 0
    report_size = report_count = 0
    sizes = {}
    for item_type, tag, value in walk_descriptor(data):
        if item_type == 1:                       # global
            if tag == 0x0:
                usage_page = value
            elif tag == 0x7:
                report_size = value
            elif tag == 0x9:
                report_count = value
            elif tag == 0x8:
                report_id = value
        elif item_type == 2 and tag == 0x0:      # local usage
            usage = usage or value
        elif item_type == 0 and tag in (0x8, 0x9, 0xB):
            kind = {0x8: "input", 0x9: "output", 0xB: "feature"}[tag]
            entry = sizes.setdefault(report_id, {})
            entry[kind] = entry.get(kind, 0) + (report_size * report_count) // 8
    return {
        "usage_page": "0x%04X" % usage_page,
        "usage": "0x%02X" % usage,
        "reports": {str(k): v for k, v in sorted(sizes.items())},
    }


# ── enumeration ───────────────────────────────────────────────────────────────

def import_hid():
    """The hidapi binding, if this machine happens to have one.

    Optional on purpose. On Linux the pad is a plain file under /dev/hidraw,
    which we can open without any Python package, and that is the path this
    script prefers. The binding is only a fallback for other systems."""
    try:
        import hid
        return hid
    except ImportError:
        return None


def describe_hid_module(module):
    """Which of the packages called `hid` is installed here.

    Two unrelated projects both install a module named `hid`: one exposes the
    class `hid.Device`, the older one `hid.device()`. A tester whose distro
    ships the second one got "module 'hid' has no attribute 'Device'" and the
    probe stopped there, so the answer belongs in the report."""
    if module is None:
        return {"present": False}
    info = {
        "present": True,
        "file": getattr(module, "__file__", None),
        "version": str(getattr(module, "__version__", "") or "") or None,
        "has_Device": hasattr(module, "Device"),
        "has_device": hasattr(module, "device"),
        "has_enumerate": hasattr(module, "enumerate"),
    }
    info["flavour"] = ("hid.Device" if info["has_Device"] else
                       "hid.device" if info["has_device"] else "unusable")
    return info


def read_text(path):
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return None


def hidraw_entries(vid, base=None):
    """Enumerate the vendor's HID interfaces straight from sysfs.

    Everything we need is already in the kernel's own bookkeeping: the vendor
    and product in HID_ID, the interface number on the parent USB interface,
    the report descriptor next to the node. /dev/hidrawN is then a file we
    read and write like any other, so this path needs no Python package."""
    base = base or HIDRAW_CLASS
    if not os.path.isdir(base):
        return []

    def order(name):
        tail = name[len("hidraw"):]
        return int(tail) if tail.isdigit() else 0

    out = []
    for name in sorted(os.listdir(base), key=order):
        if not name.startswith("hidraw"):
            continue
        device = os.path.join(base, name, "device")
        fields = {}
        for line in (read_text(os.path.join(device, "uevent")) or "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value
        parts = (fields.get("HID_ID") or "").split(":")   # bus:vendor:product
        if len(parts) != 3:
            continue
        try:
            vendor, product = int(parts[1], 16), int(parts[2], 16)
        except ValueError:
            continue
        if vid and vendor != vid:
            continue

        node = "/dev/" + name
        entry = {
            "vendor_id": vendor,
            "product_id": product,
            "path": node,
            "source": "hidraw",
            "sysfs": os.path.realpath(device),
            "product_string": fields.get("HID_NAME"),
            "manufacturer_string": None,
            "interface_number": None,
            "usage_page": 0,
            "usage": 0,
        }

        walk = os.path.realpath(device)
        for _ in range(4):                        # HID device, USB interface, ...
            walk = os.path.dirname(walk)
            number = read_text(os.path.join(walk, "bInterfaceNumber"))
            if number is not None:
                entry["interface_number"] = int(number, 16)
                entry["usb_interface"] = os.path.basename(walk)
                usb = os.path.dirname(walk)
                entry["manufacturer_string"] = read_text(os.path.join(usb, "manufacturer"))
                entry["product_string"] = (read_text(os.path.join(usb, "product"))
                                           or entry["product_string"])
                break

        descriptor = read_report_descriptor(node, base)
        if descriptor:
            summary = summarise_descriptor(descriptor)
            entry["usage_page"] = int(summary["usage_page"], 16)
            entry["usage"] = int(summary["usage"], 16)
        out.append(entry)
    return out


def library_entries(module, vid):
    """The same list as seen by the hidapi binding, when there is one."""
    if module is None or not hasattr(module, "enumerate"):
        return []
    try:
        found = list(module.enumerate(vid or 0, 0))
    except Exception as exc:
        note("enumerate through the hid module failed: %s" % exc)
        return []
    for entry in found:
        entry["source"] = "library"
    return found


def path_text(path):
    if isinstance(path, bytes):
        return path.decode(errors="replace")
    return "" if path is None else str(path)


def scan(module, vid, pid, backend="auto"):
    section("Mountain devices on this machine")
    from_sysfs = hidraw_entries(vid) if backend in ("auto", "hidraw") else []
    from_library = library_entries(module, vid) if backend in ("auto", "library") else []
    everything = from_sysfs or from_library
    report["backend"] = ("hidraw" if everything and everything[0].get("source") == "hidraw"
                         else "library" if everything else "none")

    seen = {}
    for entry in everything:
        seen.setdefault(entry.get("product_id"), entry)
    if not seen:
        print("  none found")
    for product_id, entry in sorted(seen.items()):
        name = KNOWN_MOUNTAIN_PIDS.get(product_id, "unknown")
        mark = "  <= target" if product_id == pid else ""
        print("  0x%04X  %-20s %s%s" % (product_id, name,
                                        entry.get("product_string") or "", mark))
        report["mountain_devices"].append({
            "pid": "0x%04X" % product_id,
            "guess": name,
            "product_string": entry.get("product_string"),
            "manufacturer": entry.get("manufacturer_string"),
        })

    section("Interfaces of 0x%04X:0x%04X" % (vid, pid))
    entries = [e for e in everything if e.get("product_id") == pid]
    if not entries:
        print("  not connected")
        return []
    entries.sort(key=lambda e: e.get("interface_number") or 0)

    # If both lists exist, remember the binding's path as a second way in: a
    # libusb-backed binding can still reach the pad when /dev/hidraw refuses.
    if from_sysfs and from_library:
        for entry in entries:
            for other in from_library:
                if (other.get("product_id") == entry.get("product_id") and
                        other.get("interface_number") == entry.get("interface_number")):
                    entry["library_path"] = other.get("path")
                    break

    for entry in entries:
        node = path_text(entry.get("path"))
        info = {
            "interface_number": entry.get("interface_number"),
            "usage_page": "0x%04X" % (entry.get("usage_page") or 0),
            "usage": "0x%02X" % (entry.get("usage") or 0),
            "path": node,
            "source": entry.get("source"),
            "release": entry.get("release_number"),
        }
        descriptor = read_report_descriptor(node)
        if descriptor:
            info["descriptor"] = hexs(descriptor)
            info["descriptor_summary"] = summarise_descriptor(descriptor)
        writable = os.access(node, os.R_OK | os.W_OK) if node.startswith("/dev/") else None
        info["writable"] = writable
        entry["writable"] = writable
        report["interfaces"].append(info)
        print("  interface %-3s usage page %s usage %s  %s%s" % (
            info["interface_number"], info["usage_page"], info["usage"],
            node, "" if writable is not False else "   (no permission)"))
        if "descriptor_summary" in info:
            summary = info["descriptor_summary"]
            print("      descriptor: usage page %s usage %s, reports %s" % (
                summary["usage_page"], summary["usage"], summary["reports"] or "{}"))
    if any(i.get("writable") is False for i in report["interfaces"]):
        permission_help(pid)
    return entries


def permission_help(pid):
    note("No write permission on at least one hidraw node.")
    print()
    print("  Either run this script once with sudo:")
    print("      sudo python3 %s" % os.path.basename(sys.argv[0] or "macropad_probe.py"))
    print("  or give your user access permanently and replug the pad:")
    print("      echo 'SUBSYSTEM==\"hidraw\", ATTRS{idVendor}==\"%04x\", "
          "ATTRS{idProduct}==\"%04x\", MODE=\"0666\", TAG+=\"uaccess\"' \\" % (VID, pid))
    print("        | sudo tee /etc/udev/rules.d/99-mountain-probe.rules")
    print("      sudo udevadm control --reload-rules && sudo udevadm trigger")
    print()


# ── device conversation ───────────────────────────────────────────────────────

class Link:
    """One open HID interface, with reads that keep what they cannot use."""

    def close(self):
        raise NotImplementedError

    def write(self, payload):
        raise NotImplementedError

    def read(self, timeout_ms):
        raise NotImplementedError

    def ask(self, payload, timeout_ms=700):
        """Send, then collect replies until the timeout. Returns them all,
        because we do not yet know which reports are answers and which are
        key state, and that distinction is exactly what we are here to find."""
        self.write(payload)
        deadline = time.monotonic() + timeout_ms / 1000.0
        replies = []
        while time.monotonic() < deadline:
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                break
            data = self.read(remaining)
            if data:
                replies.append(data)
        return replies


class HidrawLink(Link):
    """The kernel node, opened directly. No Python binding involved.

    Writes carry the report number in front of the payload, which is what
    hidraw expects and what hidapi does for us elsewhere; report 0 means the
    device does not number its reports and the kernel drops the byte again."""

    kind = "hidraw"

    def __init__(self, entry):
        self.path = path_text(entry.get("path"))
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

    def read(self, timeout_ms):
        if not self.poller.poll(max(0, int(timeout_ms))):
            return None
        try:
            data = os.read(self.fd, PAYLOAD_LEN + 1)
        except OSError:
            return None
        return bytes(data) if data else None


class LibraryLink(Link):
    """The hidapi binding, either flavour of it."""

    kind = "library"

    def __init__(self, module, entry, path=None):
        raw = path if path is not None else entry.get("path")
        self.path = path_text(raw)
        opened = raw if isinstance(raw, bytes) else self.path.encode()
        if hasattr(module, "Device"):
            self.dev = module.Device(path=opened)
            self.kind = "hid.Device"
            try:
                self.dev.nonblocking = False
            except Exception:
                pass
        elif hasattr(module, "device"):
            self.dev = module.device()
            self.dev.open_path(opened)
            self.kind = "hid.device"
            try:
                self.dev.set_nonblocking(0)
            except Exception:
                pass
        else:
            raise RuntimeError("the installed hid module offers neither "
                               "Device nor device()")

    def close(self):
        try:
            self.dev.close()
        except Exception:
            pass

    def write(self, payload):
        self.dev.write(b"\x00" + bytes(payload))

    def read(self, timeout_ms):
        try:
            data = self.dev.read(PAYLOAD_LEN, int(timeout_ms))
        except TypeError:                     # binding without a timeout argument
            try:
                data = self.dev.read(PAYLOAD_LEN)
            except Exception:
                return None
        except Exception:
            return None
        return bytes(data) if data else None


def open_link(module, entry):
    """Open an interface the best way this machine allows.

    Tries the kernel node first and the binding second, and reports every
    attempt, so a failure says which door was locked rather than just that
    something went wrong."""
    attempts = []
    if entry.get("source") == "hidraw" and entry.get("path"):
        attempts.append(("hidraw", lambda: HidrawLink(entry)))
    if module is not None:
        for candidate in (entry.get("library_path"),
                          entry.get("path") if entry.get("source") == "library" else None):
            if candidate:
                attempts.append(("hid module",
                                 lambda c=candidate: LibraryLink(module, entry, c)))
                break
    if not attempts:
        raise RuntimeError("no way to open this interface: no /dev/hidraw node "
                           "and no usable hid module")
    errors = []
    for name, opener in attempts:
        try:
            return opener()
        except Exception as exc:
            errors.append("%s: %s" % (name, exc))
    raise RuntimeError("; ".join(errors))


def try_handshake(module, entries, forced_interface=None):
    """Send the handshake to each candidate interface, see which one answers.

    On the DisplayPad this exact packet is answered with an echo of its first
    five bytes, so that is what we look for first, but anything at all coming
    back is worth recording."""
    section("Handshake")
    winner = None
    denied = False
    for entry in entries:
        number = entry.get("interface_number")
        if forced_interface is not None and number != forced_interface:
            continue
        result = {"interface_number": number, "path": path_text(entry.get("path"))}
        try:
            link = open_link(module, entry)
        except PermissionError as exc:
            denied = True
            result["error"] = str(exc)
            print("  interface %-3s no permission: %s" % (number, exc))
            report["handshake"].append(result)
            continue
        except Exception as exc:
            if "permission" in str(exc).lower():
                denied = True
            result["error"] = str(exc)
            print("  interface %-3s cannot open: %s" % (number, exc))
            report["handshake"].append(result)
            continue
        result["opened_with"] = link.kind
        try:
            replies = link.ask(INIT_PACKET)
            result["replies"] = [hexs(r) for r in replies]
            if replies:
                echo = replies[0][:5] == INIT_PACKET[:5]
                result["echoes_init"] = echo
                print("  interface %-3s answered %s%s" % (
                    number, hexs(replies[0][:8]),
                    "  (echoes the handshake)" if echo else ""))
                if winner is None:
                    winner = (entry, link)
                else:
                    link.close()
            else:
                print("  interface %-3s silent  (via %s)" % (number, link.kind))
                link.close()
        except Exception as exc:
            result["error"] = str(exc)
            print("  interface %-3s error: %s" % (number, exc))
            link.close()
        report["handshake"].append(result)
    if winner is None:
        if denied or any(e.get("writable") is False for e in entries):
            print("  every attempt was refused before it reached the pad, which")
            print("  is a permission problem, not a protocol one.")
            permission_help(entries[0].get("product_id") if entries else PID)
        else:
            print("  no interface answered. The pad may need a replug, or another")
            print("  program (Base Camp under Wine, an earlier run of this script)")
            print("  may still hold it.")
    return winner


def read_firmware(link):
    section("Firmware")
    for name, packet in (("info", FW_INFO_PACKET), ("layout", FW_LAYOUT_PACKET)):
        replies = link.ask(packet)
        report["firmware"][name] = [hexs(r) for r in replies]
        if replies:
            print("  %-7s %s" % (name, hexs(replies[0][:16])))
        else:
            print("  %-7s no answer" % name)


# ── the part we actually need ─────────────────────────────────────────────────

def capture_keys(link, seconds_per_key):
    """Record raw reports while the user presses each key in turn."""
    section("Key capture")
    print("This is the measurement we cannot do without you.")
    print("Press the key the prompt asks for, hold it about a second, release.")
    print("Do not press anything else while a key is being recorded.")
    print()

    input("First a baseline with nothing pressed. Press ENTER, then hands off. ")
    baseline = collect(link, 2.0)
    report["key_capture"]["baseline"] = [hexs(r) for r in baseline]
    print("  %d report(s) while idle" % len(baseline))

    per_key = {}
    for index in range(1, NUM_KEYS + 1):
        try:
            input("Press ENTER, then press and release key M%-2d " % index)
        except (EOFError, KeyboardInterrupt):
            print()
            note("Key capture stopped early at M%d." % index)
            break
        captured = collect(link, seconds_per_key)
        per_key["M%d" % index] = [hexs(r) for r in captured]
        print("  M%-2d %d report(s)%s" % (
            index, len(captured), "" if captured else "   nothing arrived"))
    report["key_capture"]["keys"] = per_key
    analyse_capture(baseline, per_key)


def collect(link, seconds):
    """Drain every report that arrives in the next `seconds`."""
    deadline = time.monotonic() + seconds
    out = []
    while time.monotonic() < deadline:
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            break
        data = link.read(min(remaining, 200))
        if data:
            out.append(data)
    return out


def analyse_capture(baseline, per_key):
    """Say what changed per key, so the result is readable without a decoder."""
    section("What the reports say")
    idle = set()
    for row in baseline:
        idle.add(bytes(row))
    if not per_key:
        print("  nothing captured")
        return

    first_bytes = set()
    findings = {}
    for name, rows in per_key.items():
        bits = set()
        for hex_row in rows:
            row = bytes.fromhex(hex_row.replace(" ", ""))
            if row in idle:
                continue
            first_bytes.add(row[0])
            for position, value in enumerate(row):
                if not value:
                    continue
                for bit in range(8):
                    if value & (1 << bit):
                        bits.add((position, bit))
        findings[name] = sorted(bits)
        if bits:
            print("  %-4s %s" % (name, ", ".join("byte %d bit %d" % b for b in sorted(bits)[:6])))
        else:
            print("  %-4s no report differed from idle" % name)
    report["key_capture"]["analysis"] = {
        k: [{"byte": b, "bit": i} for b, i in v] for k, v in findings.items()}
    if first_bytes:
        report["key_capture"]["first_bytes"] = sorted(first_bytes)
        print()
        print("  first byte of key reports: %s" % ", ".join(
            "0x%02X" % b for b in sorted(first_bytes)))
        if first_bytes == {0x01}:
            print("  that matches the DisplayPad, which is what we hoped for")


# ── optional lighting check ───────────────────────────────────────────────────

def effect_packet(effect, brightness=60, speed=60, color=(255, 0, 0)):
    packet = bytearray(PAYLOAD_LEN)
    packet[0] = 0x14
    packet[1] = 0x2C
    packet[2] = effect
    packet[4] = 0xFF if effect in (0, 12) else speed
    packet[5] = brightness
    packet[6] = 0x00
    packet[7] = 0xFF
    packet[8] = 0xFF
    packet[9], packet[10], packet[11] = color
    return bytes(packet)


def test_lighting(link):
    """Walk the lighting commands and ask which of them the pad actually shows.

    The first run of this (issue #85) found that Static works and Wave and the
    per key colours do not. Reading the Windows software afterwards turned up
    two candidate reasons, so this now sends the old form and the new one and
    asks about each. The pad answers every one of these packets either way;
    only a person looking at it can say which lit up.
    """
    section("Lighting")
    print("Nothing here is written to flash. Unplug the pad to undo it.")
    print("Watch the pad. You will be asked which steps you saw.\n")

    steps = [
        ("backlight on", bytes([0x12, 0x03]) + bytes(PAYLOAD_LEN - 2), None),
        ("static red", effect_packet(0, color=(255, 0, 0)), None),
        ("static green", effect_packet(0, color=(0, 255, 0)), None),
        ("static blue", effect_packet(0, color=(0, 0, 255)), None),
        # Wave, the way it was sent before: the ChangeEffect struct.
        ("wave, old form", effect_packet(4),
         "Did 'wave, old form' light the pad?"),
        # Wave the way Base Camp sends it: ChangeBlockEffect, which is the same
        # command carrying a struct with a block number, a real direction and a
        # width of 2.
        ("wave, block form", block_effect_packet(4, direction=6),
         "Did 'wave, block form' light the pad?"),
        ("tornado, block form", block_effect_packet(7, direction=10),
         "Did 'tornado, block form' light the pad?"),
    ]

    results = {}
    questions = []
    for name, packet, question in steps:
        replies = link.ask(packet, timeout_ms=400)
        results[name] = [hexs(r) for r in replies]
        print("  %-20s sent, %d reply/replies" % (name, len(replies)))
        if question:
            questions.append((name, question))
        time.sleep(1.6)

    # The custom path, in Base Camp's order: activate first, then the colours.
    # The other way round was tried in #85 and stayed dark.
    print()
    for name, packet in (("custom effect on", custom_activate_packet()),
                         ("per-key colours", per_key_packet())):
        replies = link.ask(packet, timeout_ms=400)
        results[name] = [hexs(r) for r in replies]
        print("  %-20s sent, %d reply/replies" % (name, len(replies)))
        time.sleep(1.6)

    report["lighting"] = results
    print()
    for name, question in questions:
        report["lighting"]["saw_" + name.replace(", ", "_").replace(" ", "_")] = \
            ask_yes_no(question)
    report["lighting"]["visible_change"] = ask_yes_no(
        "Did the static colours light the pad?")
    report["lighting"]["per_key_worked"] = ask_yes_no(
        "Did the last two steps light the 12 keys in different colours?")


def block_effect_packet(effect, brightness=60, speed=60, color=(255, 0, 0),
                        direction=6):
    """Wave or Tornado, as `ChangeBlockEffect` builds it.

    Same `14 2C` command as an ordinary effect, different 62 byte struct:
    byBlockNum sits after byWidth, so the colours start one byte later, and
    byDirection and byWidth carry real values instead of 0xFF.
    """
    packet = bytearray(PAYLOAD_LEN)
    packet[0] = 0x14
    packet[1] = 0x2C
    packet[2] = int(effect) & 0xFF
    packet[3] = 0x00                      # byAll
    packet[4] = max(0, min(100, speed))
    packet[5] = max(0, min(100, brightness))
    packet[6] = 0                         # byRandColor: single colour
    packet[7] = int(direction) & 0xFF
    packet[8] = 2                         # byWidth
    packet[9] = 1                         # byBlockNum
    # FWBColor is four bytes, a leading `pos` and then r, g, b. The first run
    # of this put the colour one byte early, which is why the pad lit white
    # instead of red. The SDK writes 100 into the first pos and 0xFF into the
    # second, so this does too.
    packet[10] = 100
    packet[11], packet[12], packet[13] = (c & 0xFF for c in color)
    packet[14] = 0xFF
    return bytes(packet)


def per_key_packet():
    """Twelve visibly different colours, one per key."""
    palette = [(255, 0, 0), (255, 128, 0), (255, 255, 0), (128, 255, 0),
               (0, 255, 0), (0, 255, 128), (0, 255, 255), (0, 128, 255),
               (0, 0, 255), (128, 0, 255), (255, 0, 255), (255, 255, 255)]
    packet = bytearray(PAYLOAD_LEN)
    packet[0] = 0x14
    packet[1] = 0x2C
    packet[2] = 0x00
    packet[3] = 0x01
    packet[4] = 0x00
    packet[5] = 0x4B
    offset = 7
    for red, green, blue in palette:
        packet[offset], packet[offset + 1], packet[offset + 2] = red, green, blue
        offset += 3
    return bytes(packet)


def custom_activate_packet(brightness=70):
    packet = bytearray([0xFF]) * PAYLOAD_LEN
    packet[0] = 0x14
    packet[1] = 0x2C
    packet[2] = 0x0A
    packet[3] = 0x00
    packet[5] = brightness
    return bytes(packet)


def ask_yes_no(question):
    try:
        answer = input("%s [y/n] " % question).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if answer.startswith("y"):
        return True
    if answer.startswith("n"):
        return False
    return None


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Collect what BaseCamp-Linux still needs to support the "
                    "Mountain MacroPad.")
    parser.add_argument("--vid", type=lambda v: int(v, 0), default=VID)
    parser.add_argument("--pid", type=lambda v: int(v, 0), default=PID,
                        help="default 0x0008 (MacroPad)")
    parser.add_argument("--interface", type=int, default=None,
                        help="only talk to this interface number")
    parser.add_argument("--seconds", type=float, default=3.0,
                        help="recording window per key, default 3")
    parser.add_argument("--lighting", action="store_true",
                        help="also try the lighting commands (not saved to flash)")
    parser.add_argument("--no-keys", action="store_true",
                        help="skip the key capture")
    parser.add_argument("--dry-run", action="store_true",
                        help="list interfaces only, never open or write")
    parser.add_argument("--backend", choices=("auto", "hidraw", "library"),
                        default="auto",
                        help="how to reach the pad: the kernel node, the hidapi "
                             "binding, or whichever works (default)")
    parser.add_argument("--out", default=None, help="where to write the report")
    args = parser.parse_args()

    print(__doc__.strip().split("\n\n")[0])
    report["environment"] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "vid": "0x%04X" % args.vid,
        "pid": "0x%04X" % args.pid,
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
    }

    hid = import_hid()
    report["environment"]["hid_module"] = describe_hid_module(hid)
    if hid is None and not os.path.isdir(HIDRAW_CLASS):
        print()
        print("No /dev/hidraw on this system and no hidapi binding installed.")
        print("Install one of these and run the script again:")
        print("    pip install --user hid")
        print("    sudo apt install python3-hid       # Debian, Ubuntu")
        print("    sudo dnf install python3-hidapi    # Fedora")
        return 2

    entries = scan(hid, args.vid, args.pid, args.backend)
    if not entries:
        print()
        print("No device with PID 0x%04X found. Plug the pad in and try again." % args.pid)
        print("If it is plugged in, run this with sudo once to rule out permissions.")
        save(args.out)
        return 1

    if args.dry_run:
        print()
        print("Dry run, nothing was sent to the device.")
        save(args.out)
        return 0

    winner = try_handshake(hid, entries, args.interface)
    if winner is None:
        save(args.out)
        return 1
    entry, link = winner
    report["command_interface"] = entry.get("interface_number")

    try:
        read_firmware(link)
        if not args.no_keys:
            capture_keys(link, args.seconds)
        if args.lighting:
            test_lighting(link)
    finally:
        link.close()

    path = save(args.out)
    print()
    print("Written: %s" % path)
    print("Please attach that file to the MacroPad issue at")
    print("https://github.com/ramisotti13-eng/BaseCamp-Linux/issues")
    print("It contains device identifiers and raw HID reports, nothing else.")
    return 0


def save(out):
    path = out or ("macropad-probe-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    with open(path, "w") as handle:
        json.dump(report, handle, indent=1)
    return os.path.abspath(path)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
