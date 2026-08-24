#!/usr/bin/env python3
"""
Checks the MacroPad packet builders against the bytes read out of
MacroPadSDK.dll. No hardware and no hidapi needed.

    python3 tools/test_macropad_protocol.py

Every expectation here is a fact taken from the disassembly, written down so
that a later refactor cannot quietly change what goes on the wire. Two of them
are cross-checks rather than MacroPad facts: the INIT handshake and the
DisplayPad brightness packet, which our shipping DisplayPad driver sends to
real hardware. They are the reason to believe the rest.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from devices.macropad import controller as mp   # noqa: E402

failures = []


def check(name, actual, expected_prefix, length=64):
    """Compare the leading bytes and the total length."""
    problems = []
    if len(actual) != length:
        problems.append("length %d, expected %d" % (len(actual), length))
    got = actual[:len(expected_prefix)]
    if bytes(got) != bytes(expected_prefix):
        problems.append("bytes %s, expected %s" % (got.hex(" "), bytes(expected_prefix).hex(" ")))
    if problems:
        failures.append("%s: %s" % (name, "; ".join(problems)))
        print("FAIL  %s" % name)
        for problem in problems:
            print("      %s" % problem)
    else:
        print("ok    %-28s %s" % (name, got.hex(" ")))


# ── The handshake, cross-checked against the shipping DisplayPad driver ───────
# devices/displaypad/panel.py sends INIT_MSG = 00 11 80 00 00 01 ... to real
# hardware. Ours must be the same 64 bytes without the report ID.
check("init", mp.pkt_init(True), bytes([0x11, 0x80, 0x00, 0x00, 0x01]))
check("init disable", mp.pkt_init(False), bytes([0x11, 0x80, 0x00, 0x00, 0x00]))

# ── Reads ────────────────────────────────────────────────────────────────────
check("firmware_info", mp.pkt_firmware_info(), bytes([0x11, 0x00]))
check("firmware_layout", mp.pkt_firmware_layout(), bytes([0x11, 0x12]))

# ── Settings, resets, flash ──────────────────────────────────────────────────
check("led on", mp.pkt_led(True), bytes([0x12, 0x03]))
check("led off", mp.pkt_led(False), bytes([0x12, 0x02]))
check("reset keys", mp.pkt_reset_keys(), bytes([0x13, 0x60]))
check("reset effects", mp.pkt_reset_effects(), bytes([0x13, 0x61]))
check("save slot 3", mp.pkt_save(3), bytes([0x13, 0x55, 0x00, 0x00, 0x03]))

# ── Profiles ─────────────────────────────────────────────────────────────────
check("switch profile 2/4", mp.pkt_switch_profile(2, 4),
      bytes([0x14, 0x00, 0x00, 0x00, 0x02, 0x04]))

# The SDK validates before building; so do we.
for bad in (0, 6, -1):
    try:
        mp.pkt_switch_profile(bad)
        failures.append("switch profile %r was accepted" % bad)
        print("FAIL  profile %r accepted" % bad)
    except ValueError:
        print("ok    profile %-22r rejected" % bad)

# ── Key remapping ────────────────────────────────────────────────────────────
# 14 20, source as uint16 little endian in [2:4], target in [4:6].
check("remap key 3 -> 0x1234", mp.pkt_remap_key(3, 0x1234),
      bytes([0x14, 0x20, 0x03, 0x00, 0x34, 0x12]))
check("shortcut 5 + ctrl", mp.pkt_shortcut(5, 0x2C, 0x01),
      bytes([0x14, 0x21, 0x05, 0x00, 0x2C, 0x01]))

# ── Lighting ─────────────────────────────────────────────────────────────────
# Static: speed goes out as 0xFF, direction and width likewise, colour 1 at [9].
static = mp.pkt_effect(mp.EFFECT_STATIC, brightness=75, color1=(0x00, 0x44, 0xFF))
check("static effect", static,
      bytes([0x14, 0x2C, 0x00, 0x00, 0xFF, 75, 0x00, 0xFF, 0xFF,
             0x00, 0x44, 0xFF]))

# Wave: a real speed value, dual colour raises byRandColor to 16.
wave = mp.pkt_effect(mp.EFFECT_WAVE, brightness=50, speed=60,
                     color1=(1, 2, 3), color2=(4, 5, 6))
check("wave dual colour", wave,
      bytes([0x14, 0x2C, 0x04, 0x00, 60, 50, 0x10, 0xFF, 0xFF,
             1, 2, 3, 4, 5, 6]))

# Off carries no colour at all.
check("off", mp.pkt_effect(mp.EFFECT_OFF),
      bytes([0x14, 0x2C, 0x0C, 0x00, 0xFF, mp.DEFAULT_BRIGHTNESS, 0x00,
             0xFF, 0xFF, 0x00, 0x00, 0x00]))

# Custom activation is the odd one: the SDK fills the buffer with 0xFF first.
custom = mp.pkt_custom_activate(80)
check("custom activate", custom,
      bytes([0x14, 0x2C, 0x0A, 0x00, 0xFF, 80, 0xFF, 0xFF]))
if custom[-1] != 0xFF:
    failures.append("custom activate: tail should stay 0xFF")
    print("FAIL  custom activate tail is 0x%02x, expected 0xff" % custom[-1])
else:
    print("ok    custom activate tail        ff")

# Per-key colours: 14 2C 00 01 <chunk> 4B 00, then 12 RGB triples at offset 7.
colors = [(i, i + 1, i + 2) for i in range(0, 36, 3)]
packet = mp.pkt_custom_colors(colors)
check("custom colours header", packet,
      bytes([0x14, 0x2C, 0x00, 0x01, 0x00, 0x4B, 0x00]))
expected_body = bytes(b for color in colors for b in color)
if packet[7:7 + 36] != expected_body:
    failures.append("custom colours: body at offset 7 does not match")
    print("FAIL  custom colours body")
else:
    print("ok    custom colours body        %s ..." % packet[7:13].hex(" "))
if any(packet[7 + 36:]):
    failures.append("custom colours: bytes after the 36 colour bytes are not zero")
    print("FAIL  custom colours tail not zero")
else:
    print("ok    custom colours tail        zero")

try:
    mp.pkt_custom_colors(colors[:5])
    failures.append("custom colours accepted a short list")
    print("FAIL  short colour list accepted")
except ValueError:
    print("ok    short colour list          rejected")

# ── Response helpers ─────────────────────────────────────────────────────────
if not mp.is_ack(bytes([0xFF, 0xAA] + [0] * 62)):
    failures.append("is_ack rejected FF AA")
if mp.is_ack(bytes([0x14, 0x2C] + [0] * 62)):
    failures.append("is_ack accepted a non-ack")
print("ok    ack detection")

# decode_key_event is the unverified part; check it is at least self-consistent.
event = bytearray(64)
event[0] = 0x01
event[1] = 0b00000101   # keys 0 and 2
event[2] = 0b00001000   # key 11
decoded = mp.decode_key_event(bytes(event))
if decoded != {0, 2, 11}:
    failures.append("decode_key_event returned %r, expected {0, 2, 11}" % decoded)
    print("FAIL  decode_key_event %r" % decoded)
else:
    print("ok    decode_key_event (hypothesis, not verified on hardware)")

# ── The probe script must agree with the driver ──────────────────────────────
# tools/macropad_probe.py is deliberately standalone so testers can download
# one file, which means it carries its own copy of the packet layout. That is
# the kind of duplication that drifts, so pin the two together here.
import macropad_probe as probe   # noqa: E402

pairs = [
    ("probe init", probe.INIT_PACKET, mp.pkt_init(True)),
    ("probe firmware info", probe.FW_INFO_PACKET, mp.pkt_firmware_info()),
    ("probe firmware layout", probe.FW_LAYOUT_PACKET, mp.pkt_firmware_layout()),
    ("probe static red", probe.effect_packet(0, brightness=60, color=(255, 0, 0)),
     mp.pkt_effect(mp.EFFECT_STATIC, brightness=60, color1=(255, 0, 0))),
    ("probe wave", probe.effect_packet(4, brightness=60, speed=60),
     mp.pkt_effect(mp.EFFECT_WAVE, brightness=60, speed=60, color1=(255, 0, 0))),
    ("probe custom activate", probe.custom_activate_packet(70),
     mp.pkt_custom_activate(70)),
]
for name, from_probe, from_driver in pairs:
    if bytes(from_probe) == bytes(from_driver):
        print("ok    %-28s matches driver" % name)
    else:
        failures.append("%s differs from the driver" % name)
        print("FAIL  %s" % name)
        print("      probe  %s" % bytes(from_probe)[:14].hex(" "))
        print("      driver %s" % bytes(from_driver)[:14].hex(" "))

palette = [(255, 0, 0), (255, 128, 0), (255, 255, 0), (128, 255, 0),
           (0, 255, 0), (0, 255, 128), (0, 255, 255), (0, 128, 255),
           (0, 0, 255), (128, 0, 255), (255, 0, 255), (255, 255, 255)]
if bytes(probe.per_key_packet()) == bytes(mp.pkt_custom_colors(palette)):
    print("ok    probe per-key colours       matches driver")
else:
    failures.append("probe per-key colour packet differs from the driver")
    print("FAIL  probe per-key colours")

# ── The capture analysis, on synthetic reports ───────────────────────────────
# The real run needs hardware; this at least proves the analysis does not throw
# and picks the right bits out of a DisplayPad-shaped report.
probe.report["key_capture"] = {}
idle = [bytes(64)]
captured = {
    "M1": [bytes([0x01, 0x01] + [0] * 62).hex(" ")],
    "M9": [bytes([0x01, 0x00, 0x01] + [0] * 61).hex(" ")],
    "M5": [bytes(64).hex(" ")],          # nothing but idle, must not crash
}
probe.analyse_capture(idle, captured)
analysis = probe.report["key_capture"].get("analysis", {})
if analysis.get("M1") == [{"byte": 0, "bit": 0}, {"byte": 1, "bit": 0}] and \
        analysis.get("M9") == [{"byte": 0, "bit": 0}, {"byte": 2, "bit": 0}] and \
        analysis.get("M5") == []:
    print("ok    capture analysis")
else:
    failures.append("capture analysis returned %r" % analysis)
    print("FAIL  capture analysis %r" % analysis)

if probe.report["key_capture"].get("first_bytes") != [0x01]:
    failures.append("capture analysis did not report the leading 0x01")
    print("FAIL  capture analysis first_bytes")
else:
    print("ok    capture analysis first byte")

# ── The report descriptor summary, on a real descriptor ──────────────────────
# Taken from this machine's DisplayPad (interface 3): a vendor collection with
# one 64 byte report in each direction. Same shape the MacroPad should show.
descriptor = bytes.fromhex(
    "06 00 ff 09 01 a1 01 09 01 15 00 26 ff 00 75 08 95 40 81 02 09 01 "
    "15 00 26 ff 00 75 08 95 40 91 02 c0".replace(" ", ""))
summary = probe.summarise_descriptor(descriptor)
if summary["usage_page"] == "0xFF00" and summary["usage"] == "0x01" and \
        summary["reports"].get("0", {}).get("input") == 64 and \
        summary["reports"].get("0", {}).get("output") == 64:
    print("ok    descriptor summary          %s" % summary["reports"])
else:
    failures.append("descriptor summary returned %r" % summary)
    print("FAIL  descriptor summary %r" % summary)

# ── Enumeration without any hidapi binding ───────────────────────────────────
# A tester on Ubuntu ran the probe and got "module 'hid' has no attribute
# 'Device'": there are two unrelated packages called `hid` and his distro ships
# the other one (#85). The probe now reads sysfs and /dev/hidraw itself, so
# build a fake sysfs tree shaped like a real USB pad and check what it finds.
import shutil                                                     # noqa: E402
import tempfile                                                   # noqa: E402

fake = tempfile.mkdtemp(prefix="macropad-sysfs-")
try:
    usb = os.path.join(fake, "devices", "usb1", "1-1")
    interface = os.path.join(usb, "1-1:1.1")
    hid_device = os.path.join(interface, "0003:3282:0008.0004")
    os.makedirs(hid_device)
    write = lambda where, what: open(where, "w").write(what)
    write(os.path.join(usb, "manufacturer"), "Mountain\n")
    write(os.path.join(usb, "product"), "MOUNTAIN MacroPad\n")
    write(os.path.join(interface, "bInterfaceNumber"), "01\n")
    write(os.path.join(hid_device, "uevent"),
          "DRIVER=hid-generic\nHID_ID=0003:00003282:00000008\n"
          "HID_NAME=Mountain MOUNTAIN MacroPad\n")
    open(os.path.join(hid_device, "report_descriptor"), "wb").write(descriptor)
    os.makedirs(os.path.join(fake, "class", "hidraw"))
    os.symlink(hid_device, os.path.join(fake, "class", "hidraw", "hidraw7"))
    # /sys/class/hidraw/hidraw7 is itself a link to the HID device, and the
    # probe looks inside it for "device"; mirror that with a directory holding
    # the link, which is what the kernel actually presents.
    shutil.rmtree(os.path.join(fake, "class", "hidraw"))
    node_dir = os.path.join(fake, "class", "hidraw", "hidraw7")
    os.makedirs(node_dir)
    os.symlink(hid_device, os.path.join(node_dir, "device"))

    found = probe.hidraw_entries(0x3282, base=os.path.join(fake, "class", "hidraw"))
    expected = {
        "product_id": 0x0008,
        "interface_number": 1,
        "path": "/dev/hidraw7",
        "usage_page": 0xFF00,
        "usage": 0x01,
        "product_string": "MOUNTAIN MacroPad",
        "manufacturer_string": "Mountain",
    }
    if len(found) == 1 and all(found[0].get(k) == v for k, v in expected.items()):
        print("ok    sysfs enumeration          interface %d, usage page 0x%04X"
              % (found[0]["interface_number"], found[0]["usage_page"]))
    else:
        failures.append("sysfs enumeration returned %r" % (found,))
        print("FAIL  sysfs enumeration %r" % (found,))

    if probe.hidraw_entries(0x1234, base=os.path.join(fake, "class", "hidraw")) == []:
        print("ok    sysfs enumeration filters other vendors")
    else:
        failures.append("sysfs enumeration ignored the vendor filter")
        print("FAIL  sysfs enumeration vendor filter")
finally:
    shutil.rmtree(fake, ignore_errors=True)

# ── The kernel node link, on a pipe ──────────────────────────────────────────
# Proves the mechanics without hardware: the report number goes in front of the
# payload, a read that finds nothing returns None instead of blocking forever.
fifo_dir = tempfile.mkdtemp(prefix="macropad-fifo-")
try:
    fifo = os.path.join(fifo_dir, "hidraw99")
    os.mkfifo(fifo)
    link = probe.HidrawLink({"path": fifo})
    link.write(probe.INIT_PACKET)
    echoed = os.read(link.fd, 65)
    if echoed == b"\x00" + probe.INIT_PACKET:
        print("ok    hidraw write                report id 0 + 64 bytes")
    else:
        failures.append("hidraw write sent %r" % echoed[:8])
        print("FAIL  hidraw write %r" % echoed[:8])

    started = time.monotonic()
    if link.read(120) is None and time.monotonic() - started < 1.0:
        print("ok    hidraw read timeout")
    else:
        failures.append("hidraw read did not time out cleanly")
        print("FAIL  hidraw read timeout")

    os.write(link.fd, bytes([0x01, 0x08] + [0] * 62))
    answer = link.read(500)
    if answer and answer[:2] == b"\x01\x08":
        print("ok    hidraw read                 %s" % answer[:4].hex(" "))
    else:
        failures.append("hidraw read returned %r" % (answer,))
        print("FAIL  hidraw read %r" % (answer,))
    link.close()
finally:
    shutil.rmtree(fifo_dir, ignore_errors=True)

# ── Both hidapi flavours ─────────────────────────────────────────────────────
# One package calls it hid.Device, the other hid.device(). The probe has to
# open either, so hand it a stand-in for each and see that it does.
class FakeDeviceClass:
    """Looks like the `hid` package: a Device class taking path=."""
    class Device:
        def __init__(self, path=None):
            self.path, self.written = path, []
        def write(self, data):
            self.written.append(data)
        def read(self, size, timeout=None):
            return bytes([0xAA] * 4)
        def close(self):
            pass


class FakeDeviceFunction:
    """Looks like the `hidapi` package: device() plus open_path()."""
    class device:
        def __init__(self):
            self.path, self.written = None, []
        def open_path(self, path):
            self.path = path
        def set_nonblocking(self, value):
            self.nonblocking = value
        def write(self, data):
            self.written.append(data)
        def read(self, size, timeout_ms=0):
            return bytes([0xBB] * 4)
        def close(self):
            pass


for label, module in (("hid.Device", FakeDeviceClass), ("hid.device", FakeDeviceFunction)):
    try:
        opened = probe.LibraryLink(module, {"path": "/dev/hidraw3", "source": "library"})
        opened.write(probe.INIT_PACKET)
        sent = opened.dev.written[0]
        ok = (opened.kind == label and opened.dev.path == b"/dev/hidraw3" and
              sent == b"\x00" + probe.INIT_PACKET and len(opened.read(10)) == 4)
    except Exception as exc:
        ok = False
        print("      %s" % exc)
    if ok:
        print("ok    library link                %s" % label)
    else:
        failures.append("LibraryLink cannot drive the %s flavour" % label)
        print("FAIL  library link %s" % label)

no_flavour = type("Empty", (), {})
try:
    probe.LibraryLink(no_flavour, {"path": "/dev/hidraw3", "source": "library"})
    failures.append("LibraryLink accepted a module with no usable API")
    print("FAIL  library link rejects unusable module")
except RuntimeError:
    print("ok    library link rejects unusable module")

flavour = probe.describe_hid_module(FakeDeviceFunction)
if flavour["flavour"] == "hid.device" and flavour["present"]:
    print("ok    hid module diagnosis        %s" % flavour["flavour"])
else:
    failures.append("describe_hid_module returned %r" % flavour)
    print("FAIL  hid module diagnosis %r" % flavour)

print()
if failures:
    print("%d check(s) failed:" % len(failures))
    for failure in failures:
        print("  - %s" % failure)
    sys.exit(1)
print("all checks passed")
