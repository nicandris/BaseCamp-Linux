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


def verify(name, ok, detail=""):
    """Plain pass or fail, for what is not a packet prefix."""
    if ok:
        print("ok    %-34s %s" % (name, detail))
    else:
        failures.append("%s: %s" % (name, detail))
        print("FAIL  %-34s %s" % (name, detail))


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

# ── Key events, measured on real hardware ────────────────────────────────────
# Issue #85: two owners ran tools/macropad_probe.py on their own MacroPads,
# on Ubuntu and on Arch, with different firmware builds (11 00 .. 06 04 01 01
# and 06 0a 01 06). Their captures agree byte for byte. This is where that
# measurement is written down, so a refactor cannot quietly undo it.
#
# One capture kept verbatim as it came off the wire, M1 pressed:
M1_PRESSED = bytes.fromhex(
    "01000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000002000000000000000000000000000000000000000000"
)
# and the report that followed when the key came up again:
M1_RELEASED = bytes.fromhex(
    "01000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000"
)

# The rest as the byte/bit pairs both dumps show, M1 through M12:
CAPTURED_KEYS = (
    [(42, mask) for mask in (0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)] +
    [(47, mask) for mask in (0x01, 0x02, 0x04, 0x08, 0x10)]
)


def key_report(pairs):
    """Build the report the pad sends while `pairs` are held down."""
    report = bytearray(64)
    report[0] = 0x01
    for byte, mask in pairs:
        report[byte] |= mask
    return bytes(report)


if len(M1_PRESSED) != 64:
    failures.append("the verbatim M1 capture is %d bytes, expected 64" % len(M1_PRESSED))
    print("FAIL  verbatim capture length %d" % len(M1_PRESSED))
elif mp.decode_key_event(M1_PRESSED) != {0}:
    failures.append("verbatim M1 capture decoded as %r" % mp.decode_key_event(M1_PRESSED))
    print("FAIL  verbatim M1 capture %r" % mp.decode_key_event(M1_PRESSED))
else:
    print("ok    verbatim M1 capture        key 0")

if mp.decode_key_event(M1_RELEASED) != set():
    failures.append("the release report decoded as a press: %r"
                    % mp.decode_key_event(M1_RELEASED))
    print("FAIL  release report %r" % mp.decode_key_event(M1_RELEASED))
else:
    print("ok    release report            nothing pressed")

wrong = []
for index, pair in enumerate(CAPTURED_KEYS):
    decoded = mp.decode_key_event(key_report([pair]))
    if decoded != {index}:
        wrong.append("M%d (byte %d mask 0x%02x) decoded as %r"
                     % (index + 1, pair[0], pair[1], decoded))
if wrong:
    failures.extend(wrong)
    print("FAIL  captured key map")
    for problem in wrong:
        print("      %s" % problem)
else:
    print("ok    captured key map          M1-M12 on hardware")

# Nobody captured two keys at once, so this is derived from the map rather
# than measured. It is still worth pinning: the bits are independent.
both = mp.decode_key_event(key_report([CAPTURED_KEYS[0], CAPTURED_KEYS[11]]))
if both != {0, 11}:
    failures.append("two keys at once decoded as %r, expected {0, 11}" % both)
    print("FAIL  two keys at once %r" % both)
else:
    print("ok    two keys at once          {0, 11}")

# Interface 2 also answers with 0x11 packets (init echo, firmware). Those must
# never be mistaken for a key event, and a short read must not pass either.
for label, other in (("init echo", mp.pkt_init(True)),
                     ("firmware info", mp.pkt_firmware_info()),
                     ("ack", bytes([0xFF, 0xAA] + [0] * 62)),
                     ("truncated", bytes([0x01] + [0] * 20))):
    if mp.decode_key_event(other) != set() or mp.is_key_event(other):
        failures.append("%s was taken for a key event" % label)
        print("FAIL  %s taken for a key event" % label)
    else:
        print("ok    %-28s not a key event" % label)

# The DisplayPad reports the same way, and its map is the one the shipping
# driver has been using against real hardware for months. Drifting apart would
# mean one of the two is wrong.
displaypad_map = [
    (42, 0x02), (42, 0x04), (42, 0x08), (42, 0x10), (42, 0x20), (42, 0x40),
    (42, 0x80), (47, 0x01), (47, 0x02), (47, 0x04), (47, 0x08), (47, 0x10),
]
if list(mp.KEY_MAP) != displaypad_map:
    failures.append("KEY_MAP no longer matches the DisplayPad map")
    print("FAIL  key map matches DisplayPad")
else:
    print("ok    key map                   matches the DisplayPad")

# ── Wave and Tornado ride a different struct ─────────────────────────────────
# Found because @Thargorrr's lighting run in #85 lit up for Static and stayed
# dark for Wave. Base Camp routes exactly these two through ChangeBlockEffect,
# which is the same `14 2C` command carrying a different 62 byte struct:
# byBlockNum sits after byWidth, so the colours move one byte along, and the
# two fields we were sending as unused carry real values.
verify("wave is a block effect", mp.uses_block_effect(mp.EFFECT_WAVE) is True)
verify("tornado is a block effect", mp.uses_block_effect(mp.EFFECT_TORNADO) is True)
for effect in (mp.EFFECT_STATIC, mp.EFFECT_BREATHING, mp.EFFECT_MATRIX,
               mp.EFFECT_CUSTOM, mp.EFFECT_OFF):
    if mp.uses_block_effect(effect):
        failures.append("effect %d must not use the block command" % effect)
print("ok    the other effects are not         ChangeEffect as before")

wave = mp.pkt_block_effect(mp.EFFECT_WAVE, brightness=60, speed=60,
                           color1=(255, 0, 0), direction=0)
verify("wave: 14 2c and the effect index", wave[:3] == bytes([0x14, 0x2C, 0x04]),
      wave[:3].hex(" "))
verify("wave: speed and brightness", (wave[4], wave[5]) == (60, 60))
verify("wave: direction 0 goes out as 6", wave[7] == 6, wave[7])
verify("wave: width is 2, not unused", wave[8] == mp.BLOCK_WIDTH, wave[8])
verify("wave: one block", wave[9] == 1, wave[9])
# FWBColor is four bytes: pos, then r, g, b. @Thargorrr's second run showed
# the block form lighting the pad white instead of the red it was sent, which
# is what a colour written one byte early looks like from the front.
verify("wave: the first colour is pos then rgb",
       wave[10] == mp.BLOCK_POS_FIRST and wave[11:14] == b"\xff\x00\x00",
       wave[10:14].hex(" "))
verify("wave: the second colour carries a pos too",
       wave[14] == mp.BLOCK_POS_SECOND, wave[14])

for ui, wire in enumerate(mp.WAVE_DIRECTIONS):
    got = mp.pkt_block_effect(mp.EFFECT_WAVE, direction=ui)[7]
    if got != wire:
        failures.append("wave direction %d went out as %d, expected %d" % (ui, got, wire))
print("ok    wave directions                    %s" % (list(mp.WAVE_DIRECTIONS),))
for ui, wire in enumerate(mp.TORNADO_DIRECTIONS):
    got = mp.pkt_block_effect(mp.EFFECT_TORNADO, direction=ui)[7]
    if got != wire:
        failures.append("tornado direction %d went out as %d, expected %d" % (ui, got, wire))
print("ok    tornado directions                 %s" % (list(mp.TORNADO_DIRECTIONS),))

dual = mp.pkt_block_effect(mp.EFFECT_WAVE, color1=(1, 2, 3), color2=(4, 5, 6))
verify("wave: two colours, four bytes each",
       dual[10:18] == bytes([mp.BLOCK_POS_FIRST, 1, 2, 3,
                             mp.BLOCK_POS_SECOND, 4, 5, 6])
       and dual[6] == mp.COLOR_DUAL, dual[10:18].hex(" "))

# Each struct is 62 bytes only with its own colour type, which is the
# arithmetic that says which one belongs where.
verify("EffData adds up with a 3 byte colour", 7 + 3 * 3 + 3 + 43 == 62)
verify("BlockData adds up with a 4 byte colour", 8 + 2 * 4 + 5 * 4 + 3 + 23 == 62)
rand = mp.pkt_block_effect(mp.EFFECT_WAVE, color_mode=mp.COLOR_RANDOM)
verify("wave: a random colour carries no block", rand[9] == 0, rand[9])

try:
    mp.pkt_block_effect(mp.EFFECT_STATIC)
    failures.append("pkt_block_effect accepted an effect that is not a block one")
    print("FAIL  block command refuses static")
except ValueError:
    print("ok    block command refuses static     the DLL refuses it too")


# ── Stored settings must never take the application down ─────────────────────
# The MacroPad screen is built at startup, not on first visit, so anything
# that raises while reading its config file stops the window from appearing.
# These files are plain json in the config directory and people do edit them.
import json as _json          # noqa: E402
import tempfile as _tempfile  # noqa: E402
from shared import config as _cfg   # noqa: E402


def stored_rgb(payload):
    """What _load_macropad_rgb makes of a file containing `payload`."""
    handle, path = _tempfile.mkstemp(suffix=".json")
    with os.fdopen(handle, "w") as f:
        f.write(payload if isinstance(payload, str) else _json.dumps(payload))
    real = _cfg.MACROPAD_RGB_FILE
    _cfg.MACROPAD_RGB_FILE = path
    try:
        return _cfg._load_macropad_rgb()
    finally:
        _cfg.MACROPAD_RGB_FILE = real
        os.unlink(path)


def usable(rgb):
    """Do to it exactly what the screen does when it builds itself."""
    int(rgb["brightness"]), int(rgb["speed"]), int(rgb["effect"])
    for color in rgb["colors"] + [rgb["color1"], rgb["color2"]]:
        "#%02x%02x%02x" % (int(color[0]) & 0xFF, int(color[1]) & 0xFF,
                           int(color[2]) & 0xFF)
    return len(rgb["colors"]) == mp.NUM_KEYS


for label, payload in (
        ("colours as words", {"colors": [["a", "b", "c"]] * 12}),
        ("brightness as a word", {"brightness": "bright"}),
        ("effect as a word", {"effect": "static"}),
        ("colour pairs, not triples", {"colors": [[1, 2]] * 12}),
        ("colours out of range", {"colors": [[999, -5, 0]] * 12}),
        ("a list where a dict belongs", [1, 2, 3]),
        ("truncated json", '{"effect": 0, "brig'),
        ("too few colours", {"colors": [[1, 2, 3]]}),
        ("too many colours", {"colors": [[1, 2, 3]] * 40}),
        ("colours not a list", {"colors": "red"}),
        ("an empty file", ""),
):
    try:
        if usable(stored_rgb(payload)):
            print("ok    %-30s survives" % label)
        else:
            failures.append("lighting config: %s gave the wrong shape" % label)
            print("FAIL  %-30s wrong shape" % label)
    except Exception as exc:
        failures.append("lighting config: %s raised %r" % (label, exc))
        print("FAIL  %-30s raised %r" % (label, exc))

# Values that are fine must come through untouched, or the coercion is just
# throwing settings away.
kept = stored_rgb({"effect": 4, "brightness": 30, "speed": 90,
                   "color1": [10, 20, 30], "color2": [40, 50, 60],
                   "colors": [[i, i, i] for i in range(12)]})
if (kept["effect"], kept["brightness"], kept["speed"]) == (4, 30, 90) \
        and kept["color1"] == [10, 20, 30] and kept["colors"][11] == [11, 11, 11]:
    print("ok    %-30s kept as they are" % "good values")
else:
    failures.append("lighting config: good values were changed: %r" % kept)
    print("FAIL  good values were changed")


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
    # The old form of wave, kept on both sides so the probe can send it next to
    # the new one and a tester can say which of the two lights the pad (#85).
    ("probe wave, old form", probe.effect_packet(4, brightness=60, speed=60),
     mp.pkt_effect(mp.EFFECT_WAVE, brightness=60, speed=60, color1=(255, 0, 0))),
    ("probe wave, block form", probe.block_effect_packet(4, direction=6),
     mp.pkt_block_effect(mp.EFFECT_WAVE, brightness=60, speed=60,
                         color1=(255, 0, 0), direction=0)),
    ("probe tornado, block form", probe.block_effect_packet(7, direction=10),
     mp.pkt_block_effect(mp.EFFECT_TORNADO, brightness=60, speed=60,
                         color1=(255, 0, 0), direction=0)),
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
