#!/usr/bin/env python3
"""
Mountain MacroPad Controller
VID: 0x3282, PID: 0x0008
12 mechanical keys (M1-M12) with per-key RGB. No displays.

Protocol: vendor HID collection (Usage Page 0xFF00, Usage 0x01).
Reports are 64 payload bytes plus a leading Report ID 0x00, so 65 bytes go
into the HID write, exactly like the DisplayPad command interface.

Reverse-engineered on 2026-08-11 from Mountain Base Camp for Windows
(MacroPadSDK.dll disassembly plus the BaseCamp.Service.exe decompile).
Full write-up: protocol/macropad_protocol.md.

How much of this is trustworthy: the same static analysis run against
DisplayPadSDK.dll reproduces, byte for byte, the two commands our working
DisplayPad driver sends to real hardware (APEnable = 11 80 00 00 01 and
SetMainBrightness = 12 03 00 00 <percent>), and reads back the correct PIDs
for the DisplayPad and the Everest. So the method is sound. What is NOT
verified is this device: nobody on the team owns a MacroPad. Every packet
below is built from the SDK, not from a capture.

The one gap the disassembly left, the key event input report, is closed. The
SDK hands key presses to a callback as (matrix, pressed) after decoding them
inside a HID helper class that could not be read statically, so
tools/macropad_probe.py went out to collect it from owners instead. Two dumps
came back in issue #85, from different distributions and different firmware
builds, and they agree byte for byte; KEY_MAP below is that measurement.
Lighting is measured in part: @Thargorrr ran the probe's --lighting pass in
#85 and reported that the backlight and all three static colours work, while
Wave, the per key colours and the custom effect stayed dark. Wave has a fix
from the SDK below; the custom sequence is closer but probably still
incomplete. Both want another run to confirm.

Command summary (payload offsets, Report ID not counted):

  11 80  [4]=1                       AP enable, the INIT handshake
  11 00                              firmware info
  11 12                              firmware layout / version
  12 02 / 12 03                      main LED off / on
  13 55  [4]=slot                    save current state to flash
  13 60 / 13 61                      reset key bindings / reset effects
  14 00  [4]=profile 1-5 [5]=slot    switch profile
  14 20  [2:4]=src [4:6]=target      remap a key
  14 21  [2:4]=src [4]=key [5]=mods  assign a shortcut
  14 2C  [2:64]=EffData              lighting effect (62 byte struct)
  14 2C  [2:64]=BlockData            Wave and Tornado, a different struct
  14 2C 00 01 [4]=chunk [5]=4B       per-key static colours at offset 7
  14 A0  [2]=chunk [3]=01 [4:16]      which effect each of the 12 keys runs

Acknowledgement: response[0] == 0xFF and response[1] == 0xAA, except for
commands that echo their own arguments instead (switch_profile does).
"""
import os
import sys
import time

# Also importable as a standalone script, like the other device controllers.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared import hid_compat
HID_AVAILABLE = hid_compat.HID_AVAILABLE

VID = 0x3282
PID = 0x0008

# The SDK finds the device by HID usage rather than by interface number, so we
# do the same. Which interface that lands on is not known without hardware;
# find_path() falls back to trying every interface when hidapi does not report
# usage information (older builds return 0 for both fields on Linux).
USAGE_PAGE = 0xFF00
USAGE = 0x01

PAYLOAD_LEN = 64
NUM_KEYS = 12
NUM_PROFILES = 5          # FW_NUM_PROFILE
NUM_EFFECT_SLOTS = 9      # FW_EFF_MENU_NUM

DEFAULT_TIMEOUT_MS = 500   # what the SDK waits for a reply
PROFILE_TIMEOUT_MS = 950   # switch_profile is slower

# ── Effect codes (EFF_INDEX, these are the wire values) ───────────────────────

EFFECT_STATIC     = 0
EFFECT_BREATHING  = 1
EFFECT_REACTIVE_A = 3
EFFECT_WAVE       = 4
EFFECT_REACTIVE_B = 5
EFFECT_YETI       = 6
EFFECT_TORNADO    = 7
EFFECT_MATRIX     = 9
EFFECT_CUSTOM     = 10
EFFECT_REACTIVE_C = 11
EFFECT_OFF        = 12

# Ordered for a UI: value, translation key. The names are the ones Base Camp
# uses; the reactive variants are three separate firmware effects.
EFFECTS = [
    (EFFECT_STATIC,     "static"),
    (EFFECT_BREATHING,  "breathing"),
    (EFFECT_WAVE,       "wave"),
    (EFFECT_TORNADO,    "tornado"),
    (EFFECT_MATRIX,     "matrix"),
    (EFFECT_YETI,       "yeti"),
    (EFFECT_REACTIVE_A, "reactive_a"),
    (EFFECT_REACTIVE_B, "reactive_b"),
    (EFFECT_REACTIVE_C, "reactive_c"),
    (EFFECT_CUSTOM,     "custom"),
    (EFFECT_OFF,        "off"),
]

# byRandColor: how the colour fields are read by the firmware.
COLOR_SINGLE = 0    # colorLv[0] only
COLOR_DUAL   = 16   # colorLv[0] and colorLv[1]
COLOR_RANDOM = 2    # firmware picks, colour fields ignored

# The Windows UI leaves these two at 0xFF for every effect this device has;
# they belong to the shared SDK struct and are used by the Everest keyboards.
UNUSED = 0xFF

# Lighting defaults straight out of the Base Camp data model (Lighting.cs),
# which also tells us the units: both are percentages, 0-100.
DEFAULT_SPEED = 60
DEFAULT_BRIGHTNESS = 75


# ── Packet builders ───────────────────────────────────────────────────────────
#
# Pure functions returning the 64 byte payload. They are separated from the I/O
# so they can be checked without a device; tools/test_macropad_protocol.py
# asserts them against the bytes documented above.

def _pkt(fill=0x00):
    return bytearray([fill]) * PAYLOAD_LEN


def _clamp(value, low, high):
    return max(low, min(high, int(value)))


def _rgb(color):
    r, g, b = color
    return (r & 0xFF, g & 0xFF, b & 0xFF)


def pkt_init(enable=True):
    """AP enable. Base Camp sends this once after opening the device.

    This is the same handshake our DisplayPad driver calls INIT_MSG, where it
    is answered with an echo of the first five bytes."""
    p = _pkt()
    p[0] = 0x11
    p[1] = 0x80
    p[4] = 1 if enable else 0
    return bytes(p)


def pkt_firmware_info():
    p = _pkt()
    p[0] = 0x11
    p[1] = 0x00
    return bytes(p)


def pkt_firmware_layout():
    p = _pkt()
    p[0] = 0x11
    p[1] = 0x12
    return bytes(p)


def pkt_led(on):
    """Master backlight on/off. Unlike the DisplayPad this carries no
    percentage; per-effect brightness lives in the effect packet."""
    p = _pkt()
    p[0] = 0x12
    p[1] = 0x03 if on else 0x02
    return bytes(p)


def pkt_switch_profile(profile, slot=0):
    """Profile is 1-5, slot is the effect slot 0-8. The SDK rejects anything
    outside those ranges before it ever builds a packet, so we do too."""
    if not 1 <= int(profile) <= NUM_PROFILES:
        raise ValueError("profile must be 1..%d" % NUM_PROFILES)
    if not 0 <= int(slot) < NUM_EFFECT_SLOTS:
        raise ValueError("slot must be 0..%d" % (NUM_EFFECT_SLOTS - 1))
    p = _pkt()
    p[0] = 0x14
    p[1] = 0x00
    p[4] = int(profile)
    p[5] = int(slot)
    return bytes(p)


def pkt_save(slot=0):
    """Persist the current effect slot to flash. Everything set without this
    is lost on replug."""
    if not 0 <= int(slot) < NUM_EFFECT_SLOTS:
        raise ValueError("slot must be 0..%d" % (NUM_EFFECT_SLOTS - 1))
    p = _pkt()
    p[0] = 0x13
    p[1] = 0x55
    p[4] = int(slot)
    return bytes(p)


def pkt_reset_keys():
    p = _pkt()
    p[0] = 0x13
    p[1] = 0x60
    return bytes(p)


def pkt_reset_effects():
    p = _pkt()
    p[0] = 0x13
    p[1] = 0x61
    return bytes(p)


def pkt_effect(effect, brightness=DEFAULT_BRIGHTNESS, speed=DEFAULT_SPEED,
               color1=(255, 255, 255), color2=None, background=None,
               color_mode=None, all_keys=0):
    """Lighting effect: 14 2C followed by the 62 byte EffData struct.

    EffData maps onto the payload like this:
      [2] effect index   [3] byAll        [4] speed     [5] brightness
      [6] colour mode    [7] direction    [8] width
      [9:18] colour 1-3  [18:21] background   [21:64] effect specific

    Static and Off carry speed 0xFF, which is what Base Camp sends; direction
    and width are 0xFF for every effect this device supports."""
    p = _pkt()
    p[0] = 0x14
    p[1] = 0x2C
    p[2] = int(effect) & 0xFF
    p[3] = int(all_keys) & 0xFF

    if effect in (EFFECT_STATIC, EFFECT_OFF):
        p[4] = UNUSED
    else:
        p[4] = _clamp(speed, 0, 100)
    p[5] = _clamp(brightness, 0, 100)

    if color_mode is None:
        color_mode = COLOR_DUAL if color2 is not None else COLOR_SINGLE
    p[6] = int(color_mode) & 0xFF
    p[7] = UNUSED   # byDirection
    p[8] = UNUSED   # byWidth

    if effect != EFFECT_OFF and color_mode != COLOR_RANDOM:
        p[9], p[10], p[11] = _rgb(color1)
        if color2 is not None:
            p[12], p[13], p[14] = _rgb(color2)
    if background is not None:
        p[18], p[19], p[20] = _rgb(background)
    return bytes(p)


# ── Wave and Tornado: a different struct behind the same command ─────────────
#
# Measured by @Thargorrr in #85: Static lit up, Wave stayed dark. The reason is
# in the Windows software rather than in the pad. Base Camp routes exactly two
# effects, Colorwave and Tornado, through `ChangeBlockEffect` instead of
# `ChangeEffect`:
#
#     (EffMenuIndex != Colorwave && EffMenuIndex != Tornado)
#         ? ChangeEffect(...)       // EffData
#         : ChangeBlockEffect(...)  // BlockData
#
# Both go out as `14 2C` with 62 bytes at payload offset 2, so the command is
# the same; the struct is not. BlockData inserts byBlockNum after byWidth,
# which pushes the colours one byte along, and carries two colours instead of
# three. And the two fields we were sending as "unused" are real here: the
# SDK sets byWidth to 2 and a genuine direction. The wrapper in the DLL also
# refuses any effect index other than 4, 5 and 7.
#
#   [2] byEffectIndex   [3] byAll       [4] bySpeed    [5] byLightness
#   [6] byRandColor     [7] byDirection [8] byWidth    [9] byBlockNum
#   [10:18] colorLv[2]  [18:38] undef[5]  [38:41] bkColor  [41:64] undef[23]
#
# And the colours are not the same type either. EffData carries FWColor, three
# bytes of r, g, b. BlockData carries FWBColor, **four**: a leading `pos`, then
# r, g, b. @Thargorrr's second run in #85 is what forced this out: the block
# form lit the pad where the old form left it dark, but it lit white rather
# than the red it was sent, because the red had been written one byte early
# and the pad read pos=255, r=0, g=0. The two structs add up to 62 bytes only
# with the right colour type, which is the arithmetic that confirms it:
#
#   EffData    7 + 3x3 + 3 + 43                = 62
#   BlockData  8 + 2x4 + 5x4 + 3 + 23          = 62
#
# The SDK does not leave `pos` at zero either. Its wrapper writes 100 into the
# first colour and 0xFF into the second before the packet goes out.
BLOCK_POS_FIRST  = 100
BLOCK_POS_SECOND = 0xFF
#
# Direction is not the plain 0 to 3 the UI shows either. Base Camp maps it:
BLOCK_EFFECTS = (EFFECT_WAVE, EFFECT_TORNADO)

WAVE_DIRECTIONS    = (6, 2, 4, 0)     # UI 0..3, from getChangeBlockEffect()
TORNADO_DIRECTIONS = (10, 9)          # UI 0..1

# getChangeBlockEffect() builds the struct, and then the SDK's own wrapper
# rewrites parts of it before the packet goes out. Reading only the first of
# those is what left Wave lit but standing still in @Thargorrr's third run:
# the builder sets byWidth to 2, and the wrapper overwrites it with 0 for both
# of these effects. Tornado rotated anyway, so it tolerates the 2; Wave does
# not, and a single block two wide is a block that does not travel.
#
# A dual colour Wave is a different shape again: the wrapper copies the two
# colours into the next two slots and spaces all four along the strip at
# 25, 50, 75 and 100, with byBlockNum set to 4.
BLOCK_WIDTH_MOVING = 0                # single colour, and Tornado always
BLOCK_WIDTH_SPREAD = 2                # a dual colour Wave, and random
WAVE_GRADIENT_POS  = (25, 50, 75, 100)


def uses_block_effect(effect):
    """True for the two effects that go through the block command."""
    return int(effect) in BLOCK_EFFECTS


def pkt_block_effect(effect, brightness=DEFAULT_BRIGHTNESS, speed=DEFAULT_SPEED,
                     color1=(255, 255, 255), color2=None, color_mode=None,
                     direction=0, all_keys=0):
    """Wave or Tornado: `14 2C` followed by the 62 byte BlockData struct.

    Derived from MacroPadSDK.dll and Base Camp's own call site, not measured on
    hardware yet: the run that found the problem could only show that the old
    packet did nothing.
    """
    effect = int(effect)
    if effect not in BLOCK_EFFECTS:
        raise ValueError("effect %d does not use the block command" % effect)
    p = _pkt()
    p[0] = 0x14
    p[1] = 0x2C
    p[2] = effect & 0xFF
    p[3] = int(all_keys) & 0xFF
    p[4] = _clamp(speed, 0, 100)
    p[5] = _clamp(brightness, 0, 100)

    if color_mode is None:
        color_mode = COLOR_DUAL if color2 is not None else COLOR_SINGLE
    p[6] = int(color_mode) & 0xFF

    table = WAVE_DIRECTIONS if effect == EFFECT_WAVE else TORNADO_DIRECTIONS
    p[7] = table[int(direction) % len(table)]

    # From here on this follows the SDK wrapper rather than the builder, since
    # the wrapper is what decides the bytes that leave the machine.
    if color_mode == COLOR_RANDOM:
        p[6] = COLOR_RANDOM
        p[8] = BLOCK_WIDTH_SPREAD
        p[9] = 0                       # no block: the firmware picks
        p[10] = BLOCK_POS_SECOND
        return bytes(p)

    p[6] = COLOR_SINGLE                # the wrapper clears this for both

    if effect == EFFECT_WAVE and color2 is not None:
        # Four stops: the two colours, then the same two again.
        p[8] = BLOCK_WIDTH_SPREAD
        p[9] = 4
        first, second = _rgb(color1), _rgb(color2)
        for slot, (pos, rgb) in enumerate(zip(WAVE_GRADIENT_POS,
                                              (first, second, first, second))):
            at = 10 + slot * 4
            p[at] = pos
            p[at + 1], p[at + 2], p[at + 3] = rgb
        return bytes(p)

    # One colour, one block, and a width of zero so it travels.
    p[8] = BLOCK_WIDTH_MOVING
    p[9] = 1
    p[10] = BLOCK_POS_FIRST
    p[11], p[12], p[13] = _rgb(color1)
    p[14] = BLOCK_POS_SECOND
    return bytes(p)


def pkt_custom_activate(brightness=DEFAULT_BRIGHTNESS):
    """Switch to the custom (per-key) effect.

    This is just pkt_effect(EFFECT_CUSTOM) with one twist worth keeping: the
    SDK memsets the buffer to 0xFF here rather than 0x00, so every field it
    does not set explicitly goes out as 0xFF. Reproduced exactly, because a
    firmware that treats 0x00 as a real value would behave differently."""
    p = _pkt(0xFF)
    p[0] = 0x14
    p[1] = 0x2C
    p[2] = EFFECT_CUSTOM
    p[3] = 0x00
    p[5] = _clamp(brightness, 0, 100)
    return bytes(p)


def pkt_custom_colors(colors, chunk=0):
    """Per-key static colours: 12 RGB triples starting at payload offset 7.

    36 bytes fit in one packet (the SDK chunks at 57 bytes, so it only ever
    sends one), but the chunk index in byte 4 is part of the format and is
    kept here for the day someone needs it."""
    if len(colors) != NUM_KEYS:
        raise ValueError("need exactly %d colours" % NUM_KEYS)
    p = _pkt()
    p[0] = 0x14
    p[1] = 0x2C
    p[2] = 0x00
    p[3] = 0x01
    p[4] = int(chunk) & 0xFF
    p[5] = 0x4B
    off = 7
    for color in colors:
        p[off], p[off + 1], p[off + 2] = _rgb(color)
        off += 3
    return bytes(p)


def pkt_customize_table(values=None):
    """`SetCustomizeTable`: which effect each of the 12 keys runs.

    `14 A0`, chunk index in byte 2, `0x01` in byte 3, then the twelve bytes at
    offset 4, one per key. Disassembled from the export's worker, which memsets
    a 64 byte buffer, writes `14 a0`, puts `(chunk | 0x0100)` as a word at
    offset 2 and copies the 12 byte table to offset 4 in a single chunk.

    This is the step the driver was missing entirely. @Thargorrr's second run
    in #85 had the corrected order already and the custom colours still stayed
    dark, so the order was necessary and not sufficient.

    All zeroes means every key runs effect 0, Static, which is what "show the
    twelve colours I just uploaded" should be. That last part is a reading of
    Base Camp's call site rather than something measured.
    """
    if values is None:
        values = [EFFECT_STATIC] * NUM_KEYS
    if len(values) != NUM_KEYS:
        raise ValueError("need exactly %d entries" % NUM_KEYS)
    p = _pkt()
    p[0] = 0x14
    p[1] = 0xA0
    p[2] = 0x00                      # chunk index
    p[3] = 0x01
    for i, value in enumerate(values):
        p[4 + i] = int(value) & 0xFF
    return bytes(p)


def pkt_remap_key(source, target):
    """Remap key `source` (0-11) to HID key code `target`."""
    p = _pkt()
    p[0] = 0x14
    p[1] = 0x20
    p[2] = int(source) & 0xFF
    p[3] = (int(source) >> 8) & 0xFF
    p[4] = int(target) & 0xFF
    p[5] = (int(target) >> 8) & 0xFF
    return bytes(p)


def pkt_shortcut(source, target, modifiers=0):
    """Assign a modifier plus key combination to key `source`."""
    p = _pkt()
    p[0] = 0x14
    p[1] = 0x21
    p[2] = int(source) & 0xFF
    p[3] = (int(source) >> 8) & 0xFF
    p[4] = int(target) & 0xFF
    p[5] = int(modifiers) & 0xFF
    return bytes(p)


# ── Responses ─────────────────────────────────────────────────────────────────

def is_ack(response):
    """The generic acknowledgement the SDK looks for."""
    return bool(response) and len(response) >= 2 and \
        response[0] == 0xFF and response[1] == 0xAA


# Key state map, measured on real hardware (issue #85). Two owners on
# different distributions and different firmware builds sent probe dumps that
# agree byte for byte, and both match the DisplayPad map in
# devices/displaypad/panel.py, gap and unused bit included: M1 to M7 live in
# byte 42 starting at bit 1, M8 to M12 in byte 47 starting at bit 0.
KEY_MAP = (
    [(42, mask) for mask in (0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)] +
    [(47, mask) for mask in (0x01, 0x02, 0x04, 0x08, 0x10)]
)

# The highest byte the map touches, so a truncated read is dropped rather than
# silently read as "nothing pressed".
KEY_EVENT_MIN_LEN = max(byte for byte, _ in KEY_MAP) + 1


def is_key_event(response):
    """Key state reports carry 0x01 in byte 0, like the DisplayPad. Confirmed
    on hardware by both probe dumps in issue #85."""
    return bool(response) and len(response) >= KEY_EVENT_MIN_LEN and \
        response[0] == 0x01


def decode_key_event(response):
    """Turn a key state report into a set of pressed key indices (0 to 11).

    Releasing sends the same report with every key bit cleared, so an empty
    set is a real answer and not an error."""
    if not is_key_event(response):
        return set()
    return set(index for index, (byte, mask) in enumerate(KEY_MAP)
               if response[byte] & mask)


# ── Device discovery ──────────────────────────────────────────────────────────

def enumerate_interfaces():
    """Every HID interface the MacroPad exposes, as hidapi reports them."""
    if not HID_AVAILABLE:
        return []
    return hid_compat.enumerate(VID, PID)


def find_path():
    """HID path of the vendor command interface, or None.

    Preference order: the collection the SDK asks for (usage page 0xFF00,
    usage 1), then anything with a vendor-defined usage page, then the
    highest interface number, which is where this page sits on the DisplayPad
    and the Everest."""
    entries = enumerate_interfaces()
    if not entries:
        return None
    for entry in entries:
        if entry.get('usage_page') == USAGE_PAGE and entry.get('usage') == USAGE:
            return entry['path']
    for entry in entries:
        if (entry.get('usage_page') or 0) >= 0xFF00:
            return entry['path']
    entries.sort(key=lambda e: e.get('interface_number') or 0)
    return entries[-1]['path']


def is_connected():
    return bool(enumerate_interfaces())


# ── Device ────────────────────────────────────────────────────────────────────

class MacroPad:
    """Thin wrapper around the command interface.

    Key state reports arriving while we wait for a command reply are not
    thrown away: they land in .key_events so a listener can drain them. That
    is the same split our DisplayPad driver needed once uploads and key
    presses started sharing one interface (issues #26-#28)."""

    def __init__(self, path=None):
        if not HID_AVAILABLE:
            raise RuntimeError(
                "no usable 'hid' module; install the 'hid' or the 'hidapi' "
                "package (see shared/hid_compat.py)")
        if path is None:
            path = find_path()
        if path is None:
            raise RuntimeError(
                "MacroPad not found (VID=0x%04X PID=0x%04X)" % (VID, PID))
        self.dev = hid_compat.open_path(path)
        self.dev.nonblocking = False
        self.key_events = []

    def close(self):
        try:
            self.dev.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def write(self, payload):
        """Send one payload. hidapi wants the report ID in front."""
        if len(payload) != PAYLOAD_LEN:
            raise ValueError("payload must be %d bytes" % PAYLOAD_LEN)
        self.dev.write(b"\x00" + bytes(payload))

    def read(self, timeout_ms=DEFAULT_TIMEOUT_MS):
        """Read one report, skipping key state reports (they are queued)."""
        deadline = time.monotonic() + timeout_ms / 1000.0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            data = self.dev.read(PAYLOAD_LEN, timeout=int(remaining * 1000))
            if not data:
                return None
            if is_key_event(data):
                self.key_events.append(bytes(data))
                continue
            return bytes(data)

    def command(self, payload, timeout_ms=DEFAULT_TIMEOUT_MS):
        """Send and wait for the reply. Returns the raw response or None."""
        self.write(payload)
        return self.read(timeout_ms)

    def drain_key_events(self):
        events, self.key_events = self.key_events, []
        return events

    # High level operations. Each one returns the device response so a caller
    # can decide how strict to be; is_ack() covers the common case.

    def init(self):
        return self.command(pkt_init(True))

    def firmware_info(self):
        return self.command(pkt_firmware_info())

    def firmware_layout(self):
        return self.command(pkt_firmware_layout())

    def set_led(self, on):
        return self.command(pkt_led(on))

    def switch_profile(self, profile, slot=0):
        return self.command(pkt_switch_profile(profile, slot),
                            timeout_ms=PROFILE_TIMEOUT_MS)

    def set_effect(self, effect, **kwargs):
        return self.command(pkt_effect(effect, **kwargs))

    def set_key_colors(self, colors, brightness=DEFAULT_BRIGHTNESS):
        """Paint the 12 keys individually.

        The order is Base Camp's, and it is the other way round from what
        looks natural: switch to the custom effect first, then send the
        colours. @Thargorrr's run in #85 sent the colours first and then
        activated, both packets were accepted, and the pad stayed dark.

        The table write at the end is the step that was missing altogether.
        His second run had the corrected order and still stayed dark, so the
        order alone was not it. Base Camp also calls SaveFlash twice in this
        sequence; that is left to the Save to pad button rather than done
        behind the person's back on every colour change.
        """
        self.command(pkt_custom_activate(brightness))
        response = self.command(pkt_custom_colors(colors))
        self.command(pkt_customize_table())
        return response

    def set_effect_auto(self, effect, **kwargs):
        """Send an effect over whichever of the two commands it belongs to."""
        if uses_block_effect(effect):
            return self.command(pkt_block_effect(effect, **kwargs))
        return self.command(pkt_effect(effect, **kwargs))

    def remap_key(self, source, target):
        return self.command(pkt_remap_key(source, target))

    def set_shortcut(self, source, target, modifiers=0):
        return self.command(pkt_shortcut(source, target, modifiers))

    def reset_keys(self):
        return self.command(pkt_reset_keys())

    def reset_effects(self):
        return self.command(pkt_reset_effects())

    def save(self, slot=0):
        return self.command(pkt_save(slot))
