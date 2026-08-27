#!/usr/bin/env python3
"""
Mountain Everest 60 Controller
VID: 0x3282, PID: 0x0005 (ANSI) / 0x0006 (ISO)
Protocol: HID Feature Reports on Interface 2

Reverse-engineered from OpenRGB MountainKeyboard60Controller + FransM's findings.
Report size: 65 bytes (Report ID 0x00 + 64 bytes data).
Magic bytes [2..4] = 0x46 0x23 0xEA on every command.

SetMode (cmd=0x16):
  [1]    = 0x16
  [2..4] = 0x46 0x23 0xEA
  [5]    = 0x01
  [9]    = effect code (activates the mode)

SendModeDetails (cmd=0x17):
  [1]    = 0x17
  [2..4] = 0x46 0x23 0xEA
  [5]    = effect code
  [7]    = speed   × 25   (0/25/50/75/100)
  [8]    = brightness × 25
  [9]    = color_mode (0=single, 2=rainbow cycle, 0x10=dual)
  [10]   = direction
  [12..14] = color1 R,G,B
  [15..17] = color2 R,G,B

After set_report, get_report should echo cmd byte in resp[1].
If not, retry (device may be busy).

Direct color mode (custom per-key):
  Begin:  cmd=0x34, [5]=brightness×25, [6]=0xC0
  Map:    cmd=0x35, [5]=stream_ctl (0x0E=more, 0x0A=last), then 14 × RGBI (56 bytes)
          byte[3] of each entry = LED hardware index (LEDIDX mapping)
  End:    cmd=0x36
"""
import os
import sys
import time

# The device controllers also run as standalone scripts (the app spawns them
# as subprocesses), so the repository root is not on sys.path by itself.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared import hid_compat
HID_AVAILABLE = hid_compat.HID_AVAILABLE

VID         = 0x3282
PID_ANSI    = 0x0005
PID_ISO     = 0x0006
PID         = PID_ANSI   # updated at runtime by detect_model()
INTERFACE   = 2

MAGIC = (0x46, 0x23, 0xEA)

# Effect codes
EFFECT_STATIC    = 0x01
EFFECT_WAVE      = 0x02
EFFECT_TORNADO   = 0x03
EFFECT_BREATHING = 0x04
EFFECT_REACTIVE  = 0x05
EFFECT_MATRIX    = 0x06   # issue #38 — confirmed from matrix.pcapng (dual colour)
EFFECT_CUSTOM    = 0x07
EFFECT_YETI      = 0x08
EFFECT_OFF       = 0x09

# Color mode
COLOR_SINGLE  = 0x00
COLOR_RAINBOW = 0x02
COLOR_DUAL    = 0x10

# Direction values (Wave/Tornado)
DIR_WAVE    = {"L→R": 0x00, "T→B": 0x02, "R→L": 0x04, "B→T": 0x06}
DIR_TORNADO = {"CW": 0x0A, "CCW": 0x09}

NUM_KEYS = 64

# Side LED ring — 44 RGB LEDs around the keyboard perimeter (indices 126..169).
# Reverse-engineered from a USBPcap of the Windows software lighting the
# LEDs one at a time, starting top-left (above ESC) and going clockwise.
SIDE_LED_INDICES = list(range(126, 170))
NUM_SIDE_LEDS = len(SIDE_LED_INDICES)

# LED hardware index mapping — maps logical key position to firmware LED address.
# ESC is 0 (confirmed by @FransM on the hardware, issue #46). It read dark in
# #15 not because address 0 has no LED but because a zero index is
# indistinguishable from the zero padding at the tail of a 0x35 packet, so the
# padding's [0,0,0,0] entries re-wrote ESC black after it was set. That padding
# is now filled with a real entry instead of zeros (see _write_custom_map), so
# ESC at index 0 lights correctly. The earlier stopgap (21) drove a phantom LED.
LEDIDX = [
    # Row 0: ESC  1    2    3    4    5    6    7    8    9    0    -    =   BSPC
    0,   22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,
    # Row 1: TAB  Q    W    E    R    T    Y    U    I    O    P    [    ]    \
    42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,
    # Row 2: CAPS A    S    D    F    G    H    J    K    L    ;    '   ENTER
    63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  76,
    # Row 3: LSFT Z    X    C    V    B    N    M    ,    .    /   RSFT  ↑   DEL
    84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  97,  99,  56,
    # Row 4: LCTL LWIN LALT SPC  RALT FN   ←    ↓    →
    105, 106, 107, 110, 113, 115, 119, 120, 121,
]


def detect_model():
    """Detect which Everest 60 variant is connected. Returns (pid, name) or (None, None)."""
    global PID
    if not HID_AVAILABLE:
        return None, None

    for pid, name in [(PID_ANSI, "Everest 60"), (PID_ISO, "Everest 60 ISO")]:
        for d in hid_compat.enumerate(VID, pid):
            if d.get('interface_number') == INTERFACE:
                PID = pid
                return pid, name
    return None, None


def find_path():
    """Return HID path for Interface 2, or None."""
    if not HID_AVAILABLE:
        return None
    for pid in (PID_ANSI, PID_ISO):
        for d in hid_compat.enumerate(VID, pid):
            if d.get('interface_number') == INTERFACE:
                return d['path']
    return None


def open_device():
    path = find_path()
    if path is None:
        raise RuntimeError("Everest 60 not found (VID=0x3282 PID=0x0005/0x0006 IF2)")
    dev = hid_compat.open_path(path)
    return dev


def _send(dev, buf, retries=3):
    """Send feature report, verify response echoes cmd byte in resp[1], retry if not."""
    cmd = buf[1]
    for attempt in range(retries):
        dev.send_feature_report(bytes(buf))
        time.sleep(0.05)
        resp = dev.get_feature_report(0x00, 65)
        time.sleep(0.05)
        if resp and len(resp) >= 2 and resp[1] == cmd:
            return resp
    return resp if 'resp' in locals() else None


def _make_buf(cmd):
    buf = [0x00] * 65
    buf[1] = cmd
    buf[2], buf[3], buf[4] = MAGIC
    return buf


def _brightness_val(pct):
    """Convert 0-100% to nearest 25-step value."""
    pct = max(0, min(100, int(pct)))
    return round(pct / 25) * 25


def _speed_val(pct):
    """Convert 0-100% to nearest 25-step value."""
    pct = max(0, min(100, int(pct)))
    return round(pct / 25) * 25


# ── Lighting commands ─────────────────────────────────────────────────────────

def _send_mode(dev, effect, speed=50, brightness=100,
               r1=255, g1=255, b1=255, r2=0, g2=0, b2=0,
               color_mode=COLOR_DUAL, direction=0):
    # Step 1: Switch mode (cmd 0x16) — activates the effect
    buf = _make_buf(0x16)
    buf[5] = 1
    buf[9] = effect
    _send(dev, buf)

    # Step 2: Send mode details (cmd 0x17) — colors/speed/brightness
    buf = _make_buf(0x17)
    buf[5]  = effect
    buf[7]  = _speed_val(speed)
    buf[8]  = _brightness_val(brightness)
    buf[9]  = color_mode
    buf[10] = direction
    if color_mode != COLOR_RAINBOW:
        buf[12] = r1 & 0xFF
        buf[13] = g1 & 0xFF
        buf[14] = b1 & 0xFF
        if color_mode == COLOR_DUAL:
            buf[15] = r2 & 0xFF
            buf[16] = g2 & 0xFF
            buf[17] = b2 & 0xFF
    _send(dev, buf)


def _set_mode_only(dev, effect):
    """Activate an effect (cmd 0x16) without sending colour details (0x17).

    Custom mode paints via the 0x34/0x35 map, so it must NOT send 0x17: the
    Windows Base Camp capture (custom_allred.pcapng) contains no 0x17 in custom
    mode, and our 0x17 defaults colour1 to white — that stray packet is what
    briefly flashed the whole keyboard white before the map landed (issue #33)."""
    buf = _make_buf(0x16)
    buf[5] = 1
    buf[9] = effect
    _send(dev, buf)


def _commit_mode(dev, effect):
    """Latch the active effect (cmd 0x1a).

    Windows sends this right after switching mode and again after each custom
    colour map. Without the trailing latch a freshly written custom map could
    leave keys showing their pre-apply colour (the 'commit/latch packet' half of
    issue #33). Byte layout: [1]=0x1a [2..4]=magic [5]=effect code."""
    buf = _make_buf(0x1a)
    buf[5] = effect
    _send(dev, buf)


def set_lighting_off(brightness=100):
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_OFF, brightness=brightness)
    finally:
        dev.close()


def set_lighting_static(r, g, b, brightness=100):
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_STATIC, color_mode=COLOR_SINGLE, brightness=brightness,
                   r1=r, g1=g, b1=b)
    finally:
        dev.close()


def set_lighting_breathing(r=255, g=0, b=0, r2=0, g2=0, b2=0, brightness=100, speed=50,
                           color_mode=COLOR_DUAL):
    # color_mode: COLOR_SINGLE (one colour) or COLOR_DUAL (two). Breathing also
    # supports rainbow via set_lighting_breathing_rainbow (issue #32).
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_BREATHING, speed=speed, brightness=brightness,
                   r1=r, g1=g, b1=b, r2=r2, g2=g2, b2=b2, color_mode=color_mode)
    finally:
        dev.close()


def set_lighting_breathing_rainbow(brightness=100, speed=50):
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_BREATHING, speed=speed, brightness=brightness,
                   color_mode=COLOR_RAINBOW)
    finally:
        dev.close()


def set_lighting_wave(r=255, g=0, b=0, r2=0, g2=0, b2=0, brightness=100, speed=50,
                      direction=0, color_mode=COLOR_DUAL):
    # color_mode: COLOR_SINGLE or COLOR_DUAL. Rainbow via set_lighting_wave_rainbow.
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_WAVE, speed=speed, brightness=brightness,
                   r1=r, g1=g, b1=b, r2=r2, g2=g2, b2=b2, direction=direction,
                   color_mode=color_mode)
    finally:
        dev.close()


def set_lighting_wave_rainbow(brightness=100, speed=50, direction=0):
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_WAVE, speed=speed, brightness=brightness,
                   color_mode=COLOR_RAINBOW, direction=direction)
    finally:
        dev.close()


def set_lighting_tornado(r=255, g=0, b=0, brightness=100, speed=50, direction=0):
    direction = max(0, min(10, direction))
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_TORNADO, speed=speed, brightness=brightness,
                   color_mode=COLOR_SINGLE, r1=r, g1=g, b1=b, direction=10 - direction)
    finally:
        dev.close()


def set_lighting_tornado_rainbow(brightness=100, speed=50, direction=0):
    direction = max(0, min(10, direction))
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_TORNADO, speed=speed, brightness=brightness,
                   color_mode=COLOR_RAINBOW, direction=10 - direction)
    finally:
        dev.close()


def set_lighting_reactive(r=255, g=0, b=0, r2=0, g2=0, b2=0, brightness=100, speed=50):
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_REACTIVE, speed=speed, brightness=brightness,
                   r1=r, g1=g, b1=b, r2=r2, g2=g2, b2=b2)
    finally:
        dev.close()


def set_lighting_matrix(r=255, g=0, b=0, r2=0, g2=0, b2=255, brightness=100, speed=50):
    # Matrix is a dual-colour firmware effect (issue #38). Its 0x17 mode-detail
    # packet is byte-for-byte the same shape as the other effects, so it rides
    # the shared _send_mode path — only the effect code (0x06) differs.
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_MATRIX, speed=speed, brightness=brightness,
                   r1=r, g1=g, b1=b, r2=r2, g2=g2, b2=b2)
    finally:
        dev.close()


def set_lighting_yeti(r=255, g=0, b=0, r2=0, g2=0, b2=255, brightness=100, speed=50):
    dev = open_device()
    try:
        _send_mode(dev, EFFECT_YETI, speed=speed, brightness=brightness,
                   r1=r, g1=g, b1=b, r2=r2, g2=g2, b2=b2)
    finally:
        dev.close()


def set_lighting_custom(colors, brightness=100, side_colors=None):
    """Set per-key RGB. colors: list of 64 (r,g,b) tuples mapped via LEDIDX.

    side_colors: optional list of NUM_SIDE_LEDS (r,g,b) for the perimeter ring,
                 clockwise starting top-left (above ESC). When None, side ring
                 LEDs are left untouched in this call but the device's custom
                 mode keeps them dark unless they were set previously.
    """
    num_keys = len(LEDIDX)
    colors = list(colors)[:num_keys]
    while len(colors) < num_keys:
        colors.append((0, 0, 0))

    # Build a combined (hw_index, r, g, b) stream so the chunking loop below
    # doesn't have to special-case main vs side LEDs.
    stream = [(LEDIDX[i], colors[i][0], colors[i][1], colors[i][2])
              for i in range(num_keys)]
    if side_colors is not None:
        side = list(side_colors)[:NUM_SIDE_LEDS]
        while len(side) < NUM_SIDE_LEDS:
            side.append((0, 0, 0))
        for i, hw in enumerate(SIDE_LED_INDICES):
            r, g, b = side[i]
            stream.append((hw, r & 0xFF, g & 0xFF, b & 0xFF))

    dev = open_device()
    try:
        _write_custom_map(dev, stream, brightness=brightness)
    finally:
        dev.close()


def _write_custom_map(dev, stream, brightness=100):
    """Paint an explicit [(hw_index, r, g, b), ...] stream in custom mode.

    Shared by set_lighting_custom and the ESC-index diagnostic (#46). Activates
    custom mode WITHOUT 0x17 colour details (issue #33 white flash), streams the
    map in 0x35 packets, then latches with 0x1a so the keys hold the colours."""
    _set_mode_only(dev, EFFECT_CUSTOM)
    _commit_mode(dev, EFFECT_CUSTOM)

    # Begin
    buf = _make_buf(0x34)
    buf[5] = _brightness_val(brightness)
    buf[6] = 0xC0
    _send(dev, buf)

    # Map — 14 IRGB entries per packet (65 - 9 header bytes = 56, 56//4 = 14)
    COLORS_PER_PKT = 14
    # Pad the final packet with copies of the last real entry rather than leaving
    # zero bytes: an all-zero [0,0,0,0] slot is an index-0 write of black, which
    # would blank the ESC key (hw index 0) after it was set — the root cause of
    # ESC staying dark on a full fill (#15/#46). The duplicate is idempotent (it
    # just re-writes some other key its own colour) and never touches index 0
    # unless index 0 is itself the last entry, in which case it keeps ESC's own
    # colour. Empty streams are left as-is.
    stream = list(stream)
    if stream:
        while len(stream) % COLORS_PER_PKT != 0:
            stream.append(stream[-1])
    total = len(stream)
    idx = 0
    while idx < total:
        buf = _make_buf(0x35)
        pos = 9
        count = 0
        while idx < total and count < COLORS_PER_PKT:
            hw, r, g, b = stream[idx]
            buf[pos]     = hw & 0xFF
            buf[pos + 1] = r & 0xFF
            buf[pos + 2] = g & 0xFF
            buf[pos + 3] = b & 0xFF
            pos += 4
            idx += 1
            count += 1
        buf[5] = 0x0A if idx == total else 0x0E
        _send(dev, buf)

    # End
    _send(dev, _make_buf(0x36))
    # Latch the map so the keys hold the colours we just wrote (issue #33).
    _commit_mode(dev, EFFECT_CUSTOM)


def diagnose_esc_index(start=0, end=21, hold=3.0):
    """ESC-index finder for issue #46.

    ESC is index 0 (confirmed by @FransM), which is what LEDIDX[0] now uses. This
    scanner stays as a way to re-verify or to map a variant: it walks a range of
    candidate indices, lighting every other key dim blue and ONE candidate index
    bright red at a time, so someone with the keyboard can watch and report which
    index turns the physical ESC key red."""
    # Baseline: every confirmed key LED (all LEDIDX entries except ESC's slot).
    base = [(hw, 0, 0, 40) for hw in LEDIDX[1:]]
    dev = open_device()
    print(f"ESC-index scan {start}..{end}. Watch the ESC key; note the index that "
          f"turns it RED. All other keys stay dim blue. {hold}s per index.\n")
    try:
        for cand in range(start, end + 1):
            stream = list(base) + [(cand, 255, 0, 0)]
            _write_custom_map(dev, stream, brightness=100)
            print(f"  index {cand:3d}: ESC red now?", flush=True)
            time.sleep(hold)
    finally:
        dev.close()
    print("\nDone. Report the index that lit ESC so LEDIDX[0] can be corrected.")


def set_lighting_side_static(r, g, b, brightness=100, key_colors=None):
    """Light all 44 side-ring LEDs in a single colour.

    Convenience wrapper around set_lighting_custom — because the device only
    addresses the side ring through custom mode, we have to also push a main
    key colour map. If `key_colors` is None the main keys are blanked out.
    """
    side = [(r & 0xFF, g & 0xFF, b & 0xFF)] * NUM_SIDE_LEDS
    # When we have no saved per-key state to preserve, light the keys white
    # rather than blanking them — a dark keyboard under low light is worse than
    # a neutral default (issue #4, FransM). Callers pass the saved colours when
    # they have them so the user's layout is kept instead.
    keys = key_colors if key_colors is not None else [(255, 255, 255)] * NUM_KEYS
    set_lighting_custom(keys, brightness=brightness, side_colors=side)


def _load_saved_key_colors():
    """Return the user's last per-key colours so a side-ring command keeps the
    main keys lit instead of blanking them (issue #4). The GUI side picker does
    this via per-key-rgb; loading the same saved state here makes the CLI /
    control-interface `side-static` behave identically. None if unavailable."""
    try:
        from shared.config import _load_per_key_60
        leds, _side, _bri = _load_per_key_60()
        return [tuple(c) for c in leds][:NUM_KEYS]
    except Exception:
        return None


# ── CLI ───────────────────────────────────────────────────────────────────────

def _die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: everest60-controller <rgb|status> [args]")
        sys.exit(1)

    cmd = args[0]

    if cmd == "status":
        path = find_path()
        if path:
            pid, name = detect_model()
            print(f"connected: {name} {path.decode() if isinstance(path, bytes) else path}")
        else:
            print("not connected")
            sys.exit(1)

    elif cmd == "rgb":
        if len(args) < 2:
            _die("rgb: subcommand required")
        live = args[1] == "live"
        sub_args = args[2:] if live else args[1:]
        sub = sub_args[0] if sub_args else ""
        try:
            if sub == "off":
                set_lighting_off()
            elif sub == "static":
                if len(sub_args) < 4:
                    _die("rgb static R G B [brightness]")
                r, g, b = int(sub_args[1]), int(sub_args[2]), int(sub_args[3])
                bri = int(sub_args[4]) if len(sub_args) > 4 else 100
                set_lighting_static(r, g, b, brightness=bri)
            elif sub == "breathing":
                r  = int(sub_args[1]) if len(sub_args) > 1 else 255
                g  = int(sub_args[2]) if len(sub_args) > 2 else 0
                b  = int(sub_args[3]) if len(sub_args) > 3 else 0
                r2 = int(sub_args[4]) if len(sub_args) > 4 else 0
                g2 = int(sub_args[5]) if len(sub_args) > 5 else 0
                b2 = int(sub_args[6]) if len(sub_args) > 6 else 0
                bri = int(sub_args[7]) if len(sub_args) > 7 else 100
                spd = int(sub_args[8]) if len(sub_args) > 8 else 50
                cm  = int(sub_args[9]) if len(sub_args) > 9 else COLOR_DUAL
                set_lighting_breathing(r, g, b, r2, g2, b2, brightness=bri, speed=spd,
                                       color_mode=cm)
            elif sub == "breathing-rainbow":
                bri = int(sub_args[1]) if len(sub_args) > 1 else 100
                spd = int(sub_args[2]) if len(sub_args) > 2 else 50
                set_lighting_breathing_rainbow(brightness=bri, speed=spd)
            elif sub == "wave":
                r  = int(sub_args[1]) if len(sub_args) > 1 else 255
                g  = int(sub_args[2]) if len(sub_args) > 2 else 0
                b  = int(sub_args[3]) if len(sub_args) > 3 else 0
                r2 = int(sub_args[4]) if len(sub_args) > 4 else 0
                g2 = int(sub_args[5]) if len(sub_args) > 5 else 0
                b2 = int(sub_args[6]) if len(sub_args) > 6 else 0
                bri = int(sub_args[7]) if len(sub_args) > 7 else 100
                spd = int(sub_args[8]) if len(sub_args) > 8 else 50
                d   = int(sub_args[9]) if len(sub_args) > 9 else 0
                cm  = int(sub_args[10]) if len(sub_args) > 10 else COLOR_DUAL
                set_lighting_wave(r, g, b, r2, g2, b2, brightness=bri, speed=spd,
                                  direction=d, color_mode=cm)
            elif sub == "wave-rainbow":
                bri = int(sub_args[1]) if len(sub_args) > 1 else 100
                spd = int(sub_args[2]) if len(sub_args) > 2 else 50
                d   = int(sub_args[3]) if len(sub_args) > 3 else 0
                set_lighting_wave_rainbow(brightness=bri, speed=spd, direction=d)
            elif sub == "tornado":
                r  = int(sub_args[1]) if len(sub_args) > 1 else 255
                g  = int(sub_args[2]) if len(sub_args) > 2 else 0
                b  = int(sub_args[3]) if len(sub_args) > 3 else 0
                bri = int(sub_args[4]) if len(sub_args) > 4 else 100
                spd = int(sub_args[5]) if len(sub_args) > 5 else 50
                d   = int(sub_args[6]) if len(sub_args) > 6 else 0
                set_lighting_tornado(r, g, b, brightness=bri, speed=spd, direction=d)
            elif sub == "tornado-rainbow":
                bri = int(sub_args[1]) if len(sub_args) > 1 else 100
                spd = int(sub_args[2]) if len(sub_args) > 2 else 50
                d   = int(sub_args[3]) if len(sub_args) > 3 else 0
                set_lighting_tornado_rainbow(brightness=bri, speed=spd, direction=d)
            elif sub == "reactive":
                r  = int(sub_args[1]) if len(sub_args) > 1 else 255
                g  = int(sub_args[2]) if len(sub_args) > 2 else 0
                b  = int(sub_args[3]) if len(sub_args) > 3 else 0
                r2 = int(sub_args[4]) if len(sub_args) > 4 else 0
                g2 = int(sub_args[5]) if len(sub_args) > 5 else 0
                b2 = int(sub_args[6]) if len(sub_args) > 6 else 0
                bri = int(sub_args[7]) if len(sub_args) > 7 else 100
                spd = int(sub_args[8]) if len(sub_args) > 8 else 50
                set_lighting_reactive(r, g, b, r2, g2, b2, brightness=bri, speed=spd)
            elif sub == "yeti":
                r  = int(sub_args[1]) if len(sub_args) > 1 else 255
                g  = int(sub_args[2]) if len(sub_args) > 2 else 0
                b  = int(sub_args[3]) if len(sub_args) > 3 else 0
                r2 = int(sub_args[4]) if len(sub_args) > 4 else 0
                g2 = int(sub_args[5]) if len(sub_args) > 5 else 0
                b2 = int(sub_args[6]) if len(sub_args) > 6 else 255
                bri = int(sub_args[7]) if len(sub_args) > 7 else 100
                spd = int(sub_args[8]) if len(sub_args) > 8 else 50
                set_lighting_yeti(r, g, b, r2, g2, b2, brightness=bri, speed=spd)
            elif sub == "matrix":
                r  = int(sub_args[1]) if len(sub_args) > 1 else 255
                g  = int(sub_args[2]) if len(sub_args) > 2 else 0
                b  = int(sub_args[3]) if len(sub_args) > 3 else 0
                r2 = int(sub_args[4]) if len(sub_args) > 4 else 0
                g2 = int(sub_args[5]) if len(sub_args) > 5 else 0
                b2 = int(sub_args[6]) if len(sub_args) > 6 else 255
                bri = int(sub_args[7]) if len(sub_args) > 7 else 100
                spd = int(sub_args[8]) if len(sub_args) > 8 else 50
                set_lighting_matrix(r, g, b, r2, g2, b2, brightness=bri, speed=spd)
            elif sub == "side-static":
                if len(sub_args) < 4:
                    _die("rgb side-static R G B [brightness]")
                r, g, b = int(sub_args[1]), int(sub_args[2]), int(sub_args[3])
                bri = int(sub_args[4]) if len(sub_args) > 4 else 100
                # Keep the user's main-key colours instead of blanking the
                # keyboard (issue #4) — matches what the GUI side picker does.
                set_lighting_side_static(r, g, b, brightness=bri,
                                         key_colors=_load_saved_key_colors())
            elif sub == "esc-scan":
                # ESC-index finder (issue #46): rgb esc-scan [start] [end] [hold]
                start = int(sub_args[1]) if len(sub_args) > 1 else 0
                end   = int(sub_args[2]) if len(sub_args) > 2 else 21
                hold  = float(sub_args[3]) if len(sub_args) > 3 else 3.0
                diagnose_esc_index(start=start, end=end, hold=hold)
            else:
                _die(f"unknown rgb subcommand '{sub}'")
            print("ok")
        except RuntimeError as e:
            _die(str(e))
    elif cmd == "per-key-rgb":
        if len(args) < 2:
            _die("per-key-rgb: JSON payload required")
        import json as _j
        try:
            d = _j.loads(args[1])
        except Exception as e:
            _die(f"per-key-rgb: invalid JSON: {e}")
        leds_raw   = d.get("leds", [])
        side_raw   = d.get("side", [])
        brightness = int(d.get("brightness", 100))
        colors = [tuple(c) for c in leds_raw]
        side = [tuple(c) for c in side_raw] if side_raw else None
        try:
            set_lighting_custom(colors, brightness=brightness, side_colors=side)
            print("ok")
        except RuntimeError as e:
            _die(str(e))

    else:
        _die(f"unknown command '{cmd}'")


if __name__ == "__main__":
    main()
