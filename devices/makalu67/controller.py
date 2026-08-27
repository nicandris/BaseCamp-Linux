#!/usr/bin/env python3
"""
Makalu 67 Controller
VID: 0x3282, PID: 0x0003
Protocol: HID Feature Reports on Interface 1

Protocol reverse-engineered from USB capture (Windows VirtualBox session).
Report ID 0xA1, 64 bytes, SET_REPORT to Interface 1.
Response: Report ID 0xA0, byte[1]=0x01 = OK.

Command 0x0C layout (64 bytes):
  [0]      = 0xA1  (Report ID)
  [1]      = 0x0C  (command = Update_lighting_settings)
  [5]      = 0x01  (always 1)
  [16]     = effect (0=Off, 1=Static, 2=Rainbow, 5=Breathing, 6=RGB Breathing,
                     7=Responsive, 8=Yeti, 0x0F=Custom per-LED)
  [17]     = R (Zone 1 / LED 0 for Custom)
  [18]     = G
  [19]     = B
  [41]     = brightness (0–100); device always saves to flash (resp[1]=0x03 for all values)
  [42]     = param1 (always 0)
  [43]     = param2 (animation speed: 0=slow, 1=medium, 2=fast)

Custom per-LED mode (effect=0x0F), confirmed by USB capture:
  [16]     = 0x0F
  [17..19] = LED 0 R,G,B  (top-left)
  [20..22] = LED 1 R,G,B
  [23..25] = LED 2 R,G,B
  [26..28] = LED 3 R,G,B  (bottom-left)
  [29..31] = LED 4 R,G,B  (bottom-right)
  [32..34] = LED 5 R,G,B
  [35..37] = LED 6 R,G,B
  [38..40] = LED 7 R,G,B  (top-right)
  [41]     = brightness (0–100)

  Physical layout:
    LED[0] ·· LED[7]
    LED[1]    LED[6]
    LED[2]    LED[5]
    LED[3] ·· LED[4]
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

VID = 0x3282
PID_67  = 0x0003   # Makalu 67
PID_MAX = 0x0002   # Makalu Max
PID = PID_67       # default, updated at runtime by detect_model()

REPORT_ID        = 0xA1
RESP_ID          = 0xA0
CMD_LIGHTING     = 0x0C
CMD_POLLING_RATE = 0x0D
CMD_DPI          = 0x0B  # used for GET (sub=0x04 returns actual DPI values)
CMD_WRITE_MEM    = 0xDE  # byte-by-byte RAM write (WriteMemData in Makalu.dll)
CMD_ENABLE       = 0xC4  # EnableSetting / commit written RAM to flash
CMD_REMAP        = 0x0A  # Button remapping (confirmed by USB capture)

# Physical button indices (1-based, confirmed by USB capture)
BTN_LEFT    = 1
BTN_RIGHT   = 2
BTN_MIDDLE  = 3
BTN_BACK    = 4
BTN_FORWARD = 5
BTN_DPI     = 6
# Makalu Max extra buttons
BTN_MAX_FORWARD = 7
BTN_MAX_BACK    = 8

# Function codes (confirmed by USB capture): (category, code)
REMAP_FUNCTIONS = {
    "left":       (0x00, 0x01),
    "right":      (0x00, 0x02),
    "middle":     (0x00, 0x04),
    "back":       (0x00, 0x08),
    "forward":    (0x00, 0x10),
    "dpi+":       (0x09, 0xF1),
    "dpi-":       (0x09, 0xF3),
    "scroll_up":  (0x01, 0x01),
    "scroll_down":(0x01, 0xFF),
    "disabled":   (0xFF, 0x01),
}

# Default assignments per physical button — Makalu 67
REMAP_DEFAULTS_67 = {
    BTN_LEFT:    "left",
    BTN_RIGHT:   "right",
    BTN_MIDDLE:  "middle",
    BTN_BACK:    "back",
    BTN_FORWARD: "forward",
    BTN_DPI:     "dpi+",
}

# Default assignments — Makalu Max (different button layout)
REMAP_DEFAULTS_MAX = {
    BTN_LEFT:        "left",
    BTN_RIGHT:       "right",
    BTN_MIDDLE:      "middle",
    BTN_DPI:         "dpi+",      # btn 4 = DPI on Max
    5:               "disabled",   # btn 5 = behind DPI
    6:               "disabled",   # btn 6 = side below 7/8
    BTN_MAX_FORWARD: "forward",   # btn 7 = forward
    BTN_MAX_BACK:    "back",      # btn 8 = back
}

REMAP_DEFAULTS = REMAP_DEFAULTS_67  # updated at runtime

# Confirmed by USB capture: 1000→500→250→125 Hz
POLLING_RATE_MAP = {1000: 0x01, 500: 0x02, 250: 0x04, 125: 0x08}

# Debounce time in ms (confirmed by USB capture, same CMD 0x0D, buf[2]=0x02)
DEBOUNCE_VALUES = [2, 4, 6, 8, 10, 12]

# DPI range (confirmed from USB capture GET response: min=50, max=19000, step=50)
DPI_MIN  = 50
DPI_MAX  = 19000
DPI_STEP = 50

# Confirmed effect codes (physical testing + USB capture, PID 0x0003)
EFFECT_OFF          = 0
EFFECT_STATIC       = 1
EFFECT_RAINBOW      = 2
EFFECT_BREATHING    = 5
EFFECT_RGB_BREATHING= 6
EFFECT_RESPONSIVE   = 7
EFFECT_YETI         = 8
EFFECT_CUSTOM       = 0x0F  # Per-LED custom colors (confirmed by USB capture)


# ── Device access ─────────────────────────────────────────────────────────────

def detect_model():
    """Detect which Makalu is connected. Returns (pid, model_name) or (None, None)."""
    global PID, DPI_MIN, REMAP_DEFAULTS
    if not HID_AVAILABLE:
        return None, None
    for pid, name in [(PID_67, "Makalu 67"), (PID_MAX, "Makalu Max")]:
        for d in hid_compat.enumerate(VID, pid):
            if d.get('interface_number') == 1:
                PID = pid
                if pid == PID_MAX:
                    DPI_MIN = 100
                    REMAP_DEFAULTS = REMAP_DEFAULTS_MAX
                else:
                    DPI_MIN = 50
                    REMAP_DEFAULTS = REMAP_DEFAULTS_67
                return pid, name
    return None, None


def find_path():
    """Return path of Interface 1 hidraw node, or None."""
    if not HID_AVAILABLE:
        return None
    for pid in (PID_67, PID_MAX):
        for d in hid_compat.enumerate(VID, pid):
            if d.get('interface_number') == 1:
                return d['path']
    return None


def open_device():
    path = find_path()
    if path is None:
        raise RuntimeError("Makalu mouse not found (VID=0x3282 PID=0x0003/0x0002 IF1)")
    dev = hid_compat.open_path(path)
    return dev


# ── Lighting ──────────────────────────────────────────────────────────────────

def _lighting_report(effect, r=0, g=0, b=0, brightness=100, param1=0, param2=0):
    buf = [0] * 64
    buf[0]  = REPORT_ID
    buf[1]  = CMD_LIGHTING
    buf[5]  = 0x01
    buf[16] = effect
    buf[17] = r & 0xFF
    buf[18] = g & 0xFF
    buf[19] = b & 0xFF
    buf[41] = max(0, min(100, brightness))  # brightness 0-100 (also acts as save flag)
    buf[42] = param1
    buf[43] = param2
    return buf


def _run_cmd(buf):
    """Open device, send feature report, get response, close. Returns True if OK."""
    dev = open_device()
    try:
        dev.send_feature_report(bytes(buf))
        time.sleep(0.05)
        resp = dev.get_feature_report(REPORT_ID, 64)
        return len(resp) >= 1 and resp[0] == RESP_ID
    finally:
        dev.close()


def set_lighting_off(brightness=100):
    return _run_cmd(_lighting_report(EFFECT_OFF, brightness=brightness))


def set_lighting_static(r, g, b, brightness=100):
    return _run_cmd(_lighting_report(EFFECT_STATIC, r, g, b, brightness=brightness))


def set_lighting_breathing(r=0, g=0, b=0, brightness=100, speed=1):
    return _run_cmd(_lighting_report(EFFECT_BREATHING, r, g, b,
                                     brightness=brightness, param1=speed, param2=speed))


def set_lighting_rainbow(brightness=100):
    return _run_cmd(_lighting_report(EFFECT_RAINBOW, brightness=brightness, param1=1, param2=1))


def set_lighting_rgb_breathing(brightness=100):
    return _run_cmd(_lighting_report(EFFECT_RGB_BREATHING, brightness=brightness, param1=1, param2=1))


def set_lighting_responsive(brightness=100):
    return _run_cmd(_lighting_report(EFFECT_RESPONSIVE, brightness=brightness, param1=1, param2=1))


def set_lighting_yeti(brightness=100):
    return _run_cmd(_lighting_report(EFFECT_YETI, brightness=brightness, param1=1, param2=1))


def set_lighting_custom(leds, brightness=100):
    """Set per-LED colors.

    leds: list of 8 (r, g, b) tuples.
    Physical layout:
      leds[0]=top-left   leds[7]=top-right
      leds[1]            leds[6]
      leds[2]            leds[5]
      leds[3]=bot-left   leds[4]=bot-right
    """
    buf = [0] * 64
    buf[0]  = REPORT_ID
    buf[1]  = CMD_LIGHTING
    buf[5]  = 0x01
    buf[16] = EFFECT_CUSTOM
    for i, (r, g, b) in enumerate(leds[:8]):
        buf[17 + i * 3] = r & 0xFF
        buf[18 + i * 3] = g & 0xFF
        buf[19 + i * 3] = b & 0xFF
    buf[41] = max(0, min(100, brightness))
    return _run_cmd(buf)


# ── Polling rate ──────────────────────────────────────────────────────────────

def set_polling_rate(hz):
    """Set polling rate. hz must be one of 125, 250, 500, 1000."""
    code = POLLING_RATE_MAP.get(int(hz))
    if code is None:
        raise ValueError(f"Invalid polling rate {hz}. Must be one of: 125, 250, 500, 1000")
    buf = [0] * 64
    buf[0] = REPORT_ID; buf[1] = CMD_POLLING_RATE; buf[2] = 0x01
    buf[5] = 0x01; buf[6] = code
    return _run_cmd(buf)


def set_debounce(ms):
    """Set button debounce time. ms must be one of 2, 4, 6, 8, 10, 12."""
    ms = int(ms)
    if ms not in DEBOUNCE_VALUES:
        raise ValueError(f"Invalid debounce {ms}ms. Must be one of: {DEBOUNCE_VALUES}")
    buf = [0] * 64
    buf[0] = REPORT_ID; buf[1] = CMD_POLLING_RATE; buf[2] = 0x02
    buf[5] = 0x01; buf[6] = ms
    return _run_cmd(buf)


def set_lift_off(high):
    """Set lift-off distance. high=True → High, high=False → Low."""
    buf = [0] * 64
    buf[0] = REPORT_ID; buf[1] = CMD_POLLING_RATE; buf[2] = 0x04
    buf[5] = 0x01; buf[6] = 0x01 if high else 0x00
    return _run_cmd(buf)


def set_angle_snapping(enabled):
    """Enable or disable angle snapping. enabled: True/False."""
    buf = [0] * 64
    buf[0] = REPORT_ID; buf[1] = CMD_POLLING_RATE; buf[2] = 0x03
    buf[5] = 0x01; buf[6] = 0x01 if enabled else 0x00
    return _run_cmd(buf)


# ── DPI ───────────────────────────────────────────────────────────────────────

def get_dpi():
    """Read all 5 DPI level values from the mouse. Returns list of 5 ints.

    Protocol: CMD 0x0B sub=0x07 (Read_profile_data).
    Response layout (confirmed by USB probe):
      [21] = total number of DPI levels
      [22] = current active level (0-based)
      [23..42] = 5 × (X lo, X hi, Y lo, Y hi) raw LE16 DPI values
    """
    buf = [0] * 64
    buf[0] = REPORT_ID
    buf[1] = CMD_DPI
    buf[2] = 0x07
    buf[5] = 0x01
    dev = open_device()
    try:
        dev.send_feature_report(bytes(buf))
        time.sleep(0.05)
        resp = dev.get_feature_report(REPORT_ID, 64)
        current = max(0, min(4, resp[22] - 1))  # resp[22] is 1-based active level
        levels = []
        for i in range(5):
            lo = resp[23 + i * 4]
            hi = resp[24 + i * 4]
            dpi = lo | (hi << 8)
            levels.append(max(DPI_MIN, min(DPI_MAX, dpi)))
        return levels, current
    finally:
        dev.close()


def _dpi_to_raw(dpi):
    """Convert user DPI value to PAW3335 sensor-encoded raw value.

    Reverse-engineered from Makalu.dll UpdateUIDatatoSensor (SensorID=78):
      data = dpi // 50
      if data <= 200: raw = data - 1
      else: raw = 199 + (data - 199) // 2

    The GET command (0x0B sub=0x04) returns decoded DPI (actual Hz),
    but flash storage and the WriteMemData protocol use sensor-encoded values.
    """
    dpi = max(DPI_MIN, min(DPI_MAX, int(dpi)))
    dpi = round(dpi / DPI_STEP) * DPI_STEP
    data = dpi // DPI_STEP
    if data <= 200:
        return data - 1
    else:
        return 199 + (data - 199) // 2


def _write_mem_byte(dev, address, value):
    """Write a single byte to mouse RAM at the given address.

    Protocol: CMD 0xDE, buf = [0xA1, 0xDE, addr_lo, addr_hi, value, 0, 0, ...]
    Address space: addr_lo = address % 256, addr_hi = address // 256.

    Profile memory layout (from Makalu.dll):
      profile i data starts at address 256 + i*256
      DPI1 lo byte = offset 5  → address 256 + i*256 + 5
      DPI1 hi byte = offset 6  → address 256 + i*256 + 6
    """
    buf = [0] * 64
    buf[0] = REPORT_ID
    buf[1] = CMD_WRITE_MEM
    buf[2] = address % 256
    buf[3] = address // 256
    buf[4] = value & 0xFF
    dev.send_feature_report(bytes(buf))
    time.sleep(0.05)


def set_all_dpi(dpi_list, active_level=1):
    """Set all 5 DPI levels.

    dpi_list: list of 5 ints in range 50–19000 (raw DPI values, step 50).
    These are DPI levels within the current profile (not separate profiles).
    Use the DPI button on the mouse to cycle through them.

    Protocol: CMD 0x0D sub=0x0A (Set_dpi_settings, reverse-engineered from
    BaseCamp.Service.exe DllImport + DPI_T struct + makalu_67_dll.dll disassembly).

    DPI_T struct (StructLayout Pack=1, passed by value on stack):
      byte  dpi_level_num     → buf[6]  number of DPI levels (1–5)
      byte  dpi_level_current → buf[7]  current level index (0-based)
      ushort dpi1_x           → buf[16-17]  LE16 raw DPI
      ushort dpi1_y           → buf[18-19]  same value as X
      ushort dpi2_x           → buf[20-21]
      ushort dpi2_y           → buf[22-23]
      ... (5 levels total)
      ushort dpi5_x           → buf[32-33]
      ushort dpi5_y           → buf[34-35]

    PROFILE_ID_T: Profile1=1 … Profile5=5, ALL_PROFILE=6
    buf[5] = profile_id (we use ALL_PROFILE=6 to apply to all profiles).
    DPI values are raw ushort (same units as GET response, no sensor encoding).
    """
    if len(dpi_list) != 5:
        raise ValueError("dpi_list must have exactly 5 values")
    buf = [0] * 64
    buf[0] = REPORT_ID
    buf[1] = CMD_POLLING_RATE   # 0x0D
    buf[2] = 0x0A               # sub = Set_dpi_settings
    buf[5] = 6                  # ALL_PROFILE (applies to all 5 profiles)
    buf[6] = 5                  # dpi_level_num = 5 levels
    buf[7] = max(1, min(5, int(active_level)))  # dpi_level_current (1-based)
    for i, dpi in enumerate(dpi_list):
        dpi = max(DPI_MIN, min(DPI_MAX, int(dpi)))
        dpi = round(dpi / DPI_STEP) * DPI_STEP
        lo = dpi & 0xFF
        hi = (dpi >> 8) & 0xFF
        buf[16 + i * 4]     = lo  # dpiN_x lo
        buf[16 + i * 4 + 1] = hi  # dpiN_x hi
        buf[16 + i * 4 + 2] = lo  # dpiN_y lo (same as X)
        buf[16 + i * 4 + 3] = hi  # dpiN_y hi
    return _run_cmd(buf)


# ── Button remapping ──────────────────────────────────────────────────────────

def set_button_sniper(button_index, sniper_dpi):
    """Assign DPI Sniper to a button.

    While the button is held, the firmware switches to sniper_dpi.
    On release the active profile DPI is restored automatically.

    Protocol confirmed by USB capture (capture_makalu_sniper.pcapng):
      buf[1]     = 0x0A (CMD_REMAP)
      buf[5]     = 0x01
      buf[6]     = button_index (1-based)
      buf[16]    = 0x0C  (sniper category)
      buf[17]    = 0x01  (sniper function)
      buf[18:20] = sniper_dpi (LE16, X-axis)
      buf[20:22] = sniper_dpi (LE16, Y-axis — same value)
      buf[22]    = 0x0F
    """
    max_btn = 8 if PID == PID_MAX else 6
    if not 1 <= button_index <= max_btn:
        raise ValueError(f"Button index must be 1–{max_btn}, got {button_index}")
    sniper_dpi = max(DPI_MIN, min(DPI_MAX, (sniper_dpi // DPI_STEP) * DPI_STEP))
    buf = [0] * 64
    buf[0]  = REPORT_ID
    buf[1]  = CMD_REMAP
    buf[5]  = 0x01
    buf[6]  = button_index
    buf[16] = 0x0C
    buf[17] = 0x01
    buf[18] = sniper_dpi & 0xFF
    buf[19] = (sniper_dpi >> 8) & 0xFF
    buf[20] = sniper_dpi & 0xFF
    buf[21] = (sniper_dpi >> 8) & 0xFF
    buf[22] = 0x0F
    return _run_cmd(buf)


def set_button_remap(button_index, function_name):
    """Remap a physical button to a function.

    button_index: 1–6 (1=Left, 2=Right, 3=Middle, 4=Back, 5=Forward, 6=DPI+)
    function_name: key from REMAP_FUNCTIONS dict

    Protocol confirmed by USB capture (capture_makalu_remap2.pcap):
      buf[1]  = 0x0A (CMD_REMAP)
      buf[5]  = 0x01
      buf[6]  = button_index (1-based)
      buf[16] = category byte of function
      buf[17] = code byte of function
      buf[22] = 0x0F (always)
    """
    fn = REMAP_FUNCTIONS.get(function_name.lower())
    if fn is None:
        raise ValueError(f"Unknown function '{function_name}'. Valid: {list(REMAP_FUNCTIONS)}")
    max_btn = 8 if PID == PID_MAX else 6
    if not 1 <= button_index <= max_btn:
        raise ValueError(f"Button index must be 1–{max_btn}, got {button_index}")
    buf = [0] * 64
    buf[0]  = REPORT_ID
    buf[1]  = CMD_REMAP
    buf[5]  = 0x01
    buf[6]  = button_index
    buf[16] = fn[0]
    buf[17] = fn[1]
    buf[22] = 0x0F
    return _run_cmd(buf)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def _usage():
    print("""Usage: makalu-controller <command> [args]

Commands:
  rgb off                     Turn LEDs off
  rgb static <R> <G> <B>      Static color  (0-255 each)
  rgb breathing [R G B]       Breathing effect (optional color)
  rgb rainbow                 Rainbow cycling effect
  rgb live static <R> <G> <B> Live preview (no flash write)
  status                      Check device presence
""")


def main():
    args = sys.argv[1:]
    if not args:
        _usage()
        sys.exit(1)

    cmd = args[0]

    if cmd == "status":
        path = find_path()
        if path:
            print(f"connected: {path.decode() if isinstance(path, bytes) else path}")
        else:
            print("not connected")
            sys.exit(1)

    elif cmd == "rgb":
        if len(args) < 2:
            _die("rgb: subcommand required (off/static/breathing/rainbow/live)")

        live = args[1] == "live"
        sub_args = args[2:] if live else args[1:]
        sub = sub_args[0] if sub_args else ""
        save = not live

        try:
            if sub == "off":
                ok = set_lighting_off(brightness=100)
            elif sub == "static":
                if len(sub_args) < 4:
                    _die("rgb static requires R G B")
                r, g, b = int(sub_args[1]), int(sub_args[2]), int(sub_args[3])
                ok = set_lighting_static(r, g, b)
            elif sub == "breathing":
                r = int(sub_args[1]) if len(sub_args) > 1 else 0
                g = int(sub_args[2]) if len(sub_args) > 2 else 0
                b = int(sub_args[3]) if len(sub_args) > 3 else 0
                ok = set_lighting_breathing(r, g, b)
            elif sub == "rainbow":
                ok = set_lighting_rainbow()
            elif sub == "custom":
                # rgb custom R0 G0 B0 R1 G1 B1 ... R7 G7 B7 [brightness]
                if len(sub_args) < 25:
                    _die("rgb custom requires 24 values (R G B × 8 LEDs)")
                leds = []
                for i in range(8):
                    r = int(sub_args[1 + i * 3])
                    g = int(sub_args[2 + i * 3])
                    b = int(sub_args[3 + i * 3])
                    leds.append((r, g, b))
                bri = int(sub_args[25]) if len(sub_args) > 25 else 100
                ok = set_lighting_custom(leds, brightness=bri)
            elif sub == "code":
                if len(sub_args) < 2:
                    _die("rgb code requires effect code")
                code = int(sub_args[1])
                r   = int(sub_args[2]) if len(sub_args) > 2 else 0
                g   = int(sub_args[3]) if len(sub_args) > 3 else 0
                b   = int(sub_args[4]) if len(sub_args) > 4 else 0
                bri = int(sub_args[5]) if len(sub_args) > 5 else 100
                spd = int(sub_args[6]) if len(sub_args) > 6 else 0
                dir_ = int(sub_args[7]) if len(sub_args) > 7 else 0
                buf = _lighting_report(code, r, g, b, brightness=bri, param1=dir_, param2=spd)
                ok = _run_cmd(buf)
            elif sub == "code2":
                # rgb code2 <effect> <R> <G> <B> <R2> <G2> <B2> <brightness> [speed]
                if len(sub_args) < 8:
                    _die("rgb code2 requires effect R G B R2 G2 B2")
                code = int(sub_args[1])
                r,  g,  b  = int(sub_args[2]), int(sub_args[3]), int(sub_args[4])
                r2, g2, b2 = int(sub_args[5]), int(sub_args[6]), int(sub_args[7])
                bri = int(sub_args[8]) if len(sub_args) > 8 else 100
                spd  = int(sub_args[9])  if len(sub_args) > 9  else 0
                dir_ = int(sub_args[10]) if len(sub_args) > 10 else 0
                buf = _lighting_report(code, r, g, b, brightness=bri, param1=dir_, param2=spd)
                buf[20] = r2 & 0xFF
                buf[21] = g2 & 0xFF
                buf[22] = b2 & 0xFF
                buf[23] = 0x00
                ok = _run_cmd(buf)
            else:
                _die(f"rgb: unknown subcommand '{sub}'")
            print("ok" if ok else "failed")
        except RuntimeError as e:
            _die(str(e))

    elif cmd == "lift-off":
        if len(args) < 2:
            _die("lift-off requires <low|high>")
        val = args[1].lower()
        if val not in ("low", "high"):
            _die("lift-off: must be 'low' or 'high'")
        try:
            ok = set_lift_off(val == "high")
            print("ok" if ok else "failed")
        except RuntimeError as e:
            _die(str(e))

    elif cmd == "angle-snapping":
        if len(args) < 2:
            _die("angle-snapping requires <on|off>")
        val = args[1].lower()
        if val not in ("on", "off"):
            _die("angle-snapping: must be 'on' or 'off'")
        try:
            ok = set_angle_snapping(val == "on")
            print("ok" if ok else "failed")
        except RuntimeError as e:
            _die(str(e))

    elif cmd == "debounce":
        if len(args) < 2:
            _die("debounce requires <ms>: 2, 4, 6, 8, 10, 12")
        try:
            ok = set_debounce(int(args[1]))
            print("ok" if ok else "failed")
        except (ValueError, RuntimeError) as e:
            _die(str(e))

    elif cmd == "polling-rate":
        if len(args) < 2:
            _die("polling-rate requires <hz>: 125, 250, 500, 1000")
        try:
            ok = set_polling_rate(int(args[1]))
            print("ok" if ok else "failed")
        except (ValueError, RuntimeError) as e:
            _die(str(e))

    elif cmd == "dpi":
        if len(args) < 2:
            _die("dpi requires 'get' or 5 DPI values (P1 P2 P3 P4 P5)")
        if args[1] == "dump":
            # Full 64-byte dump of sub=0x07 (Read_profile_data)
            buf = [0] * 64
            buf[0] = REPORT_ID
            buf[1] = CMD_DPI
            buf[2] = 0x07
            buf[5] = 0x01
            dev = open_device()
            try:
                dev.send_feature_report(bytes(buf))
                time.sleep(0.08)
                resp = dev.get_feature_report(REPORT_ID, 64)
                print(" ".join(f"{b:02x}" for b in resp))
                for i in range(16, len(resp)):
                    print(f"  [{i:2d}] = 0x{resp[i]:02x} ({resp[i]})")
            except RuntimeError as e:
                _die(str(e))
            finally:
                dev.close()
        elif args[1] == "get":
            try:
                levels, current = get_dpi()
                print(" ".join(str(p) for p in levels) + f" {current}")
            except RuntimeError as e:
                _die(str(e))
        else:
            if len(args) < 6:
                _die("dpi requires exactly 5 values: dpi <p1> <p2> <p3> <p4> <p5> [active]")
            try:
                dpi_list = [int(args[i + 1]) for i in range(5)]
                active = int(args[6]) if len(args) > 6 else 1
                ok = set_all_dpi(dpi_list, active_level=active)
                print("ok" if ok else "failed")
            except (ValueError, RuntimeError) as e:
                _die(str(e))

    elif cmd == "remap":
        # remap <button_index> <function>
        # e.g.: remap 2 forward
        if len(args) < 3:
            fns = ", ".join(REMAP_FUNCTIONS.keys())
            _die(f"remap requires <button 1-6> <function>\n  functions: {fns}")
        try:
            ok = set_button_remap(int(args[1]), args[2])
            print("ok" if ok else "failed")
        except (ValueError, RuntimeError) as e:
            _die(str(e))

    elif cmd == "sniper":
        # sniper <button_index> <dpi>
        # e.g.: sniper 4 400
        if len(args) < 3:
            _die("sniper requires <button 1-6> <dpi 50-19000>")
        try:
            ok = set_button_sniper(int(args[1]), int(args[2]))
            print("ok" if ok else "failed")
        except (ValueError, RuntimeError) as e:
            _die(str(e))

    else:
        _die(f"unknown command '{cmd}'")


if __name__ == "__main__":
    main()
