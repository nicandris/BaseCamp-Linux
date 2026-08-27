#!/usr/bin/env python3
"""
Checks shared/hid_compat.py against both `hid` packages. No hardware needed.

    python3 tools/test_hid_compat.py

Why this file exists: two unrelated projects install a module called `hid`,
and until issue #85 the whole app assumed the one with `hid.Device`. Both
MacroPad owners who answered the call for testers had the other one, so on
their machines every Mountain device was unreachable from a source install.
The stand-ins below are the two APIs, so a change to the adapter that only
suits the flavour on the developer's machine fails here.

Verified against real hardware on both flavours while it was written: a
Makalu 67 returns the same DPI table through either package, and a timed read
on the Everest Max vendor collection comes back empty after the timeout on
both. That cannot run here, hence the stand-ins.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import hid_compat   # noqa: E402

failures = []


def check(name, ok, detail=""):
    if ok:
        print("ok    %-34s %s" % (name, detail))
    else:
        failures.append("%s: %s" % (name, detail or "failed"))
        print("FAIL  %-34s %s" % (name, detail))


# ── Stand-ins for the two packages ───────────────────────────────────────────

class _Recorder:
    """Common bookkeeping so a test can see what reached the library."""

    def __init__(self):
        self.opened = None
        self.written = []
        self.features = []
        self.closed = False
        self.nonblocking_calls = []


class FakeNewDevice:
    """`hid` (apmorton): a class, opened by keyword, bytes in and out."""

    def __init__(self, rec, path=None):
        self.rec = rec
        rec.opened = path
        self.nonblocking = False

    def write(self, data):
        self.rec.written.append(bytes(data))
        return len(data)

    def read(self, size, timeout=None):
        self.rec.last_read = (size, timeout)
        return b"\x01\x02\x03"

    def send_feature_report(self, data):
        self.rec.features.append(bytes(data))
        return len(data)

    def get_feature_report(self, report_id, size):
        return bytes([report_id, 0xAA] + [0] * (size - 2))

    def close(self):
        self.rec.closed = True


class FakeOldDevice:
    """`hidapi` (cython): an object opened by open_path(), lists out."""

    def __init__(self, rec):
        self.rec = rec

    def open_path(self, path):
        self.rec.opened = path

    def write(self, data):
        self.rec.written.append(bytes(data))
        return len(data)

    def read(self, max_length, timeout_ms=0):
        self.rec.last_read = (max_length, timeout_ms)
        return [1, 2, 3]

    def send_feature_report(self, data):
        self.rec.features.append(bytes(data))
        return len(data)

    def get_feature_report(self, report_number, max_length):
        return [report_number, 0xAA] + [0] * (max_length - 2)

    def set_nonblocking(self, value):
        self.rec.nonblocking_calls.append(value)

    def close(self):
        self.rec.closed = True


def new_module(rec):
    mod = type("FakeHidNew", (), {})
    mod.Device = lambda path=None, _r=rec: FakeNewDevice(_r, path)
    mod.enumerate = lambda vid=0, pid=0: [{"path": b"/dev/hidraw9",
                                           "interface_number": 3}]
    return mod


def old_module(rec):
    mod = type("FakeHidOld", (), {})
    mod.device = lambda _r=rec: FakeOldDevice(_r)
    mod.enumerate = lambda vid=0, pid=0: [{"path": b"1-1:1.3",
                                           "interface_number": 3}]
    return mod


# ── Which flavour is which ───────────────────────────────────────────────────

check("flavour, new package",
      hid_compat.flavour(new_module(_Recorder())) == "hid.Device", "hid.Device")
check("flavour, old package",
      hid_compat.flavour(old_module(_Recorder())) == "hid.device", "hid.device")
check("flavour, module with neither",
      hid_compat.flavour(type("Empty", (), {})) == "unusable", "unusable")
check("flavour, no module at all", hid_compat.flavour(None) is None, "None")

# ── Both flavours have to behave the same ────────────────────────────────────

for label, factory, path in (("hid.Device", new_module, b"/dev/hidraw9"),
                             ("hid.device", old_module, b"1-1:1.3")):
    rec = _Recorder()
    dev = hid_compat.open_path(path, module=factory(rec))
    check("%s opens the given path" % label, rec.opened == path, repr(rec.opened))

    dev.write(b"\x00\x11\x80")
    check("%s write passes bytes through" % label,
          rec.written == [b"\x00\x11\x80"], repr(rec.written))

    data = dev.read(64, timeout=250)
    check("%s read returns bytes" % label,
          isinstance(data, bytes) and data == b"\x01\x02\x03", repr(data))
    check("%s read passes the timeout on" % label,
          rec.last_read == (64, 250), repr(rec.last_read))

    # No timeout means "wait for it". The older package spells that 0 and
    # will not take None, so the adapter has to translate rather than forward.
    dev.read(64)
    check("%s read without a timeout" % label,
          rec.last_read == (64, None if label == "hid.Device" else 0),
          repr(rec.last_read))

    dev.send_feature_report(bytes([0xA1, 0x0C]))
    check("%s feature report out" % label,
          rec.features == [b"\xa1\x0c"], repr(rec.features))

    feature = dev.get_feature_report(0xA1, 8)
    check("%s feature report in is bytes" % label,
          isinstance(feature, bytes) and feature[:2] == b"\xa1\xaa", repr(feature[:2]))

    dev.nonblocking = True
    check("%s nonblocking is settable" % label, dev.nonblocking is True,
          "set_nonblocking%s" % (rec.nonblocking_calls or " (property)"))

    check("%s enumerate reaches the module" % label,
          [e["interface_number"] for e in
           hid_compat.enumerate(0x3282, 0x0008, module=factory(rec))] == [3], "interface 3")

    dev.close()
    check("%s close reaches the device" % label, rec.closed, "closed")

# Anything the adapter does not define still has to reach the library, or a
# driver that calls something rarer than the six methods above breaks.
rec = _Recorder()
dev = hid_compat.open_path(b"/dev/hidraw9", module=new_module(rec))
check("unknown attributes are forwarded", dev.rec is rec, "rec")

# ── The unusable cases say so ────────────────────────────────────────────────

for label, module in (("module with neither API", type("Empty", (), {})),
                      ("no module at all", None)):
    try:
        hid_compat.open_path(b"/dev/hidraw9", module=module)
        check("open_path refuses: %s" % label, False, "it opened something")
    except RuntimeError as exc:
        check("open_path refuses: %s" % label, True, str(exc)[:44])

check("enumerate without a module",
      hid_compat.enumerate(0x3282, 0x0008, module=None) == [] or hid_compat.hid is not None,
      "empty list, no exception")

# ── The drivers must not reach for `hid` behind the adapter's back ───────────
# This is the regression that started it all: one forgotten `hid.Device` is
# enough to break a whole device on a machine with the other package.
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
offenders = []
for folder, _dirs, files in os.walk(os.path.join(root, "devices")):
    if "__pycache__" in folder:
        continue
    for filename in files:
        if not filename.endswith(".py"):
            continue
        full = os.path.join(folder, filename)
        text = open(full, encoding="utf-8").read()
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if ("hid.Device(" in stripped or "__import__('hid')" in stripped
                    or stripped == "import hid"):
                offenders.append("%s:%d" % (os.path.relpath(full, root), lineno))
check("no driver touches `hid` directly", not offenders,
      ", ".join(offenders) if offenders else "all go through hid_compat")

print()
if failures:
    print("%d check(s) failed:" % len(failures))
    for failure in failures:
        print("  - %s" % failure)
    sys.exit(1)
print("all checks passed")
