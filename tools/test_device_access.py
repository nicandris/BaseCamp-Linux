#!/usr/bin/env python3
"""
Checks the "we cannot open this device" test that puts a notice on screen.

    python3 tools/test_device_access.py

No hardware, no display. It drives gui._device_access_denied() against a
handful of made-up nodes, because getting this wrong is expensive in both
directions: a missed denial leaves someone with a screen full of controls
that quietly do nothing (issue #49), and a false one puts a full "no
permission" notice over a device that is working (issue #86).
"""
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gui   # noqa: E402

failures = []


def check(name, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + "%-48s %s" % (name, detail))
    if not ok:
        failures.append("%s: %s" % (name, detail))


def denied_for(nodes):
    """What the check makes of this list of nodes."""
    real = gui._device_nodes
    gui._device_nodes = lambda _vid, _pid: list(nodes)
    try:
        return gui._device_access_denied(0x3282, 0x0009)
    finally:
        gui._device_nodes = real


work = tempfile.mkdtemp(prefix="basecamp-access-test-")
readable = os.path.join(work, "hidraw-open")
unreadable = os.path.join(work, "hidraw-locked")
missing = os.path.join(work, "hidraw-gone")

with open(readable, "w") as f:
    f.write("")
with open(unreadable, "w") as f:
    f.write("")
os.chmod(readable, 0o666)
os.chmod(unreadable, 0o000)

running_as_root = os.geteuid() == 0

check("a node we can read and write is not reported",
      denied_for([readable]) == [], denied_for([readable]))

if running_as_root:
    print("skip  a node we cannot open                        (running as root)")
else:
    check("a node we cannot open is reported",
          denied_for([unreadable]) == [unreadable], denied_for([unreadable]))

# The one from #86: the DisplayPad drops and re-adds its hidraw node by
# itself, so the node listed a moment ago can be gone by the time it is
# checked. os.access() says False for a path that does not exist, and that
# was being reported as a permission problem on a device that was fine.
check("a node that has gone away is not a permission problem",
      denied_for([missing]) == [], denied_for([missing]))

check("a vanished node does not hide a real denial",
      denied_for([missing, unreadable]) == ([] if running_as_root else [unreadable]),
      denied_for([missing, unreadable]))

check("nothing to check means nothing to report", denied_for([]) == [])

# The log line has to carry enough to tell a false report from a real one.
described = gui._describe_node(readable)
check("the log line names owner, group and mode",
      readable in described and "666" in described, described)
check("and survives a node that is not there",
      isinstance(gui._describe_node(missing), str), gui._describe_node(missing))

os.chmod(unreadable, stat.S_IRUSR | stat.S_IWUSR)
for path in (readable, unreadable):
    os.unlink(path)
os.rmdir(work)

print()
if failures:
    print("%d check(s) failed:" % len(failures))
    for failure in failures:
        print("  - %s" % failure)
    sys.exit(1)
print("all checks passed")
