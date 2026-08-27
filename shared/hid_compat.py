"""One HID API, whichever `hid` module is installed.

Two unrelated projects on PyPI install a module called `hid`:

  * `hid` (apmorton) exposes the class `hid.Device(path=...)`
  * `hidapi` (cython/trezor) exposes `hid.device()` plus `open_path()`

They are not compatible. Distributions mostly package the second one, which
is why `python3-hid` on Ubuntu and `python-hidapi` on Arch both leave
`hid.Device` undefined. The AppImage bundles the first, so this only bites a
source installation, but it bites hard: every device screen in the app went
straight to `hid.Device` and a machine with the other flavour talked to no
Mountain hardware at all. Both MacroPad owners who answered the call for
testers in issue #85 were on that side of the split.

So nothing in the app touches `hid` directly any more. Open devices through
`open_path()` here and use the wrapper it hands back, which offers the API
the app already expects:

    write(data) · read(size, timeout=ms) · send_feature_report(data)
    get_feature_report(report_id, size) · close() · nonblocking

Reads and feature reports always come back as `bytes`, on either flavour.
"""

try:
    import hid
    HID_AVAILABLE = True
except ImportError:                                   # pragma: no cover
    hid = None
    HID_AVAILABLE = False


# "not given" and "given as None" are different answers here: the second is a
# test, or a caller that already found there is no module, asking what happens
# with nothing at all. A plain None default would silently turn that into
# "use the installed one" and the no-module path would never be exercised.
_UNSET = object()


def flavour(module=_UNSET):
    """Which of the two packages is installed: "hid.Device", "hid.device",
    "unusable" when a module called `hid` exists but offers neither, or None
    when there is no `hid` at all."""
    module = hid if module is _UNSET else module
    if module is None:
        return None
    if hasattr(module, "Device"):
        return "hid.Device"
    if hasattr(module, "device"):
        return "hid.device"
    return "unusable"


def _as_path(path):
    """hidapi wants the raw bytes that enumerate() handed out."""
    if isinstance(path, str):
        return path.encode()
    return path


class HidDevice:
    """A device opened through either flavour.

    Thin on purpose: it forwards, converts the two return types that differ,
    and turns hidapi's `set_nonblocking()` into the property the newer package
    has. Anything it does not define is forwarded to the underlying object, so
    a call this app does not make yet still reaches the library.
    """

    def __init__(self, dev, kind):
        self._dev = dev
        self.kind = kind          # "hid.Device" or "hid.device"

    # ── Reports ──────────────────────────────────────────────────────────────

    def write(self, data):
        return self._dev.write(bytes(data))

    def read(self, size, timeout=None):
        """`timeout` is in milliseconds, as both libraries count it.

        A missing timeout means "block until something arrives" in the newer
        package. hidapi spells that 0, so translate rather than pass None into
        a C call that will not take it.
        """
        if self.kind == "hid.Device":
            data = self._dev.read(size, timeout=timeout)
        else:
            data = self._dev.read(size, 0 if timeout is None else int(timeout))
        return bytes(data) if data else b""

    def send_feature_report(self, data):
        return self._dev.send_feature_report(bytes(data))

    def get_feature_report(self, report_id, size):
        data = self._dev.get_feature_report(report_id, size)
        return bytes(data) if data else b""

    # ── Everything else ──────────────────────────────────────────────────────

    @property
    def nonblocking(self):
        if self.kind == "hid.Device":
            return self._dev.nonblocking
        return getattr(self, "_nonblocking", False)

    @nonblocking.setter
    def nonblocking(self, value):
        if self.kind == "hid.Device":
            self._dev.nonblocking = value
        else:
            self._nonblocking = bool(value)
            self._dev.set_nonblocking(1 if value else 0)

    def close(self):
        try:
            self._dev.close()
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self._dev, name)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


def open_path(path, module=_UNSET):
    """Open a HID device by the path enumerate() reported.

    Raises RuntimeError when there is no usable `hid` module, so a caller sees
    what is wrong instead of an AttributeError from deep inside a driver.
    """
    module = hid if module is _UNSET else module
    kind = flavour(module)
    if kind == "hid.Device":
        return HidDevice(module.Device(path=_as_path(path)), kind)
    if kind == "hid.device":
        dev = module.device()
        dev.open_path(_as_path(path))
        return HidDevice(dev, kind)
    if kind == "unusable":
        raise RuntimeError(
            "the installed 'hid' module offers neither Device nor device(); "
            "install the 'hid' or the 'hidapi' package")
    raise RuntimeError("no 'hid' module installed; install 'hid' or 'hidapi'")


def enumerate(vid=0, pid=0, module=_UNSET):
    """List HID interfaces. Both flavours spell this the same way."""
    module = hid if module is _UNSET else module
    if module is None:
        return []
    return list(module.enumerate(vid, pid))
