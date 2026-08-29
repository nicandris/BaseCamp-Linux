#!/usr/bin/env python3
"""
Checks which language the application starts in when nobody has chosen one.

    python3 tools/test_language_default.py

No hardware, no display. It drives gui.default_lang() against a set of
locales, because the answer used to be German for all of them: the fallback
was hardcoded, so anyone outside a German system got a German interface on
first start and then had to find the setting to get out of it, in German
(issue #92, reported by @Eirikur on Linux Mint).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gui   # noqa: E402

failures = []


def check(name, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + "%-46s %s" % (name, detail))
    if not ok:
        failures.append("%s: %s" % (name, detail))


def chosen(env, available=None):
    """What the application would start in with this environment."""
    available = available if available is not None else {"de": "Deutsch",
                                                         "en": "English"}
    saved = {k: os.environ.get(k) for k in
             ("LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES")}
    try:
        for key in saved:
            os.environ.pop(key, None)
        os.environ.update(env)
        return gui.default_lang(available)
    finally:
        for key, value in saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value


# ── The report: a machine that is not German must not come up German ─────────
for label, env, want in (
        ("an English system", {"LANG": "en_US.UTF-8"}, "en"),
        ("a German system", {"LANG": "de_DE.utf8"}, "de"),
        ("Icelandic, which we do not translate", {"LANG": "is_IS.UTF-8"}, "en"),
        ("French, which we do not translate", {"LANG": "fr_FR.UTF-8"}, "en"),
        ("nothing set at all", {}, "en"),
        ("the C locale", {"LANG": "C"}, "en"),
        ("a bare code with no region", {"LANG": "de"}, "de"),
        ("LC_ALL beating LANG", {"LC_ALL": "de_AT.UTF-8",
                                 "LANG": "en_US.UTF-8"}, "de"),
        ("LC_MESSAGES beating LANG", {"LC_MESSAGES": "de_DE.UTF-8",
                                      "LANG": "en_US.UTF-8"}, "de"),
        ("a modifier on the locale", {"LANG": "de_DE.UTF-8@euro"}, "de"),
):
    got = chosen(env)
    check(label, got == want, "%s (wanted %s)" % (got, want))

# LANGUAGE is gettext's own preference list and wins, except under the C
# locale where gettext ignores it and so does this.
check("LANGUAGE wins over LANG",
      chosen({"LANG": "de_DE.UTF-8", "LANGUAGE": "en_GB:en"}) == "en")
check("the first LANGUAGE entry we have wins",
      chosen({"LANG": "en_US.UTF-8", "LANGUAGE": "fr:de:en"}) == "de")
check("LANGUAGE is ignored under the C locale",
      chosen({"LANG": "C", "LANGUAGE": "de"}) == "en")

# ── It must not fall over on an odd installation ─────────────────────────────
check("no English shipped: something is still chosen",
      chosen({"LANG": "fr_FR.UTF-8"}, {"de": "Deutsch"}) == "de")
check("nothing shipped at all", chosen({"LANG": "de_DE.UTF-8"}, {}) == "en")
check("an empty variable is not a language",
      chosen({"LANG": "", "LC_ALL": ""}) == "en")

# ── And the shipped languages really are the two this assumes ────────────────
shipped = gui.available_langs()
check("the application ships de and en",
      set(shipped) >= {"de", "en"}, sorted(shipped))

print()
if failures:
    print("%d check(s) failed:" % len(failures))
    for failure in failures:
        print("  - %s" % failure)
    sys.exit(1)
print("all checks passed")
