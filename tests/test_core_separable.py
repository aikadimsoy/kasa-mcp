# -*- coding: utf-8 -*-
"""Core separability: the headless server must import with `src.desktop` absent.

WHY THIS FILE EXISTS
--------------------
`src/dashboard/routes.py` used to do `from ..desktop import consent` with no try/except,
inside `_register_dashboard`, which `src/mcp_server/server.py` calls AT MODULE LEVEL. A
code comment right next to it claimed the module was "optional". It was not: deleting
`desktop` killed the server at import time. The audit claim "the core is separable" was
therefore false, and nothing in the suite measured it.

HOW IT IS MEASURED
------------------
In a SEPARATE INTERPRETER (never by mutating this process's sys.modules -- that lesson was
paid for once already: deleting `src.*` modules re-initialised a per-process DPAPI singleton
and knocked over 13 unrelated tests). A meta_path finder refuses the blocked package, then
the core is imported.

Turkce not: bu dosyanin degeri "import edildi" demesinde DEGIL, ALETIN KENDISINI de
denetlemesindedir. Alt surec once engelleyicinin GERCEKTEN engelledigini dogrular ve
engelleme calismiyorsa AYRI bir cikis koduyla oler -- yoksa engelleyici bozuldugunda test
sessizce yesil yanardi (klasik yanlis-PASS). Ikinci test ise tersini olcer: cekirdegin
gercekten muhtac oldugu bir modul engellenirse import BASARISIZ olmali. Ikisi birlikte,
testin "her zaman OK basan" bir sey olmadigini gosterir.
"""
import os
import subprocess
import sys
import tempfile

_KASA_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)

# Alt surec sablonu. {blocked} = import edilmesi yasaklanan paket.
_PROBE = '''
import sys

BLOCK = "{blocked}"


class _Blocker:
    """Refuse the blocked package as if it were not installed at all."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname == BLOCK or fullname.startswith(BLOCK + "."):
            raise ImportError("blocked for measurement: " + fullname)
        return None


sys.meta_path.insert(0, _Blocker())

# Aletin oz-denetimi: engelleyici calismiyorsa olcum anlamsizdir -> 2 ile ol.
try:
    __import__(BLOCK)
except ImportError:
    pass
else:
    sys.stderr.write("BLOCKER-BROKEN: " + BLOCK + " still importable\\n")
    raise SystemExit(2)

import src.mcp_server.server  # noqa: F401  <- ASIL OLCUM
print("CORE-IMPORT-OK")
'''


def _run_with_blocked(pkg: str):
    env = dict(os.environ)
    env["KASA_VAULT_PATH"] = tempfile.mkdtemp(prefix="kasa_sep_")
    env["PYTHONPATH"] = _KASA_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", _PROBE.format(blocked=pkg)],
        capture_output=True, text=True, cwd=_KASA_ROOT, env=env, timeout=180,
    )


def test_core_imports_without_desktop():
    """The claim under test: strip `desktop`, the headless core still comes up."""
    r = _run_with_blocked("src.desktop")
    assert r.returncode != 2, f"olcum araci bozuk (engelleyici tutmadi): {r.stderr[-400:]}"
    assert r.returncode == 0, (
        "cekirdek `desktop` olmadan import EDILEMIYOR -- 'ayrilabilir' iddiasi yanlis:\n"
        + (r.stderr or r.stdout)[-1200:]
    )
    assert "CORE-IMPORT-OK" in r.stdout


def test_NEGATIVE_blocking_a_real_core_dependency_does_fail():
    """Control: the probe is not a machine that always prints OK.

    Turkce not: `src.vault` cekirdegin gercek kokudur (bagimliliksiz tek modul). Engellenince
    import BASARISIZ olmali. Bu test kirmizi olsaydi, ustteki yesil hicbir sey kanitlamazdi.
    """
    r = _run_with_blocked("src.vault")
    assert r.returncode != 2, f"olcum araci bozuk (engelleyici tutmadi): {r.stderr[-400:]}"
    assert r.returncode != 0, "gercek bir cekirdek bagimliligi engellendigi halde import GECTI"
    assert "CORE-IMPORT-OK" not in r.stdout
