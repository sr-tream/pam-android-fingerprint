import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "Optional PySide6 dependency missing")
class KdeWakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "tools/kde-wake-on-unlock.py"
        spec = importlib.util.spec_from_file_location("kde_wake", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_locking_does_not_wake_displays(self):
        with patch.object(self.module.subprocess, "run") as run:
            self.module.UnlockWake().activeChanged(True)
        run.assert_not_called()

    def test_unlocking_only_requests_dpms_on(self):
        with patch.object(self.module.subprocess, "run") as run:
            self.module.UnlockWake().activeChanged(False)
        run.assert_called_once_with(
            ["/usr/bin/kscreen-doctor", "--dpms", "on"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=True, timeout=5,
        )

    def test_wake_failure_does_not_affect_authentication(self):
        for error in (OSError("unavailable"), subprocess.TimeoutExpired("kscreen-doctor", 5)):
            with self.subTest(error=type(error).__name__), \
                    patch.object(self.module.subprocess, "run", side_effect=error), \
                    patch("builtins.print") as report:
                self.module.UnlockWake().activeChanged(False)
            report.assert_called_once()

    def test_other_desktops_do_not_subscribe_or_execute_commands(self):
        with patch.dict(self.module.os.environ, {"XDG_SESSION_TYPE": "x11",
                                                "XDG_CURRENT_DESKTOP": "KDE"}), \
                patch.object(self.module.QDBusConnection, "sessionBus") as bus, \
                patch("builtins.print"):
            self.assertEqual(self.module.main(), 0)
        bus.assert_not_called()

    @unittest.skipUnless(shutil.which("dbus-run-session"), "Private D-Bus runner missing")
    def test_real_qt_slot_subscribes_on_a_private_bus(self):
        path = Path(__file__).resolve().parents[1] / "tools/kde-wake-on-unlock.py"
        program = f"""
import runpy
from unittest.mock import patch
from PySide6.QtCore import QCoreApplication, QTimer
module = runpy.run_path({str(path)!r})
main = module["main"]
def timed(args):
    app = QCoreApplication(args)
    QTimer.singleShot(50, app.quit)
    return app
main.__globals__["QCoreApplication"] = timed
with patch("subprocess.run") as run:
    assert main() == 0
    run.assert_not_called()
"""
        environment = dict(os.environ, XDG_CURRENT_DESKTOP="KDE", XDG_SESSION_TYPE="wayland")
        result = subprocess.run(
            ["dbus-run-session", "--", "/usr/bin/python3", "-I", "-c", program],
            env=environment, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
