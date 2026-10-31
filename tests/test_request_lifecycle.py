import importlib.util
import itertools
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lifecycle_helper", ROOT / "Desktop/main.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class LifetimeTests(unittest.TestCase):
    def test_signal_cancels_and_handlers_are_restored(self):
        before = signal.getsignal(signal.SIGTERM)
        with app.RequestLifetime() as lifetime:
            lifetime._signal(signal.SIGTERM, None)
            with self.assertRaises(app.RequestCancelled):
                lifetime.check()
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def pipe_lifetime(self, already_closed=False):
        reader, writer = os.pipe()
        real_dup = os.dup
        info = os.fstat(writer)
        if already_closed:
            os.close(reader)
            reader = None
        try:
            with patch.object(os, "fstat", return_value=info), \
                    patch.object(os, "dup", side_effect=lambda fd: real_dup(writer)):
                if already_closed:
                    with self.assertRaises(app.RequestCancelled):
                        with app.RequestLifetime(watch_parent=True):
                            self.fail("Accepted a closed PAM pipe")
                else:
                    with app.RequestLifetime(watch_parent=True) as lifetime:
                        lifetime.require_pam_pipe()
                        os.close(reader)
                        reader = None
                        with self.assertRaises(app.RequestCancelled):
                            lifetime.check()
        finally:
            if reader is not None:
                os.close(reader)
            os.close(writer)

    def test_pam_pipe_hangup_cancels(self):
        self.pipe_lifetime()

    def test_pam_pipe_covers_already_orphaned_child(self):
        self.pipe_lifetime(already_closed=True)

    def test_persistent_pam_requires_pipe(self):
        with app.RequestLifetime() as lifetime:
            with self.assertRaises(ValueError):
                lifetime.require_pam_pipe()

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux pidfd required")
    def test_parent_pidfd_exit_cancels(self):
        child = subprocess.Popen(
            ["/usr/bin/python3", "-I", "-c", "import threading; threading.Event().wait()"])
        try:
            with patch.object(os, "getppid", return_value=child.pid), \
                    patch.object(os, "fstat", return_value=os.stat("/dev/null")):
                with app.RequestLifetime(watch_parent=True) as lifetime:
                    lifetime.check()
                    child.kill()
                    child.wait(timeout=3)
                    with self.assertRaises(app.RequestCancelled):
                        lifetime.check()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)

    def fake_adb_wait(self, program="import threading; threading.Event().wait()", **kwargs):
        real_popen = subprocess.Popen
        children = []

        def launch(command, **options):
            child = real_popen(
                ["/usr/bin/python3", "-I", "-c", program],
                **options)
            children.append(child)
            return child

        try:
            with patch.object(app.socket, "create_connection"), \
                    patch.object(app.subprocess, "Popen", side_effect=launch):
                app.adb(None, "devices", **kwargs)
        finally:
            self.assertTrue(children)
            for child in children:
                self.assertIsNotNone(child.poll(), "Cancelled ADB child was not reaped")

    def test_unbounded_adb_wait_still_observes_cancellation(self):
        guard = MagicMock()
        guard.check.side_effect = [None, None, app.RequestCancelled("closed")]
        with self.assertRaises(app.RequestCancelled):
            self.fake_adb_wait(timeout=None, lifetime=guard)

    def test_unbounded_adb_wait_renews_lease(self):
        tick = MagicMock(side_effect=app.RequestCancelled("tick reached"))
        with patch.object(app.time, "monotonic", side_effect=itertools.count(0, 10)), \
                self.assertRaises(app.RequestCancelled):
            self.fake_adb_wait(timeout=None, on_tick=tick)
        tick.assert_called_once()

    def test_adb_rechecks_drain_deadline_before_accepting_bytes(self):
        check = MagicMock(side_effect=[None, app.RequestCancelled("drain expired")])
        with self.assertRaises(app.RequestCancelled):
            self.fake_adb_wait(program="print('late result')", timeout=None,
                               lifetime=MagicMock(), deadline_check=check)
        self.assertEqual(check.call_count, 2)


class RequestProtocolTests(unittest.TestCase):
    def setUp(self):
        self.nonce = "ab" * 32
        self.guard = MagicMock(watch_parent=False)
        self.guard.watch_parent = False
        self.calls = []

    def fake_adb(self, device, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:3] == ("shell", "getprop", "ro.serialno"):
            return b"TEST_PHONE_A\n"
        if args[:3] == ("shell", "am", "start"):
            return b""
        uri = args[-1]
        if "/lease/" in uri:
            return json.dumps(dict(nonce=self.nonce, protocol="leased-v1",
                                   alive=True, state="pending")).encode()
        if "/cancel/" in uri:
            return json.dumps(dict(nonce=self.nonce, protocol="leased-v1", cancelled=True)).encode()
        return json.dumps(dict(nonce=self.nonce)).encode()

    def run_request(self, service, implementation=None):
        with patch.object(app, "adb", side_effect=implementation or self.fake_adb), \
                patch.object(app.secrets, "token_hex", return_value=self.nonce):
            return app.request_response(dict(serial="TEST_PHONE_A"), "test-transport",
                                        "workstation", "alice", service, self.guard)

    def test_kde_has_lease_handshake_and_no_overall_read_deadline(self):
        self.run_request("kde-fingerprint")
        launch = next(args for args, _ in self.calls if "am" in args)
        self.assertEqual(launch[-3:], ("--es", "control", "leased-v1"))
        result = next(options for args, options in self.calls if "/result/" in args[-1])
        self.assertIsNone(result["timeout"])
        self.assertTrue(callable(result["on_tick"]))
        self.assertTrue(callable(result["deadline_check"]))
        self.assertTrue(any("/lease/" in args[-1] for args, _ in self.calls))
        self.assertFalse(any("/cancel/" in args[-1] for args, _ in self.calls))

    def test_sudo_stays_bounded(self):
        self.run_request("sudo")
        result = next(options for args, options in self.calls if "/result/" in args[-1])
        self.assertEqual(result["timeout"], 30)
        self.assertIsNone(result["on_tick"])
        self.assertFalse(any("/lease/" in args[-1] for args, _ in self.calls))

    def test_persistent_pam_pipe_required_before_phone_launch(self):
        self.guard.watch_parent = True
        self.guard.require_pam_pipe.side_effect = ValueError("missing pipe")
        with self.assertRaises(ValueError):
            self.run_request("kde-fingerprint")
        self.assertEqual(self.calls, [])

    def test_cancelled_read_explicitly_cancels_phone_without_cancelled_guard(self):
        def cancelled(device, *args, **kwargs):
            if "/result/" in args[-1]:
                raise app.RequestCancelled("PAM closed")
            return self.fake_adb(device, *args, **kwargs)
        with self.assertRaises(app.RequestCancelled):
            self.run_request("kde-fingerprint", cancelled)
        cancel = next(options for args, options in self.calls if "/cancel/" in args[-1])
        self.assertIsNone(cancel["lifetime"])
        self.assertEqual(cancel["timeout"], 2)

    def test_cleanup_failure_does_not_mask_cancellation(self):
        def failed_cleanup(device, *args, **kwargs):
            if "/result/" in args[-1]:
                raise app.RequestCancelled("original")
            if "/cancel/" in args[-1]:
                raise OSError("offline")
            return self.fake_adb(device, *args, **kwargs)
        with self.assertRaisesRegex(app.RequestCancelled, "original"):
            self.run_request("kde-fingerprint", failed_cleanup)

    def test_unsupported_phone_protocol_fails_closed(self):
        def old_phone(device, *args, **kwargs):
            if "/lease/" in args[-1]:
                return b'{"alive":true}'
            return self.fake_adb(device, *args, **kwargs)
        with self.assertRaises(ValueError):
            self.run_request("kde-fingerprint", old_phone)
        self.assertTrue(any("/cancel/" in args[-1] for args, _ in self.calls))
        self.assertFalse(any("/result/" in args[-1] for args, _ in self.calls))

    def test_ended_lease_has_only_a_short_result_drain_grace(self):
        lease = app.RequestLease("test-transport", self.nonce, self.guard)
        with patch.object(app, "control", return_value=dict(alive=False, state="consumed")) as control:
            with patch.object(app.time, "monotonic", return_value=10):
                lease.renew()
            with patch.object(app.time, "monotonic", return_value=14):
                with self.assertRaises(app.RequestCancelled):
                    lease.renew()
            control.assert_called_once()

    def test_cancelled_or_unknown_lease_has_no_drain_grace(self):
        for state in ("cancelled", "unknown"):
            lease = app.RequestLease("test-transport", self.nonce, self.guard)
            with patch.object(app, "control", return_value=dict(alive=False, state=state)):
                with self.assertRaises(app.RequestCancelled):
                    lease.renew()
            self.assertIsNone(lease.ended_deadline)

    def test_renewal_cannot_cross_an_existing_drain_deadline(self):
        lease = app.RequestLease("test-transport", self.nonce, self.guard)
        lease.ended_deadline = 4
        with patch.object(app, "control", return_value=dict(alive=False, state="consumed")), \
                patch.object(app.time, "monotonic", side_effect=[3.5, 4.5]):
            with self.assertRaises(app.RequestCancelled):
                lease.renew()

    def test_cli_can_select_an_allowlisted_long_wait_service(self):
        config = dict(services=["sudo", "kde-fingerprint"])
        with patch.object(app.sys, "argv", ["helper", "test", "--config", "fixture.json",
                                            "--service", "kde-fingerprint"]), \
                patch.object(app, "load_config", return_value=config), \
                patch.object(app, "request") as request, patch("builtins.print"):
            self.assertEqual(app.main(), 0)
            request.assert_called_once_with(config, "kde-fingerprint", None)

    def test_cli_cannot_select_a_service_outside_its_registry(self):
        with patch.object(app.sys, "argv", ["helper", "test", "--config", "fixture.json",
                                            "--service", "other-service"]), \
                patch.object(app, "load_config", return_value=dict(services=["sudo"])), \
                patch.object(app, "request") as request:
            with self.assertRaises(ValueError):
                app.main()
            request.assert_not_called()


@unittest.skipUnless(shutil.which("cc") and Path("/usr/lib/security/pam_exec.so").exists(),
                     "C compiler and Arch Linux-PAM modules required")
class PamPipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="pam-pipe-lifetime-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        cls.probe = cls.base / "probe"
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(ROOT / "tools/pam-check.c"),
                        "-o", str(cls.probe), "-lpam", "-lpam_misc"],
                       check=True, capture_output=True, timeout=30)

    def module_import(self):
        return (
            "import importlib.util\n"
            f"spec = importlib.util.spec_from_file_location('helper', {str(ROOT / 'Desktop/main.py')!r})\n"
            "app = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(app)\n")

    def profile(self, name, script, stdout=True):
        (self.base / name).write_text(
            f"auth requisite pam_exec.so {'stdout ' if stdout else ''}"
            f"/usr/bin/python3 -I {script}\naccount required pam_permit.so\n")

    def test_real_pam_exec_supplies_a_bound_stdout_pipe(self):
        script = self.base / "bound.py"
        script.write_text(self.module_import() +
                          "with app.RequestLifetime(watch_parent=True) as lifetime:\n"
                          "    lifetime.require_pam_pipe()\n"
                          "    print('BOUND_PAM_PIPE', flush=True)\n")
        self.profile("bound", script)
        result = subprocess.run([str(self.probe), "bound", "fixture-user", str(self.base)],
                                check=True, capture_output=True, text=True, timeout=15)
        self.assertIn("BOUND_PAM_PIPE", result.stdout)
        self.profile("unbound", script, stdout=False)
        result = subprocess.run([str(self.probe), "unbound", "fixture-user", str(self.base)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 1, "Persistent auth accepted an unbound stdout")

    def test_pipe_detects_caller_death_before_python_guard_starts(self):
        address = str(self.base / "gate.sock")
        script = self.base / "orphan.py"
        script.write_text(
            "import socket\n"
            "client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "client.settimeout(10)\n"
            f"client.connect({address!r})\n"
            "client.sendall(b'ready')\n"
            "client.recv(1)\n" + self.module_import() +
            "try:\n"
            "    with app.RequestLifetime(watch_parent=True) as lifetime:\n"
            "        lifetime.require_pam_pipe()\n"
            "        client.sendall(b'wrong-owner')\n"
            "except app.RequestCancelled:\n"
            "    client.sendall(b'cancelled')\n"
            "client.close()\n")
        self.profile("orphan", script)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(address)
            server.listen(1)
            server.settimeout(10)
            probe = subprocess.Popen([str(self.probe), "orphan", "fixture-user", str(self.base)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(10)
                    self.assertEqual(connection.recv(5), b"ready")
                    # The PAM helper has not imported the Python lifecycle code
                    # yet. Its original parent is gone before getppid() runs.
                    probe.kill()
                    probe.wait(timeout=3)
                    connection.sendall(b"go")
                    self.assertEqual(connection.recv(64), b"cancelled")
            finally:
                if probe.poll() is None:
                    probe.kill()
                    probe.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
