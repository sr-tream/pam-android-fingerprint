import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ssh_hint_helper", ROOT / "Desktop/main.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class SshHintTests(unittest.TestCase):
    def test_direct_hints_skip_parent_read(self):
        for name in app.SSH_HINTS:
            with patch.dict(os.environ, {name: "hint"}, clear=True), \
                    patch("builtins.open") as source:
                self.assertTrue(app.ssh_hint_present())
                source.assert_not_called()

    def test_parent_initial_environment(self):
        for name in app.SSH_HINTS:
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(os, "getppid", return_value=1234), \
                    patch("builtins.open", mock_open(read_data=(
                        b"PATH=/usr/bin\0" + name.encode() + b"=hint\0"))) as source:
                self.assertTrue(app.ssh_hint_present())
                source.assert_called_once_with("/proc/1234/environ", "rb")
                source().read.assert_called_once_with(app.MAX_CALLER_ENV + 1)

    def test_empty_and_similarly_named_values_not_hints(self):
        for data in (b"", b"SSH_CONNECTION=\0SSH_TTY=\0SSH_CLIENT=\0",
                     b"NOT_SSH_TTY=hint\0OTHER=SSH_CONNECTION=hint\0"):
            with patch.dict(os.environ, {}, clear=True), \
                    patch("builtins.open", mock_open(read_data=data)):
                self.assertFalse(app.ssh_hint_present())

    def test_unreadable_parent_is_unknown(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch("builtins.open", side_effect=PermissionError):
            self.assertFalse(app.ssh_hint_present())

    def test_oversized_parent_is_unknown(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch("builtins.open", mock_open(read_data=b"x" * (app.MAX_CALLER_ENV + 1))):
            self.assertFalse(app.ssh_hint_present())

    def test_sudo_ssh_hint_returns_to_password_without_phone(self):
        config = dict(user="alice", services=["sudo", "sudo-i"])
        for service in config["services"]:
            with patch.dict(os.environ, dict(PAM_USER="alice", PAM_SERVICE=service,
                                            PAM_TYPE="auth"), clear=True), \
                    patch.object(app, "load_config", return_value=config), \
                    patch.object(app, "ssh_hint_present", return_value=True), \
                    patch.object(app, "request") as request:
                self.assertEqual(app.authenticate(), 1)
                request.assert_not_called()

    def test_local_or_unknown_sudo_keeps_phone_flow(self):
        with patch.dict(os.environ, dict(PAM_USER="alice", PAM_SERVICE="sudo",
                                        PAM_TYPE="auth"), clear=True), \
                patch.object(app, "load_config", return_value=dict(user="alice", services=["sudo"])), \
                patch.object(app, "ssh_hint_present", return_value=False), \
                patch.object(app, "request") as request:
            self.assertEqual(app.authenticate(), 0)
            request.assert_called_once()

    def test_hint_does_not_change_other_services(self):
        for service in ("kde", "kde-fingerprint", "polkit-1"):
            with patch.dict(os.environ, dict(PAM_USER="alice", PAM_SERVICE=service,
                                            PAM_TYPE="auth", SSH_CONNECTION="hint"), clear=True), \
                    patch.object(app, "load_config", return_value=dict(user="alice", services=[service])), \
                    patch.object(app, "ssh_hint_present") as hint, \
                    patch.object(app, "request") as request:
                self.assertEqual(app.authenticate(), 0)
                hint.assert_not_called()
                request.assert_called_once()


@unittest.skipUnless(shutil.which("cc") and Path("/usr/lib/security/pam_exec.so").exists(),
                     "C compiler and Arch Linux-PAM modules required")
class PamCallerEnvironmentTests(unittest.TestCase):
    def test_real_pam_exec_parent_hint(self):
        """No passwords, sudo, SSH server, root or real system PAM files."""
        with tempfile.TemporaryDirectory(prefix="pam-ssh-hint-") as directory:
            base = Path(directory)
            probe = base / "probe"
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror",
                            str(ROOT / "tools/pam-check.c"), "-o", str(probe),
                            "-lpam", "-lpam_misc"], check=True, capture_output=True, timeout=30)
            script = base / "hint.py"
            script.write_text(
                "import importlib.util, os\n"
                f"spec = importlib.util.spec_from_file_location('helper', {str(ROOT / 'Desktop/main.py')!r})\n"
                "app = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(app)\n"
                "print('CHILD_HINT=' + str(bool(os.environ.get('SSH_CONNECTION'))))\n"
                "print('DETECTED_HINT=' + str(app.ssh_hint_present()))\n")
            (base / "hint-test").write_text(
                f"auth required pam_exec.so stdout /usr/bin/python3 -I {script}\n"
                "account required pam_permit.so\n")
            environment = {k: v for k, v in os.environ.items() if k not in app.SSH_HINTS}
            for present in (False, True):
                if present:
                    environment["SSH_CONNECTION"] = "192.0.2.10 50000 192.0.2.20 22"
                result = subprocess.run([str(probe), "hint-test", "fixture-user", directory],
                                        env=environment, check=True, capture_output=True,
                                        text=True, timeout=15)
                self.assertIn("CHILD_HINT=False", result.stdout)
                self.assertIn(f"DETECTED_HINT={present}", result.stdout)


if __name__ == "__main__":
    unittest.main()
