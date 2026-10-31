import base64
import importlib.util
import json
import hashlib
from pathlib import Path
import tempfile
import copy
import subprocess
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

spec = importlib.util.spec_from_file_location("fingerprint", Path(__file__).resolve().parents[1] / "Desktop/main.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.nonce = "ab" * 32
        self.der = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.pin = base64.b64encode(self.der).decode()
        self.response = {
            "nonce": self.nonce, "public_key": self.pin,
            "signature": base64.b64encode(self.key.sign(
                app.message(self.nonce, "workstation", "alice", "sudo"),
                ec.ECDSA(hashes.SHA256()))).decode()}
        self.config = dict(version=3, user="alice", host="workstation", services=["sudo"],
                           devices=[dict(label="primary", serial="TEST_PHONE_A",
                                         endpoints=["192.0.2.10:5555"], public_key=self.pin)])

    def check(self, **kwargs):
        args = dict(response=self.response, nonce=self.nonce, host="workstation",
                    user="alice", service="sudo", pinned=self.pin)
        args.update(kwargs)
        return app.verify(**args)

    def test_valid(self):
        self.assertEqual(self.check(), self.der)

    def test_other_phone(self):
        with self.assertRaises(ValueError):
            self.check(pinned=base64.b64encode(b"other-phone").decode())

    def test_null_empty_and_invalid_pins(self):
        for pin in (None, "", "!!!!", base64.b64encode(b"not-a-key").decode()):
            with self.assertRaises(ValueError):
                self.check(pinned=pin)

    def test_pairing_requires_independent_fingerprint(self):
        with self.assertRaises(ValueError):
            app.verify_pairing(self.response, self.nonce, "workstation", "alice", "sudo", "00" * 32)
        self.assertEqual(app.verify_pairing(
            self.response, self.nonce, "workstation", "alice", "sudo",
            hashlib.sha256(self.der).hexdigest()), self.der)

    def test_null_configuration_pin(self):
        config = copy.deepcopy(self.config)
        config["devices"][0]["public_key"] = None
        with self.assertRaises(ValueError):
            app.validate_config(config)

    def test_replay(self):
        with self.assertRaises(ValueError):
            self.check(nonce="cd" * 32)

    def test_modified_nonce(self):
        self.response["nonce"] = "cd" * 32
        with self.assertRaises(InvalidSignature):
            self.check(nonce="cd" * 32)

    def test_modified_context(self):
        for changed in (dict(host="attacker"), dict(user="root"), dict(service="sshd")):
            with self.assertRaises(InvalidSignature):
                self.check(**changed)

    def test_failure_cannot_authenticate(self):
        self.response["error"] = "cancelled"
        with self.assertRaises(ValueError):
            self.check()

    def test_malformed_base64(self):
        self.response["signature"] = "!!!!!"
        with self.assertRaises(ValueError):
            self.check()

    def test_context_injection(self):
        for value in ("user\nsudo", "user;id", "", "-x "):
            with self.assertRaises(ValueError):
                app.message(self.nonce, "workstation", value, "sudo")

    def test_wrong_device_before_prompt(self):
        with patch.object(app, "adb", return_value=b"OTHER_SERIAL\n") as adb:
            with self.assertRaises(ValueError):
                app.request_response(dict(serial="TEST_PHONE_A"),
                                     "192.0.2.10:5555", "workstation", "alice", "sudo")
            self.assertEqual(adb.call_count, 1)

    def test_valid_registry(self):
        self.assertEqual(app.validate_config(self.config), self.config)

    def test_no_wildcard_or_empty_registry(self):
        for devices in ([], "*", [dict(label="primary", serial="TEST_PHONE_A", public_key=None)]):
            config = dict(self.config, devices=devices)
            with self.assertRaises((ValueError, KeyError)):
                app.validate_config(config)

    def test_duplicate_identity_rejected(self):
        original = self.config["devices"][0]
        for changed in (dict(label="second"), dict(serial="OTHER"), dict()):
            config = copy.deepcopy(self.config)
            config["devices"].append(original | changed)
            with self.assertRaises(ValueError):
                app.validate_config(config)

    def test_duplicate_key_with_distinct_serial_and_label(self):
        config = copy.deepcopy(self.config)
        config["devices"].append(config["devices"][0] | dict(label="second", serial="OTHER"))
        with self.assertRaises(ValueError):
            app.validate_config(config)

    def test_duplicate_key_alternate_encoding(self):
        # Same coordinates, compressed EC point within a DER SPKI.
        point = self.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        compressed = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200") + point
        config = copy.deepcopy(self.config)
        config["devices"].append(dict(label="second", serial="OTHER",
                                      public_key=base64.b64encode(compressed).decode()))
        with self.assertRaises(ValueError):
            app.validate_config(config)

    def second_phone(self):
        key = ec.generate_private_key(ec.SECP256R1())
        der = key.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
        return key, dict(label="second", serial="SECOND_SERIAL",
                         endpoints=["192.0.2.20:5555"],
                         public_key=base64.b64encode(der).decode())

    def test_second_phone_same_user(self):
        _, second = self.second_phone()
        self.config["devices"].append(second)
        app.validate_config(self.config)
        with patch.object(app, "adb", side_effect=[
                b"List of devices attached\n192.0.2.20:5555\tdevice\n", b"SECOND_SERIAL\n"]):
            selected, endpoint = app.choose_device(self.config)
        self.assertEqual(selected, second)
        self.assertEqual(endpoint, "192.0.2.20:5555")

    def test_unknown_phone_never_prompted(self):
        with patch.object(app, "adb", side_effect=[
                b"List of devices attached\n192.0.2.30:5555\tdevice\n", b"NOT_PAIRED\n"]) as adb:
            with self.assertRaises(ValueError):
                app.request(self.config, "sudo")
            self.assertEqual(adb.call_count, 2)
            self.assertFalse(any("start" in call.args for call in adb.call_args_list))

    def test_changed_wifi_endpoint(self):
        with patch.object(app, "adb", side_effect=[
                b"List of devices attached\n192.0.2.40:5555\tdevice\n", b"TEST_PHONE_A\n"]):
            selected, endpoint = app.choose_device(self.config)
        self.assertEqual(selected["label"], "primary")
        self.assertEqual(endpoint, "192.0.2.40:5555")

    def test_each_phone_requires_its_own_key(self):
        _, second = self.second_phone()
        with self.assertRaises(ValueError):
            self.check(pinned=second["public_key"])

    def test_pairing_file_exclusive_and_add(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pair.json"
            app.save_pairing(path, self.config)
            with self.assertRaises(FileExistsError):
                app.save_pairing(path, self.config)
            expected = copy.deepcopy(self.config)
            _, second = self.second_phone()
            self.config["devices"].append(second)
            app.save_pairing(path, self.config, add=True, expected=expected)
            self.assertEqual(app.load_config(path), self.config)
            with self.assertRaises(ValueError):
                app.save_pairing(path, expected, add=True, expected=expected)
            self.assertEqual(app.load_config(path), self.config)

    def test_untrusted_pairing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pair.json"
            path.write_text("{}")
            path.chmod(0o666)
            with self.assertRaises(PermissionError):
                app.load_config(path, trusted=True)

    def test_pam_scope(self):
        config = dict(user="alice", services=["sudo"])
        for env in (
            dict(PAM_TYPE="auth", PAM_USER="root", PAM_SERVICE="sudo"),
            dict(PAM_TYPE="auth", PAM_USER="alice", PAM_SERVICE="sshd"),
            dict(PAM_TYPE="auth", PAM_USER="alice", PAM_SERVICE="sudo", PAM_RHOST="remote"),
            dict(PAM_TYPE="account", PAM_USER="alice", PAM_SERVICE="sudo"),
        ):
            with patch.object(app, "load_config", return_value=config), \
                    patch.object(app, "request") as request, patch.dict(app.os.environ, env, clear=True):
                self.assertEqual(app.authenticate(), 1)
                request.assert_not_called()

    def fake_adb(self, program, **kwargs):
        real_popen = subprocess.Popen

        def launch(command, **options):
            self.assertEqual(command[:5], ["/usr/bin/adb", "-H", "127.0.0.1", "-P", "5037"])
            self.assertNotIn("ADB_SERVER_SOCKET", options["env"])
            self.assertEqual(options["env"]["HOME"],
                             app.pwd.getpwuid(app.os.geteuid()).pw_dir)
            return real_popen(["/usr/bin/python3", "-I", "-c", program], **options)

        with patch.object(app.socket, "create_connection"), \
                patch.object(app.subprocess, "Popen", side_effect=launch):
            return app.adb(None, "devices", **kwargs)

    def test_adb_bounded_stdout_and_stderr(self):
        for descriptor in (1, 2):
            with self.assertRaises(ValueError):
                self.fake_adb(f"import os; os.write({descriptor}, b'x' * 20000)")

    def test_adb_timeout_kills_child(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.fake_adb("import threading; threading.Event().wait()", timeout=0.1)

    def test_adb_sanitized_environment(self):
        with patch.dict(app.os.environ, {"HOME": "/evil", "ADB_SERVER_SOCKET": "tcp:evil:1"}):
            self.assertEqual(self.fake_adb("print('safe')"), b"safe\n")


if __name__ == "__main__":
    unittest.main()
