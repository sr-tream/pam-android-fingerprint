"""Exercise stack jumps in a private confdir; never load real authentication files.

No pam_unix calls, password input, root privileges, system tally changes or /etc
writes. Most modules are synthetic stand-ins; one test uses real pam_faillock
with an explicitly isolated temporary tally directory for every invocation.
"""
import ctypes
import ctypes.util
import os
import pwd
from pathlib import Path
import tempfile
import unittest


class PamStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        library = ctypes.util.find_library("pam")
        if not library:
            raise unittest.SkipTest("Linux-PAM unavailable")
        cls.pam = ctypes.CDLL(library)
        if not hasattr(cls.pam, "pam_start_confdir"):
            raise unittest.SkipTest("pam_start_confdir unavailable")
        cls.callback_type = ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)

        class Conversation(ctypes.Structure):
            _fields_ = [("conv", cls.callback_type), ("appdata_ptr", ctypes.c_void_p)]

        cls.conversation_type = Conversation
        cls.pam.pam_start_confdir.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(Conversation),
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        cls.pam.pam_start_confdir.restype = ctypes.c_int
        cls.pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
        cls.pam.pam_authenticate.restype = ctypes.c_int
        cls.pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
        cls.pam.pam_end.restype = ctypes.c_int

    def authenticate(self, phone, password, precheck=True, postcheck=True):
        def module(success):
            return "pam_permit.so" if success else "pam_deny.so"

        stack = (
            f"auth required {module(precheck)}\n"
            "auth [success=3 default=ignore] pam_exec.so quiet quiet_log seteuid "
            f"/usr/bin/{'true' if phone else 'false'}\n"
            "-auth [success=2 default=ignore] pam_deny.so\n"
            f"auth [success=1 default=bad] {module(password)}\n"
            "auth [default=die] pam_deny.so\n"
            "auth optional pam_permit.so\n"
            f"auth required {module(postcheck)}\n"
        )
        # Any attempted conversation is an error; these fixtures need no input.
        callback = self.callback_type(lambda count, messages, responses, data: 19)
        conversation = self.conversation_type(callback, None)
        with tempfile.TemporaryDirectory(prefix="pam-fingerprint-test-") as directory:
            Path(directory, "fixture-stack").write_text(stack)
            Path(directory, "fixture-service").write_text("auth include fixture-stack\n")
            return self.run_service(directory, "fixture-service", conversation)

    def run_service(self, directory, service, conversation=None):
        callback = self.callback_type(lambda count, messages, responses, data: 19)
        if conversation is None:
            conversation = self.conversation_type(callback, None)
        handle = ctypes.c_void_p()
        result = self.pam.pam_start_confdir(
            service.encode(), pwd.getpwuid(os.getuid()).pw_name.encode(),
            ctypes.byref(conversation), os.fsencode(directory), ctypes.byref(handle))
        self.assertEqual(result, 0, "Could not initialize isolated PAM fixture")
        try:
            return self.pam.pam_authenticate(handle, 0)
        finally:
            self.pam.pam_end(handle, 0)

    def test_phone_success_skips_password_and_authfail(self):
        self.assertEqual(self.authenticate(phone=True, password=False), 0)

    def test_phone_failure_allows_password(self):
        self.assertEqual(self.authenticate(phone=False, password=True), 0)

    def test_phone_and_password_failure_denied(self):
        self.assertNotEqual(self.authenticate(phone=False, password=False), 0)

    def test_phone_cannot_override_precheck_failure(self):
        self.assertNotEqual(self.authenticate(phone=True, password=True, precheck=False), 0)

    def test_phone_cannot_skip_postcheck(self):
        self.assertNotEqual(self.authenticate(phone=True, password=True, postcheck=False), 0)

    def test_real_faillock_private_tally(self):
        """Real faillock, but NEVER the machine's real failure-counter directory."""
        if not Path("/usr/lib/security/pam_faillock.so").exists():
            self.skipTest("Arch Linux-PAM module path unavailable")
        with tempfile.TemporaryDirectory(prefix="pam-private-faillock-") as directory:
            tally = Path(directory, "tally")
            tally.mkdir(mode=0o700)
            options = f"dir={tally} deny=2 unlock_time=0 even_deny_root silent"
            before = f"auth required pam_faillock.so preauth {options}\n"
            failure = f"auth [default=die] pam_faillock.so authfail {options}\n"
            after = f"auth required pam_faillock.so authsucc {options}\n"
            # Record failures through the real module, without pam_unix/passwords.
            Path(directory, "record-failure").write_text(before + failure)
            # Same three-module jump as deployment, with deliberately failing
            # password stand-ins and a deterministic successful phone stand-in.
            Path(directory, "phone-success").write_text(
                before +
                "auth [success=3 default=ignore] pam_exec.so quiet quiet_log /usr/bin/true\n"
                "-auth [success=2 default=ignore] pam_deny.so\n"
                "auth [success=1 default=bad] pam_deny.so\n" + failure +
                "auth optional pam_permit.so\n" + after)
            self.assertNotEqual(self.run_service(directory, "record-failure"), 0)
            record = tally / pwd.getpwuid(os.getuid()).pw_name
            self.assertTrue(record.exists(), "Expected a private failure tally")
            self.assertEqual(self.run_service(directory, "phone-success"), 0)
            self.assertNotEqual(self.run_service(directory, "record-failure"), 0)
            self.assertEqual(self.run_service(directory, "phone-success"), 0,
                             "Successful authentication must clear earlier failures")
            self.assertNotEqual(self.run_service(directory, "record-failure"), 0)
            self.assertNotEqual(self.run_service(directory, "record-failure"), 0)
            self.assertNotEqual(self.run_service(directory, "phone-success"), 0,
                                "Phone success must not bypass a locked tally")

    def test_kde_fingerprint_profile_private_tally(self):
        """Use the shipped profile with phone/check stand-ins and private counters."""
        if not Path("/usr/lib/security/pam_faillock.so").exists():
            self.skipTest("Arch Linux-PAM module path unavailable")
        profile = (Path(__file__).resolve().parents[1] /
                   "examples/pam.d/kde-fingerprint").read_text()
        with tempfile.TemporaryDirectory(prefix="pam-private-fingerprint-") as directory:
            tally = Path(directory, "tally")
            tally.mkdir(mode=0o700)
            options = f"dir={tally} deny=2 unlock_time=0 even_deny_root silent"
            common = []
            for line in profile.splitlines():
                if not line.startswith("auth "):
                    continue
                if "pam_faillock.so" in line:
                    line += " " + options
                for check in ("pam_shells.so", "pam_nologin.so", "pam_env.so"):
                    line = line.replace(check, "pam_permit.so")
                if "pam_exec.so" in line:
                    line = "auth requisite pam_exec.so quiet quiet_log /usr/bin/PHONE"
                common.append(line)
            fixture = "\n".join(common) + "\n"
            self.assertEqual(fixture.count("/usr/bin/PHONE"), 1)
            Path(directory, "phone-success").write_text(fixture.replace("/usr/bin/PHONE", "/usr/bin/true"))
            Path(directory, "phone-cancel").write_text(fixture.replace("/usr/bin/PHONE", "/usr/bin/false"))
            Path(directory, "record-failure").write_text(
                f"auth required pam_faillock.so preauth {options}\n"
                f"auth [default=die] pam_faillock.so authfail {options}\n")
            # Cancellation alone must not lock the PC account.
            for _ in range(2):
                self.assertNotEqual(self.run_service(directory, "phone-cancel"), 0)
            self.assertEqual(self.run_service(directory, "phone-success"), 0)
            for _ in range(2):
                self.assertNotEqual(self.run_service(directory, "record-failure"), 0)
                self.assertEqual(self.run_service(directory, "phone-success"), 0,
                                 "Fingerprint success must clear previous failures")
            # Nor may cancellation clear an existing password-failure tally.
            self.assertNotEqual(self.run_service(directory, "record-failure"), 0)
            self.assertNotEqual(self.run_service(directory, "phone-cancel"), 0)
            self.assertNotEqual(self.run_service(directory, "record-failure"), 0)
            self.assertNotEqual(self.run_service(directory, "phone-success"), 0)


if __name__ == "__main__":
    unittest.main()
