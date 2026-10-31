"""Exercise stack jumps in a private confdir; never load real authentication files.

No pam_unix or pam_faillock calls, password input, root privileges, account state
changes or /etc writes. The modules are deliberately synthetic stand-ins.
"""
import ctypes
import ctypes.util
import os
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
        handle = ctypes.c_void_p()
        with tempfile.TemporaryDirectory(prefix="pam-fingerprint-test-") as directory:
            Path(directory, "fixture-stack").write_text(stack)
            Path(directory, "fixture-service").write_text("auth include fixture-stack\n")
            result = self.pam.pam_start_confdir(
                b"fixture-service", str(os.getuid()).encode(), ctypes.byref(conversation),
                os.fsencode(directory), ctypes.byref(handle))
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


if __name__ == "__main__":
    unittest.main()
