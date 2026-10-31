import base64
import copy
import datetime
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
app = load("broker_helper_test", ROOT / "Desktop/main.py")
service = load("broker_test", ROOT / "Desktop/broker.py")


class BrokerTests(unittest.TestCase):
    def test_broker_cli_help_is_valid(self):
        result = subprocess.run(["/usr/bin/python3", "-I", str(ROOT / "Desktop/broker.py"), "--help"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("%d/client.pem", result.stdout)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pam-broker-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.identity = self.base / "client.pem"
        app.create_network_identity(self.identity)
        self.bio = ec.generate_private_key(ec.SECP256R1())
        self.public = base64.b64encode(self.bio.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        self.config = dict(version=3, user=pwd.getpwuid(os.getuid()).pw_name, host="pc",
                           services=["sudo", "kde-fingerprint"], network_identity=str(self.identity),
                           broker_socket="/run/pam-android-fingerprint-broker.sock",
                           devices=[dict(label="phone", serial="TEST", public_key=self.public,
                                         network=dict(endpoint="127.0.0.1:1", tls_sha256="ab"*32))])
        self.server_errors = []

    def phone(self, action):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test phone")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now-datetime.timedelta(days=1))
                .not_valid_after(now+datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
        pem = self.base / "phone.pem"
        pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(pem)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=x509.load_pem_x509_certificate(
            self.identity.read_bytes()).public_bytes(serialization.Encoding.PEM).decode())
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        done = threading.Event()
        def run():
            try:
                raw, _ = listener.accept()
                raw.settimeout(5)
                with context.wrap_socket(raw, server_side=True) as peer:
                    action(peer)
            except Exception as error:
                self.server_errors.append(error)
            finally:
                listener.close()
                done.set()
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(lambda: thread.join(6))
        self.config["devices"][0]["network"] = dict(
            endpoint=f"127.0.0.1:{listener.getsockname()[1]}", tls_sha256=cert.fingerprint(hashes.SHA256()).hex())
        return done

    def broker(self, adb_home=None):
        instance = service.Broker(app, self.config, app.tls_context(self.identity), adb_home)
        client, peer = socket.socketpair()
        instance.slots.acquire()
        instance.peers.add(peer)
        thread = threading.Thread(target=instance.serve, args=(peer,), daemon=True)
        thread.start()
        self.addCleanup(lambda: thread.join(6))
        self.addCleanup(instance.stop)
        self.addCleanup(client.close)
        frames = app.IpcFrames(client)
        app.ipc_send(client, dict(v=1, op="connect", phone="phone"))
        self.assertEqual(frames.read(time.monotonic()+5), dict(v=1, op="connected"))
        return instance, client, frames, thread

    def test_real_mutual_tls_signature_is_verified_by_helper(self):
        def sign(peer):
            request = json.loads(peer.makefile("rb").readline())
            nonce = request["nonce"]
            response = dict(nonce=nonce, public_key=self.public, signature=base64.b64encode(
                self.bio.sign(app.message(nonce, "pc", self.config["user"], "sudo"),
                              ec.ECDSA(hashes.SHA256()))).decode())
            peer.sendall((json.dumps(dict(v=1, op="result", nonce=nonce, response=response))+"\n").encode())
        done = self.phone(sign)
        instance, client, frames, thread = self.broker()
        connection = app.BrokerConnection(client, frames)
        with patch.object(app, "choose_device", return_value=(self.config["devices"][0], connection)):
            with app.RequestLifetime() as lifetime:
                app.request(self.config, "sudo", lifetime=lifetime)
        self.assertTrue(done.wait(5))
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.server_errors, [])
        self.assertEqual(instance.slots._value, 4)

    def test_disconnect_cancels_phone_without_biometric_result(self):
        requested = threading.Event()
        def wait(peer):
            request = json.loads(peer.makefile("rb").readline())
            self.assertEqual(request["service"], "kde-fingerprint")
            requested.set()
            try:
                self.assertEqual(peer.recv(1), b"")
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                # A close/reset after the already-observed authentication
                # frame is cancellation too, never a successful response.
                pass
        done = self.phone(wait)
        _, client, _, thread = self.broker()
        app.ipc_send(client, dict(v=1, op="authenticate", nonce="cd"*32, host="pc",
                                 user=self.config["user"], service="kde-fingerprint"))
        self.assertTrue(requested.wait(5))
        client.close()
        self.assertTrue(done.wait(3))
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.server_errors, [])

    def test_wrong_context_never_reaches_phone(self):
        def wait(peer):
            try:
                self.assertEqual(peer.recv(1), b"")
            except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                # TLS 1.3 may write post-handshake tickets while the rejected
                # transport is closing. No application byte may be delivered.
                pass
        done = self.phone(wait)
        _, client, frames, thread = self.broker()
        app.ipc_send(client, dict(v=1, op="authenticate", nonce="cd"*32, host="attacker",
                                 user=self.config["user"], service="sudo"))
        self.assertEqual(frames.read(time.monotonic()+3), dict(v=1, op="rejected"))
        self.assertTrue(done.wait(3))
        thread.join(5)
        self.assertEqual(self.server_errors, [])

    def test_no_unsigned_success_or_broker_selected_nonce(self):
        for forged in ("boolean", "nonce"):
            with self.subTest(forged=forged):
                client, peer = socket.socketpair()
                self.addCleanup(client.close)
                self.addCleanup(peer.close)
                def reply():
                    request = app.IpcFrames(peer).read(time.monotonic()+2)
                    value = dict(v=1, op="result", nonce=request["nonce"], response=True)
                    if forged == "nonce":
                        value.update(nonce="00"*32, response={})
                    app.ipc_send(peer, value)
                thread = threading.Thread(target=reply)
                thread.start()
                with app.RequestLifetime() as lifetime, self.assertRaises(ValueError):
                    app.BrokerConnection(client, app.IpcFrames(client)).response("pc", self.config["user"], "sudo", lifetime)
                thread.join(3)
                self.assertFalse(thread.is_alive())

    def test_lease_expiry_cancel_and_shutdown(self):
        for reason in ("expired", "cancel", "shutdown"):
            client, peer = socket.socketpair()
            self.addCleanup(client.close)
            self.addCleanup(peer.close)
            stopped = threading.Event()
            lease = service.ClientLease(app, app.IpcFrames(peer), "ab"*32, stopped)
            if reason == "expired":
                lease.renewed = time.monotonic()-7
            elif reason == "cancel":
                app.ipc_send(client, dict(v=1, op="cancel", nonce="ab"*32))
            else:
                stopped.set()
            with self.assertRaises(app.RequestCancelled):
                lease.check()

    def test_sustained_kde_lease_does_not_become_an_absolute_timeout(self):
        client, peer = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(peer.close)
        with patch.object(service.time, "monotonic", return_value=0):
            lease = service.ClientLease(app, app.IpcFrames(peer), "ab"*32, threading.Event())
        for tick in range(2, 122, 2):
            with patch.object(service.time, "monotonic", return_value=tick):
                app.ipc_send(client, dict(v=1, op="keepalive", nonce="ab"*32))
                lease.check()
                self.assertEqual(lease.renewed, tick)

    def test_authentication_and_capacity_gate_before_workers(self):
        for forbidden in ("uid", "capacity"):
            broker = service.Broker(app, self.config, app.tls_context(self.identity))
            client, peer = socket.socketpair()
            self.addCleanup(client.close)
            listener = MagicMock()
            def accept():
                broker.stopped.set()
                return peer, None
            listener.accept.side_effect = accept
            if forbidden == "capacity":
                for _ in range(4):
                    self.assertTrue(broker.slots.acquire(False))
            with patch.object(app, "peer_uid", return_value=999999 if forbidden == "uid" else os.getuid()):
                broker.run(listener)
            self.assertEqual(peer.fileno(), -1)
            self.assertEqual(broker.threads, set())

    def test_strict_frames_and_phase_deadline(self):
        for raw in (b'{"v":1,"v":1}\n', b'{"v":true}\n', b'\xff\n', b'x'*4097):
            client, peer = socket.socketpair()
            self.addCleanup(client.close)
            self.addCleanup(peer.close)
            client.sendall(raw)
            with self.assertRaises((ValueError, UnicodeError)):
                app.IpcFrames(peer).read(time.monotonic()+1)
        client, peer = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(peer.close)
        frames = app.IpcFrames(peer)
        with self.assertRaises(app.RequestCancelled):
            frames.read(time.monotonic()-1)
        client.sendall(b'{"v":1')
        self.assertIsNone(frames.poll())
        frames.started = time.monotonic()-5
        with self.assertRaisesRegex(ValueError, "Trickled"):
            frames.poll()

    def test_local_policy_errors_never_select_a_fallback(self):
        for code in (errno.EACCES, errno.EPERM, errno.EMFILE, errno.EADDRNOTAVAIL,
                     errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN, errno.EHOSTDOWN):
            with patch.object(app.socket, "socket") as raw, self.assertRaises(ValueError) as error:
                raw.return_value.connect.side_effect = OSError(code, "local policy")
                app.NetworkConnection.connect(self.config["devices"][0]["network"], None, context=MagicMock())
            self.assertNotIsInstance(error.exception, app.NetworkUnavailable)

    def test_routing_errors_do_not_trigger_broker_adb_fallback(self):
        device = self.config["devices"][0]
        device["adb_fallback"] = True
        broker = service.Broker(app, self.config, app.tls_context(self.identity), "/test-home")
        for code in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN, errno.EHOSTDOWN):
            with self.subTest(code=code), patch.object(app.socket, "socket") as raw, \
                    patch.object(app, "select_adb") as select_adb, self.assertRaises(ValueError):
                raw.return_value.connect.side_effect = OSError(code, "routing failure")
                broker.connect_phone(device, MagicMock())
            select_adb.assert_not_called()

    def test_broker_failures_are_not_phone_unavailability(self):
        config = copy.deepcopy(self.config)
        with patch.object(app.BrokerConnection, "connect", side_effect=ValueError("broker unavailable")), \
                patch.object(app, "adb") as adb, self.assertRaises(ValueError):
            app.choose_device(config)
        adb.assert_not_called()

    def test_adb_fallback_returns_signature_for_the_client_owned_nonce(self):
        self.config["devices"][0]["adb_fallback"] = True
        target = app.AdbTarget("TEST-USB", "/test-broker-home")
        observed = {}
        def adb(device, *args, **kwargs):
            self.assertIs(device, target)
            if args[:3] == ("shell", "getprop", "ro.serialno"):
                return b"TEST"
            if args[:3] == ("shell", "am", "start"):
                observed["nonce"] = args[args.index("nonce")+1]
                self.assertIn(".AuthActivity", " ".join(args))
                return b"started"
            if args[:3] == ("exec-out", "content", "read"):
                nonce = observed["nonce"]
                return json.dumps(dict(nonce=nonce, public_key=self.public, signature=base64.b64encode(
                    self.bio.sign(app.message(nonce, "pc", self.config["user"], "sudo"),
                                  ec.ECDSA(hashes.SHA256()))).decode())).encode()
            raise AssertionError(args)
        with patch.object(app.NetworkConnection, "connect", side_effect=app.NetworkUnavailable("offline")), \
                patch.object(app, "select_adb", return_value=target) as select_adb, \
                patch.object(app, "adb", side_effect=adb):
            instance, client, frames, thread = self.broker("/test-broker-home")
            with app.RequestLifetime() as lifetime:
                response, nonce = app.BrokerConnection(client, frames).response(
                    "pc", self.config["user"], "sudo", lifetime)
            app.verify(response, nonce, "pc", self.config["user"], "sudo", self.public)
            self.assertEqual(nonce, observed["nonce"])
            select_adb.assert_called_once()
            self.assertEqual(select_adb.call_args.kwargs["home"], "/test-broker-home")
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(instance.slots._value, 4)

    def test_fallback_policy_never_downgrades_tls_or_local_failures(self):
        device = self.config["devices"][0]
        broker = service.Broker(app, self.config, app.tls_context(self.identity), "/test-home")
        for failure in (ValueError("bad TLS pin"), ValueError("TLS timeout"), PermissionError("local policy")):
            device["adb_fallback"] = True
            with patch.object(app.NetworkConnection, "connect", side_effect=failure), \
                    patch.object(app, "select_adb") as select_adb, self.assertRaises(type(failure)):
                broker.connect_phone(device, MagicMock())
            select_adb.assert_not_called()
        device["adb_fallback"] = False
        with patch.object(app.NetworkConnection, "connect", side_effect=app.NetworkUnavailable("offline")), \
                patch.object(app, "select_adb") as select_adb, self.assertRaises(app.NetworkUnavailable):
            broker.connect_phone(device, MagicMock())
        select_adb.assert_not_called()

    def test_broker_unavailability_does_not_escape_to_client_side_adb(self):
        self.config["devices"][0]["adb_fallback"] = True
        with patch.object(app.BrokerConnection, "connect", side_effect=app.NetworkUnavailable("offline")), \
                patch.object(app, "adb") as adb, self.assertRaises(ValueError):
            app.choose_device(self.config)
        adb.assert_not_called()

    def test_adb_only_device_uses_broker_and_is_preflighted_by_serial(self):
        device = self.config["devices"][0]
        del device["network"]
        target = app.AdbTarget("TEST-USB", "/test-home")
        broker = service.Broker(app, self.config, app.tls_context(self.identity), "/test-home")
        with patch.object(app, "select_adb", return_value=target) as select_adb:
            selected = broker.connect_phone(device, MagicMock())
        self.assertIsInstance(selected, service.AdbConnection)
        self.assertIs(selected.target, target)
        select_adb.assert_called_once()
        with patch.object(app, "adb") as adb:
            adb.side_effect = [b"List of devices attached\nOTHER device\nTEST-USB device\n",
                               b"WRONG", b"TEST"]
            result = app.select_adb(device, home="/test-home")
        self.assertEqual(result.endpoint, "TEST-USB")
        self.assertEqual(result.home, "/test-home")

    def test_adb_preflight_does_not_prompt_and_missing_server_is_unavailable(self):
        device = self.config["devices"][0]
        with patch.object(app, "adb", side_effect=ConnectionRefusedError()), self.assertRaises(app.NetworkUnavailable):
            app.select_adb(device, home="/test-home")
        with patch.object(app, "adb", side_effect=PermissionError()), self.assertRaises(PermissionError):
            app.select_adb(device, home="/test-home")

    def test_adb_home_is_owner_only_and_not_a_symlink(self):
        with tempfile.TemporaryDirectory(prefix=".pam-adb-home-test-", dir=Path.home()) as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            self.assertEqual(service.validate_adb_home(home), str(home))
            home.chmod(0o750)
            with self.assertRaises(PermissionError):
                service.validate_adb_home(home)
            home.chmod(0o700)
            alias = home / "alias"
            alias.symlink_to(home, target_is_directory=True)
            with self.assertRaises(PermissionError):
                service.validate_adb_home(alias)

    def test_listener_creator_uid_is_checked_not_acceptor_uid(self):
        with patch.object(app, "broker_path"), patch.object(app, "peer_uid", return_value=os.getuid() or 1234), \
                patch.object(app.socket, "socket") as peer, self.assertRaises(PermissionError):
            app.BrokerConnection.connect(self.config, self.config["devices"][0])
        peer.return_value.close.assert_called_once()

    def test_systemd_credential_policy_and_no_parent_symlinks(self):
        with tempfile.TemporaryDirectory(prefix=".pam-credential-test-", dir=Path.home()) as temporary:
            base = Path(temporary)
            path = base / "client.pem"
            path.write_bytes(b"test credential")
            path.chmod(0o400)
            self.assertEqual(service.credential(path), b"test credential")
            path.chmod(0o600)
            with self.assertRaises(PermissionError):
                service.credential(path)
            path.chmod(0o400)
            alias = base / "alias"
            alias.symlink_to(base, target_is_directory=True)
            with self.assertRaises(OSError):
                service.credential(alias / "client.pem")
            path.chmod(0o600)
            path.write_bytes(b"x"*16385)
            path.chmod(0o400)
            with self.assertRaises(ValueError):
                service.credential(path)

    def test_systemd_root_owned_acl_grants_only_service_uid(self):
        uid = 938
        info = types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o440)
        entries = [(1, 4, 0xffffffff), (2, 4, uid), (4, 0, 0xffffffff),
                   (16, 4, 0xffffffff), (32, 0, 0xffffffff)]
        def encode(values):
            return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *value) for value in values)
        self.assertTrue(service.credential_access(info, uid, encode(entries)))
        self.assertFalse(service.credential_access(info, uid+1, encode(entries)))
        self.assertFalse(service.credential_access(info, uid, None))
        for index, replacement in ((2, (4, 4, 0xffffffff)), (4, (32, 4, 0xffffffff)),
                                   (1, (2, 6, uid)), (1, (8, 4, uid))):
            changed = list(entries)
            changed[index] = replacement
            self.assertFalse(service.credential_access(info, uid, encode(changed)))
        self.assertFalse(service.credential_access(info, uid, encode(entries+[(2, 4, uid+1)])))
