import base64
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("network_helper", ROOT / "Desktop/main.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pam-network-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.identity = self.base / "client.pem"
        self.client_pin = app.create_network_identity(self.identity)
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test phone")])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                     .public_key(self.key.public_key()).serial_number(1)
                     .not_valid_before(now - datetime.timedelta(days=1))
                     .not_valid_after(now + datetime.timedelta(days=1))
                     .sign(self.key, hashes.SHA256()))
        self.server_pem = self.base / "server.pem"
        self.server_pem.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM) +
                                   self.key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.server_pin = self.cert.fingerprint(hashes.SHA256()).hex()
        self.errors = []

    def server(self, handler):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(5)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.server_pem)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=x509.load_pem_x509_certificate(
            self.identity.read_bytes()).public_bytes(serialization.Encoding.PEM).decode())
        done = threading.Event()
        self.server_done = done

        def run():
            try:
                raw, _ = listener.accept()
                raw.settimeout(5)
                with context.wrap_socket(raw, server_side=True) as peer:
                    handler(peer)
            except Exception as error:
                self.errors.append(error)
            finally:
                listener.close()
                done.set()
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(lambda: thread.join(timeout=6))
        return dict(endpoint=f"127.0.0.1:{listener.getsockname()[1]}", tls_sha256=self.server_pin)

    def test_identity_is_private_exclusive_and_public_fingerprint_matches(self):
        self.assertEqual(self.identity.stat().st_mode & 0o777, 0o600)
        self.assertEqual(x509.load_pem_x509_certificate(self.identity.read_bytes()).fingerprint(
            hashes.SHA256()).hex(), self.client_pin)
        with self.assertRaises(FileExistsError):
            app.create_network_identity(self.identity)
        self.identity.chmod(0o644)
        with self.assertRaises(PermissionError):
            app.tls_context(self.identity)

    def test_literal_endpoints_only(self):
        self.assertEqual(app.network_address("192.0.2.20:48751"), ("192.0.2.20", 48751))
        self.assertEqual(app.network_address("[::1]:48751"), ("::1", 48751))
        for value in ("localhost:48751", "https://192.0.2.20:48751", "0.0.0.0:1",
                      "224.0.0.1:1", "192.0.2.20:0", "192.0.2.20:65536", "127.0.0.1:１"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.network_address(value)

    def test_real_mutual_tls_and_original_signed_challenge(self):
        received = []
        def handler(peer):
            line = peer.makefile("rb").readline(4097)
            value = json.loads(line)
            received.append(value)
            nonce = value["nonce"]
            public = self.key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            response = dict(nonce=nonce, public_key=base64.b64encode(public).decode(),
                            signature=base64.b64encode(self.key.sign(
                                app.message(nonce, value["host"], value["user"], value["service"]),
                                ec.ECDSA(hashes.SHA256()))).decode())
            peer.sendall(json.dumps(dict(v=1, op="result", nonce=nonce, response=response)).encode() + b"\n")
        network = self.server(handler)
        connection = app.NetworkConnection.connect(network, self.identity)
        with app.RequestLifetime() as lifetime:
            response, nonce = connection.response("workstation", "alice", "sudo", lifetime)
        self.assertEqual(received[0]["op"], "authenticate")
        self.assertEqual(app.verify(response, nonce, "workstation", "alice", "sudo",
                                    response["public_key"]),
                         base64.b64decode(response["public_key"]))
        self.assertFalse(self.errors)

    def test_wrong_server_pin_sends_no_application_request(self):
        received = []
        def handler(peer):
            received.append(peer.recv(4096))
        network = self.server(handler)
        network["tls_sha256"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "pinned certificate"):
            app.NetworkConnection.connect(network, self.identity)
        # The TLS connection closes before any authentication context is sent.
        self.assertTrue(self.server_done.wait(2))
        # TLS 1.3 may observe the close before the server finishes its handshake.
        if not received:
            self.assertTrue(self.errors)
            self.assertTrue(all(isinstance(error, (ssl.SSLError, ConnectionError))
                                for error in self.errors), repr(self.errors))
        for value in received:
            self.assertEqual(value, b"")

    def test_unpaired_client_certificate_is_rejected(self):
        reached = []
        network = self.server(lambda peer: reached.append(True))
        other = self.base / "other.pem"
        app.create_network_identity(other)
        with self.assertRaises((ssl.SSLError, OSError, ValueError)):
            connection = app.NetworkConnection.connect(network, other)
            with app.RequestLifetime() as lifetime:
                connection.response("workstation", "alice", "sudo", lifetime)
        self.assertTrue(self.server_done.wait(2))
        self.assertFalse(reached)

    def test_bad_nonce_oversized_or_trailing_result_rejected(self):
        for output in (b"x" * 5000, b'{"v":1,"op":"result","nonce":"wrong"}\n',
                       b'{"v":1,"op":"result","nonce":"wrong"}\nextra'):
            def handler(peer, data=output):
                peer.makefile("rb").readline(4097)
                peer.sendall(data)
            connection = app.NetworkConnection.connect(self.server(handler), self.identity)
            with app.RequestLifetime() as lifetime, self.assertRaises(ValueError):
                connection.response("workstation", "alice", "sudo", lifetime)

    def test_cancelled_lifetime_closes_connection_without_request(self):
        sock = MagicMock()
        connection = app.NetworkConnection(sock)
        lifetime = MagicMock(watch_parent=False)
        lifetime.check.side_effect = app.RequestCancelled("closed")
        with self.assertRaises(app.RequestCancelled):
            connection.response("workstation", "alice", "sudo", lifetime)
        sock.sendall.assert_not_called()
        sock.close.assert_called_once()

    def test_network_selection_does_not_touch_adb(self):
        key = ec.generate_private_key(ec.SECP256R1())
        public = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        config = dict(version=3, host="workstation", user="alice", services=["sudo"],
                      network_identity=str(self.identity),
                      devices=[dict(label="phone", serial="TEST_PHONE_A", public_key=public,
                                    network=dict(endpoint="192.0.2.20:48751", tls_sha256="ab" * 32))])
        app.validate_config(config)
        transport = MagicMock(spec=app.NetworkConnection)
        with patch.object(app.NetworkConnection, "connect", return_value=transport), \
                patch.object(app, "adb", side_effect=AssertionError("ADB used")):
            device, selected = app.choose_device(config)
        self.assertIs(selected, transport)
        self.assertEqual(device["label"], "phone")
        malformed = copy.deepcopy(config)
        malformed["devices"][0]["network"]["tls_sha256"] = ""
        with self.assertRaises(ValueError):
            app.validate_config(malformed)

    def test_missing_pam_pipe_closes_even_before_first_request(self):
        sock = MagicMock()
        connection = app.NetworkConnection(sock)
        with app.RequestLifetime() as lifetime, self.assertRaises(ValueError):
            lifetime.watch_parent = True
            connection.response("workstation", "alice", "kde-fingerprint", lifetime)
        sock.sendall.assert_not_called()
        sock.close.assert_called_once()

    def test_only_live_connection_heartbeats_keep_a_request_waiting(self):
        sock = MagicMock()
        now = [0.0]
        nonce = "ab" * 32
        reply = json.dumps(dict(v=1, op="result", nonce=nonce,
                                response=dict(nonce=nonce, error="cancelled"))).encode() + b"\n"
        def receive(size):
            if now[0] == 0:
                now[0] = 2.1
                raise socket.timeout()
            return reply
        sock.recv.side_effect = receive
        with patch.object(app.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(app.secrets, "token_hex", return_value=nonce), \
                app.RequestLifetime() as lifetime:
            response, result_nonce = app.NetworkConnection(sock).response(
                "workstation", "alice", "sudo", lifetime)
        sent = [json.loads(call.args[0]) for call in sock.sendall.call_args_list]
        self.assertEqual([value["op"] for value in sent], ["authenticate", "keepalive"])
        self.assertTrue(all(value["nonce"] == nonce for value in sent))
        self.assertEqual(result_nonce, nonce)
        self.assertEqual(response["error"], "cancelled")

    def config(self):
        public = base64.b64encode(self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        return dict(version=3, host="workstation", user="alice", services=["sudo"],
                    network_identity=str(self.identity),
                    devices=[dict(label="phone", serial="TEST_PHONE_A", public_key=public,
                                  adb_fallback=True,
                                  network=dict(endpoint="192.0.2.20:48751", tls_sha256=self.server_pin))])

    def test_handshake_timeout_or_reset_never_selects_adb_or_another_phone(self):
        config = self.config()
        config["devices"].append(dict(label="other", serial="OTHER", public_key=config["devices"][0]["public_key"]))
        for error in (socket.timeout(), ConnectionResetError("reset")):
            raw, context = MagicMock(), MagicMock()
            context.wrap_socket.side_effect = error
            with self.subTest(error=type(error).__name__), \
                    patch.object(app, "tls_context", return_value=context), \
                    patch.object(app.socket, "socket", return_value=raw), \
                    patch.object(app, "adb", side_effect=AssertionError("Fallback used")):
                with self.assertRaisesRegex(ValueError, "TLS handshake failed"):
                    app.choose_device(config)
            context.wrap_socket.assert_called_once()
            raw.close.assert_called_once()

    def test_real_stalled_tls_handshake_does_not_fall_back(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(4)
        release = threading.Event()
        def hold():
            try:
                peer, _ = listener.accept()
                with peer:
                    release.wait(4)
            finally:
                listener.close()
        worker = threading.Thread(target=hold, daemon=True)
        worker.start()
        config = self.config()
        config["devices"][0]["network"]["endpoint"] = f"127.0.0.1:{listener.getsockname()[1]}"
        second = copy.deepcopy(config["devices"][0])
        second.update(label="other", serial="OTHER")
        config["devices"].append(second)
        try:
            with patch.object(app.NetworkConnection, "connect", wraps=app.NetworkConnection.connect) as connect, \
                    patch.object(app, "adb", side_effect=AssertionError("ADB used")), \
                    self.assertRaisesRegex(ValueError, "TLS handshake failed"):
                app.choose_device(config)
            self.assertEqual(connect.call_count, 1)
        finally:
            release.set()
            worker.join(timeout=5)

    def test_add_network_cannot_publish_using_adb_fallback(self):
        config = self.config()
        del config["devices"][0]["network"]
        original = copy.deepcopy(config)
        with patch.object(app.sys, "argv", [
                "helper", "add-network", "--config", "test-registry.json", "--phone", "phone",
                "--endpoint", "192.0.2.20:48751", "--tls-fingerprint", self.server_pin,
                "--identity", str(self.identity)]), \
                patch.object(app, "load_config", return_value=config), \
                patch.object(app.NetworkConnection, "connect", side_effect=app.NetworkUnavailable("offline")), \
                patch.object(app, "adb", side_effect=AssertionError("ADB used")), \
                patch.object(app, "save_pairing") as save, patch("builtins.print"):
            with self.assertRaises(app.NetworkUnavailable):
                app.main()
        save.assert_not_called()
        self.assertEqual(config["devices"][0]["public_key"], original["devices"][0]["public_key"])

    def test_add_network_directly_verifies_original_biometric_pin(self):
        config = self.config()
        del config["devices"][0]["network"]
        original = copy.deepcopy(config)
        nonce = "ab" * 32
        response = dict(nonce=nonce, public_key=config["devices"][0]["public_key"],
                        signature=base64.b64encode(self.key.sign(
                            app.message(nonce, "workstation", "alice", "sudo"),
                            ec.ECDSA(hashes.SHA256()))).decode())
        connection = MagicMock(spec=app.NetworkConnection)
        with patch.object(app.sys, "argv", [
                "helper", "add-network", "--config", "test-registry.json", "--phone", "phone",
                "--endpoint", "192.0.2.20:48751", "--tls-fingerprint", self.server_pin,
                "--identity", str(self.identity)]), \
                patch.object(app, "load_config", return_value=config), \
                patch.object(app.NetworkConnection, "connect", return_value=connection) as connect, \
                patch.object(app, "request_response", return_value=(response, nonce)) as request, \
                patch.object(app, "adb", side_effect=AssertionError("ADB used")), \
                patch.object(app, "save_pairing") as save, patch("builtins.print"):
            self.assertEqual(app.main(), 0)
        connect.assert_called_once()
        self.assertIs(request.call_args.args[1], connection)
        self.assertEqual(config["devices"][0]["public_key"], original["devices"][0]["public_key"])
        save.assert_called_once_with("test-registry.json", config, add=True, expected=original)

    def test_identity_symlink_ancestors_and_sealed_snapshot(self):
        link = self.base / "link.pem"
        link.symlink_to(self.identity)
        with self.assertRaises(OSError):
            app.read_network_identity(link)
        fifo = self.base / "identity-fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(PermissionError):
            app.read_network_identity(fifo)
        with patch.object(app.os, "geteuid", return_value=0):
            with self.assertRaises(PermissionError):
                app.read_network_identity(self.identity)
        data = self.identity.read_bytes()
        context = MagicMock()
        def inspect(path):
            with open(path, "rb") as source:
                self.assertEqual(source.read(), data)
            descriptor = os.open(path, os.O_RDWR)
            try:
                with self.assertRaises(OSError):
                    os.write(descriptor, b"changed")
            finally:
                os.close(descriptor)
        context.load_cert_chain.side_effect = inspect
        with patch.object(app.ssl, "SSLContext", return_value=context):
            self.assertIs(app.tls_context(self.identity), context)
        context.load_cert_chain.assert_called_once()

    def test_expired_and_future_pinned_server_certificates_rejected(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        for before, after in ((now - datetime.timedelta(days=2), now - datetime.timedelta(days=1)),
                              (now + datetime.timedelta(days=1), now + datetime.timedelta(days=2))):
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test phone")])
            self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                         .public_key(self.key.public_key()).serial_number(2)
                         .not_valid_before(before).not_valid_after(after).sign(self.key, hashes.SHA256()))
            self.server_pin = self.cert.fingerprint(hashes.SHA256()).hex()
            self.server_pem.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM) +
                                       self.key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            network = self.server(lambda peer: peer.recv(4096))
            with self.assertRaisesRegex(ValueError, "not currently valid"):
                app.NetworkConnection.connect(network, self.identity)
            self.assertTrue(self.server_done.wait(2))

    def test_ordinary_network_deadline_is_not_extended_by_socket_timeouts(self):
        sock = MagicMock()
        now = [0.0]
        def receive(size):
            now[0] = 31
            raise socket.timeout()
        sock.recv.side_effect = receive
        with patch.object(app.time, "monotonic", side_effect=lambda: now[0]), \
                app.RequestLifetime() as lifetime, self.assertRaises(app.RequestCancelled):
            app.NetworkConnection(sock).response("workstation", "alice", "sudo", lifetime)
        self.assertEqual(sock.sendall.call_count, 1)
        sock.close.assert_called_once()

    def test_trickled_response_has_absolute_frame_deadline(self):
        sock = MagicMock()
        now = [0.0]
        def receive(size):
            now[0] += 4.1
            return b"{"
        sock.recv.side_effect = receive
        with patch.object(app.time, "monotonic", side_effect=lambda: now[0]), \
                app.RequestLifetime() as lifetime, self.assertRaisesRegex(ValueError, "Trickled"):
            app.NetworkConnection(sock).response("workstation", "alice", "kde-fingerprint", lifetime)
        sock.close.assert_called_once()
