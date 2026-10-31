#!/usr/bin/python3 -I
"""Pinned Android biometric signatures over mutually authenticated TLS or optional ADB."""
import argparse
import base64
import fcntl
import datetime
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import selectors
import signal
import socket
import stat
import struct
import ssl
import subprocess
import sys
import tempfile
import time

from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

PACKAGE = "com.randiny_games.fingerprintauthenticator"
CONFIG = "/etc/pam-android-fingerprint.json"
FIELD = re.compile(r"[A-Za-z0-9_.@-]{1,64}\Z")
DEVICE = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
NONCE = re.compile(r"[0-9a-f]{64}\Z")
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}
MAX_DEVICES = 8
SSH_HINTS = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")
MAX_CALLER_ENV = 65536


class NetworkUnavailable(ConnectionError):
    """Only a pre-TLS TCP connection failure permits trying another route."""


def network_address(value):
    """Literal IPs only: no unbounded DNS or shell endpoint interpretation."""
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise ValueError("Expected a literal IP:port network endpoint")
    if value.startswith("["):
        host, separator, port = value[1:].partition("]:")
    else:
        host, separator, port = value.partition(":")
    address = ipaddress.ip_address(host)
    if not separator or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("Invalid network port")
    if address.is_unspecified or address.is_multicast or "%" in host:
        raise ValueError("Invalid network address")
    return str(address), int(port)


def network_endpoint(value):
    network_address(value)
    return value


def read_network_identity(path):
    path = Path(path)
    if os.geteuid() == 0:
        if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
            raise PermissionError("Root TLS identity requires an absolute protected path")
        for parent in path.parents:
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
                raise PermissionError("Untrusted TLS identity directory")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise PermissionError("TLS identity must be an owner-only 0600 regular file")
        data = source.read(16385)
    if len(data) > 16384:
        raise ValueError("Oversized TLS identity")
    return data


def tls_context(identity):
    # Load an immutable snapshot, never re-open a user-replaceable PEM path.
    return tls_context_bytes(read_network_identity(identity))


def tls_context_bytes(data):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    # Authentication is the exact out-of-band certificate pin below, not a CA.
    context.verify_mode = ssl.CERT_NONE
    descriptor = os.memfd_create("pam-network-identity", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(descriptor, data)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        context.load_cert_chain(f"/proc/self/fd/{descriptor}")
    finally:
        os.close(descriptor)
    return context


def create_network_identity(path):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAM desktop TLS client")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                   .sign(key, hashes.SHA256()))
    data = certificate.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600), "wb") as out:
        os.fchmod(out.fileno(), 0o600)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    return certificate.fingerprint(hashes.SHA256()).hex()


class NetworkConnection:
    def __init__(self, sock):
        self.sock = sock

    @classmethod
    def connect(cls, network, identity, lifetime=None, context=None):
        host, port = network_address(network["endpoint"])
        if lifetime is not None:
            lifetime.check()
        if context is None:
            context = tls_context(identity)
        raw = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(2)
        try:
            raw.connect((host, port))
        except OSError as error:
            raw.close()
            if isinstance(error, TimeoutError) or error.errno in (
                    errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EHOSTUNREACH,
                    errno.ENETUNREACH, errno.ENETDOWN, errno.EHOSTDOWN):
                raise NetworkUnavailable("Phone TCP endpoint is unreachable") from error
            raise ValueError("Phone TCP connection failed locally; refusing fallback") from error
        except BaseException:
            raw.close()
            raise
        try:
            sock = context.wrap_socket(raw, server_hostname=None)
        except OSError as error:
            raw.close()
            raise ValueError("Phone TLS handshake failed; refusing transport fallback") from error
        except BaseException:
            raw.close()
            raise
        try:
            received = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
            if not secrets.compare_digest(received, network["tls_sha256"]):
                raise ValueError("Phone TLS certificate differs from its pinned certificate")
            certificate = x509.load_der_x509_certificate(sock.getpeercert(binary_form=True))
            now = datetime.datetime.now(datetime.timezone.utc)
            if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
                raise ValueError("Phone TLS certificate is not currently valid")
            if lifetime is not None:
                lifetime.check()
            return cls(sock)
        except BaseException:
            sock.close()
            raise

    def close(self):
        self.sock.close()

    def send(self, value):
        data = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if len(data) > 4096:
            raise ValueError("Oversized network request")
        self.sock.settimeout(1)
        self.sock.sendall(data)

    def response(self, host, user, service, lifetime, nonce=None):
        nonce = secrets.token_hex(32) if nonce is None else nonce
        if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
            raise ValueError("Invalid request nonce")
        deadline = None if service == "kde-fingerprint" else time.monotonic() + 30
        buffer = bytearray()
        received = 0
        try:
            if deadline is None and lifetime.watch_parent:
                lifetime.require_pam_pipe()
            lifetime.check()
            self.send(dict(v=1, op="authenticate", nonce=nonce, host=field(host),
                           user=field(user), service=field(service)))
            next_tick = time.monotonic() + 2
            frame_started = None
            while True:
                lifetime.check()
                now = time.monotonic()
                if deadline is not None and now >= deadline:
                    raise RequestCancelled("Phone authentication timed out")
                if frame_started is not None and now - frame_started >= 4:
                    raise ValueError("Trickled network response")
                if now >= next_tick:
                    self.send(dict(v=1, op="keepalive", nonce=nonce))
                    next_tick = time.monotonic() + 2
                self.sock.settimeout(0.2)
                try:
                    chunk = self.sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    raise RequestCancelled("Phone disconnected")
                if frame_started is None:
                    frame_started = time.monotonic()
                received += len(chunk)
                buffer.extend(chunk)
                if received > 16384 or len(buffer) > 4096:
                    raise ValueError("Oversized network response")
                if b"\n" not in buffer:
                    continue
                line, _, trailing = buffer.partition(b"\n")
                value = json.loads(line)
                if (not isinstance(value, dict) or type(value.get("v")) is not int or value["v"] != 1 or
                        value.get("nonce") != nonce or value.get("op") != "result" or trailing):
                    raise ValueError("Invalid network result")
                lifetime.check()
                if deadline is not None and time.monotonic() >= deadline:
                    raise RequestCancelled("Phone authentication timed out")
                if not isinstance(value.get("response"), dict):
                    raise ValueError("Missing signed phone response")
                return value["response"], nonce
        finally:
            # EOF is authoritative cancellation; no reconnect or transport fallback
            # may resurrect this request after the PAM owner has gone.
            self.close()


class RequestCancelled(ValueError):
    pass


def ipc_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate IPC field")
        value[key] = item
    return value


def ipc_send(peer, value):
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    if len(raw) > 4096:
        raise ValueError("Oversized broker frame")
    peer.settimeout(1)
    peer.sendall(raw)


class IpcFrames:
    """Bounded strict JSON frames; incomplete frames have an absolute deadline."""
    def __init__(self, peer):
        self.peer = peer
        self.buffer = bytearray()
        self.started = None

    def poll(self):
        if self.started is not None and time.monotonic() - self.started >= 4:
            raise ValueError("Trickled broker frame")
        if b"\n" not in self.buffer:
            self.peer.settimeout(0.2)
            try:
                chunk = self.peer.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                raise RequestCancelled("Broker peer disconnected")
            if self.started is None:
                self.started = time.monotonic()
            self.buffer.extend(chunk)
        if b"\n" not in self.buffer:
            if len(self.buffer) > 4096:
                raise ValueError("Oversized broker frame")
            return None
        line, _, trailing = self.buffer.partition(b"\n")
        if len(line) > 4095:
            raise ValueError("Oversized broker frame")
        self.buffer = bytearray(trailing)
        self.started = time.monotonic() if trailing else None
        value = json.loads(line.decode("utf-8"), object_pairs_hook=ipc_object)
        if not isinstance(value, dict) or type(value.get("v")) is not int or value["v"] != 1:
            raise ValueError("Invalid broker protocol")
        return value

    def read(self, deadline, lifetime=None):
        while time.monotonic() < deadline:
            if lifetime is not None:
                lifetime.check()
            value = self.poll()
            if value is not None:
                if time.monotonic() >= deadline:
                    break
                return value
        raise RequestCancelled("Broker phase timed out")


def broker_path(path, user_uid):
    value = Path(path)
    if not value.is_absolute() or str(value) != os.path.normpath(str(value)) or not str(value).startswith("/run/"):
        raise PermissionError("Broker socket must use a protected absolute /run path")
    for parent in value.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("Untrusted broker socket directory")
    info = value.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid not in (0, user_uid) or stat.S_IMODE(info.st_mode) != 0o600:
        raise PermissionError("Untrusted broker socket")


def peer_uid(peer):
    return struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


class BrokerConnection:
    def __init__(self, peer, frames):
        self.peer, self.frames = peer, frames

    @classmethod
    def connect(cls, config, device, lifetime=None):
        if lifetime is not None:
            lifetime.check()
        broker_path(config["broker_socket"], pwd.getpwnam(config["user"]).pw_uid)
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer.settimeout(2)
            peer.connect(config["broker_socket"])
            # An activated listener reports its creator (systemd/root), not
            # the unprivileged accepting service. Filesystem ownership differs.
            if peer_uid(peer) != 0:
                raise PermissionError("Broker listener was not created by the system manager")
            ipc_send(peer, dict(v=1, op="connect", phone=device["label"]))
            frames = IpcFrames(peer)
            value = frames.read(time.monotonic() + 6, lifetime)
            if set(value) != {"v", "op"}:
                raise ValueError("Invalid broker connection reply")
            if value["op"] == "unavailable":
                raise NetworkUnavailable("Selected phone TCP endpoint is unreachable")
            if value["op"] != "connected":
                raise ValueError("Broker refused the connection; no fallback")
            return cls(peer, frames)
        except BaseException:
            peer.close()
            raise

    def close(self):
        self.peer.close()

    def response(self, host, user, service, lifetime):
        nonce = secrets.token_hex(32)  # Never accept a broker-selected challenge.
        deadline = None if service == "kde-fingerprint" else time.monotonic() + 30
        try:
            if deadline is None and lifetime.watch_parent:
                lifetime.require_pam_pipe()
            lifetime.check()
            ipc_send(self.peer, dict(v=1, op="authenticate", nonce=nonce,
                                    host=field(host), user=field(user), service=field(service)))
            heartbeat = time.monotonic() + 2
            while True:
                lifetime.check()
                now = time.monotonic()
                if deadline is not None and now >= deadline:
                    raise RequestCancelled("Phone authentication timed out")
                if now >= heartbeat:
                    ipc_send(self.peer, dict(v=1, op="keepalive", nonce=nonce))
                    heartbeat = time.monotonic() + 2
                value = self.frames.poll()
                if value is None:
                    continue
                lifetime.check()
                if deadline is not None and time.monotonic() >= deadline:
                    raise RequestCancelled("Phone authentication timed out")
                if (set(value) != {"v", "op", "nonce", "response"} or value["op"] != "result"
                        or value["nonce"] != nonce or not isinstance(value["response"], dict)):
                    raise ValueError("Invalid broker result")
                return value["response"], nonce
        finally:
            self.close()


class RequestLifetime:
    """Cancel on signals/PAM-owner death; the stdout pipe also covers early orphaning."""
    def __init__(self, watch_parent=False):
        self.watch_parent = watch_parent
        self.parent = os.getppid()
        self.cancelled = False
        self.poll = select.poll()
        self.fds = []
        self.pipe_fd = None
        self.handlers = {}

    def __enter__(self):
        try:
            for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                self.handlers[signum] = signal.signal(signum, self._signal)
            if self.watch_parent:
                if stat.S_ISFIFO(os.fstat(1).st_mode):
                    self.pipe_fd = os.dup(1)
                    self.fds.append(self.pipe_fd)
                    self.poll.register(self.pipe_fd, select.POLLERR | select.POLLHUP)
                if hasattr(os, "pidfd_open"):
                    try:
                        descriptor = os.pidfd_open(self.parent)
                    except OSError:
                        descriptor = None
                    if descriptor is not None:
                        self.fds.append(descriptor)
                        self.poll.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
            self.check()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _signal(self, signum, frame):
        self.cancelled = True

    def check(self):
        if (self.cancelled or self.poll.poll(0) or
                self.watch_parent and os.getppid() != self.parent):
            raise RequestCancelled("Authentication request was cancelled")

    def require_pam_pipe(self):
        if self.pipe_fd is None:
            raise ValueError("Persistent PAM authentication requires pam_exec stdout")
        self.check()

    def __exit__(self, *args):
        for signum, previous in self.handlers.items():
            signal.signal(signum, previous)
        self.handlers.clear()
        for descriptor in self.fds:
            self.poll.unregister(descriptor)
            os.close(descriptor)
        self.fds.clear()
        self.pipe_fd = None


def field(value):
    if not isinstance(value, str) or not FIELD.fullmatch(value):
        raise ValueError("Invalid authentication context")
    return value


def normalize_fingerprint(value):
    """Normalize only the human-entered public-key digest, never protocol nonces."""
    if (not isinstance(value, str) or len(value) not in (64, 71) or
            re.fullmatch(r"(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{8}){7})",
                         value) is None):
        raise ValueError("Expected 64 hex digits, compact or eight 8-digit groups joined by '-'")
    return value.replace("-", "").lower()


def message(nonce, host, user, service):
    if not NONCE.fullmatch(nonce):
        raise ValueError("Invalid nonce")
    return ("pam-android-fingerprint:v2\n" + nonce + "\n" +
            "\n".join(map(field, (host, user, service))) + "\n").encode("ascii")


def public_key(encoded):
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("A non-empty pinned public key is mandatory")
    der = base64.b64decode(encoded, validate=True)
    key = serialization.load_der_public_key(der)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Expected a P-256 key")
    return der, key


def verify(response, nonce, host, user, service, pinned):
    pinned_der, _ = public_key(pinned)
    check_response(response, nonce)
    der, key = public_key(response["public_key"])
    if der != pinned_der:
        raise ValueError("Phone key does not match the selected paired phone")
    return verify_signature(response, nonce, host, user, service, der, key)


def verify_pairing(response, nonce, host, user, service, expected_fingerprint):
    # The expected fingerprint must be read from the physical phone screen,
    # independently of ADB. Self-signed responses alone cannot establish identity.
    expected_fingerprint = normalize_fingerprint(expected_fingerprint)
    check_response(response, nonce)
    der, key = public_key(response["public_key"])
    if not secrets.compare_digest(hashlib.sha256(der).hexdigest(), expected_fingerprint):
        raise ValueError("Key fingerprint differs from the physical phone screen")
    return verify_signature(response, nonce, host, user, service, der, key)


def check_response(response, nonce):
    if not isinstance(response, dict):
        raise ValueError("Invalid phone response")
    if response.get("nonce") != nonce or response.get("error"):
        raise ValueError("Phone refused authentication: " + str(response.get("error", "")))


def verify_signature(response, nonce, host, user, service, der, key):
    check_response(response, nonce)
    key.verify(base64.b64decode(response["signature"], validate=True),
               message(nonce, host, user, service), ec.ECDSA(hashes.SHA256()))
    return der


def adb(device, *args, timeout=4, lifetime=None, on_tick=None, deadline_check=None):
    # Never start an ADB server as root or inherit caller-controlled ADB settings.
    if lifetime is not None:
        lifetime.check()
    with socket.create_connection(("127.0.0.1", 5037), timeout=1):
        pass
    command = ["/usr/bin/adb", "-H", "127.0.0.1", "-P", "5037"]
    if device is not None:
        if not DEVICE.fullmatch(device):
            raise ValueError("Invalid ADB transport")
        command.extend(("-s", device))
    command.extend(args)
    # ADB creates HOME/.android even when merely connecting to an existing
    # server. Use the effective account's passwd entry, never caller HOME.
    environment = dict(ENV, HOME=pwd.getpwuid(os.geteuid()).pw_dir)
    # Bound both streams while reading, not after an unbounded communicate().
    with subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        output = bytearray()
        sizes = {process.stdout: 0, process.stderr: 0}
        deadline = None if timeout is None else time.monotonic() + timeout
        next_tick = time.monotonic() + 2 if on_tick is not None else None
        try:
            with selectors.DefaultSelector() as selector:
                for stream in sizes:
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    if lifetime is not None:
                        lifetime.check()
                    if deadline_check is not None:
                        deadline_check()
                    now = time.monotonic()
                    if next_tick is not None and now >= next_tick:
                        on_tick()
                        next_tick = time.monotonic() + 2
                        now = time.monotonic()
                    remaining = None if deadline is None else deadline - now
                    if remaining is not None and remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    wait = 2 if remaining is None else remaining
                    if next_tick is not None:
                        wait = min(wait, max(0, next_tick - now))
                    if lifetime is not None:
                        wait = min(wait, 0.2)
                    for event, _ in selector.select(wait):
                        if deadline_check is not None:
                            deadline_check()
                        chunk = os.read(event.fileobj.fileno(), 4096)
                        if not chunk:
                            selector.unregister(event.fileobj)
                            continue
                        sizes[event.fileobj] += len(chunk)
                        if sizes[event.fileobj] > 16384:
                            raise ValueError("Oversized ADB response")
                        if event.fileobj is process.stdout:
                            output.extend(chunk)
            returncode = process.wait(timeout=2 if deadline is None else
                                      max(0.01, deadline - time.monotonic()))
            if lifetime is not None:
                lifetime.check()
            if deadline_check is not None:
                deadline_check()
            if returncode:
                raise subprocess.CalledProcessError(returncode, command)
            return bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def validate_config(config):
    if not isinstance(config, dict) or type(config.get("version")) is not int or config["version"] != 3:
        raise ValueError("Unsupported pairing format")
    for name in ("user", "host"):
        field(config[name])
    if not isinstance(config["services"], list) or not 1 <= len(config["services"]) <= 16:
        raise ValueError("Missing PAM service allowlist")
    for service in config["services"]:
        field(service)
    if "broker_socket" in config:
        path = config["broker_socket"]
        if (not isinstance(path, str) or len(path) > 107 or "\0" in path or
                not path.startswith("/run/") or os.path.normpath(path) != path):
            raise ValueError("Invalid protected broker socket path")
    if len(set(config["services"])) != len(config["services"]):
        raise ValueError("Duplicate PAM service")
    if not isinstance(config["devices"], list) or not 1 <= len(config["devices"]) <= MAX_DEVICES:
        raise ValueError("Expected one to eight explicitly paired phones")
    labels, serials, keys = set(), set(), set()
    for device in config["devices"]:
        if not isinstance(device, dict):
            raise ValueError("Invalid phone entry")
        label, serial = field(device["label"]), field(device["serial"])
        _, key = public_key(device["public_key"])
        numbers = key.public_numbers()
        identity = (numbers.x, numbers.y)
        if label in labels or serial in serials or identity in keys:
            raise ValueError("Each phone must have a unique label, serial and private-key identity")
        labels.add(label)
        serials.add(serial)
        keys.add(identity)
        endpoints = device.get("endpoints", [])
        if not isinstance(endpoints, list) or len(endpoints) > 8:
            raise ValueError("Invalid endpoint hints")
        for endpoint in endpoints:
            if not isinstance(endpoint, str) or not DEVICE.fullmatch(endpoint):
                raise ValueError("Invalid ADB endpoint")
        if device.get("pairing", "verified-hash") not in ("verified-hash", "trusted-adb"):
            raise ValueError("Unknown pairing trust mode")
        if "network" in device:
            network = device["network"]
            if not isinstance(network, dict):
                raise ValueError("Invalid network configuration")
            network_address(network["endpoint"])
            if not isinstance(network.get("tls_sha256"), str) or not NONCE.fullmatch(network["tls_sha256"]):
                raise ValueError("Missing pinned phone TLS certificate SHA256")
            if type(device.get("adb_fallback", False)) is not bool:
                raise ValueError("Invalid ADB fallback flag")
            if (not isinstance(config.get("network_identity"), str) or
                    not config["network_identity"] or len(config["network_identity"]) > 4096 or
                    "\0" in config["network_identity"]):
                raise ValueError("Missing desktop TLS client identity")
    return config


def load_config(path, trusted=False):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "r") as source:
        if trusted:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_mode & 0o022):
                raise PermissionError("Pairing must be a root-owned, non-writable regular file")
        data = source.read(65537)
        if len(data) > 65536:
            raise ValueError("Oversized pairing configuration")
    return validate_config(json.loads(data))


def control(transport, operation, nonce, lifetime=None):
    raw = adb(transport, "exec-out", "content", "read", "--uri",
              f"content://{PACKAGE}.results/{operation}/{nonce}",
              timeout=2, lifetime=lifetime)
    response = json.loads(raw)
    if (not isinstance(response, dict) or response.get("nonce") != nonce or
            response.get("protocol") != "leased-v1"):
        raise ValueError("Phone does not support request lifecycle control")
    return response


class RequestLease:
    def __init__(self, transport, nonce, lifetime):
        self.transport, self.nonce, self.lifetime = transport, nonce, lifetime
        self.ended_deadline = None

    def check(self):
        if self.ended_deadline is not None and time.monotonic() >= self.ended_deadline:
            raise RequestCancelled("Phone request ended without a result")

    def renew(self, required=False):
        self.check()
        response = control(self.transport, "lease", self.nonce, self.lifetime)
        if type(response.get("alive")) is not bool:
            raise ValueError("Invalid request lease response")
        state = response.get("state")
        if state in ("pending", "complete"):
            if not response["alive"] or self.ended_deadline is not None:
                raise ValueError("Inconsistent request lease state")
        elif state == "consumed":
            if response["alive"]:
                raise ValueError("Inconsistent consumed result")
            if required:
                raise ValueError("Phone request is not active")
            # The provider may have consumed its result before those final bytes
            # reach this ADB client. Allow only a short transport-drain grace.
            if self.ended_deadline is None:
                self.ended_deadline = time.monotonic() + 4
        elif state in ("cancelled", "unknown"):
            raise RequestCancelled("Phone request is no longer active")
        else:
            raise ValueError("Unknown request lease state")
        self.check()


def request_response(device, transport, host, user, service, lifetime=None):
    if lifetime is None:
        with RequestLifetime() as owned:
            return request_response(device, transport, host, user, service, owned)
    if isinstance(transport, (NetworkConnection, BrokerConnection)):
        return transport.response(host, user, service, lifetime)
    field(service)
    persistent = service == "kde-fingerprint"
    if persistent and lifetime.watch_parent:
        lifetime.require_pam_pipe()
    serial = adb(transport, "shell", "getprop", "ro.serialno",
                 timeout=2, lifetime=lifetime).decode().strip()
    if serial != device["serial"]:
        raise ValueError("Connected device is not the selected paired phone")
    nonce = secrets.token_hex(32)
    finished = False
    try:
        extra = ("--es", "control", "leased-v1") if persistent else ()
        # NEW_TASK | MULTIPLE_TASK: never reuse the app's settings task or
        # another request's short-lived confirmation task.
        adb(transport, "shell", "am", "start", "-f", "0x18000000", "-W", "-n",
            PACKAGE + "/.AuthActivity", "--es", "nonce", nonce,
            "--es", "host", field(host), "--es", "user", field(user),
            "--es", "service", service, *extra, timeout=8, lifetime=lifetime)
        lease = RequestLease(transport, nonce, lifetime) if persistent else None
        if lease is not None:
            lease.renew(required=True)
        raw = adb(transport, "exec-out", "content", "read", "--uri",
                  f"content://{PACKAGE}.results/result/{nonce}",
                  timeout=None if persistent else 30, lifetime=lifetime,
                  on_tick=lease.renew if lease is not None else None,
                  deadline_check=lease.check if lease is not None else None)
        response = json.loads(raw)
        if lease is not None:
            lease.check()
        lifetime.check()
        finished = True
        return response, nonce
    finally:
        if not finished:
            # Cleanup must still run after the lifetime itself is cancelled.
            # If ADB is unavailable, the Android lease is the final safety net.
            try:
                control(transport, "cancel", nonce)
            except (OSError, ValueError, TypeError, subprocess.SubprocessError):
                pass


def choose_device(config, label=None, lifetime=None):
    """Use the first available paired identity; never prompt an unknown phone."""
    devices = config["devices"]
    if label is not None:
        devices = [device for device in devices if device["label"] == label]
        if not devices:
            raise ValueError("Unknown phone label")
    connected = None
    serials = {}
    for device in devices:
        if "network" in device:
            try:
                if "broker_socket" in config:
                    return device, BrokerConnection.connect(config, device, lifetime)
                return device, NetworkConnection.connect(
                    device["network"], config["network_identity"], lifetime)
            except NetworkUnavailable:
                if not device.get("adb_fallback", False):
                    continue
        if connected is None:
            try:
                output = adb(None, "devices", timeout=2, lifetime=lifetime).decode()
            except OSError:
                connected = []
            else:
                connected = []
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == "device" and DEVICE.fullmatch(parts[0]):
                        connected.append(parts[0])
                if len(connected) > 8:
                    raise ValueError("Too many connected transports")
        # Hints improve speed; the serial and mandatory pinned key remain the
        # identity. Enumerating also supports a changed wireless IP or USB.
        candidates = sorted(connected, key=lambda endpoint: (
            endpoint not in device.get("endpoints", []),
            endpoint != device["serial"], endpoint))
        for endpoint in candidates:
            if endpoint not in serials:
                try:
                    serials[endpoint] = adb(endpoint, "shell", "getprop",
                                            "ro.serialno", timeout=2, lifetime=lifetime).decode().strip()
                except RequestCancelled:
                    raise
                except (OSError, ValueError, subprocess.SubprocessError):
                    serials[endpoint] = None
            if serials[endpoint] == device["serial"]:
                return device, endpoint
    raise ValueError("No paired phone is connected")


def request(config, service, label=None, lifetime=None):
    device, endpoint = choose_device(config, label, lifetime)
    response, nonce = request_response(device, endpoint, config["host"], config["user"], service, lifetime)
    if lifetime is not None:
        lifetime.check()
    return verify(response, nonce, config["host"], config["user"], service, device["public_key"])


def save_pairing(path, config, add=False, expected=None):
    """Atomic publication; adding another identity always requires --add."""
    validate_config(config)
    path = Path(path)
    # Lock a stable sidecar, not the replaced inode. Concurrent enrollment must
    # not silently discard another phone added while waiting for a fingerprint.
    lock_path = path.with_name(path.name + ".lock")
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    with os.fdopen(os.open(lock_path, flags, 0o600), "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if add:
            if expected is None or load_config(path) != expected:
                raise ValueError("Pairing changed during enrollment; retry with the current file")
        elif path.exists():
            raise FileExistsError("Pairing already exists")
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent,
                                         prefix=".pairing-", delete=False) as output:
            temporary = Path(output.name)
            try:
                json.dump(config, output, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
                if add:
                    os.replace(temporary, path)
                else:
                    os.link(temporary, path)  # Atomic, never overwrite an existing path.
            finally:
                temporary.unlink(missing_ok=True)


def ssh_hint_present():
    """Best-effort UX hint: skip phone waiting, never authorize anything.

    pam_exec builds its child's environment from the PAM environment, which
    normally omits SSH_*. Its immediate parent is the PAM caller (e.g. sudo);
    Linux exposes that process's initial environment through procfs. No
    ancestor walking, process-name matching or sudoers env_keep is needed.
    Missing hints, inaccessible procfs or oversized data mean "unknown", not
    proof of locality. A user can remove/spoof hints or delegate to a daemon.
    """
    if any(os.environ.get(name) for name in SSH_HINTS):
        return True
    try:
        with open(f"/proc/{os.getppid()}/environ", "rb") as source:
            data = source.read(MAX_CALLER_ENV + 1)
    except OSError:
        return False
    if len(data) > MAX_CALLER_ENV:
        return False
    prefixes = tuple((name + "=").encode("ascii") for name in SSH_HINTS)
    return any(entry.startswith(prefix) and len(entry) > len(prefix)
               for entry in data.split(b"\0") for prefix in prefixes)


def authenticate():
    config = load_config(CONFIG, trusted=True)
    if (os.environ.get("PAM_TYPE") != "auth" or
            os.environ.get("PAM_USER") != config["user"] or
            os.environ.get("PAM_SERVICE") not in config["services"] or
            os.environ.get("PAM_RHOST", "")):
        return 1
    if os.environ["PAM_SERVICE"] in ("sudo", "sudo-i") and ssh_hint_present():
        # Nonzero -> pam_exec default=ignore -> the existing password path.
        return 1
    with RequestLifetime(watch_parent=True) as lifetime:
        request(config, os.environ["PAM_SERVICE"], lifetime=lifetime)
        lifetime.check()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("authenticate")
    identity = commands.add_parser("network-identity", help="Create a private desktop mTLS identity")
    identity.add_argument("--output", required=True)
    attach = commands.add_parser("add-network", help="Verify and attach LAN transport to an enrolled phone")
    attach.add_argument("--config", required=True)
    attach.add_argument("--phone", required=True)
    attach.add_argument("--endpoint", required=True, type=network_endpoint)
    attach.add_argument("--tls-fingerprint", required=True, type=normalize_fingerprint)
    attach.add_argument("--identity", required=True)
    pair = commands.add_parser("pair")
    transport = pair.add_mutually_exclusive_group(required=True)
    transport.add_argument("--device", help="Optional ADB transport")
    transport.add_argument("--network", type=network_endpoint, help="Direct literal IP:port")
    pair.add_argument("--serial", help="Required for ADB; network-only defaults to net-LABEL")
    pair.add_argument("--identity", help="Private desktop TLS PEM for direct network pairing")
    pair.add_argument("--tls-fingerprint", type=normalize_fingerprint, help="Phone TLS certificate SHA256")
    pair.add_argument("--label", required=True)
    pair.add_argument("--user", required=True)
    pair.add_argument("--host", required=True)
    pair.add_argument("--services", default="sudo,sudo-i,kde-fingerprint,polkit-1")
    pair.add_argument("--output", required=True)
    pair.add_argument("--add", action="store_true", help="Add another phone to an existing pairing file")
    trust = pair.add_mutually_exclusive_group(required=True)
    trust.add_argument("--expect-fingerprint", type=normalize_fingerprint,
                      help="Phone key SHA256: 64 hex digits or eight 8-digit groups joined by '-'")
    trust.add_argument("--trust-adb", action="store_true",
                       help="Explicit first-use trust in this ADB channel; not independent key verification")
    test = commands.add_parser("test")
    test.add_argument("--config", required=True)
    test.add_argument("--phone", help="Select an enrolled label; otherwise use the first connected phone")
    test.add_argument("--service", help="Test an allowlisted service; defaults to the first service")
    args = parser.parse_args()
    if args.command == "authenticate":
        return authenticate()
    if args.command == "network-identity":
        print("Desktop TLS certificate SHA256:", create_network_identity(args.output))
        print("Enter this PUBLIC certificate fingerprint in the phone's network settings.")
        print("Keep the identity PEM PRIVATE; never copy it to the phone.")
        return 0
    if args.command == "add-network":
        config = load_config(args.config)
        previous = json.loads(json.dumps(config))
        devices = [d for d in config["devices"] if d["label"] == args.phone]
        if len(devices) != 1:
            raise ValueError("Unknown phone label")
        identity = str(Path(args.identity).absolute())
        if "network_identity" in config and config["network_identity"] != identity:
            raise ValueError("All network phones must use the same desktop identity")
        config["network_identity"] = identity
        device = devices[0]
        device["network"] = dict(endpoint=args.endpoint, tls_sha256=args.tls_fingerprint)
        validate_config(config)
        print("Confirm a fresh biometric on the selected phone; open its notification if needed.", flush=True)
        with RequestLifetime() as lifetime:
            connection = NetworkConnection.connect(device["network"], config["network_identity"], lifetime)
            response, nonce = request_response(device, connection, config["host"], config["user"],
                                               config["services"][0], lifetime)
            verify(response, nonce, config["host"], config["user"],
                   config["services"][0], device["public_key"])
        save_pairing(args.config, config, add=True, expected=previous)
        print("Network transport verified; existing biometric key pin preserved.")
        return 0
    if args.command == "pair":
        expected = None
        field(args.label)
        if args.network:
            if args.trust_adb or not args.identity or not args.tls_fingerprint:
                raise ValueError("Network pairing requires TLS identity, phone TLS pin and biometric key SHA256")
            args.serial = args.serial or "net-" + args.label
        elif not args.serial:
            raise ValueError("ADB pairing requires --serial")
        field(args.serial)
        field(args.user)
        field(args.host)
        if args.add:
            config = load_config(args.output)
            expected = json.loads(json.dumps(config))
            if (config["user"], config["host"], config["services"]) != (
                    args.user, args.host, args.services.split(",")):
                raise ValueError("An additional phone must use the existing user, host and services")
            if any(d["label"] == args.label or d["serial"] == args.serial for d in config["devices"]):
                raise ValueError("Phone label or serial already enrolled")
        else:
            if Path(args.output).exists():
                raise FileExistsError("Pairing exists; use --add to enroll a different phone")
            config = dict(version=3, user=args.user, host=args.host,
                          services=args.services.split(","), devices=[])
        device = dict(label=args.label, serial=args.serial, endpoints=[args.device] if args.device else [])
        if args.network:
            identity_path = str(Path(args.identity).absolute())
            if "network_identity" in config and config["network_identity"] != identity_path:
                raise ValueError("All network phones must use the same desktop identity")
            config["network_identity"] = identity_path
            device["network"] = dict(endpoint=args.network, tls_sha256=args.tls_fingerprint)
        if args.trust_adb:
            print("WARNING: first-use pairing trusts the existing ADB channel, not remote attestation.", flush=True)
        print(f"Confirm pairing {args.label} with a fingerprint on the phone.", flush=True)
        selected = NetworkConnection.connect(device["network"], config["network_identity"]) if args.network else args.device
        response, nonce = request_response(device, selected, args.host, args.user, "pair")
        if args.trust_adb:
            check_response(response, nonce)
            der, key = public_key(response["public_key"])
            verify_signature(response, nonce, args.host, args.user, "pair", der, key)
        else:
            der = verify_pairing(response, nonce, args.host, args.user, "pair", args.expect_fingerprint)
        device["public_key"] = base64.b64encode(der).decode()
        device["pairing"] = "trusted-adb" if args.trust_adb else "verified-hash"
        config["devices"].append(device)
        save_pairing(args.output, config, add=args.add, expected=expected)
        print("Paired key SHA256:", hashlib.sha256(der).hexdigest())
    elif args.command == "test":
        config = load_config(args.config)
        service = args.service or config["services"][0]
        if service not in config["services"]:
            raise ValueError("Test service is not allowlisted")
        print("Touch the selected phone's fingerprint sensor.", flush=True)
        started = time.monotonic()
        request(config, service, args.phone)
        print(f"Verified: signature from the selected paired phone ({time.monotonic() - started:.1f} s).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, InvalidSignature,
            subprocess.SubprocessError) as error:
        # Never print signatures or arbitrary ADB output in PAM conversations.
        if len(sys.argv) > 1 and sys.argv[1] != "authenticate":
            print(f"Authentication failed ({type(error).__name__}): {error}", file=sys.stderr)
        sys.exit(1)
