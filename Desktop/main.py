#!/usr/bin/python3 -I
"""Pinned Android Keystore challenge-response authentication, over existing ADB."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import selectors
import socket
import stat
import subprocess
import sys
import tempfile
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PACKAGE = "com.randiny_games.fingerprintauthenticator"
CONFIG = "/etc/pam-android-fingerprint.json"
FIELD = re.compile(r"[A-Za-z0-9_.@-]{1,64}\Z")
DEVICE = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
NONCE = re.compile(r"[0-9a-f]{64}\Z")
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}
MAX_DEVICES = 8


def field(value):
    if not isinstance(value, str) or not FIELD.fullmatch(value):
        raise ValueError("Invalid authentication context")
    return value


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
    if not isinstance(expected_fingerprint, str) or not NONCE.fullmatch(expected_fingerprint):
        raise ValueError("Expected phone key SHA256 must contain 64 lowercase hex digits")
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


def adb(device, *args, timeout=4):
    # Never start an ADB server as root or inherit caller-controlled ADB settings.
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
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                for stream in sizes:
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for event, _ in selector.select(remaining):
                        chunk = os.read(event.fileobj.fileno(), 4096)
                        if not chunk:
                            selector.unregister(event.fileobj)
                            continue
                        sizes[event.fileobj] += len(chunk)
                        if sizes[event.fileobj] > 16384:
                            raise ValueError("Oversized ADB response")
                        if event.fileobj is process.stdout:
                            output.extend(chunk)
            returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
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


def request_response(device, transport, host, user, service):
    field(service)
    serial = adb(transport, "shell", "getprop", "ro.serialno", timeout=2).decode().strip()
    if serial != device["serial"]:
        raise ValueError("Connected device is not the selected paired phone")
    nonce = secrets.token_hex(32)
    adb(transport, "shell", "am", "start", "-W", "-n",
        PACKAGE + "/.AuthActivity", "--es", "nonce", nonce,
        "--es", "host", field(host), "--es", "user", field(user),
        "--es", "service", service, timeout=8)
    raw = adb(transport, "exec-out", "content", "read", "--uri",
              f"content://{PACKAGE}.results/result/{nonce}", timeout=30)
    return json.loads(raw), nonce


def choose_device(config, label=None):
    """Use the first available paired identity; never prompt an unknown phone."""
    devices = config["devices"]
    if label is not None:
        devices = [device for device in devices if device["label"] == label]
        if not devices:
            raise ValueError("Unknown phone label")
    output = adb(None, "devices", timeout=2).decode()
    connected = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "device" and DEVICE.fullmatch(parts[0]):
            connected.append(parts[0])
    if len(connected) > 8:
        raise ValueError("Too many connected transports")
    serials = {}
    for device in devices:
        # Hints improve speed; the serial and mandatory pinned key remain the
        # identity. Enumerating also supports a changed wireless IP or USB.
        candidates = sorted(connected, key=lambda endpoint: (
            endpoint not in device.get("endpoints", []),
            endpoint != device["serial"], endpoint))
        for endpoint in candidates:
            if endpoint not in serials:
                try:
                    serials[endpoint] = adb(endpoint, "shell", "getprop",
                                            "ro.serialno", timeout=2).decode().strip()
                except (OSError, ValueError, subprocess.SubprocessError):
                    serials[endpoint] = None
            if serials[endpoint] == device["serial"]:
                return device, endpoint
    raise ValueError("No paired phone is connected")


def request(config, service, label=None):
    device, endpoint = choose_device(config, label)
    response, nonce = request_response(device, endpoint, config["host"], config["user"], service)
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


def authenticate():
    config = load_config(CONFIG, trusted=True)
    if (os.environ.get("PAM_TYPE") != "auth" or
            os.environ.get("PAM_USER") != config["user"] or
            os.environ.get("PAM_SERVICE") not in config["services"] or
            os.environ.get("PAM_RHOST", "")):
        return 1
    request(config, os.environ["PAM_SERVICE"])
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("authenticate")
    pair = commands.add_parser("pair")
    pair.add_argument("--device", required=True)
    pair.add_argument("--serial", required=True)
    pair.add_argument("--label", required=True)
    pair.add_argument("--user", required=True)
    pair.add_argument("--host", required=True)
    pair.add_argument("--services", default="sudo,sudo-i,kde,polkit-1")
    pair.add_argument("--output", required=True)
    pair.add_argument("--add", action="store_true", help="Add another phone to an existing pairing file")
    trust = pair.add_mutually_exclusive_group(required=True)
    trust.add_argument("--expect-fingerprint",
                      help="SHA256 shown on the physical phone screen (not obtained via ADB)")
    trust.add_argument("--trust-adb", action="store_true",
                       help="Explicit first-use trust in this ADB channel; not independent key verification")
    test = commands.add_parser("test")
    test.add_argument("--config", required=True)
    test.add_argument("--phone", help="Select an enrolled label; otherwise use the first connected phone")
    args = parser.parse_args()
    if args.command == "authenticate":
        return authenticate()
    if args.command == "pair":
        expected = None
        field(args.label)
        field(args.serial)
        field(args.user)
        field(args.host)
        if args.expect_fingerprint is not None and not NONCE.fullmatch(args.expect_fingerprint):
            raise ValueError("Expected phone key SHA256 must contain 64 lowercase hex digits")
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
        device = dict(label=args.label, serial=args.serial, endpoints=[args.device])
        if args.trust_adb:
            print("WARNING: first-use pairing trusts the existing ADB channel, not remote attestation.", flush=True)
        print(f"Confirm pairing {args.label} with a fingerprint on the phone.", flush=True)
        response, nonce = request_response(device, args.device, args.host, args.user, "pair")
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
        print("Touch the selected phone's fingerprint sensor.", flush=True)
        request(config, config["services"][0], args.phone)
        print("Verified: signature from the selected paired phone.")
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
