#!/usr/bin/python3 -I
"""Socket-activated, unprivileged TLS transport. Never decides PAM success."""
import argparse
import os
from pathlib import Path
import pwd
import runpy
import select
import signal
import socket
import stat
import struct
import threading
import time
import types


def credential_access(info, uid, acl=None):
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid == uid and mode == 0o400:
        return True
    # systemd may retain root ownership and grant only the service UID read
    # access with a POSIX ACL. The mode's group bits then describe the ACL
    # mask, NOT access for the owning group. Reject all extra ACL principals.
    if info.st_uid != 0 or info.st_gid != 0 or mode != 0o440 or acl is None:
        return False
    if len(acl) != 44 or struct.unpack_from("<I", acl)[0] != 2:
        return False
    entries = [struct.unpack_from("<HHI", acl, offset) for offset in range(4, len(acl), 8)]
    return len(set(entries)) == 5 and set(entries) == {
        (1, 4, 0xffffffff), (2, 4, uid), (4, 0, 0xffffffff),
        (16, 4, 0xffffffff), (32, 0, 0xffffffff),
    }


def credential(path):
    """Read a systemd-provided read-only credential, not the root source PEM."""
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise PermissionError("Invalid credential path")
    # Traverse held directory descriptors: no parent-symlink/rename TOCTOU.
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC |
                            os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                raise PermissionError("Untrusted credential parent")
        fd = os.open(path.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                     os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            acl = None
            if info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o440:
                acl = os.getxattr(source.fileno(), "system.posix_acl_access")
            if not stat.S_ISREG(info.st_mode) or not credential_access(info, os.geteuid(), acl):
                raise PermissionError("Expected an owner-only systemd credential")
            value = source.read(16385)
            if not value or len(value) > 16384:
                raise ValueError("Invalid credential size")
            return value
    finally:
        os.close(descriptor)


class ClientLease:
    watch_parent = False
    def __init__(self, helper, frames, nonce, stopped):
        self.helper, self.frames, self.nonce, self.stopped = helper, frames, nonce, stopped
        self.renewed = time.monotonic()

    def check(self):
        if self.stopped.is_set() or time.monotonic() - self.renewed >= 6:
            raise self.helper.RequestCancelled("Broker client lease ended")
        # Process a bounded number of complete frames per tick; never let a
        # flooding client starve cancellation, phone reads, or the lease check.
        for _ in range(8):
            if not self.frames.buffer and not select.select([self.frames.peer], [], [], 0)[0]:
                return
            value = self.frames.poll()
            if value is None:
                return
            if (set(value) != {"v", "op", "nonce"} or value["nonce"] != self.nonce
                    or value["op"] not in ("keepalive", "cancel")):
                raise ValueError("Invalid client lease frame")
            if value["op"] == "cancel":
                raise self.helper.RequestCancelled("Client cancelled")
            self.renewed = time.monotonic()


class Broker:
    def __init__(self, helper, config, context):
        self.helper, self.config, self.context = helper, config, context
        self.user_uid = pwd.getpwnam(config["user"]).pw_uid
        self.slots = threading.BoundedSemaphore(4)
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.peers = set()
        self.threads = set()
        self.listener = None

    def serve(self, peer):
        phone = None
        try:
            frames = self.helper.IpcFrames(peer)
            first = frames.read(time.monotonic() + 5)
            if set(first) != {"v", "op", "phone"} or first["op"] != "connect":
                raise ValueError("Expected connection selection")
            devices = [d for d in self.config["devices"]
                       if d["label"] == first["phone"] and "network" in d]
            if len(devices) != 1:
                raise ValueError("Unregistered network phone")
            try:
                phone = self.helper.NetworkConnection.connect(
                    devices[0]["network"], None, context=self.context)
            except self.helper.NetworkUnavailable:
                self.helper.ipc_send(peer, dict(v=1, op="unavailable"))
                return
            with self.lock:
                if self.stopped.is_set():
                    return
                self.peers.add(phone.sock)
            self.helper.ipc_send(peer, dict(v=1, op="connected"))
            request = frames.read(time.monotonic() + 5)
            if (set(request) != {"v", "op", "nonce", "host", "user", "service"}
                    or request["op"] != "authenticate"
                    or request["host"] != self.config["host"]
                    or request["user"] != self.config["user"]
                    or request["service"] not in self.config["services"]
                    or not isinstance(request["nonce"], str)
                    or not self.helper.NONCE.fullmatch(request["nonce"])):
                raise ValueError("Unregistered authentication context")
            lease = ClientLease(self.helper, frames, request["nonce"], self.stopped)
            lease.check()
            response, nonce = phone.response(request["host"], request["user"], request["service"],
                                             lease, nonce=request["nonce"])
            lease.check()  # EOF/cancel wins over a concurrently delivered result.
            self.helper.ipc_send(peer, dict(v=1, op="result", nonce=nonce, response=response))
        except Exception:
            # Generic transport rejection, never phone/user-supplied details.
            try:
                self.helper.ipc_send(peer, dict(v=1, op="rejected"))
            except Exception:
                pass
        finally:
            if phone is not None:
                with self.lock:
                    self.peers.discard(phone.sock)
                phone.close()
            with self.lock:
                self.peers.discard(peer)
                self.threads.discard(threading.current_thread())
            peer.close()
            self.slots.release()

    def run(self, listener):
        self.listener = listener
        listener.settimeout(0.5)
        try:
            while not self.stopped.is_set():
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stopped.is_set():
                        break
                    raise
                if self.helper.peer_uid(peer) not in (0, self.user_uid) or not self.slots.acquire(False):
                    peer.close()
                    continue
                thread = threading.Thread(target=self.serve, args=(peer,), daemon=True)
                with self.lock:
                    self.peers.add(peer)
                    self.threads.add(thread)
                try:
                    thread.start()
                except BaseException:
                    with self.lock:
                        self.peers.discard(peer)
                        self.threads.discard(thread)
                    peer.close()
                    self.slots.release()
                    raise
        finally:
            self.stop()
            with self.lock:
                threads = list(self.threads)
            for thread in threads:
                thread.join(timeout=5)

    def stop(self):
        self.stopped.set()
        if self.listener is not None:
            self.listener.close()
        with self.lock:
            peers = list(self.peers)
        for peer in peers:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            peer.close()


def activated_listener(path):
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("Exactly one systemd-activated socket is required")
    peer = socket.socket(fileno=3)
    if (peer.family != socket.AF_UNIX or peer.type != socket.SOCK_STREAM
            or not peer.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            or peer.getsockname() != path):
        peer.close()
        raise RuntimeError("Wrong activated socket")
    os.set_inheritable(3, False)
    return peer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", default=str(Path(__file__).with_name("main.py")))
    parser.add_argument("--config", default="/etc/pam-android-fingerprint.json")
    parser.add_argument("--identity", required=True, help="systemd %%d/client.pem credential")
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise PermissionError("The broker must run as its dedicated unprivileged service user")
    helper = types.SimpleNamespace(**runpy.run_path(args.helper, run_name="broker_helper"))
    config = helper.load_config(args.config, trusted=True)
    context = helper.tls_context_bytes(credential(args.identity))
    broker = Broker(helper, config, context)
    for signum in (signal.SIGTERM, signal.SIGINT):
        # Never acquire worker locks from a signal handler.
        signal.signal(signum, lambda *_: broker.stopped.set())
    broker.run(activated_listener(config["broker_socket"]))


if __name__ == "__main__":
    main()
