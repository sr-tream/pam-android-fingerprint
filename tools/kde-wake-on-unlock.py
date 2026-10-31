#!/usr/bin/python3 -I
"""Optional KDE Wayland session companion: wake outputs after screen unlock."""
import os
import subprocess
import sys

from PySide6.QtCore import QCoreApplication, QObject, Slot, SLOT
from PySide6.QtDBus import QDBusConnection


class UnlockWake(QObject):
    @Slot(bool)
    def activeChanged(self, active):
        if active:
            return
        try:
            subprocess.run(
                ["/usr/bin/kscreen-doctor", "--dpms", "on"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            print("Could not wake KDE displays after unlock.", file=sys.stderr, flush=True)


def main():
    if (os.environ.get("XDG_SESSION_TYPE") != "wayland" or
            "KDE" not in os.environ.get("XDG_CURRENT_DESKTOP", "").split(":")):
        print("This companion requires a KDE Wayland session.", file=sys.stderr)
        return 0
    app = QCoreApplication(sys.argv)
    bus = QDBusConnection.sessionBus()
    receiver = UnlockWake()
    if not bus.isConnected() or not bus.connect(
        "org.freedesktop.ScreenSaver", "/ScreenSaver",
        "org.freedesktop.ScreenSaver", "ActiveChanged", "b",
        receiver, SLOT("activeChanged(bool)"),
    ):
        print("Could not subscribe to KDE screen-lock state.", file=sys.stderr)
        return 1
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
