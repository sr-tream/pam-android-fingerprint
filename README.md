# PAM Android Fingerprint

Use an Android phone's strong biometric sensor to authorize local Linux PAM
authentication over an **existing, authorized ADB connection**.

A modernization of [jrandiny/pam-android-fingerprint](https://github.com/jrandiny/pam-android-fingerprint),
under the original MIT license. The original Python 2, `pam_python`, HTTP and
TOTP implementation has been replaced. This fork is experimental: review it
before using it in an authentication stack. **No automatic PAM installer is
provided. Password fallback must remain available.**

## Requirements

* Android 11 / API 30 or newer, an enrolled strong biometric and a hardware-backed
  Android Keystore supporting biometric authorization for every signature.
  Runtime checks reject unsupported key policies.
* Linux, Python 3 with `cryptography`, `/usr/bin/adb` and an already running,
  authorized ADB server at `127.0.0.1:5037`.
* For building: JDK 17, Android SDK platform 36 and build-tools 36.0.0.

The SDK build and basic pairing/fresh-touch verification have been exercised
on Android 14. Other devices, locked/folded states and PAM service configurations
require separate validation. Multi-phone selection has automated coverage;
two physical phones have not yet been tested together.

## Build

```sh
export ANDROID_HOME="$HOME/Android/Sdk"
bash Android/build-sdk.sh
adb -s PHONE_TRANSPORT install -r build/android/pam-fingerprint.apk
```

This dependency-free build uses installed SDK tools without Maven downloads.
It creates a **local development APK signing key** in `build/android/signing.p12`.
Preserve that file for compatible updates, but never commit or share it.
Its development password is not suitable for published release signing.
The phone's biometric key is separate and is never exported.

An Android Gradle project is also provided; the SDK script is the verified
build path. A public release needs separately managed release signing.

Open **PAM Fingerprint** and check biometric/key readiness. If the key policy
check fails, stop rather than relaxing the hardware or authorization checks.

## Pair a phone

Read its 64-character lowercase **Key SHA256** directly from the physical phone
screen, independently of ADB. Substitute your own values:

```sh
python3 -I Desktop/main.py pair \
  --device PHONE_TRANSPORT --serial PHONE_SERIAL --label primary \
  --user alice --host workstation --services sudo,sudo-i \
  --expect-fingerprint PHONE_SCREEN_SHA256 \
  --output build/pairing.json
```

`PHONE_TRANSPORT` is an already connected entry from `adb devices`, such as a USB
serial or wireless address. Pairing verifies the serial, a fresh biometric-backed
signature and the independently supplied public-key fingerprint. An existing
registry is never silently overwritten.

If independent physical verification is impossible, use **`--trust-adb` instead
of `--expect-fingerprint`**. This explicitly trusts the authorized ADB channel on
first use: a substituted server can enroll a substituted initial key. A key
viewed through scrcpy is not independent verification. Neither method provides
remote hardware attestation.

Then verify a **second, new** biometric authorization:

```sh
python3 -I Desktop/main.py test --config build/pairing.json --phone primary
```

### Two interchangeable phones

Install the app on the second phone and enroll its own biometrics. Repeat `pair`
using its own transport, serial, label and fingerprint, adding
`--add --output build/pairing.json`. Keep the same user, host and service list.

Registry version 3 allows up to eight explicitly enrolled phones for **one
Linux user**. Each phone has its own independent hardware key. Do not copy
private keys or share a biometric key between phones. Concurrent registry
changes are rejected rather than silently losing an enrollment.

Authentication selects the first connected enrolled phone in registry order.
Serial and endpoint hints select a candidate; the mandatory pinned public key
authenticates it. Already connected USB and changed wireless endpoints can be
discovered. Unknown phones are never prompted. Cancellation or timeout fails
back to the PC password, not to another phone.

## Damaged-screen accessibility

Open **Confirmation display settings** in the app:

* Enable **Use a custom screen area**.
* Set left, top, width and height as percentages of the screen **after rotation**.
  The origin is the top-left corner; the rectangle must stay within the display
  and have at least 5% width and height.
* Choose **Follow system**, portrait, landscape, reverse portrait or reverse
  landscape. Forced orientation affects confirmation and preview only.
* Use **Save & preview** to show a harmless sample for ten seconds. Preview does
  not access a key or request biometric authentication.

The black-background panel shows the PAM service, user/host and instruction
inside the selected area. Ordinary requests show a 25-second countdown;
leased KDE fingerprint requests show “Until PC unlock”. Small panels automatically shrink
text; long values can be ellipsized. Check readability using preview before use.
No touchscreen action is required for successful fingerprint authorization.

These settings move **the app's panel only**. Android's standard BiometricPrompt
dialog remains system-controlled and may dim or cover it. The app does not
disable secure-window protections, bypass the lock screen or override biometric
lockout/post-reboot strong-auth requirements. Orientation requests may be
restricted by the OS, multi-window mode or device policy.

## Security model

* P-256 private keys remain in Android Keystore. The app checks hardware backing,
  hardware-enforced authorization, biometric-only policy and enrollment
  invalidation. Every signature uses a new `Signature` CryptoObject requiring
  **fresh strong-biometric authorization**. No PIN/device-credential fallback.
* On fingerprint-only strong-biometric devices, any enrolled fingerprint can
  authorize. Android does not identify which finger was used. Other supported
  devices may offer a different strong biometric.
* Signatures bind a random 256-bit nonce, host, Linux username and PAM service.
  Replays, changed context and responses from a different pinned key fail.
* No HTTP/network listener, Internet permission, exported private key or biometric
  data transfer. Results are temporary, in memory, readable only by Android's
  shell UID. ADB output and individual control-command durations are bounded.
  Only the leased KDE fingerprint result wait has no overall deadline while its
  authentication owner and phone connection remain alive.
* The helper uses a sanitized subprocess environment and the literal
  `-H 127.0.0.1 -P 5037`. Do not replace the numeric address with `localhost`:
  ADB treats that differently when considering daemon startup. Verify your ADB
  build does not auto-start a server at the chosen numeric endpoint.
* Authentication always requires the selected enrolled key. First-use trusted-ADB
  enrollment is available only through the explicit `pair` option, never PAM.
* A compromised Android OS/TEE or privileged Linux environment is outside this
  threat model. Installation, initial enrollment and the device platform must
  be trusted; hardware guarantees are not remotely attested.
* Changed biometric enrollment invalidates the key rather than silently
  replacing it. Explicitly reset the app and re-pair if necessary. Uninstalling
  or clearing app data can destroy the key.
* A fingerprint does not supply the password needed for KWallet, fscrypt or
  other password-encrypted storage.

## PAM integration: manual and stack-specific

**Do not enable PAM until pairing, a second fresh-touch test, cancellation,
timeout/offline behavior and real password fallback have been checked.** Keep an
authenticated administrative recovery session open and back up the original
PAM configuration. Do not lock or log out the desktop for the first test.

Install reviewed files into protected locations, using your system's authorized
privilege mechanism:

| File | Source | Ownership/mode |
| --- | --- | --- |
| `/usr/local/libexec/pam-android-fingerprint` | `Desktop/main.py` | root:root 0644 |
| `/etc/pam-android-fingerprint.json` | your pairing registry | root:root 0644 |

The helper is executed explicitly by isolated system Python. Never reference a
user-writable script or checkout from PAM. The registry contains public keys,
but its integrity is critical: the helper uses a fixed path and rejects symlinks,
non-root ownership and group/world-writable files. Preserve root-only write
access to all containing directories.

**Example only:** for a Linux-PAM stack containing this exact consecutive
sequence:

```pam
auth required pam_faillock.so preauth
-auth [success=2 default=ignore] pam_systemd_home.so
auth [success=1 default=bad] pam_unix.so try_first_pass nullok
auth [default=die] pam_faillock.so authfail
auth optional pam_permit.so
auth required pam_env.so
auth required pam_faillock.so authsucc
```

The proposed additional line between `preauth` and `pam_systemd_home` is:

```pam
auth [success=3 default=ignore] pam_exec.so quiet quiet_log seteuid /usr/bin/python3 -I /usr/local/libexec/pam-android-fingerprint authenticate
```

`success=3` skips exactly the next three auth modules, not required checks before
or after them. Failure leaves the original password path in place. Account,
password and session stacks must remain unchanged. **This numeric jump is not
portable**: inspect the installed stack and the `pam.conf(5)`, `pam_exec(8)` and
`pam_faillock(8)` manuals before adapting it.

The helper only permits the configured username and allowlisted PAM services,
with `PAM_TYPE=auth` and an empty `PAM_RHOST`. Other requests fail without
prompting a phone. **An empty `PAM_RHOST` does not prove a physically local
session:** sudo invoked inside SSH may omit this item and can therefore request
phone approval too. This implementation does not enforce trusted session-origin
restrictions. Excluding the `sshd` service does not exclude sudo used within SSH.
Choose service names deliberately; console, SSH and display-manager login should
not be enabled casually.

For convenience, `sudo` and `sudo-i` skip the phone and continue to the ordinary
password path when a nonempty `SSH_CONNECTION`, `SSH_CLIENT` or `SSH_TTY` hint
is present. `pam_exec` normally omits these from its child environment, so the
helper also checks the immediate PAM caller's initial `/proc/PID/environ`,
with a bounded read. No sudoers `env_keep`, SSH configuration changes or
ancestor/process-name heuristics are needed.

This is **only a best-effort latency shortcut, not a security boundary**.
Hints may be removed/spoofed, and a shared daemon or user manager can lose the
original environment. Missing/unreadable/oversized caller data leaves normal
phone authentication available; it does not establish physical locality.
Spoofing a hint never authenticates: it merely asks PAM to use the password.
This shortcut does not change KDE or Polkit authentication.

Check account restrictions and lockout behavior in the actual service, not just
this helper. Faillock lockout and account checks are preserved by the example,
but a locked shadow password is not necessarily a disabled account: the phone
path deliberately skips Unix **password** authentication. Do not use a password
lock alone to revoke alternative authentication; revoke the pairing or apply
appropriate account/access restrictions.

Rollback: restore the backed-up PAM file or remove only the added line, then
remove the installed helper/registry if desired. New authentication transactions
read the changed configuration; a service restart is normally unnecessary.

### Socket-activated Polkit and its sandbox

Some Polkit 128 packages run `polkit-agent-helper@.service` with
`PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` and `ProtectHome=yes`.
That prevents this helper from reaching the existing loopback ADB server.
Polkit may therefore fall back to a password even when the same PAM stack works
for sudo. First check the selected authorization identity: it must match the
paired Linux user, not a different administrator.

An optional systemd drop-in example is provided at
[`examples/systemd/polkit-agent-helper@.service.d/phone-adb.conf`](examples/systemd/polkit-agent-helper@.service.d/phone-adb.conf).
It enables IPv4 loopback connectivity, uses `IPAddressDeny=any` with an allow
entry for `127.0.0.1`, and retains the vendor's other sandbox restrictions.
Real home directories stay hidden: an empty root-owned state directory is
mounted read-only at both its state path and `/root/.android`, satisfying the ADB client's directory
check without exposing any user's ADB private keys. Adapt that destination if
root's passwd home differs. Do not disable `ProtectHome` or copy real ADB keys.

The example requires **systemd 257 or newer** for `StateDirectory=...::ro`;
do not remove that flag to accommodate an older version.

**This is a sandbox policy change for every instance of the Polkit helper
template**, not just phone authentication. Review all vendor settings and other
drop-ins first. IP filtering requires kernel/systemd cgroup-BPF support and can
be ineffective on unsupported systems; verify it on the target system.
The filter restricts addresses, not TCP ports or the identity of the local ADB
server. Other inherited allow entries can broaden access.

Before enabling this drop-in, test the same sandbox in a separate transient
service, including ADB connectivity, home-directory isolation and an ordinary
password fallback. Keep administrative recovery access. Install the reviewed
file under `/etc/systemd/system/polkit-agent-helper@.service.d/`, run
`systemctl daemon-reload`, then test a new, uncached authorization without typing
a password. Do not restart an in-progress authorization or the desktop agent.
Rollback is removal of this drop-in followed by `systemctl daemon-reload`;
subsequent helper instances use the vendor sandbox again.

### KDE: unlock without pressing the Unlock button

KScreenLocker has a separate, noninteractive fingerprint PAM authenticator.
The regular `kde` password path may not start until pressing Unlock; putting the
phone in that path does not provide automatic fingerprint unlock.

An **Arch-style example**, not a portable drop-in, is provided in
[`examples/pam.d/kde-fingerprint`](examples/pam.d/kde-fingerprint). With a reviewed
profile installed as `/etc/pam.d/kde-fingerprint`:

* Allow `kde-fingerprint` in the root-owned phone registry and remove `kde`
  from that allowlist. The normal password branch remains unchanged and no
  longer starts a second phone request.
* Retain the distribution's shell/nologin restrictions and faillock precheck.
  The example clears the tally only after phone success. Cancellation, timeout
  and offline phones fail the fingerprint branch without counting as failed
  PC passwords; normal password attempts retain their existing failure policy.
* KScreenLocker 6.8.1 starts the fingerprint PAM path without an fprintd device
  probe. No fprintd installation, fake scanner, theme patch or disabled screen
  locking is required. Other builds/service names must be checked separately.
* Successful phone authentication can unlock without a PC button click.
  With matching current Android and desktop versions, this service waits until
  fingerprint success or request cancellation; it has no 25-second overall
  deadline. An Android sensor-operation timeout re-arms a fresh signing
  CryptoObject while the PC request is still alive. Sensor lockout, user cancel
  and other errors still end the attempt rather than bypassing Android policy.
* Keep the example's `pam_exec stdout` option. Its inherited pipe binds the
  helper to the actual PAM worker, including the race where the worker dies
  before Python starts. The helper monitors this pipe, parent lifetime and
  termination signals. Password unlock or cancellation closes the phone request
  by its nonce. No passwords or signatures are written to this pipe.
* The Android operation also requires a renewable eight-second connection lease,
  refreshed by the live helper every two seconds. This is **not** a fingerprint
  timeout: a healthy request can wait indefinitely. If the helper is forcibly
  killed or ADB disappears, an abandoned phone prompt expires without granting
  authentication. Ordinary sudo/pairing requests keep their bounded wait.

KScreenLocker uses this profile's **auth** stack; do not assume the included
account/session entries enforce account expiry during screen unlock. This is
not a replacement for reviewing the actual lock-screen policy.

Back up any existing `/etc/pam.d/kde-fingerprint` and the registry first.
Test password unlocking and phone cancellation as well as automatic success.
For a standalone long-wait test, use `test --service kde-fingerprint` with that
service allowlisted; `Ctrl+C` cancels the phone request. This test does not watch
a KDE lock screen—it demonstrates the leased transport on its own.
To roll back, restore the profile/registry backups; if there was no local
profile, removing the override restores the vendor profile.
Upgrade the APK before enabling the new desktop/profile combination. Old desktop
clients retain the bounded behavior with the newer APK; persistent mode requires
an explicit lifecycle-protocol handshake. Roll back the helper and profile
together if necessary.

### Optional: wake KDE Wayland monitors after unlock

When authentication succeeds without keyboard/mouse input, monitors may remain
in DPMS power-saving mode even though the session is unlocked. An optional
**user-session** companion listens for KDE's `org.freedesktop.ScreenSaver`
`ActiveChanged(false)` signal and runs `kscreen-doctor --dpms on`.
It also wakes displays after password unlock. It does not unlock the session,
simulate input, change power-saving settings or run from root/PAM.

Requires `kscreen-doctor` and system Python's PySide6 (Arch: `kscreen` and
`pyside6`). Install as the desktop user, without privilege escalation:

```sh
install -Dm644 tools/kde-wake-on-unlock.py \
  ~/.local/libexec/pam-android-fingerprint-kde-wake.py
install -Dm644 examples/systemd/user/pam-android-fingerprint-kde-wake.service \
  ~/.config/systemd/user/pam-android-fingerprint-kde-wake.service
systemctl --user daemon-reload
systemctl --user enable --now pam-android-fingerprint-kde-wake.service
```

Test fingerprint unlock with monitors already asleep, then test password unlock.
This optional companion is separate from authentication; failure to wake a
monitor cannot grant or deny access. It is intended for one KDE Wayland session
per user; shared user managers with multiple graphical sessions need separate
session-specific integration. Remove it with `systemctl --user disable --now
pam-android-fingerprint-kde-wake.service` and delete the two installed files.

## Tests and publication

```sh
python3 -m unittest discover -s tests -v
git diff --check
```

Tests cover signatures, replay/context/key rejection, multi-phone selection,
registry updates, subprocess bounds, environment sanitation and SSH latency
hints (including an actual isolated `pam_exec` parent-environment check).
Lifecycle tests cover signals, pipe/parent death (including an already orphaned
PAM child), leases, cancellation/result races and bounded operation ownership.
Five isolated
Linux-PAM fixtures use `pam_start_confdir`, permit/deny stand-ins and true/false
commands: they validate control flow, **not** real password/faillock enforcement.
An additional test runs the real `pam_faillock` against a private temporary
tally directory: it checks clearing failures on success and rejecting even
phone success after lockout, without changing the machine's actual counters.
Automated tests do not change `/etc`, prompt for a password or require root.

For manual tests against a reviewed private PAM configuration, a small
`pam_start_confdir` probe is available:

```sh
cc -Wall -Wextra -Werror tools/pam-check.c -o build/pam-check-probe -lpam -lpam_misc
build/pam-check-probe SERVICE USER /absolute/path/to/reviewed/confdir
```

It performs authentication and account checks using the standard non-echoing PAM
conversation. Unlike automated fixtures, a configuration using real `pam_unix`
may ask for a password and may update its configured failure tally. Use an
isolated tally and never put passwords in command arguments or logs.

Before publishing, review tracked and non-ignored untracked files, diffs and any
new commit history. Never include pairing registries, signing keys, captures,
device logs, personal identifiers or local deployment notes. `build/` and common
key/registry patterns are ignored; ignore rules are not a substitute for review.
Do not upload or archive the entire working directory as a release.

License: [MIT](LICENSE), retaining upstream attribution.
