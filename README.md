# PAM Android Fingerprint

Use an Android phone's strong biometric sensor to authorize local Linux PAM
authentication over **mutually authenticated TLS on your LAN**, or an optional
existing authorized ADB connection.

A modernization of [jrandiny/pam-android-fingerprint](https://github.com/jrandiny/pam-android-fingerprint),
under the original MIT license. The original Python 2, `pam_python`, HTTP and
TOTP implementation has been replaced. This fork is experimental: review it
before using it in an authentication stack. **No automatic PAM installer is
provided. Password fallback must remain available.**

## Changes in this fork

* Replaced Python 2, `pam_python`, plaintext HTTP and TOTP with Python 3 and
  signed challenge–response. The opt-in LAN listener requires mutual TLS;
  ADB remains an optional transport, not a runtime requirement for LAN.
* Added pinned P-256 Android Keystore keys with hardware-enforced, per-use
  strong-biometric authorization. Signatures bind a fresh nonce, computer,
  Linux user and PAM service; there is no phone PIN fallback.
* Added explicit pairing and multiple independent phone keys for one Linux
  user. The first connected enrolled phone is selected; requests are not
  broadcast and cancellation does not automatically try another phone.
* Added configurable confirmation areas and forced orientation for damaged
  screens, plus public-key SHA256 Copy/Share with security confirmations,
  eight-character hyphenated groups and high-contrast symbol colors.
  Confirmation windows use a separate task from settings and finish only their
  own activity, without bringing the app's main window to the foreground.
* Added KDE's dedicated fingerprint PAM example for automatic unlock,
  request-lifetime cancellation and renewable phone leases without an overall
  fingerprint deadline. Ordinary sudo/Polkit requests remain time-limited.
* Added a socket-activated, unprivileged systemd TLS broker so KDE's user-mode
  PAM worker does not need access to the root-owned desktop TLS private key.
  PAM helpers still verify fresh phone signatures independently.
* Added optional KDE Wayland monitor wake after unlock, a narrowly scoped
  socket-activated Polkit sandbox example, and best-effort SSH hints that let
  sudo skip phone waiting and continue to the normal password path.
* Added an offline Android SDK build, protocol/UI-data regression tests,
  isolated Linux-PAM fixtures and manual verification/rollback guidance.
  PAM integration remains manual and distribution-specific.

## Requirements

* Android 11 / API 30 or newer, an enrolled strong biometric and a hardware-backed
  Android Keystore supporting biometric authorization for every signature.
  Runtime checks reject unsupported key policies.
* Linux, Python 3 with `cryptography` 42+ and a reachable LAN endpoint.
  For the optional ADB transport only: `/usr/bin/adb` and an already running,
  authorized ADB server at `127.0.0.1:5037`.
* For building: JDK 17, Android SDK platform 36 and build-tools 36.0.0.

The SDK build and pairing/fresh-touch verification have been exercised on
Android 11 and 14. Two physical phones have been enrolled and connected together
for a real PAM request. KDE unlock/cancellation, monitor wake, Polkit fingerprint
authorization and password fallback have been exercised on one Arch/KDE setup.
Other devices, locked/folded states and PAM service configurations require
separate validation; these examples are not universal compatibility guarantees.

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

## Direct LAN setup (no ADB at runtime)

The listener is **off by default**. Installation of the APK can use USB/ADB,
but a configured LAN request does not need an ADB daemon or connection.
Only literal IPv4 or bracketed IPv6 endpoints are accepted; use a DHCP
reservation/stable address. Do not forward this listener through an Internet
router. The listener accepts only private/site-local, IPv6 ULA or loopback
client addresses, in addition to mandatory mTLS. Local-network reachability
and device power management still matter.

Three fingerprints have distinct roles:

* **Desktop TLS certificate SHA256:** the phone pins this before accepting a
  connection or opening an authentication prompt.
* **Phone TLS certificate SHA256:** the PC pins this before sending a request.
  Both TLS pins hash the complete DER leaf certificate, not its PEM text.
* **Biometric key SHA256:** the existing hardware-backed, per-use signing key.
  Channel authentication never replaces its fresh biometric signature.

For an unprivileged development test, create a private desktop identity:

```sh
python3 -I Desktop/main.py network-identity --output build/desktop-tls.pem
```

Keep the PEM private and mode `0600`; **never send it to a phone or commit it**.
Only transfer its printed public certificate fingerprint. For production PAM,
create the identity directly in a root-owned, protected location such as
`/etc/pam-android-fingerprint-client.pem` using the reviewed root-owned helper.
Root-mode requests reject user-owned/readable identity files and untrusted or
symlinked parent paths. TLS loads a sealed memory snapshot, not a reopened
caller-controlled path.

On the phone, open **Direct network settings**, enter the desktop certificate
fingerprint, enable the listener, and allow authentication notifications.
Read/copy the separate **Phone TLS certificate SHA256** and the displayed
network endpoint. The app uses an ongoing `connectedDevice` foreground service.

For an already enrolled phone, add the network transport without replacing its
biometric pin:

```sh
python3 -I Desktop/main.py add-network --config build/pairing.json \
  --phone primary --endpoint 192.0.2.20:48751 \
  --tls-fingerprint PHONE_TLS_CERTIFICATE_SHA256 \
  --identity build/desktop-tls.pem
```

This requires a new biometric signature from the original pinned phone before
updating the registry. All network phones in one registry use one desktop
identity. A network-enabled entry is LAN-only by default: optional ADB fallback
must be explicitly enabled with `"adb_fallback": true`. Certificate-pin or
protocol failures never retry a request through another transport.

For a new phone, pairing can also be entirely over LAN:

```sh
python3 -I Desktop/main.py pair \
  --network 192.0.2.20:48751 --identity build/desktop-tls.pem \
  --tls-fingerprint PHONE_TLS_CERTIFICATE_SHA256 \
  --label primary --user alice --host workstation --services sudo,sudo-i \
  --expect-fingerprint PHONE_BIOMETRIC_KEY_SHA256 \
  --output build/pairing.json
```

Use `--add` and the identical registry user/host/services for a second phone.
No first-use network trust bypass or automatic certificate replacement exists.
Replacing either certificate requires deliberate repinning; replacing a
biometric key still requires explicit re-enrollment. Desktop certificates have
a ten-year validity; the separate phone TLS certificate expires in 2100.
Both sides enforce current certificate validity.
The phone's **Reset phone TLS certificate** action disables the listener and
replaces only the channel identity after confirmation. It does not delete or
regenerate the biometric signing key. Re-enable the listener and explicitly
repin the new TLS certificate on each PC afterward. The separate TLS key allows
raw ECDSA transcript-hash signing as required by Android TLS; the biometric
key's SHA-256-only, strong-biometric-per-use policy is unchanged.

### Systemd broker for KDE and other PAM callers

KDE's screen-lock fingerprint worker runs as the session user, unlike sudo and
Polkit's privileged helpers. It cannot read a root-owned `0600` TLS identity.
**Do not make that private key public or make the Python helper setuid.**
Use the broker examples in `examples/systemd/` and `examples/sysusers.d/`:

1. Install `Desktop/main.py` as the reviewed, root-owned
   `/usr/local/libexec/pam-android-fingerprint` and `Desktop/broker.py` as
   `/usr/local/libexec/pam-android-fingerprint-broker.py`.
2. Create the dedicated system account using the sysusers example. Install the
   broker service/socket units. In a socket drop-in set `SocketUser=alice`
   (your enrolled Linux user); retain `SocketMode=0600`.
3. Keep the desktop PEM **root-owned `0600`**. `LoadCredential=` provides a
   read-only copy only to the dedicated service account; root/user PAM clients
   never receive its contents. The service does not run as root.
4. In a service drop-in use `IPAddressDeny=any` and an `IPAddressAllow=` entry
   for each phone's literal IP (`/32` for IPv4, `/128` for IPv6).
5. Add `"broker_socket": "/run/pam-android-fingerprint-broker.sock"` to the
   root-owned pairing registry, retaining its existing pins, user, host,
   services and `network_identity`. Validate units, reload systemd, then enable
   `pam-android-fingerprint-broker.socket`. Restart the broker service after
   changing the registry, phone endpoint/pins, or desktop credential.

This remains a manual, distribution-specific installation, not an automatic PAM
installer. Stage and test the socket and loaded credential before switching the
active registry. Keep password fallback and a recovery path.

The broker accepts only root and the registered user's kernel-reported
`SO_PEERCRED` identity. Clients require a protected filesystem socket created
by the system manager: an activated listener reports root's credentials, not
the accepting service account's. The service resolves targets/context only from
its protected registry, bounds concurrent requests, and relays signed responses.
Each PAM helper generates its own nonce and verifies the original pinned
biometric signature. A broker “success” flag is never authentication.

Closing/cancelling the PAM request closes the Unix connection and cancels the
phone request. A frozen/dead client also loses its renewable six-second broker
lease. Only the dedicated KDE branch waits indefinitely while its owner remains
alive. No `loginctl unlock-session`, D-Bus unlock shortcut, authentication cache,
or alternate lock-screen mechanism is used.

With the broker, Polkit needs only filesystem Unix-socket access; it does not
need its network sandbox opened for TLS or ADB. Test this under the actual vendor
unit before removing an existing network drop-in. ADB-only fallback phones still
need the separately documented ADB path.

### Background requests and reboot

* On Android 11–14, the owner can optionally grant **display over other apps**
  access for automatic prompt opening. The app does not draw a hidden overlay.
  Without that grant, tap the authenticated request notification.
* On Android 15+, background requests use notification-tap fallback; no
  unsupported automatic-window or full-screen-intent guarantee is made.
* App notifications and the authentication channel must be enabled.
* Enable unrestricted battery/background use in Android app settings if needed.
  OEM power management, Doze, force-stop and user-stopped services can prevent
  availability; a foreground service is not an unconditional uptime guarantee.
* An enabled listener is started by normal `BOOT_COMPLETED`, after the first
  phone unlock. First unlock with the phone PIN/password and biometric lockout
  rules remain mandatory. The service cannot bypass them.
* The PC makes a new authenticated phone connection for each request. There is
  no PC-side ADB reconnect step. The optional systemd broker is socket-activated;
  without it, the helper connects directly using its own accessible identity.

Disabling the listener or changing its desktop pin closes existing connections.
Disconnect, cancellation, invalid frames and an expired eight-second heartbeat
lease cancel the exact owned request. A stale notification cannot recreate it.
Ordinary requests retain a bounded wait; only `kde-fingerprint` can wait
indefinitely while its PAM owner and authenticated connection remain alive.

Keep the registry, private client PEM and all their parent directories protected
when installing for PAM. Back up the working configuration and test fresh-touch,
bad pins, disconnect/cancel, phone/PC reboot and real password fallback before
switching the active stack.

## Pair a phone over optional ADB

Read its **Key SHA256** directly from the physical phone screen, independently
of ADB. The 64 hex characters are displayed in eight-character groups joined
by `-` for manual comparison. **Copy SHA256** and **Share SHA256** are available
before pairing, after the hardware key readiness check succeeds. They transfer
only that public-key digest in the displayed hyphenated format, never a private
key or biometric data.
Each button asks for confirmation; sharing opens Android's app chooser, where
you can select KDE Connect or another installed app.

The phone also colors digits blue, `a/e` amber and `b/c/d/f` purple, with lighter
shades for higher symbols within each group. Colors are an additional visual cue,
not verification data: the complete text stays visible and Copy/Share contain
plain text only. The fingerprint panel uses a fixed light background and colors
tested for at least 4.5:1 text contrast.

The digest is public, but its integrity matters during pairing. Sending it
through another app trusts that transfer channel; it is not hardware attestation.
Sending it through the same potentially compromised ADB channel is not
independent verification. Substitute your own values:

```sh
python3 -I Desktop/main.py pair \
  --device PHONE_TRANSPORT --serial PHONE_SERIAL --label primary \
  --user alice --host workstation --services sudo,sudo-i \
  --expect-fingerprint PHONE_SCREEN_SHA256 \
  --output build/pairing.json
```

`--expect-fingerprint` accepts either 64 consecutive hex characters or exactly
eight groups of eight hex characters joined by `-`, matching the phone's
display and Copy/Share payload. Upper-case hex is also accepted. Hyphenated
input needs no shell quoting. Spaces, colons, line breaks, other separators and
misplaced hyphens are rejected. The helper removes the seven hyphens before
comparing the complete 64-character digest. Protocol nonces and the cryptographic
key comparison remain strict and unchanged.

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

* P-256 biometric private keys remain in Android Keystore. The app checks hardware backing,
  hardware-enforced authorization, biometric-only policy and enrollment
  invalidation. Every signature uses a new `Signature` CryptoObject requiring
  **fresh strong-biometric authorization**. No PIN/device-credential fallback.
* On fingerprint-only strong-biometric devices, any enrolled fingerprint can
  authorize. Android does not identify which finger was used. Other supported
  devices may offer a different strong biometric.
* Signatures bind a random 256-bit nonce, host, Linux username and PAM service.
  Replays, changed context and responses from a different pinned key fail.
* The optional LAN listener uses TLS 1.2+ with an explicitly pinned client
  certificate before dispatching any request. The desktop pins the phone's
  separate TLS certificate before sending a nonce/context. No plaintext HTTP,
  exported phone private keys or biometric data transfer. The desktop TLS
  private PEM is a distinct, owner-only secret, not a biometric credential.
* Results are temporary and in memory. The optional ADB provider permits only
  Android's shell UID; LAN results belong to the authenticated connection.
  Bounded frames, absolute deadlines and bounded workers limit malformed input
  and resource use, but cannot eliminate network denial of service.
  ADB output and individual control-command durations are also bounded.
  Only the leased KDE fingerprint result wait has no overall deadline while its
  authentication owner and phone connection remain alive.
* For optional ADB, the helper uses a sanitized subprocess environment and the literal
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
| `/etc/pam-android-fingerprint-client.pem` (LAN only) | private desktop TLS identity | root:root 0600 |

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

For direct LAN, allow only the enrolled phones' exact literal IPs in the same
service's `IPAddressAllow` list, retaining `IPAddressDeny=any` and the other
restrictions. For example, a documentation-only phone at `192.0.2.20` would need
`IPAddressAllow=192.0.2.20/32`. IPv6 also needs `AF_INET6` and exact IPv6 host
allows. Recheck effective inherited policy and actual cgroup-BPF enforcement.
The client PEM can be read from its protected `/etc` path; no home-directory
exposure or writable state directory is required for direct TLS. The ADB-specific
state/bind settings are needed only if ADB fallback is deliberately retained.

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
  killed or its transport disappears, an abandoned phone prompt expires without granting
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
