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

The black-background panel shows the PAM service, user/host, instruction and
25-second countdown inside the selected area. Small panels automatically shrink
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
  shell UID. ADB output sizes and operation durations are bounded.
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
with `PAM_TYPE=auth` and no remote host. Other requests fail without prompting a
phone. Choose service names deliberately; console, SSH and display-manager login
should not be enabled casually. Check account restrictions and lockout behavior
in the actual service, not just this helper.

Rollback: restore the backed-up PAM file or remove only the added line, then
remove the installed helper/registry if desired. New authentication transactions
read the changed configuration; a service restart is normally unnecessary.

## Tests and publication

```sh
python3 -m unittest discover -s tests -v
git diff --check
```

Tests cover signatures, replay/context/key rejection, multi-phone selection,
registry updates, subprocess bounds and environment sanitation. Five isolated
Linux-PAM fixtures use `pam_start_confdir`, permit/deny stand-ins and true/false
commands: they validate control flow, **not** real password/faillock enforcement.
They do not change `/etc`, prompt for a password or require root.

Before publishing, review tracked and non-ignored untracked files, diffs and any
new commit history. Never include pairing registries, signing keys, captures,
device logs, personal identifiers or local deployment notes. `build/` and common
key/registry patterns are ignored; ignore rules are not a substitute for review.
Do not upload or archive the entire working directory as a release.

License: [MIT](LICENSE), retaining upstream attribution.
