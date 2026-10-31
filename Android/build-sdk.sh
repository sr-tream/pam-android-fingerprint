#!/usr/bin/env bash
# Offline build using the official installed Android SDK; no Maven dependencies.
set -euo pipefail
cd -- "$(dirname -- "$0")"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
tools="$sdk/build-tools/36.0.0"
android="$sdk/platforms/android-36/android.jar"
out="$PWD/../build/android"
rm -rf -- "$out/classes" "$out/dex"
mkdir -p "$out/classes" "$out/dex"
sources=(app/src/main/java/com/randiny_games/fingerprintauthenticator/*.java)
javac -source 8 -target 8 -bootclasspath "$android:$tools/core-lambda-stubs.jar" \
    -d "$out/classes" "${sources[@]}"
jar cf "$out/classes.jar" -C "$out/classes" .
"$tools/d8" --lib "$android" --min-api 30 --output "$out/dex" "$out/classes.jar"
# AGP supplies the namespace itself; standalone aapt2 needs a package attribute.
python3 - app/src/main/AndroidManifest.xml "$out/AndroidManifest.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET
ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
manifest = ET.parse(sys.argv[1])
manifest.getroot().set("package", "com.randiny_games.fingerprintauthenticator")
manifest.write(sys.argv[2], encoding="utf-8", xml_declaration=True)
PY
"$tools/aapt2" link -I "$android" --manifest "$out/AndroidManifest.xml" \
    --version-code 2 --version-name 2.0 -o "$out/unsigned.apk"
(cd "$out/dex" && zip -q -j "$out/unsigned.apk" classes.dex)
"$tools/zipalign" -f -p 4 "$out/unsigned.apk" "$out/aligned.apk"
if [[ ! -e "$out/signing.p12" ]]; then
    # This APK signing key is not the device's biometric private key.
    keytool -genkeypair -keystore "$out/signing.p12" -storetype PKCS12 \
        -storepass android -keypass android -alias local \
        -keyalg RSA -keysize 3072 -validity 3650 -dname 'CN=Local PAM Fingerprint'
    chmod 600 "$out/signing.p12"
fi
"$tools/apksigner" sign --ks "$out/signing.p12" --ks-pass pass:android \
    --out "$out/pam-fingerprint.apk" "$out/aligned.apk"
"$tools/apksigner" verify --verbose "$out/pam-fingerprint.apk"
printf '\nAPK: %s\n' "$out/pam-fingerprint.apk"
