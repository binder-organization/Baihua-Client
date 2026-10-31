#!/bin/zsh
# Build an iPhone .ipa from this crate WITHOUT cargo-mobile (whose
# `cargo apple` path needs Homebrew taps that are currently unreachable here).
#
# Prerequisites (all local, no network beyond rustup crates already vendored):
#   rustup target add aarch64-apple-ios
#   Xcode command line tools (`xcrun`, `swiftc`, `codesign`)
#
# Usage (from the repository root):
#   baihua-client-gui/ios/build-ipa.sh
# The bundle receives an ad hoc signature. Without a provisioning profile and
# Apple-issued signature, this IPA cannot be installed normally on a device.
set -euo pipefail

target_triple="aarch64-apple-ios"
sdk_name="iphoneos"
script_directory="$(cd "$(dirname "$0")" && pwd)"
crate_directory="$(dirname "$script_directory")"
repository_root="$(dirname "$crate_directory")"
output_directory="$script_directory/target/ipa"
deployment_target="15.0"

# The deployment target must be pinned for the whole graph: aws-lc-sys builds C
# objects through cc-rs, and without this it defaults to the SDK version (27.0
# here) while the Rust side links at 10.0 — the mismatch makes ld drop
# ___chkstk_darwin (introduced iOS 13) and the final link fails.
export IPHONEOS_DEPLOYMENT_TARGET="$deployment_target"

echo "==> cargo build --release --target $target_triple (iOS $deployment_target)"
(cd "$repository_root" && cargo build --locked --release -p baihua-client-gui --target "$target_triple")

static_library="$repository_root/target/$target_triple/release/libbaihua_client_gui.a"
sdk_path="$(xcrun --sdk $sdk_name --show-sdk-path)"

echo "==> swiftc (UIKit runner) + link the Rust static library"
# Foundation must be listed explicitly: the runner stopped `import UIKit`ing
# (its entry is one bare call now), so swiftc no longer auto-links Foundation,
# while the Rust static library still references Foundation symbols (e.g.
# _NSKeyValueChangeNewKey via raw-window-metal's KVO observer on wgpu/iOS).
# UserNotifications must be listed for the same reason: `src/ios_platform.rs`
# looks up UNUserNotificationCenter through the Objective-C runtime, and the
# class only exists once that framework is loaded (an unlinked framework means
# `objc_getClass` returns null and every notification silently vanishes).
# AudioToolbox is new: `ios_platform` plays the built-in alert sound through
# AudioServicesPlayAlertSound when a sideload host leaves banners impossible.
rm -rf "$output_directory/Baihua.app"
mkdir -p "$output_directory/Baihua.app"
xcrun --sdk $sdk_name swiftc \
    -target arm64-apple-ios"$deployment_target" \
    -module-cache-path "$output_directory/ModuleCache" \
    -import-objc-header "$script_directory/Runner/baihua.h" \
    -framework UIKit -framework Metal -framework QuartzCore -framework CoreGraphics \
    -framework Security -framework CoreFoundation -framework IOKit \
    -framework Foundation -framework UserNotifications \
    -framework AudioToolbox \
    -L "$repository_root/target/$target_triple/release/deps" \
    "$static_library" \
    -o "$output_directory/Baihua.app/Baihua" \
    "$script_directory/Runner/main.swift"

echo "==> vtool: record a pre-iOS-26 linked SDK"
# iOS 26+ hard-crashes ("no scene lifecycle adoption", function
# ___UIApplicationEvaluateRuntimeIssueForNoSceneLifecycleAdoption) apps whose
# LC_BUILD_VERSION says they linked against the iOS 26 (or newer) SDK and that
# do not adopt UIScene. winit 0.30.13 (and even the 0.31-beta `winit-uikit`
# split) has zero scene support -- tracked upstream as winit issue 4224 -- so
# the only lever left is the recorded SDK field: rewriting it to 18.5 puts the
# binary back under the legacy rules (warning, not death). The deployment
# target (minos) stays at $deployment_target. Must run before ad hoc signing.
# vtool spells the platform "ios" (lower-case); `iphoneos` is the SDK name,
# not a platform token, and would be rejected with "unknown platform".
xcrun vtool -arch arm64 \
    -set-build-version ios "$deployment_target" 18.5 \
    -replace \
    -output "$output_directory/Baihua.app/Baihua.rewritten" \
    "$output_directory/Baihua.app/Baihua"
mv "$output_directory/Baihua.app/Baihua.rewritten" "$output_directory/Baihua.app/Baihua"
xcrun vtool -arch arm64 -show-build "$output_directory/Baihua.app/Baihua" | sed -n '1,8p'  # show the pinned version

echo "==> bundle metadata"
cp "$script_directory/Runner/Info.plist" "$output_directory/Baihua.app/Info.plist"
# One flat icon file is enough for a non-asset-catalog bundle; the dedicated
# iOS artwork (ios_icon.png) is what the home screen shows, never the generic logo.
icon_source="$crate_directory/assets/images/ios_icon.png"
sips -z 60 60 "$icon_source" --out "$output_directory/Baihua.app/AppIcon60x60.png" >/dev/null
sips -z 120 120 "$icon_source" --out "$output_directory/Baihua.app/AppIcon120x120.png" >/dev/null
printf 'APPL????' > "$output_directory/Baihua.app/PkgInfo"

echo "==> ad hoc codesign"
codesign --force --sign - --timestamp=none "$output_directory/Baihua.app"

echo "==> package .ipa"
mkdir -p "$output_directory/Payload"
rm -rf "$output_directory/Payload/Baihua.app"
mv "$output_directory/Baihua.app" "$output_directory/Payload/Baihua.app"
rm -f "$output_directory/Baihua.ipa"
(cd "$output_directory" && zip -qry Baihua.ipa Payload)
echo "done: $output_directory/Baihua.ipa"
