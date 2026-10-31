#!/usr/bin/env bash
# One entry point that turns a built crate into every shipped package, locally or
# in CI: the graphical end produces the installers (.dmg x2, .msi, .AppImage,
# .apk, .ipa), the command line and terminal ends produce archive bundles, and
# every package lands in dist/ together with its .sha256 digest.
#
# Usage (from anywhere; paths resolve against the repository root):
#   scripts/build_packages.sh                          # this end, this machine
#   scripts/build_packages.sh --end gui --platform mac --arch all
#   scripts/build_packages.sh --end all --platform android
#   scripts/build_packages.sh --platform all           # every platform this
#                                                      # machine can really
#                                                      # produce
# Flags: --end cli|gui|tui|all (default: the caller's usual set: all)
#        --platform mac|windows|linux|android|ios|all (default: host platform)
#        --arch arm|x86|all (mac only, default: both mac architectures)
# Windows and Linux packages build inside Docker containers on hosts that lack
# their toolchains; every platform runs the same packaging scripts as CI.
# A named platform that cannot build fails the run immediately. Under
# --platform all every platform runs as an isolated step: a missing tool skips
# with a printed reason, a failing step is recorded and the following steps
# still build, so one command really drives a full distribution attempt. The
# exit code is 1 when at least one attempted platform failed.
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_root}"

selected_end="all"
selected_platform="host"
selected_arch="all"
skip_build="false"

# Skip/failure notes live in files, not shell variables: isolated platform
# steps run in subshells and must still report their outcome to the summary.
note_directory="$(mktemp -d)"
skipped_note_file="${note_directory}/skipped"
failed_note_file="${note_directory}/failed"
: > "${skipped_note_file}"
: > "${failed_note_file}"
trap 'rm -rf "${note_directory}"' EXIT

read_version() {
  grep -m1 '^version' "$1" | sed 's/.*"\(.*\)".*/\1/'
}

host_platform() {
  case "$(uname -s)" in
    Darwin) echo mac ;;
    Linux) echo linux ;;
    MINGW*|MSYS**) echo windows ;;
    *) echo unsupported ;;
  esac
}

record_skipped() { printf '%s\n' "$1" >> "${skipped_note_file}"; }
record_failure() { printf '%s\n' "$1" >> "${failed_note_file}"; }

# Flags -----------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --end) selected_end="$2"; shift 2 ;;
    --platform) selected_platform="$2"; shift 2 ;;
    --arch) selected_arch="$2"; shift 2 ;;
    --skip-build) skip_build="true"; shift ;;
    --help)
      awk '/^set -euo/{exit} NR>=3{print}' "${BASH_SOURCE[0]}"
      exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ "${selected_platform}" = "host" ]; then
  selected_platform="$(host_platform)"
fi

# Skips are tolerated only under --platform all; a named platform must work.
platform_is_optional() { [ "${selected_platform}" = "all" ]; }

# A running Docker daemon unlocks the cross-platform container packaging paths.
docker_is_available() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

need_tool() {
  local tool="$1" hint="$2"
  if command -v "${tool}" >/dev/null; then
    return 0
  fi
  if platform_is_optional; then
    record_skipped "${platform}: ${tool} missing (${hint})"
    echo "SKIP ${platform}: ${tool} missing (${hint})" >&2
    return 1
  fi
  echo "${platform}: ${tool} is required (${hint})" >&2
  exit 1
}

# Isolation for --platform all: one platform step runs with errexit inside a
# subshell, so its first hard failure stops that platform only; the batch
# records the failure and continues with the next platform.
attempt_platform() {
  local name="$1"
  shift
  if ( set -euo pipefail; "$@" ); then
    return 0
  fi
  record_failure "${name}: build failed (see the output above)"
  echo "FAILED ${name}: continuing with the remaining platforms" >&2
  return 0
}

# Package identity ------------------------------------------------------------
gui_version="$(read_version baihua-client-gui/Cargo.toml)"
cli_version="$(read_version baihua-cli/Cargo.toml)"
tui_version="$(read_version baihua-client-tui/Cargo.toml)"
gui_prefix="baihua-gui-"
cli_prefix="baihua-cli-"
tui_prefix="baihua-tui-"

# Graphical end: installer packages -------------------------------------------
platform=""
build_gui_mac() {
  platform="mac"
  local architectures=()
  case "${selected_arch}" in
    arm) architectures=(aarch64-apple-darwin) ;;
    x86) architectures=(x86_64-apple-darwin) ;;
    all) architectures=(aarch64-apple-darwin x86_64-apple-darwin) ;;
    *) architectures=(aarch64-apple-darwin x86_64-apple-darwin) ;;
  esac
  need_tool hdiutil "part of the command line tools" || return 0
  local target
  for target in "${architectures[@]}"; do
    rustup target list --installed | grep -qx "${target}" \
      || rustup target add "${target}"
    if [ "${skip_build}" != true ]; then cargo build --locked --release -p baihua-client-gui --target "${target}"; fi
    test -f "target/${target}/release/baihua-gui"
    TARGET="${target}" VERSION="${gui_version}" PACKAGE_PREFIX="${gui_prefix}" \
      BINARY=baihua-gui BUNDLE_NAME=Baihua bash scripts/package_macos_bundle.sh
  done
}

build_gui_windows() {
  platform="windows"
  if [ "$(host_platform)" = windows ]; then
    if [ ! -x "${HOME}/.cargo/bin/cargo-wix" ] && ! command -v cargo-wix >/dev/null; then
      echo "windows: cargo-wix is required (cargo install cargo-wix)" >&2
      return 1
    fi
    local target="x86_64-pc-windows-msvc"
    rustup target list --installed | grep -qx "${target}" || rustup target add "${target}"
    if [ "${skip_build}" != true ]; then cargo build --locked --release -p baihua-client-gui --target "${target}"; fi
    test -f "target/${target}/release/baihua-gui.exe"
    TARGET="${target}" VERSION="${gui_version}" PACKAGE_PREFIX="${gui_prefix}" \
      BINARY=baihua-gui.exe BUNDLE_NAME=Baihua bash scripts/package_windows_installer.sh
    return 0
  fi
  if docker_is_available; then
    VERSION="${gui_version}" PACKAGE_PREFIX="${gui_prefix}" \
      bash scripts/package_windows_installer_in_docker.sh
    return 0
  fi
  if platform_is_optional; then
    record_skipped "windows: needs a Windows host with cargo-wix or a running Docker daemon (build it in CI)"
    echo "SKIP windows: no Windows toolchain here and Docker is not running" >&2
    return 0
  fi
  echo "windows: run this on Windows (cargo-wix) or keep the Docker daemon running" >&2
  return 1
}

build_gui_linux() {
  platform="linux"
  if [ "$(host_platform)" = linux ]; then
    local deploy="${LINUXDEPLOY:-}"
    if [ -z "${deploy}" ] && command -v linuxdeploy >/dev/null; then
      deploy="$(command -v linuxdeploy)"
    fi
    if [ -z "${deploy}" ]; then
      if platform_is_optional; then
        record_skipped "linux: LINUXDEPLOY/linuxdeploy missing (set LINUXDEPLOY or install it)"
        echo "SKIP linux: linuxdeploy missing (set LINUXDEPLOY or install it)" >&2
        return 0
      fi
      echo "linux: linuxdeploy is required (set LINUXDEPLOY to its path)" >&2
      return 1
    fi
    local target="x86_64-unknown-linux-gnu"
    rustup target list --installed | grep -qx "${target}" || rustup target add "${target}"
    if [ "${skip_build}" != true ]; then cargo build --locked --release -p baihua-client-gui --target "${target}"; fi
    test -f "target/${target}/release/baihua-gui"
    TARGET="${target}" VERSION="${gui_version}" PACKAGE_PREFIX="${gui_prefix}" \
      BINARY=baihua-gui BUNDLE_NAME=Baihua LINUXDEPLOY="${deploy}" \
      bash scripts/package_linux_appimage.sh
    return 0
  fi
  if docker_is_available; then
    VERSION="${gui_version}" PACKAGE_PREFIX="${gui_prefix}" \
      bash scripts/package_linux_appimage_in_docker.sh
    return 0
  fi
  if platform_is_optional; then
    record_skipped "linux: needs a Linux host with linuxdeploy or a running Docker daemon (build it in CI)"
    echo "SKIP linux: no Linux host here and Docker is not running" >&2
    return 0
  fi
  echo "linux: run this on Linux (linuxdeploy) or keep the Docker daemon running" >&2
  return 1
}

# cargo-apk reads the NDK location through ANDROID_NDK_ROOT, ANDROID_NDK_PATH,
# ANDROID_NDK_HOME, NDK_HOME in that order and panics on a path without content.
find_android_ndk() {
  local candidate sdk_home newest
  sdk_home="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}}"
  for candidate in "${ANDROID_NDK_ROOT:-}" "${ANDROID_NDK_PATH:-}" \
      "${ANDROID_NDK_HOME:-}" "${NDK_HOME:-}" "${sdk_home}/ndk-bundle"; do
    if [ -n "${candidate}" ] && [ -f "${candidate}/source.properties" ]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  if [ -d "${sdk_home}/ndk" ]; then
    newest="$(ls "${sdk_home}/ndk" | sort -V | tail -n 1)"
    if [ -n "${newest}" ] && [ -f "${sdk_home}/ndk/${newest}/source.properties" ]; then
      printf '%s\n' "${sdk_home}/ndk/${newest}"
      return 0
    fi
  fi
  for candidate in /opt/homebrew/share/android-ndk /usr/local/share/android-ndk; do
    if [ -f "${candidate}/source.properties" ]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

build_gui_android() {
  platform="android"
  need_tool cargo-apk "cargo install cargo-apk" || return 0
  if [ -z "${ANDROID_HOME:-}" ] && [ -d "${HOME}/Library/Android/sdk" ]; then
    export ANDROID_HOME="${HOME}/Library/Android/sdk"
  fi
  if [ -z "${ANDROID_HOME:-}" ]; then
    if platform_is_optional; then
      record_skipped "android: ANDROID_HOME unset and ~/Library/Android/sdk missing"
      echo "SKIP android: ANDROID_HOME unset and ~/Library/Android/sdk missing" >&2
      return 0
    fi
    echo "android: ANDROID_HOME is required" >&2
    return 1
  fi
  if ! android_ndk="$(find_android_ndk)"; then
    if platform_is_optional; then
      record_skipped "android: no Android NDK found inside the SDK or the Homebrew paths"
      echo "SKIP android: no Android NDK found inside the SDK or the Homebrew paths" >&2
      return 0
    fi
    echo "android: install an NDK under \$ANDROID_HOME/ndk or export a valid ANDROID_NDK_HOME" >&2
    return 1
  fi
  export ANDROID_NDK_HOME="${android_ndk}" ANDROID_NDK_ROOT="${android_ndk}"
  echo "android: using NDK ${android_ndk}"
  rustup target list --installed | grep -qx aarch64-linux-android \
    || rustup target add aarch64-linux-android
  TARGET="aarch64-linux-android" VERSION="${gui_version}" \
    PACKAGE_PREFIX="${gui_prefix}" bash scripts/package_android_apk.sh
}

build_gui_ios() {
  platform="ios"
  need_tool xcrun "part of the Xcode command line tools" || return 0
  rustup target list --installed | grep -qx aarch64-apple-ios \
    || rustup target add aarch64-apple-ios
  baihua-client-gui/ios/build-ipa.sh
  local package="${gui_prefix}${gui_version}-aarch64-apple-ios.ipa"
  mkdir -p dist
  cp baihua-client-gui/ios/target/ipa/Baihua.ipa "dist/${package}"
  (cd dist && shasum -a 256 "${package}" > "${package}.sha256")
  printf "archive=dist/%s\n" "${package}" >> "${GITHUB_ENV:-/dev/null}"
  echo "built dist/${package}"
}

# Command line and terminal ends: archive bundles ------------------------------
build_archive_bundle() {
  local end="$1" package="$2" prefix="$3" version="$4" binary="$5"
  local archive staging
  if [ "$(host_platform)" = "windows" ]; then
    archive="${prefix}${version}-$(uname -m | sed 's/amd64/x86_64/').zip"
    staging="staging-${binary}"
    mkdir -p "${staging}/config"
    cp "target/release/${binary}.exe" "${staging}/"
    cp -R config/. "${staging}/config/"
    powershell.exe -NoProfile -Command "Compress-Archive -Path '${staging}\*' -DestinationPath '${archive}'"
    rm -rf "${staging}"
    mkdir -p dist
    mv "${archive}" "dist/"
    powershell.exe -NoProfile -Command "(Get-FileHash -Algorithm SHA256 'dist/${archive}').Hash.ToLower() + '  ${archive}' | Set-Content 'dist/${archive}.sha256'"
  else
    archive="${prefix}${version}-$(uname -m | sed 's/arm64/aarch64/;s/x86_64/x86_64/')-$(uname -s | sed 's/Darwin/apple-darwin/;s/Linux/unknown-linux-gnu/').tar.gz"
    staging="staging-${binary}"
    rm -rf "${staging}"
    mkdir -p "${staging}/config"
    cp "target/release/${binary}" "${staging}/"
    cp -R config/. "${staging}/config/"
    tar -czf "${archive}" -C "${staging}" .
    rm -rf "${staging}"
    mkdir -p dist
    mv "${archive}" dist/
    (cd dist && shasum -a 256 "${archive}" > "${archive}.sha256")
  fi
  echo "built dist/${archive} (${end})"
}

build_cli_archives() {
  cargo build --locked --release -p baihua-cli
  build_archive_bundle cli baihua-cli "${cli_prefix}" "${cli_version}" baihua
}

build_tui_archives() {
  cargo build --locked --release -p baihua-client-tui
  build_archive_bundle tui baihua-client-tui "${tui_prefix}" "${tui_version}" baihua-tui
}

# Routing ----------------------------------------------------------------------
run_gui_platform() {
  case "$1" in
    mac) build_gui_mac ;;
    windows) build_gui_windows ;;
    linux) build_gui_linux ;;
    android) build_gui_android ;;
    ios) build_gui_ios ;;
    *) echo "unknown platform: $1" >&2; return 2 ;;
  esac
}

case "${selected_platform}" in
  all)
    if [ "${selected_end}" = "all" ] || [ "${selected_end}" = "gui" ]; then
      attempt_platform mac run_gui_platform mac
      attempt_platform windows run_gui_platform windows
      attempt_platform linux run_gui_platform linux
      attempt_platform android run_gui_platform android
      attempt_platform ios run_gui_platform ios
    fi
    ;;
  *)
    if [ "${selected_end}" = "all" ] || [ "${selected_end}" = "gui" ]; then
      run_gui_platform "${selected_platform}"
    fi
    ;;
esac

if [ "${selected_platform}" = "$(host_platform)" ] || [ "${selected_platform}" = "all" ]; then
  if [ "${selected_end}" = "all" ] || [ "${selected_end}" = "cli" ]; then
    if platform_is_optional; then
      attempt_platform cli build_cli_archives
    else
      build_cli_archives
    fi
  fi
  if [ "${selected_end}" = "all" ] || [ "${selected_end}" = "tui" ]; then
    if platform_is_optional; then
      attempt_platform tui build_tui_archives
    else
      build_tui_archives
    fi
  fi
fi

echo
echo "dist/ now holds:"
ls -1 dist/ 2>/dev/null || echo "(nothing built)"
if [ -s "${skipped_note_file}" ]; then
  echo
  echo "skipped:"
  cat "${skipped_note_file}"
fi
if [ -s "${failed_note_file}" ]; then
  echo
  echo "failed:"
  cat "${failed_note_file}"
  exit 1
fi
