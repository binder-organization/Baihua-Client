#!/usr/bin/env bash
set -euo pipefail
: "${PRODUCTS?}"
: "${TARGET?}"

mkdir -p dist
for product in cli tui; do
  case ",${PRODUCTS}," in *,"$product",*) ;; *) continue ;; esac
  case "$product" in
    cli) manifest=baihua-cli/Cargo.toml; prefix=baihua-cli-; binary=baihua ;;
    tui) manifest=baihua-client-tui/Cargo.toml; prefix=baihua-tui-; binary=baihua-tui ;;
  esac
  version="$(grep -m1 '^version = ' "$manifest" | sed -E 's/.*"([^"]+)".*/\1/')"
  case "$TARGET" in
    *windows*) binary="${binary}.exe"; extension=zip ;;
    *) extension=tar.gz ;;
  esac
  archive="${prefix}${version}-${TARGET}.${extension}"
  staging="staging-${product}-${TARGET}"
  rm -rf "$staging"
  mkdir -p "$staging/config"
  cp "target/${TARGET}/release/${binary}" "$staging/"
  cp -R config/. "$staging/config/"
  if [ "$extension" = zip ]; then
    powershell.exe -NoProfile -Command "Compress-Archive -Path '${staging}/*' -DestinationPath 'dist/${archive}' -Force"
    standalone="${prefix}${version}-${TARGET}.exe"
  else
    tar -czf "dist/$archive" -C "$staging" .
    standalone="${prefix}${version}-${TARGET}"
  fi
  if command -v shasum >/dev/null 2>&1; then
    (cd dist && shasum -a 256 "$archive" > "$archive.sha256")
  else
    (cd dist && sha256sum "$archive" > "$archive.sha256")
  fi
  cp "target/${TARGET}/release/${binary}" "dist/${standalone}"
  rm -rf "$staging"
done
