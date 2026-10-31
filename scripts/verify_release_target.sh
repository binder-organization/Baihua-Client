#!/usr/bin/env bash
set -euo pipefail
: "${RELEASE_MATRIX?}"
: "${TARGET?}"

count=0
while IFS=$'\t' read -r product prefix version target kind standalone; do
  if [ "$product" = gui ]; then
    case "$kind" in
      dmg|msi|apk|ipa) extension="$kind" ;;
      appimage) extension=AppImage ;;
      *) echo "unknown GUI package kind: $kind" >&2; exit 1 ;;
    esac
  else
    case "$target" in *windows*) extension=zip ;; *) extension=tar.gz ;; esac
  fi
  archive="${prefix}${version}-${target}.${extension}"
  test -s "dist/$archive"
  test -s "dist/$archive.sha256"
  if command -v shasum >/dev/null 2>&1; then
    (cd dist && shasum -a 256 -c "$archive.sha256")
  else
    (cd dist && sha256sum -c "$archive.sha256")
  fi
  case "$product" in cli|tui) test -s "dist/$standalone" ;; esac
  count=$((count + 1))
done < <(jq -r --arg target "$TARGET" '.[] | select(.target == $target) | [.product,.package_prefix,.version,.target,.package_kind,.standalone] | @tsv' <<< "$RELEASE_MATRIX")
test "$count" -gt 0
