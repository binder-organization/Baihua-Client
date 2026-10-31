#!/usr/bin/env bash
# Called only after every selected target has uploaded its artifacts.
set -euo pipefail

marker="<!-- baihua-release-run:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT} sha:${RELEASE_SHA} -->"
created_tags=()
created_tag_refs=()
publish_tags=()

archive_for() {
  local product="$1" prefix="$2" version="$3" target="$4" kind="$5" extension
  if [ "$product" = gui ]; then
    case "$kind" in
      dmg|msi|apk|ipa) extension="$kind" ;;
      appimage) extension=AppImage ;;
      *) echo "unknown GUI package kind: $kind" >&2; return 1 ;;
    esac
  else
    case "$target" in *windows*) extension=zip ;; *) extension=tar.gz ;; esac
  fi
  printf '%s%s-%s.%s' "$prefix" "$version" "$target" "$extension"
}

release_id_for() {
  local tag="$1"
  gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}" --jq '.id' 2>/dev/null || true
}

tag_sha_or_missing() {
  local ref response first_line
  if ref="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${1}" 2>/dev/null)"; then
    jq -r '.object.sha' <<< "$ref"
    return
  fi
  response="$(gh api -i "repos/${GITHUB_REPOSITORY}/git/ref/tags/${1}" 2>&1)" || true
  first_line="${response%%$'\n'*}"
  [[ "$first_line" =~ ^HTTP/[0-9.]+[[:space:]]+404([[:space:]]|$) ]] || return 1
  printf 'missing\n'
}

tag_commit_for() {
  local tag="$1" ref object_type object_sha
  ref="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" 2>/dev/null || true)"
  [ -n "$ref" ] || return 1
  object_type="$(jq -r '.object.type' <<< "$ref")"
  object_sha="$(jq -r '.object.sha' <<< "$ref")"
  if [ "$object_type" = tag ]; then
    object_sha="$(gh api "repos/${GITHUB_REPOSITORY}/git/tags/${object_sha}" --jq '.object.sha')"
  fi
  printf '%s' "$object_sha"
}

cleanup() {
  local tag id body tag_sha owned_tag failed=0
  for tag in "${created_tags[@]}"; do
    id="$(release_id_for "$tag")"
    [ -n "$id" ] || continue
    body="$(gh api "repos/${GITHUB_REPOSITORY}/releases/${id}" --jq '.body' 2>/dev/null || true)"
    [[ "$body" == *"$marker"* ]] || continue
    owned_tag=no
    for owned_tag in "${created_tag_refs[@]}"; do
      if [ "$owned_tag" = "$tag" ]; then
        if ! tag_sha="$(tag_sha_or_missing "$tag")"; then
          echo "::error::could not verify this run's tag ${tag}" >&2
          failed=1
          continue 2
        fi
        if [ "$tag_sha" != missing ]; then
          if [ "$tag_sha" != "$RELEASE_SHA" ] || \
             ! gh api -X DELETE "repos/${GITHUB_REPOSITORY}/git/refs/tags/${tag}"; then
            echo "::error::could not delete this run's tag ${tag}" >&2
            failed=1
            continue 2
          fi
        fi
      fi
    done
    if ! gh api -X DELETE "repos/${GITHUB_REPOSITORY}/releases/${id}"; then
      echo "::error::could not delete this run's release ${tag}" >&2
      failed=1
    fi
  done
  return "$failed"
}
trap 'status=$?; if [ "$status" -ne 0 ]; then cleanup || true; fi' EXIT

verify_main_ci() {
  local main_sha latest
  main_sha="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq '.commit.sha')"
  [ "$main_sha" = "$RELEASE_SHA" ] || { echo 'main advanced before publication' >&2; return 1; }
  latest="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs?branch=main&event=push&per_page=100" \
    --jq "[.workflow_runs[] | select(.head_sha == \"${RELEASE_SHA}\")] | sort_by(.updated_at // .run_started_at // .created_at, .id) | last | .conclusion // empty")"
  [ "$latest" = success ] || { echo "latest main CI is ${latest:-missing}" >&2; return 1; }
}

reconcile_assets() {
  local tag="$1" release_json name id expected_names actual_names path found
  shift
  release_json="$(gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}")"
  while IFS=$'\t' read -r id name; do
    found=no
    for path in "$@"; do
      [ "${path##*/}" != "$name" ] || found=yes
    done
    if [ "$found" = no ]; then
      gh api -X DELETE "repos/${GITHUB_REPOSITORY}/releases/assets/${id}"
    fi
  done < <(jq -r '.assets[] | [.id,.name] | @tsv' <<< "$release_json")
  release_json="$(gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}")"
  expected_names="$(printf '%s\n' "$@" | sed 's|.*/||' | sort)"
  actual_names="$(jq -r '.assets[] | select(.size > 0) | .name' <<< "$release_json" | sort)"
  [ "$expected_names" = "$actual_names" ] || {
    echo "release asset manifest differs from verified build artifacts: $tag" >&2
    return 1
  }
}

# Check every archive, digest and standalone binary before creating any release.
checked=0
while IFS=$'\t' read -r product prefix version target kind standalone; do
  archive="$(archive_for "$product" "$prefix" "$version" "$target" "$kind")"
  test -s "artifacts/$archive"
  test -s "artifacts/$archive.sha256"
  (cd artifacts && sha256sum -c "$archive.sha256")
  case "$product" in
    cli|tui) test -s "artifacts/$standalone" ;;
  esac
  checked=$((checked + 1))
done < <(jq -r '.[] | [.product,.package_prefix,.version,.target,.package_kind,.standalone] | @tsv' <<< "$BUILD_MATRIX")
test "$checked" -gt 0

verify_main_ci

for product in cli gui tui; do
  upper="$(printf '%s' "$product" | tr '[:lower:]' '[:upper:]')"
  enabled="${upper}_ENABLED"
  [ "${!enabled}" = true ] || continue
  tag_var="${upper}_TAG"
  prerelease_var="${upper}_PRERELEASE"
  notes_var="${upper}_NOTES"
  tag="${!tag_var}"
  notes_file="${RUNNER_TEMP}/${product}-notes.md"
  notes="${!notes_var}"
  if [ "$product" = gui ]; then
    notes="${notes}

The iOS IPA is ad hoc signed and has no Apple provisioning profile. It cannot be installed on an iPhone through the normal installation process."
  fi
  tag_commit="$(tag_commit_for "$tag" || true)"
  if [ -n "$tag_commit" ] && [ "$tag_commit" != "$RELEASE_SHA" ]; then
    echo "tag ${tag} points to ${tag_commit}, not ${RELEASE_SHA}" >&2
    exit 1
  fi

  assets=()
  while IFS=$'\t' read -r prefix version target kind standalone; do
    archive="$(archive_for "$product" "$prefix" "$version" "$target" "$kind")"
    assets+=("artifacts/$archive" "artifacts/$archive.sha256")
    case "$product" in cli|tui) assets+=("artifacts/$standalone") ;; esac
  done < <(jq -r --arg product "$product" '.[] | select(.product == $product) | [.package_prefix,.version,.target,.package_kind,.standalone] | @tsv' <<< "$BUILD_MATRIX")
  test "${#assets[@]}" -gt 0

  existing="$(gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}" 2>/dev/null || true)"
  if [ -n "$existing" ]; then
    existing_draft="$(jq -r '.draft' <<< "$existing")"
    existing_sha="$(jq -r '.target_commitish' <<< "$existing")"
    existing_body="$(jq -r '.body' <<< "$existing")"
    if [ "$existing_draft" != true ] || [ "$existing_sha" != "$RELEASE_SHA" ] || \
       [[ "$existing_body" != *"baihua-release-run:"*"sha:${RELEASE_SHA} -->"* ]]; then
      echo "refusing to modify an unrelated release: $tag" >&2
      exit 1
    fi
    owned_tag=no
    [[ "$existing_body" != *'baihua-release-owned-tag:yes'* ]] || owned_tag=yes
    printf '%s\n\n%s\n<!-- baihua-release-owned-tag:%s -->\n' "$notes" "$marker" "$owned_tag" > "$notes_file"
    created_tags+=("$tag")
    [ "$owned_tag" != yes ] || created_tag_refs+=("$tag")
    gh release edit "$tag" --draft=true --notes-file "$notes_file"
    gh release upload "$tag" "${assets[@]}" --clobber
  else
    # Track the intended tag before creation so a partial API failure is cleaned up.
    created_tags+=("$tag")
    if [ -z "$tag_commit" ]; then
      created_tag_refs+=("$tag")
      owned_tag=yes
    else
      owned_tag=no
    fi
    printf '%s\n\n%s\n<!-- baihua-release-owned-tag:%s -->\n' "$notes" "$marker" "$owned_tag" > "$notes_file"
    args=("$tag" --draft --title "$tag" --target "$RELEASE_SHA" --notes-file "$notes_file")
    [ "${!prerelease_var}" != true ] || args+=(--prerelease)
    gh release create "${args[@]}" "${assets[@]}"
  fi
  test -n "$(release_id_for "$tag")"
  reconcile_assets "$tag" "${assets[@]}"
  publish_tags+=("$tag")
done

for tag in "${publish_tags[@]}"; do
  verify_main_ci
  gh release edit "$tag" --draft=false
done
verify_main_ci
trap - EXIT
