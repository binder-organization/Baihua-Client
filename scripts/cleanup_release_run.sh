#!/usr/bin/env bash
# Independent cleanup for a failed or cancelled publish job.
set -euo pipefail
: "${RELEASE_SHA?}"
: "${GITHUB_RUN_ID?}"
: "${GITHUB_RUN_ATTEMPT?}"

matches="$(gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" |
  jq -sc --arg run "$GITHUB_RUN_ID" --arg sha "$RELEASE_SHA" \
    '[.[][] | select(.target_commitish == $sha and ((.body // "") | test("<!-- baihua-release-run:" + $run + ":[0-9]+ sha:" + $sha + " -->"))) | {id,tag_name,body}]')"

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

failed=0
while IFS= read -r release; do
  id="$(jq -r '.id' <<< "$release")"
  tag="$(jq -r '.tag_name' <<< "$release")"
  body="$(jq -r '.body' <<< "$release")"
  if [[ "$body" == *'baihua-release-owned-tag:yes'* ]]; then
    if ! tag_sha="$(tag_sha_or_missing "$tag")"; then
      echo "::error::could not verify this run's tag ${tag}"
      failed=1
      continue
    fi
    if [ "$tag_sha" != missing ]; then
      if [ "$tag_sha" != "$RELEASE_SHA" ] || \
         ! gh api -X DELETE "repos/${GITHUB_REPOSITORY}/git/refs/tags/${tag}"; then
        echo "::error::could not delete this run's tag ${tag}"
        failed=1
        continue
      fi
    fi
  fi
  if ! gh api -X DELETE "repos/${GITHUB_REPOSITORY}/releases/${id}"; then
    echo "::error::could not delete this run's release ${tag} (${id})"
    failed=1
  fi
done < <(jq -c '.[]' <<< "$matches")

exit "$failed"
