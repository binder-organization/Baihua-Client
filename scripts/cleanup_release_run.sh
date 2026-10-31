#!/usr/bin/env bash
# Independent cleanup for a failed or cancelled publish job.
set -euo pipefail
: "${RELEASE_SHA?}"
: "${GITHUB_RUN_ID?}"
: "${GITHUB_RUN_ATTEMPT?}"

marker="<!-- baihua-release-run:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT} sha:${RELEASE_SHA} -->"
matches="$(gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" |
  jq -sc --arg marker "$marker" --arg sha "$RELEASE_SHA" \
    '[.[][] | select(.target_commitish == $sha and ((.body // "") | contains($marker))) | {id,tag_name,body}]')"

failed=0
while IFS= read -r release; do
  id="$(jq -r '.id' <<< "$release")"
  tag="$(jq -r '.tag_name' <<< "$release")"
  body="$(jq -r '.body' <<< "$release")"
  if ! gh api -X DELETE "repos/${GITHUB_REPOSITORY}/releases/${id}"; then
    echo "::error::could not delete this run's release ${tag} (${id})"
    failed=1
    continue
  fi
  if [[ "$body" == *'baihua-release-owned-tag:yes'* ]]; then
    tag_sha="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" --jq '.object.sha' 2>/dev/null || true)"
    if [ "$tag_sha" = "$RELEASE_SHA" ] && \
       ! gh api -X DELETE "repos/${GITHUB_REPOSITORY}/git/refs/tags/${tag}"; then
      echo "::error::could not delete this run's tag ${tag}"
      failed=1
    fi
  fi
done < <(jq -c '.[]' <<< "$matches")

exit "$failed"
