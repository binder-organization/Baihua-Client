#!/usr/bin/env bash
# Look up published releases and drafts visible to the authenticated caller.
set -euo pipefail

tag="${1:?release tag required}"
gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" |
  jq -sc --arg tag "$tag" '[.[][] | select(.tag_name == $tag)] | if length > 1 then error("duplicate release tag: " + $tag) else .[0] // empty end'
