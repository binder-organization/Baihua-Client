#!/usr/bin/env bash
# Preview by default. Run with --apply only after ci.yml has passed on main.
set -euo pipefail

repo="${GITHUB_REPOSITORY:-GavZheng/Baihua-Client}"
bypass_users="${BYPASS_USERS:-GavZheng}"
apply=false
case "${1:-}" in
  '') ;;
  --apply) apply=true ;;
  *) echo 'usage: scripts/activate_ci_ruleset.sh [--apply]' >&2; exit 2 ;;
esac

actors='[]'
IFS=',' read -r -a users <<< "$bypass_users"
for username in "${users[@]}"; do
  [[ "$username" =~ ^[A-Za-z0-9-]+$ ]] || { echo "invalid bypass username: $username" >&2; exit 2; }
  user_id="$(gh api "users/${username}" --jq '.id')"
  actors="$(jq -c --argjson id "$user_id" '. + [{actor_id:$id,actor_type:"User",bypass_mode:"pull_request"}]' <<< "$actors")"
done
test "$(jq 'length' <<< "$actors")" -gt 0

payload="$(jq -n --argjson actors "$actors" '{
  name:"Human-reviewed CI for main and develop",
  target:"branch",
  enforcement:"active",
  bypass_actors:$actors,
  conditions:{ref_name:{include:["refs/heads/main","refs/heads/develop"],exclude:[]}},
  rules:[
    {type:"pull_request",parameters:{
      dismiss_stale_reviews_on_push:true,
      require_code_owner_review:false,
      require_last_push_approval:false,
      required_approving_review_count:1,
      required_review_thread_resolution:true,
      allowed_merge_methods:["merge","squash","rebase"]
    }},
    {type:"required_status_checks",parameters:{
      required_status_checks:[{context:"Lint and test"}],
      strict_required_status_checks_policy:true
    }},
    {type:"non_fast_forward"},
    {type:"deletion"}
  ]
}')"

if [ "$apply" = false ]; then
  printf '%s\n' "$payload"
  echo 'Preview only. Use --apply after the workflow is on main and its check passes.' >&2
  exit 0
fi

metadata="$(gh api "repos/${repo}")"
[ "$(jq -r '.allow_auto_merge' <<< "$metadata")" = false ] || {
  echo 'disable repository auto-merge before activating the ruleset' >&2
  exit 1
}
workflow_state="$(gh api "repos/${repo}/actions/workflows/ci.yml" --jq '.state')"
[ "$workflow_state" = active ] || { echo 'CI workflow is not active on the default branch' >&2; exit 1; }
main_sha="$(gh api "repos/${repo}/branches/main" --jq '.commit.sha')"
latest="$(gh api "repos/${repo}/actions/workflows/ci.yml/runs?branch=main&event=push&per_page=100" \
  --jq "[.workflow_runs[] | select(.head_sha == \"${main_sha}\")] | sort_by(.updated_at // .run_started_at // .created_at, .id) | last | .conclusion // empty")"
[ "$latest" = success ] || { echo 'latest main CI is not successful yet' >&2; exit 1; }
check_count="$(gh api "repos/${repo}/commits/${main_sha}/check-runs?per_page=100" \
  --jq '[.check_runs[] | select(.name == "Lint and test" and .app.slug == "github-actions")] | length')"
[ "$check_count" -gt 0 ] || { echo 'Lint and test context has not appeared on main' >&2; exit 1; }
existing="$(gh api "repos/${repo}/rulesets" --jq '[.[] | select(.name == "Human-reviewed CI for main and develop")] | length')"
[ "$existing" -eq 0 ] || { echo 'the managed ruleset already exists; review it in GitHub settings' >&2; exit 1; }

payload_file="$(mktemp)"
trap 'rm -f "$payload_file"' EXIT
printf '%s\n' "$payload" > "$payload_file"
gh api -X POST "repos/${repo}/rulesets" --input "$payload_file" --jq '{id,name,enforcement,bypass_actors}'
