#!/usr/bin/env bash
set -euo pipefail

manifest=$1
tag=$2
role='Discovered, installed, recovered, final latest release'
test "$tag" != "$(jq -r .releases[0].tag "$manifest")" || role='Clean-installed source release'
test "$(jq -r .source_state "$manifest")" != rescue || role='Rescue direct-install and lower-sequence replacement release'
printf '%s\n' "$role"
