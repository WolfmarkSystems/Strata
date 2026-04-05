#!/usr/bin/env bash
set -euo pipefail

BASELINE_UNWRAP_EXPECT=2307
BASELINE_UNSAFE=6

ALLOWED_UNSAFE_FILES=(
  "apps/forge/apps/strata-forge-desktop/src-tauri/src/lib.rs"
  "crates/strata-core/src/plugin.rs"
  "crates/strata-fs/src/virtualization/mod.rs"
  "crates/strata-shield-engine/src/plugin.rs"
)

normalize_path() {
  local p="$1"
  p="${p#./}"
  echo "$p"
}

count_unwrap_expect=0
while IFS= read -r file; do
  match_count=$(grep -Eo 'unwrap\(|expect\(' "$file" 2>/dev/null | wc -l | tr -d ' ')
  count_unwrap_expect=$((count_unwrap_expect + match_count))
done < <(find . -type f -name '*.rs' \
  ! -path '*/target/*' \
  ! -path '*/target_*/*' \
  ! -path '*/node_modules/*' \
  ! -path '*/tests/*' \
  ! -name '*_test.rs')

count_unsafe=0
unsafe_files=()
while IFS= read -r file; do
  match_count=$(grep -Eo '\bunsafe\b' "$file" 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$match_count" -gt 0 ]]; then
    count_unsafe=$((count_unsafe + match_count))
    unsafe_files+=("$(normalize_path "$file")")
  fi
done < <(find . -type f -name '*.rs' \
  ! -path '*/target/*' \
  ! -path '*/target_*/*' \
  ! -path '*/node_modules/*')

printf 'Reliability baseline check\n'
printf '  unwrap/expect (prod): current=%s baseline=%s\n' "$count_unwrap_expect" "$BASELINE_UNWRAP_EXPECT"
printf '  unsafe (all rust): current=%s baseline=%s\n' "$count_unsafe" "$BASELINE_UNSAFE"

if [[ "$count_unwrap_expect" -gt "$BASELINE_UNWRAP_EXPECT" ]]; then
  echo "ERROR: unwrap/expect count increased above baseline."
  exit 1
fi

if [[ "$count_unsafe" -gt "$BASELINE_UNSAFE" ]]; then
  echo "ERROR: unsafe usage count increased above baseline."
  exit 1
fi

for file in "${unsafe_files[@]}"; do
  allowed=false
  for allowed_file in "${ALLOWED_UNSAFE_FILES[@]}"; do
    if [[ "$file" == "$allowed_file" ]]; then
      allowed=true
      break
    fi
  done

  if [[ "$allowed" == false ]]; then
    echo "ERROR: unsafe usage found outside allowlist: $file"
    exit 1
  fi
done

echo "Reliability baseline check passed."
