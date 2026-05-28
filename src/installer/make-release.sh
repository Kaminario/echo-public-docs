#!/usr/bin/env bash
# Linux port of make-release.ps1 — bumps the version, inlines orc_*.ps1
# imports into orchestrator.ps1, and writes the combined release file.

set -euo pipefail

# --- Argument parsing -------------------------------------------------------
PART="patch"
FINAL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -Part|--part|-p) PART="$2"; shift 2 ;;
        -Final|--final|-f) FINAL=1; shift ;;
        major|minor|patch) PART="$1"; shift ;;
        -h|--help)
            echo "Usage: $(basename "$0") [major|minor|patch] [--final]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

case "$PART" in
    major|minor|patch) ;;
    *)
        echo "Invalid Part value: $PART (must be major/minor/patch)" >&2
        exit 1
        ;;
esac

cat <<'BANNER'
Copyright (c) 2025 Silk Technologies, Inc.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
BANNER

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_FILE="${SCRIPT_DIR}/../../installer-release/version"
ORCHESTRATOR_FILE="${SCRIPT_DIR}/orchestrator.ps1"
RELEASE_FILE="${SCRIPT_DIR}/../../installer-release/orchestrator.ps1"

# --- Bump version -----------------------------------------------------------
CURRENT_VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"

IFS='.' read -r MAJOR MINOR PATCH _extra <<< "$CURRENT_VERSION"
if [[ -z "${MAJOR:-}" || -z "${MINOR:-}" || -z "${PATCH:-}" || -n "${_extra:-}" ]] \
   || ! [[ "$MAJOR" =~ ^[0-9]+$ && "$MINOR" =~ ^[0-9]+$ && "$PATCH" =~ ^[0-9]+$ ]]; then
    echo "Invalid version format. Expected x.y.z, got: $CURRENT_VERSION" >&2
    exit 1
fi

case "$PART" in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
echo "Incrementing $PART version from $CURRENT_VERSION to $NEW_VERSION"

printf '%s\n' "$NEW_VERSION" > "$VERSION_FILE"
echo "Version updated in $VERSION_FILE"

# --- Expand `. ./orc_*.ps1` imports inline (mirrors orc_import_expander.ps1)
expand_imports_inline() {
    local input="$1" output="$2"
    local cur next imports iteration

    cur=$(mktemp); next=$(mktemp)
    cp "$input" "$cur"

    for iteration in 1 2 3; do
        imports=0
        : > "$next"

        while IFS= read -r line || [[ -n "$line" ]]; do
            # PS expander splits on `[\r\n]+`, which collapses runs of newlines —
            # blank lines disappear everywhere, not just inside imports.
            [[ -z "${line//[[:space:]]/}" ]] && continue

            if [[ "$line" =~ ^[[:space:]]*\.[[:space:]]+(\./orc_[A-Za-z0-9_-]+\.ps1)[[:space:]]*$ ]]; then
                local rel="${BASH_REMATCH[1]}"
                local file_path="${SCRIPT_DIR}/${rel#./}"
                local region="${rel#./}"; region="${region%.ps1}"

                if [[ -f "$file_path" ]]; then
                    printf '#region %s\n' "$region" >> "$next"
                    awk 'NF' "$file_path" >> "$next"
                    printf '#endregion %s\n' "$region" >> "$next"
                    imports=$((imports + 1))
                else
                    echo "WARNING: Could not find import file: $rel. Keeping original import line." >&2
                    printf '%s\n' "$line" >> "$next"
                fi
            else
                printf '%s\n' "$line" >> "$next"
            fi
        done < "$cur"

        mv "$next" "$cur"
        : > "$next"

        [[ $imports -eq 0 ]] && break
    done

    cp "$cur" "$output"
    rm -f "$cur" "$next"
}

TMP_EXPANDED=$(mktemp)
trap 'rm -f "$TMP_EXPANDED"' EXIT

expand_imports_inline "$ORCHESTRATOR_FILE" "$TMP_EXPANDED"

# Replace the version placeholder.
# Use a delimiter unlikely to appear in version numbers.
sed -i "s|{{VERSION_PLACEHOLDER}}|$NEW_VERSION|g" "$TMP_EXPANDED"

# TrimEnd() + single trailing "\n": drop trailing blank lines, keep one LF at EOF.
awk '
/^[[:space:]]*$/ { pending = pending $0 "\n"; next }
{ printf "%s%s\n", pending, $0; pending = "" }
' "$TMP_EXPANDED" > "$RELEASE_FILE"

echo "$RELEASE_FILE created successfully."

# --- Optional: commit and tag ----------------------------------------------
if [[ $FINAL -eq 1 ]]; then
    git add "$VERSION_FILE" "$RELEASE_FILE"
    if git commit -m "Release orchestrator v$NEW_VERSION"; then
        git tag "orchestrator-v$NEW_VERSION"
        echo "Tagged as orchestrator-v$NEW_VERSION"
    else
        echo "Commit failed. Tag not created."
    fi
fi
