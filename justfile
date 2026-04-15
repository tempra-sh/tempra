# Tempra development & release tasks
# Usage: just <recipe>       (or just --list for all recipes)
#
# Release examples:
#   just release              # interactive (gum prompts)
#   just release --sign       # interactive + GPG-sign
#   just release-ci patch     # non-interactive for CI/agents
#   just release-ci minor --sign

set shell := ["bash", "-euo", "pipefail", "-c"]

# Version from Cargo.toml
cargo_version := `grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/'`

# ==================== Development ====================

# Run all pre-push checks (fmt, clippy, test)
check:
    @echo "Running pre-push checks..."
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test
    @echo "All checks passed."

# Format code
fmt:
    cargo fmt

# Run tests
test:
    cargo test

# Run clippy
lint:
    cargo clippy --all-targets -- -D warnings

# Build debug binary
build:
    cargo build

# Build release binary
build-release:
    cargo build --release

# Build static musl binary via Docker (works on any Linux, no local musl needed)
build-static:
    docker run --rm -v "$(pwd)":/work -w /work rust:latest sh -c \
        "rustup target add x86_64-unknown-linux-musl && apt-get update -qq && apt-get install -y -qq musl-tools && cargo build --release --target x86_64-unknown-linux-musl"
    @echo "Binary: target/x86_64-unknown-linux-musl/release/tempra"

# Copy binary to a remote server (e.g., just deploy ubuntu@1.2.3.4)
deploy host:
    #!/usr/bin/env bash
    set -euo pipefail
    BINARY="target/release/tempra"
    if [[ -f "target/x86_64-unknown-linux-musl/release/tempra" ]]; then
        BINARY="target/x86_64-unknown-linux-musl/release/tempra"
        echo "Using static musl binary"
    fi
    scp "${BINARY}" "{{ host }}:/tmp/tempra"
    ssh "{{ host }}" "sudo mv /tmp/tempra /usr/local/bin/tempra && sudo chmod +x /usr/local/bin/tempra && tempra --version"

# Run tempra with arguments (e.g., just run scan)
run *args:
    cargo run -- {{ args }}

# ==================== CI ====================

# Run CI workflow locally via act (mirrors .github/workflows/ci.yml)
ci:
    act push -W .github/workflows/ci.yml

# Run release workflow locally via act (dry run, no actual release)
ci-release:
    act push -W .github/workflows/release.yml --dryrun

# ==================== Git helpers ====================

# Sign all commits on current branch (for re-signing after Claude's unsigned commits)
sign-commits:
    #!/usr/bin/env bash
    set -euo pipefail
    UPSTREAM=$(git rev-parse --abbrev-ref '@{upstream}' 2>/dev/null || echo "")
    if [[ -z "${UPSTREAM}" ]]; then
        echo "No upstream branch — signing all commits from root"
        git rebase --exec 'git commit --amend -S --no-edit' --root
    else
        DIVERGE=$(git merge-base HEAD "${UPSTREAM}")
        COUNT=$(git rev-list --count "${DIVERGE}..HEAD")
        echo "Signing ${COUNT} commit(s) since ${DIVERGE}"
        git rebase --exec 'git commit --amend -S --no-edit' "${DIVERGE}"
    fi
    echo "All commits signed."

# ==================== Release ====================

# Interactive release flow (add --sign to GPG-sign commits and tags)
release *flags:
    #!/usr/bin/env bash
    set -euo pipefail

    SIGN=false
    for flag in {{ flags }}; do
        case "${flag}" in
            --sign|-s) SIGN=true ;;
            *) echo "Unknown flag: ${flag}"; exit 1 ;;
        esac
    done

    # Get current tag
    CURRENT_TAG=$(git tag --sort=-v:refname --list "v*" | head -1)
    if [[ -z "${CURRENT_TAG}" ]]; then
        CURRENT_VERSION="0.0.0"
    else
        CURRENT_VERSION="${CURRENT_TAG#v}"
    fi

    echo "Current: v${CURRENT_VERSION}  |  Cargo.toml: {{ cargo_version }}"

    # Parse semver components
    IFS='.' read -r MAJOR MINOR PATCH <<< "${CURRENT_VERSION}"

    # Suggest next versions
    NEXT_PATCH="${MAJOR}.${MINOR}.$((PATCH + 1))"
    NEXT_MINOR="${MAJOR}.$((MINOR + 1)).0"
    NEXT_MAJOR="$((MAJOR + 1)).0.0"

    if command -v gum >/dev/null 2>&1; then
        NEXT_VERSION=$(gum choose --header "Next version?" \
            "${NEXT_PATCH} (patch)" \
            "${NEXT_MINOR} (minor)" \
            "${NEXT_MAJOR} (major)" \
            "custom")

        case "${NEXT_VERSION}" in
            *patch*)  NEXT_VERSION="${NEXT_PATCH}" ;;
            *minor*)  NEXT_VERSION="${NEXT_MINOR}" ;;
            *major*)  NEXT_VERSION="${NEXT_MAJOR}" ;;
            custom)   NEXT_VERSION=$(gum input --header "Enter version:" --placeholder "${NEXT_PATCH}") ;;
        esac
    else
        echo ""
        echo "  1) ${NEXT_PATCH} (patch)"
        echo "  2) ${NEXT_MINOR} (minor)"
        echo "  3) ${NEXT_MAJOR} (major)"
        read -rp "Pick [1-3]: " choice
        case "${choice}" in
            1) NEXT_VERSION="${NEXT_PATCH}" ;;
            2) NEXT_VERSION="${NEXT_MINOR}" ;;
            3) NEXT_VERSION="${NEXT_MAJOR}" ;;
            *) echo "Invalid choice"; exit 1 ;;
        esac
    fi

    just _do-release "${NEXT_VERSION}" "${SIGN}"

# Non-interactive release for CI/agents (add --sign for GPG)
release-ci bump *flags:
    #!/usr/bin/env bash
    set -euo pipefail

    SIGN=false
    for flag in {{ flags }}; do
        case "${flag}" in
            --sign|-s) SIGN=true ;;
            *) echo "Unknown flag: ${flag}"; exit 1 ;;
        esac
    done

    BUMP="{{ bump }}"

    # Get current tag
    CURRENT_TAG=$(git tag --sort=-v:refname --list "v*" | head -1)
    if [[ -z "${CURRENT_TAG}" ]]; then
        CURRENT_VERSION="0.0.0"
    else
        CURRENT_VERSION="${CURRENT_TAG#v}"
    fi

    IFS='.' read -r MAJOR MINOR PATCH <<< "${CURRENT_VERSION}"

    case "${BUMP}" in
        patch)   NEXT_VERSION="${MAJOR}.${MINOR}.$((PATCH + 1))" ;;
        minor)   NEXT_VERSION="${MAJOR}.$((MINOR + 1)).0" ;;
        major)   NEXT_VERSION="$((MAJOR + 1)).0.0" ;;
        *)
            if echo "${BUMP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
                NEXT_VERSION="${BUMP}"
            else
                echo "ERROR: Invalid bump type or version: ${BUMP}"
                echo "Usage: just release-ci <patch|minor|major|X.Y.Z> [--sign]"
                exit 1
            fi
            ;;
    esac

    just _do-release "${NEXT_VERSION}" "${SIGN}"

# Shared release logic (not meant to be called directly)
_do-release version sign:
    #!/usr/bin/env bash
    set -euo pipefail

    NEXT_VERSION="{{ version }}"
    SIGN="{{ sign }}"
    TAG="v${NEXT_VERSION}"

    # Validate semver format
    if ! echo "${NEXT_VERSION}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "ERROR: Invalid semver: ${NEXT_VERSION}"
        exit 1
    fi

    # Check tag doesn't already exist
    if git rev-parse "${TAG}" >/dev/null 2>&1; then
        echo "ERROR: Tag ${TAG} already exists"
        exit 1
    fi

    # Check CHANGELOG.md has an entry for this version
    if ! grep -q "## v${NEXT_VERSION}" CHANGELOG.md 2>/dev/null; then
        echo "WARNING: No CHANGELOG.md entry for v${NEXT_VERSION}"
        echo "Add a '## v${NEXT_VERSION}' section to CHANGELOG.md before releasing."
        exit 1
    fi

    # Commit flags
    if [[ "${SIGN}" == "true" ]]; then
        COMMIT_FLAGS=("-S")
        TAG_FLAGS=("-s")
    else
        COMMIT_FLAGS=("--no-gpg-sign")
        TAG_FLAGS=("-a")
    fi

    # Update Cargo.toml if version differs
    CARGO_VERSION="{{ cargo_version }}"
    if [[ "${CARGO_VERSION}" != "${NEXT_VERSION}" ]]; then
        sed -i "s/^version = \".*\"/version = \"${NEXT_VERSION}\"/" Cargo.toml
        cargo generate-lockfile 2>/dev/null || true
        git add Cargo.toml
        git add Cargo.lock 2>/dev/null || true
        git commit "${COMMIT_FLAGS[@]}" -m "chore: bump version to ${NEXT_VERSION}"
        echo "Committed version bump to ${NEXT_VERSION}"
    fi

    # Create tag
    git tag "${TAG_FLAGS[@]}" "${TAG}" -m "Release ${TAG}"

    echo ""
    echo "============================================"
    echo "  Tag ${TAG} created"
    if [[ "${SIGN}" == "true" ]]; then
        echo "  (GPG-signed commit + tag)"
    else
        echo "  (unsigned — sign before pushing)"
    fi
    echo "============================================"
    echo ""
    echo "Next steps:"
    echo "  git push && git push origin ${TAG}"

# Show current version
version:
    @echo "Cargo.toml: {{ cargo_version }}"
    @git tag --sort=-v:refname --list "v*" | head -1 || echo "(no tags)"
