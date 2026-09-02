#!/usr/bin/env bash
#
# Print the path of a JDK new enough to build this project, or exit non-zero.
#
# Maven refuses to start when JAVA_HOME points somewhere that no longer exists,
# and it reports that as "The JAVA_HOME environment variable is not defined
# correctly" without saying what it found. This script is what the Makefile uses
# instead, so a stale JAVA_HOME in a shell profile cannot block the build.
#
# Candidates are tried in order: an already-usable JAVA_HOME, the macOS JDK
# registry, the usual install locations, then whatever `java` is on PATH.

set -u

MIN_VERSION="${JAVA_MIN_VERSION:-17}"

# Succeeds when $1 is a JDK (it must have javac, not just java) of at least
# $MIN_VERSION.
usable() {
    local home="${1:-}"
    [ -n "$home" ] && [ -x "$home/bin/javac" ] || return 1

    local version
    version=$("$home/bin/javac" -version 2>&1) || return 1
    # "javac 17.0.2" -> 17 ; "javac 1.8.0_292" -> 8
    version=${version##* }
    version=${version%%.*}
    [ "$version" = "1" ] && return 1
    [ "$version" -ge "$MIN_VERSION" ] 2>/dev/null
}

candidates() {
    # An explicit, working JAVA_HOME always wins.
    echo "${JAVA_HOME:-}"

    # macOS keeps a registry of installed JDKs.
    if [ -x /usr/libexec/java_home ]; then
        /usr/libexec/java_home -v "$MIN_VERSION+" 2>/dev/null || true
    fi

    # Common install locations, newest last so the loop below can prefer any of
    # them; each glob quietly expands to nothing when the directory is absent.
    local pattern
    for pattern in \
        "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home \
        /Library/Java/JavaVirtualMachines/*/Contents/Home \
        "$HOME"/OpenJDK/*/Contents/Home \
        "$HOME"/.sdkman/candidates/java/*/ \
        /usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
        /opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
        /usr/lib/jvm/*; do
        [ -e "$pattern" ] && echo "${pattern%/}"
    done

    # Finally, whatever `java` resolves to on PATH. Symlinks are followed by
    # hand because `readlink -f` is not available on macOS, and a link target
    # may be relative to the directory the link lives in.
    local on_path target
    on_path=$(command -v java 2>/dev/null) || return 0
    while [ -L "$on_path" ]; do
        target=$(readlink "$on_path")
        case "$target" in
            /*) on_path=$target ;;
            *) on_path=$(dirname "$on_path")/$target ;;
        esac
    done
    [ -e "$on_path" ] && echo "$(cd "$(dirname "$on_path")/.." && pwd)"
}

while read -r candidate; do
    [ -n "$candidate" ] || continue
    if usable "$candidate"; then
        echo "$candidate"
        exit 0
    fi
done < <(candidates)

cat >&2 <<MSG
error: no JDK $MIN_VERSION or newer found.

  JAVA_HOME is currently: ${JAVA_HOME:-<unset>}
$([ -n "${JAVA_HOME:-}" ] && [ ! -d "${JAVA_HOME:-}" ] && echo "  ...which does not exist.")

Install one, for example:

  brew install --cask temurin@21        # macOS, Homebrew
  sudo apt install openjdk-21-jdk       # Debian / Ubuntu

or point JAVA_HOME at a JDK you already have:

  export JAVA_HOME=/path/to/jdk-17
MSG
exit 1
