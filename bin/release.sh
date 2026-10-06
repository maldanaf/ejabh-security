#!/usr/bin/env bash
#
# Publish a signed release that every site picks up automatically.
#
#   1. Bump the version in ejabh-security.php (header *and* EJABH_SEC_VERSION).
#   2. Commit.
#   3. bin/release.sh            (or: bin/release.sh "what changed")
#
# The signing key lives at ~/.ejabh-security/release-signing.key and must never
# be committed, uploaded, or stored in GitHub secrets — it is what stops a
# hijacked GitHub account from shipping code to the sites.
set -euo pipefail

cd "$(dirname "$0")/.."

KEY="${EJABH_SIGNING_KEY:-$HOME/.ejabh-security/release-signing.key}"
PHP="${PHP:-$(command -v php || ls -d /Applications/MAMP/bin/php/php8*/bin/php 2>/dev/null | tail -1)}"

die() { echo "✖ $*" >&2; exit 1; }

[ -f "$KEY" ] || die "signing key not found at $KEY"
[ -x "$PHP" ] || die "php not found (set PHP=/path/to/php)"
command -v gh >/dev/null || die "GitHub CLI (gh) is required"

HEADER=$(sed -n 's/^ \* Version: *//p' ejabh-security.php | tr -d '[:space:]')
CONST=$(sed -n "s/^define( 'EJABH_SEC_VERSION', '\(.*\)' );/\1/p" ejabh-security.php)
[ -n "$HEADER" ] && [ "$HEADER" = "$CONST" ] || die "version mismatch: header '$HEADER' vs EJABH_SEC_VERSION '$CONST'"
VERSION="$HEADER"
TAG="v$VERSION"

git diff --quiet && git diff --cached --quiet || die "commit your changes first"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "$TAG already exists — bump the version"

for f in $(git ls-files '*.php'); do "$PHP" -l "$f" >/dev/null || die "syntax error in $f"; done

OUT=$(mktemp -d)
ZIP="$OUT/ejabh-security.zip"
git archive --format=zip --prefix=ejabh-security/ -o "$ZIP" HEAD
"$PHP" bin/sign.php sign "$ZIP" "$KEY" > "$ZIP.sig"
"$PHP" bin/sign.php verify "$ZIP" "$ZIP.sig"

git tag -a "$TAG" -m "Ejabh Security $VERSION"
git push origin HEAD "$TAG"

NOTES="${1:-}"
if [ -n "$NOTES" ]; then
	gh release create "$TAG" "$ZIP" "$ZIP.sig" --title "Ejabh Security $VERSION" --notes "$NOTES"
else
	gh release create "$TAG" "$ZIP" "$ZIP.sig" --title "Ejabh Security $VERSION" --generate-notes
fi

echo "✔ $TAG published. Sites pick it up within ~12 hours (Dashboard → Updates → Check again for immediate)."
