#!/bin/bash
# shellcheck disable=all

# jscpd:ignore-start

set -euo pipefail

trap 'echo "🚨🚨 Tests failed! 🚨🚨"' ERR

go install -buildvcs=false .

# Create and move to temporary directory
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cd "${TMPDIR}"

echo "🧪 Testing basic redact"

echo "secret data" >file1.txt
gonc -q redact file1.txt
[[ -f "file1.txt.enc" ]] || (echo '❌ test: Redacted file was not created' && exit 1)
[[ "$(cat file1.txt.enc)" == "<REDACTED>" ]] || (echo '❌ test: Redacted content mismatch' && exit 1)
echo "✅ Basic redact works"

rm -f file1.txt file1.txt.enc

echo "🧪 Testing redact with custom content"

echo "secret data" >file1.txt
gonc -q redact --content "CLASSIFIED" file1.txt
[[ "$(cat file1.txt.enc)" == "CLASSIFIED" ]] || (echo '❌ test: Custom content mismatch' && exit 1)
echo "✅ Custom content works"

rm -f file1.txt file1.txt.enc

echo "🧪 Testing redact with --hash"

echo "hello world" >file1.txt
gonc -q redact --hash file1.txt
CONTENT=$(cat file1.txt.enc)
[[ $CONTENT == "<REDACTED>:"* ]] || (echo '❌ test: Hash output should start with <REDACTED>:' && exit 1)
HASH=${CONTENT#"<REDACTED>:"}
[[ ${#HASH} -eq 64 ]] || (echo "❌ test: SHA-256 hash should be 64 hex chars, got ${#HASH}" && exit 1)
echo "✅ Redact with --hash works"

rm -f file1.txt file1.txt.enc

echo "🧪 Testing redact --hash determinism (same file = same hash)"

echo "hello world" >file1.txt
gonc -q redact --hash file1.txt
FIRST=$(cat file1.txt.enc)
rm -f file1.txt.enc

echo "hello world" >file1.txt
gonc -q redact --hash file1.txt
SECOND=$(cat file1.txt.enc)

[[ $FIRST == "$SECOND" ]] || (echo '❌ test: Same input should produce same hash' && exit 1)
echo "✅ Hash is deterministic"

rm -f file1.txt file1.txt.enc

echo "🧪 Testing redact --hash changes when file changes"

echo "version 1" >file1.txt
gonc -q redact --hash file1.txt
HASH1=$(cat file1.txt.enc)
rm -f file1.txt.enc

echo "version 2" >file1.txt
gonc -q redact --hash file1.txt
HASH2=$(cat file1.txt.enc)

[[ $HASH1 != "$HASH2" ]] || (echo '❌ test: Different input should produce different hash' && exit 1)
echo "✅ Hash changes when file changes"

rm -f file1.txt file1.txt.enc

echo "🧪 Testing redact --hash with custom content"

echo "data" >file1.txt
gonc -q redact --hash --content "CUSTOM" file1.txt
CONTENT=$(cat file1.txt.enc)
[[ $CONTENT == "CUSTOM:"* ]] || (echo '❌ test: Hash with custom content should start with CUSTOM:' && exit 1)
echo "✅ Hash with custom content works"

rm -f file1.txt file1.txt.enc

echo "🧪 Testing redact preserves executable bit"

cat >script.sh <<'INNER'
#!/bin/bash
echo "I am executable"
INNER
chmod +x script.sh

gonc -q redact --hash script.sh
[[ -x "script.sh.enc" ]] || (echo '❌ test: Redacted file lost executable bit' && exit 1)
echo "✅ Executable bit preserved"

rm -f script.sh script.sh.enc

echo "🧪 Testing redact with --delete"

echo "to be deleted" >file1.txt
gonc -q --delete redact file1.txt
[[ -f "file1.txt.enc" ]] || (echo '❌ test: Redacted file was not created' && exit 1)
[[ ! -f "file1.txt" ]] || (echo '❌ test: Original file should be deleted' && exit 1)
echo "✅ --delete works with redact"

rm -f file1.txt.enc

echo "🧪 Testing redact dry run"

echo "keep me" >file1.txt
gonc -q --dry redact file1.txt
[[ ! -f "file1.txt.enc" ]] || (echo '❌ test: Dry run should not create files' && exit 1)
echo "✅ Dry run works with redact"

rm -f file1.txt

echo "✨ ALL REDACT TESTS PASSED ! ✨"

# jscpd:ignore-end
