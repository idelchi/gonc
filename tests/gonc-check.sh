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

# Create test file tree
mkdir -p src doc vendor/lib
echo "package main" >src/main.go
echo "package util" >src/util.go
echo "readme" >doc/readme.md
echo "notes" >doc/notes.txt
echo "dep" >vendor/lib/dep.go
echo "root" >root.txt

echo "🧪 Testing check with valid include pattern"

gonc --include "*.go" check .
echo "✅ Valid include pattern accepted"

echo "🧪 Testing check with valid exclude pattern"

gonc --exclude "vendor/*" check .
echo "✅ Valid exclude pattern accepted"

echo "🧪 Testing check with multiple valid patterns"

gonc --include "*.go" --include "*.md" --exclude "vendor/*" check .
echo "✅ Multiple valid patterns accepted"

echo "🧪 Testing check with invalid include pattern (should fail)"

if gonc --include "*.typo" check . 2>/dev/null; then
  echo "❌ test: check should have failed for *.typo" && exit 1
fi
echo "✅ Invalid include pattern rejected"

echo "🧪 Testing check with invalid exclude pattern (should fail)"

if gonc --exclude "nonexistent_dir/*" check . 2>/dev/null; then
  echo "❌ test: check should have failed for nonexistent_dir/*" && exit 1
fi
echo "✅ Invalid exclude pattern rejected"

echo "🧪 Testing check with mix of valid and invalid patterns (should fail)"

if gonc --include "*.go" --include "*.xyz" check . 2>/dev/null; then
  echo "❌ test: check should have failed with one bad pattern" && exit 1
fi
echo "✅ Mixed valid/invalid correctly rejected"

echo "🧪 Testing check error message content"

OUTPUT=$(gonc --include "*.bogus" --exclude "fake/*" check . 2>&1 || true)
echo "$OUTPUT" | grep -q 'include: \*.bogus' || (echo "❌ test: Missing include error in output" && exit 1)
echo "$OUTPUT" | grep -q 'exclude: fake/\*' || (echo "❌ test: Missing exclude error in output" && exit 1)
echo "$OUTPUT" | grep -q '2 pattern(s) matched no files' || (echo "❌ test: Missing summary in output" && exit 1)
echo "✅ Error messages are correct"

echo "🧪 Testing check quiet mode (only errors shown)"

OUTPUT=$(gonc -q --include "*.go" --include "*.nope" check . 2>&1 || true)
echo "$OUTPUT" | grep -q 'include: \*.go' && (echo "❌ test: Quiet mode should suppress valid patterns" && exit 1)
echo "$OUTPUT" | grep -q 'include: \*.nope' || (echo "❌ test: Quiet mode should still show errors" && exit 1)
echo "✅ Quiet mode works correctly"

echo "🧪 Testing check with --include-from file"

cat >patterns.jsonc <<'EOF'
[
  "*.go",   // Go source files
  "*.fake"  // Does not exist
]
EOF

if gonc --include-from patterns.jsonc check . 2>/dev/null; then
  echo "❌ test: check should have failed with *.fake from file" && exit 1
fi
echo "✅ --include-from pattern validation works"

echo "🧪 Testing check with --exclude-from file"

cat >exclude.jsonc <<'EOF'
[
  "vendor/*"
]
EOF

gonc --exclude-from exclude.jsonc check .
echo "✅ --exclude-from pattern validation works"

echo "🧪 Testing check with subdirectory target"

gonc --include "*.go" check src/
echo "✅ Subdirectory target works"

echo "🧪 Testing check with no patterns (should fail)"

if gonc check . 2>/dev/null; then
  echo "❌ test: check should have failed with no patterns" && exit 1
fi
echo "✅ No patterns correctly rejected"

echo "✨ ALL CHECK TESTS PASSED ! ✨"

# jscpd:ignore-end
