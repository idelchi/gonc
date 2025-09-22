#!/bin/bash
# shellcheck disable=all

# jscpd:ignore-start

set -euo pipefail

trap 'echo "🚨🚨 Tests failed! 🚨🚨"' ERR

if ! command -v gogen &>/dev/null; then
  echo "gogen not found, installing..."
  mkdir -p ~/.local/bin
  export PATH="$HOME/.local/bin:$PATH"
  curl -sSL https://raw.githubusercontent.com/idelchi/gogen/refs/heads/main/install.sh | sh -s -- -v v0.0.0 -d ~/.local/bin
fi

go install -buildvcs=false .

# Create and move to temporary directory
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cd "${TMPDIR}"

echo "🧪 Testing with DEFAULT KEY"

# Generate encryption key
gogen key >key
KEY=$(cat key)

# Create executable test file
cat >test.sh <<'EOF'
#!/bin/bash
# shellcheck disable=all
echo "Hello, I am executable!"
EOF
chmod +x test.sh

[[ -x "test.sh" ]] || (echo '❌ test: Initial file is not executable' && exit 1)

# Test default encryption/decryption
gonc -q -k "${KEY}" encrypt test.sh
[[ -f "test.sh.enc" ]] || (echo '❌ test: Encrypted file was not created' && exit 1)

gonc -q -k "${KEY}" --decrypt-ext .dec decrypt test.sh.enc
[[ -f "test.sh.dec" ]] || (echo '❌ test: Decrypted file was not created' && exit 1)
[[ -x "test.sh.dec" ]] || (echo '❌ test: Decrypted file lost executable bit' && exit 1)
cmp -s test.sh.dec test.sh || (echo '❌ test: File content changed' && exit 1)

# Test indeterministic encryption/decryption
gonc -q -k "${KEY}" encrypt test.sh
mv test.sh.enc test.sh.enc1
gonc -q -k "${KEY}" encrypt test.sh
mv test.sh.enc test.sh.enc2
gonc -q -k "${KEY}" encrypt test.sh
mv test.sh.enc test.sh.enc3

cmp -s test.sh.enc1 test.sh.enc2 && (echo '❌ File content did not change' && exit 1)
cmp -s test.sh.enc1 test.sh.enc3 && (echo '❌ File content did not change' && exit 1)
cmp -s test.sh.enc2 test.sh.enc3 && (echo '❌ File content did not change' && exit 1)

rm -f test.sh test.sh.enc test.sh.dec key test.sh.enc1 test.sh.enc2 test.sh.enc3

echo "🧪 Testing with LONG KEY (64 bytes) and deterministic mode"

export GONC_DETERMINISTIC=true

# Generate long key
gogen key -l 64 >key
KEY=$(cat key)

# Create executable test file
cat >test.sh <<'EOF'
#!/bin/bash
# shellcheck disable=all
echo "Hello, I am executable!"
EOF
chmod +x test.sh

[[ -x "test.sh" ]] || (echo '❌ test: Initial file is not executable' && exit 1)

# Test deterministic encryption/decryption
gonc -q -k "${KEY}" encrypt test.sh
[[ -f "test.sh.enc" ]] || (echo '❌ test: Encrypted file was not created' && exit 1)

gonc -q -k "${KEY}" --decrypt-ext .dec decrypt test.sh.enc
[[ -f "test.sh.dec" ]] || (echo '❌ test: Decrypted file was not created' && exit 1)
[[ -x "test.sh.dec" ]] || (echo '❌ test: Decrypted file lost executable bit' && exit 1)
cmp -s test.sh.dec test.sh || (echo '❌ test: File content changed' && exit 1)

rm -f test.sh test.sh.enc test.sh.dec key

export GONC_DETERMINISTIC=false

echo "🧪 Testing NON-EXECUTABLE with DEFAULT KEY"

# Generate key
gogen key >key
KEY=$(cat key)

# Create non-executable test file
cat >test2.sh <<'EOF'
# shellcheck disable=all
echo "Hello, I am NOT executable!"
EOF

[[ ! -x "test2.sh" ]] || (echo '❌ test: Initial file should not be executable' && exit 1)

# Test default encryption/decryption
gonc -q -k "${KEY}" encrypt test2.sh
[[ -f "test2.sh.enc" ]] || (echo '❌ test: Encrypted file was not created' && exit 1)

gonc -q -k "${KEY}" --decrypt-ext .dec decrypt test2.sh.enc
[[ -f "test2.sh.dec" ]] || (echo '❌ test: Decrypted file was not created' && exit 1)
[[ ! -x "test2.sh.dec" ]] || (echo '❌ test: Decrypted file should not be executable' && exit 1)
cmp -s test2.sh.dec test2.sh || (echo '❌ test: File content changed' && exit 1)

rm -f test2.sh test2.sh.enc test2.sh.dec key

echo "🧪 Testing NON-EXECUTABLE with LONG KEY (64 bytes) and deterministic mode"

export GONC_DETERMINISTIC=true

# Generate long key
gogen key -l 64 >key
KEY=$(cat key)

# Create non-executable test file
cat >test2.sh <<'EOF'
# shellcheck disable=all
echo "Hello, I am NOT executable!"
EOF

[[ ! -x "test2.sh" ]] || (echo '❌ test: Initial file should not be executable' && exit 1)

# Test deterministic encryption/decryption
gonc -q -k "${KEY}" encrypt test2.sh
[[ -f "test2.sh.enc" ]] || (echo '❌ test: Encrypted file was not created' && exit 1)

gonc -q -k "${KEY}" --decrypt-ext .dec decrypt test2.sh.enc
[[ -f "test2.sh.dec" ]] || (echo '❌ test: Decrypted file was not created' && exit 1)
[[ ! -x "test2.sh.dec" ]] || (echo '❌ test: Decrypted file should not be executable' && exit 1)
cmp -s test2.sh.dec test2.sh || (echo '❌ test: File content changed' && exit 1)

gonc -q -k "${KEY}" encrypt test2.sh
mv test2.sh.enc test.sh.enc1
gonc -q -k "${KEY}" encrypt test2.sh
mv test2.sh.enc test.sh.enc2
gonc -q -k "${KEY}" encrypt test2.sh
mv test2.sh.enc test.sh.enc3

cmp -s test.sh.enc1 test.sh.enc2 || (echo '❌ File content changed' && exit 1)
cmp -s test.sh.enc1 test.sh.enc3 || (echo '❌ File content changed' && exit 1)
cmp -s test.sh.enc2 test.sh.enc3 || (echo '❌ File content changed' && exit 1)

echo "✨ ALL TESTS PASSED ! ✨"

# jscpd:ignore-end
