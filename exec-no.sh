#!/bin/bash
set -euo pipefail

# cd to script directory
cd "$(dirname "$0")"
git config --global --add safe.directory "*"
go install ./...

rm -rf __tmp__
mkdir __tmp__
cd __tmp__

KEY=$(gonc generate)

# Create a test executable file
cat > test2.sh << 'EOF'
echo "Hello, I am NOT executable!"
EOF

# Verify initial executable status
if [ -x "test2.sh" ]; then
    echo "✗ Failed: Initial file is executable"
    exit 1

else
    echo "✓ Initial file is not executable"
fi

# Encrypt the file
# Assuming your binary is called 'gonc' and in PATH
# Replace with actual path if needed
gonc -k "${KEY}" encrypt test2.sh

# Verify encrypted file was created
if [ ! -f "test2.sh.enc" ]; then
    echo "✗ Failed: Encrypted file was not created"
    exit 1
fi

# Decrypt the file
gonc --decrypt-ext .dec -k "${KEY}" decrypt test2.sh.enc

# Verify decrypted file was created
if [ ! -f "test2.sh.dec" ]; then
    echo "✗ Failed: Decrypted file was not created"
    exit 1
fi

# Verify executable bit was preserved
if [ -x "test2.sh.dec" ]; then
    echo "✗ Failed: Decrypted file is executable"
    exit 1
else
    echo "✓ Decrypted file has no executable bit"
fi

if cmp -s test2.sh.dec test2.sh; then
    echo "✓ File content preserved correctly"
else
    echo "✗ Failed: File content changed"
    exit 1
fi
