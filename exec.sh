#!/bin/bash
set -euo pipefail

# cd to script directory
cd "$(dirname "$0")"
git config --global --add safe.directory "*"
go install ./...

rm -rf __tmp__
mkdir __tmp__
cd __tmp__

gonc generate > key

KEY=$(cat key)

# Create a test executable file
cat > test.sh << 'EOF'
#!/bin/bash
echo "Hello, I am executable!"
EOF

# Make it executable
chmod +x test.sh

# Verify initial executable status
if [ -x "test.sh" ]; then
    echo "✓ Initial file is executable"
else
    echo "✗ Failed: Initial file is not executable"
    exit 1
fi

# Encrypt the file
# Assuming your binary is called 'gonc' and in PATH
# Replace with actual path if needed
gonc -k "${KEY}" encrypt test.sh

# Verify encrypted file was created
if [ ! -f "test.sh.enc" ]; then
    echo "✗ Failed: Encrypted file was not created"
    exit 1
fi

# Decrypt the file
gonc -k "${KEY}" --decrypt-ext .dec decrypt test.sh.enc


# Verify decrypted file was created
if [ ! -f "test.sh.dec" ]; then
    echo "✗ Failed: Decrypted file was not created"
    exit 1
fi

# Verify executable bit was preserved
if [ -x "test.sh.dec" ]; then
    echo "✓ Decrypted file is still executable"
else
    echo "✗ Failed: Decrypted file lost executable bit"
    exit 1
fi

if cmp -s test.sh.dec test.sh; then
    echo "✓ File content preserved correctly"
else
    echo "✗ Failed: File content changed"
    exit 1
fi

# Cleanup
# rm -f test.sh test.sh.enc test.sh test.sh.dec

echo "All tests passed!"
