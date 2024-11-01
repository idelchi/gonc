#!/bin/bash
set -euo pipefail

# Configuration
TEST_DIR="test_files"
NUM_FILES=50
MIN_LINES=1000
MAX_LINES=2000

# Create test directory
mkdir -p "$TEST_DIR"

generate_content() {
    local num_lines=$1
    # Mix of patterns to create somewhat realistic content
    for ((i=1; i<=num_lines; i++)); do
        case $((RANDOM % 4)) in
            0) # JSON-like content
                echo "{\"id\": $i, \"data\": \"$(openssl rand -hex 16)\", \"timestamp\": $(date +%s)}"
                ;;
            1) # Log-like content
                echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [INFO] Process $i: $(openssl rand -hex 32)"
                ;;
            2) # CSV-like content
                echo "$i,$(openssl rand -hex 8),$(openssl rand -hex 8),$(date +%s)"
                ;;
            3) # Text-like content
                echo "Line $i: $(openssl rand -base64 32)"
                ;;
        esac
    done
}

# Generate files
for i in $(seq 1 "$NUM_FILES"); do
    # Random number of lines between MIN_LINES and MAX_LINES
    num_lines=$((RANDOM % (MAX_LINES - MIN_LINES + 1) + MIN_LINES))

    filename="$TEST_DIR/file_${i}.txt"
    echo "Generating $filename with $num_lines lines..."
    generate_content "$num_lines" > "$filename"
done

# Print statistics
echo "Generated $NUM_FILES files in $TEST_DIR"
echo "File sizes:"
du -h "$TEST_DIR"/* | sort -h

# Create a test script for encryption
cat > test_encryption.sh << 'EOF'
#!/bin/bash
set -euo pipefail

# Generate a key for testing
KEY=$(./gonc generate)
echo "Using key: $KEY"

# Test functions
test_encryption() {
    local mode=$1
    local parallel=$2

    echo "Testing $mode encryption with -j $parallel"
    time ./gonc -k "$KEY" -j "$parallel" enc $([[ "$mode" == "deterministic" ]] && echo "-d") "$TEST_DIR"/*

    echo "Testing decryption with -j $parallel"
    time ./gonc -k "$KEY" -j "$parallel" dec "$TEST_DIR"/*.enc

    # Cleanup
    rm -f "$TEST_DIR"/*.enc "$TEST_DIR"/*.dec
}

# Run tests
echo "Starting tests..."
echo "=== Non-deterministic ==="
test_encryption "normal" 1
test_encryption "normal" 4
test_encryption "normal" 8

echo "=== Deterministic ==="
test_encryption "deterministic" 1
test_encryption "deterministic" 4
test_encryption "deterministic" 8
EOF

chmod +x test_encryption.sh

echo "Setup complete. Run ./test_encryption.sh to test encryption performance"
