#!/bin/bash
set -euo pipefail

INPUT_FILE="test_files/file.txt"

# Generate a key for testing
KEY=$(./gonc generate)
echo "Using key: $KEY"

time ./gonc -k "$KEY" -j 1 enc --deterministic "$INPUT_FILE" "$INPUT_FILE" "$INPUT_FILE" "$INPUT_FILE" "$INPUT_FILE" "$INPUT_FILE" "$INPUT_FILE" "$INPUT_FILE"
time ./gonc -k "$KEY" -j 1 dec "$INPUT_FILE.enc"
