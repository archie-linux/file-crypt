#!/bin/bash

# Script to create dummy files and directories with dummy text for testing FileCrypt
# Run from /Users/anish/anpa6841/github-projects/file-crypt
# Creates files in uploads/encrypted_files/

set -e

# Define directories
BASE_DIR="/Users/anish/anpa6841/github-projects/file-crypt"
TEST_DIR="$BASE_DIR/test_data"

# Create directories
mkdir -p "$TEST_DIR"

# Create 10 dummy files with content
for i in {1..10}; do
  echo "This is dummy file $i content" > "$TEST_DIR/dummy$i.txt"
done

echo "Dummy files created successfully!"
