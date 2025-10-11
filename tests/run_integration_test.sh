#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.
set -o pipefail # Fail a pipeline if any command fails

# --- Configuration ---
TEST_DIR="tests"
TARGET_SOURCE="$TEST_DIR/test_target.c"
TARGET_BINARY="$TEST_DIR/test_target"
PACKED_BINARY="$TEST_DIR/test_target_packed"
PACKER_SCRIPT="organull/organull.py"
EXPECTED_OUTPUT="Hello from the packed binary!"

# --- Helper Functions ---
info() {
    echo -e "\e[34m[INFO]\e[0m $1"
}

success() {
    echo -e "\e[32m[SUCCESS]\e[0m $1"
}

fail() {
    echo -e "\e[31m[FAIL]\e[0m $1" >&2
    exit 1
}

cleanup() {
    info "Cleaning up..."
    rm -f "$TARGET_BINARY" "$PACKED_BINARY"
    info "Cleanup complete."
}

# --- Main Test Logic ---
# trap cleanup EXIT # Register cleanup function to run on script exit

# 0. Create test directory
mkdir -p "$TEST_DIR"

# 1. Compile the test target
info "Compiling test target: $TARGET_SOURCE..."
# Use -no-pie to create a non-position-independent executable for simplicity
gcc -no-pie -o "$TARGET_BINARY" "$TARGET_SOURCE"
if [ ! -f "$TARGET_BINARY" ]; then
    fail "Test target compilation failed."
fi
success "Test target compiled: $TARGET_BINARY"

# 2. Run the packer
info "Packing the binary with default settings (debug stub)..."
python3 "$PACKER_SCRIPT" "$TARGET_BINARY" "$PACKED_BINARY" --debug-stub
if [ ! -f "$PACKED_BINARY" ]; then
    fail "Packing failed."
fi
success "Binary packed successfully: $PACKED_BINARY"

# 3. Make the packed binary executable
chmod +x "$PACKED_BINARY"

# 4. Run the packed binary and capture output
info "Executing packed binary and capturing output..."
# We add `|| true` to prevent `set -e` from exiting the script if the packed binary fails.
# This allows us to capture the empty output and properly report the test failure.
OUTPUT=$(./"$PACKED_BINARY" || true)

# 5. Verify the output
info "Verifying output..."
# Use printf to handle potential newline issues with echo
EXPECTED_OUTPUT_NL=$(printf "%s\n" "$EXPECTED_OUTPUT")
if [ "$OUTPUT" == "$EXPECTED_OUTPUT_NL" ]; then
    success "Output matches expected value."
else
    fail "Output mismatch! Expected: '$EXPECTED_OUTPUT_NL', Got: '$OUTPUT'"
fi

# --- Test Release Mode ---
info "--- Testing Release Mode ---"

# 1. Run packer in release mode
info "Packing the binary in release mode..."
python3 "$PACKER_SCRIPT" "$TARGET_BINARY" "$PACKED_BINARY"
if [ ! -f "$PACKED_BINARY" ]; then
    fail "Packing in release mode failed."
fi
success "Binary packed successfully in release mode: $PACKED_BINARY"

# 2. Make executable
chmod +x "$PACKED_BINARY"

# 3. Run and verify
info "Executing release-mode packed binary..."
OUTPUT_RELEASE=$(./"$PACKED_BINARY" || true)

info "Verifying release-mode output..."
if [ "$OUTPUT_RELEASE" == "$EXPECTED_OUTPUT_NL" ]; then
    success "Release mode output matches expected value."
else
    fail "Release mode output mismatch! Expected: '$EXPECTED_OUTPUT_NL', Got: '$OUTPUT_RELEASE'"
fi

success "All integration tests passed!"
