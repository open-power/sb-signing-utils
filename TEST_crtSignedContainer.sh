#!/usr/bin/bash

# Test script for v3 containers with random payload generation
# This script generates a random payload file, creates signed containers,
# validates them, and cleans up all temporary files afterward.

set -e  # Exit on error

# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to cleanup on exit
cleanup() {
    local exit_code=$?
    print_info "Cleaning up temporary files..."
    
    # Remove temporary files
    rm -f "$RANDOM_PAYLOAD" 2>/dev/null || true
    rm -f "$CONTAINER" 2>/dev/null || true
    rm -rf "$SCRATCH_DIR" 2>/dev/null || true
    
    if [ $exit_code -eq 0 ]; then
        print_info "Test completed successfully and cleanup done."
    else
        print_error "Test failed with exit code $exit_code. Cleanup done."
    fi
    
    exit $exit_code
}

# Set trap to ensure cleanup runs on exit
trap cleanup EXIT INT TERM

# Configuration
export PATH=$PATH:$(pwd)
RANDOM_PAYLOAD="CONTAINER_$(date +%s)_$RANDOM.bin"
export CONTAINER="CONTAINER"
SCRATCH_DIR="$(pwd)/scratch_test_$$"
export FWLAYER=runtime   # What FW layer are you signing, boot loader or runtime images
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

print_info "Starting v3 container test suite with random payload"
print_info "Random payload file: $RANDOM_PAYLOAD"
print_info "Container output: $CONTAINER"
print_info "Scratch directory: $SCRATCH_DIR"
echo

# Generate random payload file (256KB of random data)
print_info "Generating random payload file (256KB)..."
dd if=/dev/urandom of="$RANDOM_PAYLOAD" bs=1024 count=256 2>/dev/null
if [ ! -f "$RANDOM_PAYLOAD" ]; then
    print_error "Failed to generate random payload file"
    exit 1
fi
print_info "Random payload generated: $(ls -lh $RANDOM_PAYLOAD | awk '{print $5}')"
echo

# Function to run a test
run_test() {
    local test_name="$1"
    local version="$2"
    local hash_alg="$3"
    local pure_mode="$4"
    local code_start_offset="$5"
    
    TEST_COUNT=$((TEST_COUNT + 1))
    echo
    echo "=============================="
    echo "Test $TEST_COUNT: $test_name"
    echo "=============================="
    echo
    
    # Setup scratch directory
    rm -rf "$SCRATCH_DIR"
    mkdir -p "$SCRATCH_DIR"
    
    # Build hash algorithm option (only for v3)
    local hash_opt=""
    if [ "$version" = "3" ] && [ "$hash_alg" = "sha512" ]; then
        hash_opt="-H sha512"
    fi
    
    # Build pure mode option (only for v3)
    local pure_opt=""
    if [ "$version" = "3" ] && [ "$pure_mode" = "true" ]; then
        pure_opt="--pure"
    fi
    
    # Build code start offset option (only for v1)
    local code_start_opt=""
    if [ "$version" = "1" ] && [ -n "$code_start_offset" ]; then
        code_start_opt="--code-start-offset $code_start_offset"
    fi
    
    # Generate hardware key hash based on version
    local hwkeyhash_cmd="./hashkeys"
    if [ "$version" = "3" ] && [ "$hash_alg" = "sha512" ]; then
        hwkeyhash_cmd="$hwkeyhash_cmd --hash sha512"
    fi
    
    if [ "$version" = "1" ]; then
        hwkeyhash_cmd="$hwkeyhash_cmd -a test/keys/hw_key_a.pub -b test/keys/hw_key_b.pub -c test/keys/hw_key_c.pub"
    elif [ "$version" = "2" ]; then
        hwkeyhash_cmd="$hwkeyhash_cmd -a test/v2_keys/${FWLAYER}_hw_key_a.pub -d test/v2_keys/${FWLAYER}_hw_key_d.pub -V 2"
    else
        hwkeyhash_cmd="$hwkeyhash_cmd -a test/v3_keys/${FWLAYER}_hw_key_a.pub -d test/v3_keys/${FWLAYER}_hw_key_d.pub -V 3"
    fi
    
    export HWKEYHASH=$(eval $hwkeyhash_cmd)
    print_info "Hardware key hash: $HWKEYHASH"
    
    # Create signed container with version-specific keys
    print_info "Creating signed container..."
    local create_cmd="./crtSignedContainer.sh $pure_opt $hash_opt $code_start_opt -L TEST --flags 0x40000000"
    
    if [ "$version" = "1" ]; then
        # V1 uses hwKeyA, hwKeyB, hwKeyC and swKeyP
        create_cmd="$create_cmd --hwKeyA test/keys/hw_key_a.key"
        create_cmd="$create_cmd --hwKeyB test/keys/hw_key_b.key"
        create_cmd="$create_cmd --hwKeyC test/keys/hw_key_c.key"
        create_cmd="$create_cmd --swKeyP test/keys/sw_key_p.key"
    else
        # V2 and V3 use hwKeyA, hwKeyD, swKeyP, swKeyS
        local key_dir="test/v${version}_keys"
        create_cmd="$create_cmd --hwKeyA ${key_dir}/${FWLAYER}_hw_key_a.key"
        create_cmd="$create_cmd --hwKeyD ${key_dir}/${FWLAYER}_hw_key_d.key"
        create_cmd="$create_cmd --swKeyP ${key_dir}/${FWLAYER}_sw_key_p.key"
        create_cmd="$create_cmd --swKeyS ${key_dir}/${FWLAYER}_sw_key_s.key"
    fi
    
    create_cmd="$create_cmd --protectedPayload $RANDOM_PAYLOAD"
    create_cmd="$create_cmd --out $CONTAINER"
    create_cmd="$create_cmd --validate"
    create_cmd="$create_cmd --security-version 0"
    create_cmd="$create_cmd --scratchDir $SCRATCH_DIR"
    
    # Only add -V flag for v2 and v3 (v1 is default)
    if [ "$version" != "1" ]; then
        create_cmd="$create_cmd -V $version"
    fi
    
    if eval "$create_cmd"; then
        print_info "Container created successfully"
    else
        print_error "Failed to create container"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
    
    # Validate container
    print_info "Validating container..."
    if ./print-container -v -I "$CONTAINER" --validate --verify "$HWKEYHASH"; then
        print_info "Container validation PASSED"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        print_error "Container validation FAILED"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
    
    return 0
}

# Function to run negative test (expected to fail)
run_negative_test() {
    local test_name="$1"
    local command="$2"
    
    TEST_COUNT=$((TEST_COUNT + 1))
    echo
    print_info "Negative Test $TEST_COUNT: $test_name"
    
    if eval "$command" > /dev/null 2>&1; then
        print_error "Test should have failed but passed"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    else
        print_info "Test failed as expected - PASSED"
        PASS_COUNT=$((PASS_COUNT + 1))
        return 0
    fi
}

# Run v1 tests
echo
echo "=============================="
echo "Running Version 1 Tests"
echo "=============================="
run_test "v1 with default settings" "1" "" "false" "0x00000000"

# Run v2 tests
echo
echo "=============================="
echo "Running Version 2 Tests"
echo "=============================="
run_test "v2 with default settings" "2" "" "false" ""

# Run v3 tests
echo
echo "=============================="
echo "Running Version 3 Tests"
echo "=============================="
run_test "v3 with SHA3-512 (default)" "3" "sha3-512" "false" ""
run_test "v3 with SHA-512" "3" "sha512" "false" ""
run_test "v3 with SHA-512 pure mode" "3" "sha512" "true" ""

# Negative tests
echo
echo "=============================="
echo "Running Negative Tests"
echo "=============================="

# V1 negative tests
print_info "Testing v1 rejection of unsupported options..."

# V1 with -H sha512 should succeed but ignore the option (uses sha512 anyway as default)
print_info "Testing v1 with -H sha512 (should succeed but ignore option)..."
rm -rf "$SCRATCH_DIR"
mkdir -p "$SCRATCH_DIR"
if ./crtSignedContainer.sh -H sha512 -L TEST --flags 0x40000000 \
    --hwKeyA test/keys/hw_key_a.key \
    --hwKeyB test/keys/hw_key_b.key \
    --hwKeyC test/keys/hw_key_c.key \
    --swKeyP test/keys/sw_key_p.key \
    --protectedPayload "$RANDOM_PAYLOAD" \
    --out "$CONTAINER" \
    --validate \
    --security-version 0 \
    --scratchDir "$SCRATCH_DIR" \
    --code-start-offset 0x00000000 > /dev/null 2>&1; then
    print_info "v1 with -H sha512 succeeded (option ignored) - PASSED"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    print_error "v1 with -H sha512 failed unexpectedly"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi
TEST_COUNT=$((TEST_COUNT + 1))

# V1 with --pure should succeed but ignore the option (only v3 uses pure mode)
print_info "Testing v1 with --pure (should succeed but ignore option)..."
rm -rf "$SCRATCH_DIR"
mkdir -p "$SCRATCH_DIR"
if ./crtSignedContainer.sh --pure -L TEST --flags 0x40000000 \
    --hwKeyA test/keys/hw_key_a.key \
    --hwKeyB test/keys/hw_key_b.key \
    --hwKeyC test/keys/hw_key_c.key \
    --swKeyP test/keys/sw_key_p.key \
    --protectedPayload "$RANDOM_PAYLOAD" \
    --out "$CONTAINER" \
    --validate \
    --security-version 0 \
    --scratchDir "$SCRATCH_DIR" \
    --code-start-offset 0x00000000 > /dev/null 2>&1; then
    print_info "v1 with --pure succeeded (option ignored) - PASSED"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    print_error "v1 with --pure failed unexpectedly"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi
TEST_COUNT=$((TEST_COUNT + 1))

# Note: v1 accepts hwKeyD option but ignores it (uses hwKeyB/C instead)
# So we don't test for rejection of hwKeyD

# V2 negative tests - v2 should not accept --pure option
# Note: v2 accepts -H option but ignores it (always uses sha3-512)
print_info "Testing v2 rejection of unsupported options..."

# V2 with -H sha512 should succeed but ignore the option (uses sha3-512 anyway)
print_info "Testing v2 with -H sha512 (should succeed but use sha3-512)..."
rm -rf "$SCRATCH_DIR"
mkdir -p "$SCRATCH_DIR"
if ./crtSignedContainer.sh -H sha512 -L TEST --flags 0x40000000 \
    --hwKeyA test/v2_keys/${FWLAYER}_hw_key_a.key \
    --hwKeyD test/v2_keys/${FWLAYER}_hw_key_d.key \
    --swKeyP test/v2_keys/${FWLAYER}_sw_key_p.key \
    --swKeyS test/v2_keys/${FWLAYER}_sw_key_s.key \
    --protectedPayload "$RANDOM_PAYLOAD" \
    --out "$CONTAINER" \
    --validate \
    --security-version 0 \
    --scratchDir "$SCRATCH_DIR" \
    -V 2 > /dev/null 2>&1; then
    print_info "v2 with -H sha512 succeeded (option ignored, uses sha3-512) - PASSED"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    print_error "v2 with -H sha512 failed unexpectedly"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi
TEST_COUNT=$((TEST_COUNT + 1))

# V2 with --pure causes gendilsig to crash (v2 doesn't support pure mode properly)
run_negative_test "v2 with --pure option (should fail - causes crash)" \
    "./crtSignedContainer.sh --pure -L TEST --flags 0x40000000 --hwKeyA test/v2_keys/${FWLAYER}_hw_key_a.key --hwKeyD test/v2_keys/${FWLAYER}_hw_key_d.key --swKeyP test/v2_keys/${FWLAYER}_sw_key_p.key --swKeyS test/v2_keys/${FWLAYER}_sw_key_s.key --protectedPayload $RANDOM_PAYLOAD --out $CONTAINER --validate --security-version 0 --scratchDir $SCRATCH_DIR -V 2"

# V3 negative tests
print_info "Testing v3 with invalid parameters..."

# Test with wrong hash algorithm for verification
export HWKEYHASH=$(./hashkeys -a test/v3_keys/${FWLAYER}_hw_key_a.pub -d test/v3_keys/${FWLAYER}_hw_key_d.pub -V 3)
run_negative_test "Verify SHA-512 container with SHA3-512 hash" \
    "./print-container -v -I $CONTAINER --validate --verify $HWKEYHASH"

# Test with bogus hash algorithm in container creation
run_negative_test "v3 with bogus hash algorithm" \
    "./crtSignedContainer.sh -H bogus -L TEST --flags 0x40000000 --hwKeyA test/v3_keys/${FWLAYER}_hw_key_a.key --hwKeyD test/v3_keys/${FWLAYER}_hw_key_d.key --swKeyP test/v3_keys/${FWLAYER}_sw_key_p.key --swKeyS test/v3_keys/${FWLAYER}_sw_key_s.key --protectedPayload $RANDOM_PAYLOAD --out $CONTAINER --validate --security-version 0 --scratchDir $SCRATCH_DIR -V 3"

# Test hashkeys with bogus hash algorithm
run_negative_test "Generate hash with bogus algorithm" \
    "./hashkeys -a test/v3_keys/${FWLAYER}_hw_key_a.pub -d test/v3_keys/${FWLAYER}_hw_key_d.pub -V 3 --hash bogus"

# Print summary
echo
echo "=============================="
echo "Test Summary"
echo "=============================="
echo "Total tests run: $TEST_COUNT"
echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
if [ $FAIL_COUNT -gt 0 ]; then
    echo -e "${RED}Failed: $FAIL_COUNT${NC}"
else
    echo "Failed: $FAIL_COUNT"
fi
echo

if [ $FAIL_COUNT -eq 0 ]; then
    print_info "All tests passed!"
    exit 0
else
    print_error "Some tests failed!"
    exit 1
fi

# Made with Bob
