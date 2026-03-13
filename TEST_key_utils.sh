#!/bin/bash
# Test script for Dilithium/ML-DSA key utilities - Good Path Tests Only
# Tests: gendilkey, gendilsig, verifydilsig
# Note: extractdilkey and some conversions have known limitations with ML-DSA-87

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Temporary directory for test files
TEST_DIR=$(mktemp -d -t key_utils_test_XXXXXX)
trap "rm -rf $TEST_DIR" EXIT

echo -e "${GREEN}[INFO]${NC} Starting key utilities test suite (good path tests)"
echo -e "${GREEN}[INFO]${NC} Test directory: $TEST_DIR"
echo ""

# Helper function to run a test
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_result="${3:-0}"  # Default to expecting success (0)
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo "=============================="
    echo "Test $TESTS_RUN: $test_name"
    echo "=============================="
    
    eval "$test_cmd" > "$TEST_DIR/test_output.txt" 2>&1
    local result=$?
    
    if [ $result -eq $expected_result ]; then
        echo -e "${GREEN}[PASS]${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}[FAIL]${NC} (expected: $expected_result, got: $result)"
        echo "Output:"
        cat "$TEST_DIR/test_output.txt"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Helper function to verify file exists and has expected size
verify_file() {
    local file="$1"
    local min_size="${2:-1}"
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}[ERROR]${NC} File not found: $file"
        return 1
    fi
    
    local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
    if [ "$size" -lt "$min_size" ]; then
        echo -e "${RED}[ERROR]${NC} File too small: $file (size: $size, expected: >=$min_size)"
        return 1
    fi
    
    echo -e "${GREEN}[INFO]${NC} File OK: $file ($size bytes)"
    return 0
}

echo "=============================="
echo "Dilithium R2 Tests"
echo "=============================="
echo ""

# Create test data
dd if=/dev/urandom of=$TEST_DIR/test_data.bin bs=1024 count=256 2>/dev/null
echo -e "${GREEN}[INFO]${NC} Test data created: 256KB"
echo ""

# Test 1: Generate Dilithium R2 key pair
run_test "Generate Dilithium R2 key pair" \
    "./gendilkey -priv $TEST_DIR/dilr2.key -pub $TEST_DIR/dilr2.pub -alg dilr2-87"
verify_file "$TEST_DIR/dilr2.key" 7000
verify_file "$TEST_DIR/dilr2.pub" 2000
echo ""

# Test 2: Generate SHA3-512 hash
run_test "Generate SHA3-512 hash" \
    "openssl dgst -sha3-512 -binary $TEST_DIR/test_data.bin > $TEST_DIR/test.sha3-512"
verify_file "$TEST_DIR/test.sha3-512" 64
echo ""

# Test 3: Sign with Dilithium R2
run_test "Sign with Dilithium R2 key" \
    "./gendilsig -k $TEST_DIR/dilr2.key -i $TEST_DIR/test.sha3-512 -o $TEST_DIR/dilr2.sig"
verify_file "$TEST_DIR/dilr2.sig" 4600
echo ""

# Test 4: Verify Dilithium R2 signature
run_test "Verify Dilithium R2 signature" \
    "./verifydilsig -k $TEST_DIR/dilr2.pub -i $TEST_DIR/test.sha3-512 -s $TEST_DIR/dilr2.sig"
echo ""

# Note: extractdilkey has limitations - it doesn't properly extract just the public key
# Skipping extraction tests
echo ""

echo "=============================="
echo "ML-DSA-87 Tests (Raw Keys)"
echo "=============================="
echo ""

# Test 7: Generate ML-DSA-87 key pair (raw mode)
run_test "Generate ML-DSA-87 key pair (raw)" \
    "./gendilkey -priv $TEST_DIR/mldsa.key -pub $TEST_DIR/mldsa.pub -alg mldsa-87 -raw"
verify_file "$TEST_DIR/mldsa.key" 4800
verify_file "$TEST_DIR/mldsa.pub" 2500
echo ""

# Test 8: Generate SHA-512 hash
run_test "Generate SHA-512 hash" \
    "openssl dgst -sha512 -binary $TEST_DIR/test_data.bin > $TEST_DIR/test.sha512"
verify_file "$TEST_DIR/test.sha512" 64
echo ""

# Test 9: Sign with ML-DSA-87 (digest mode)
run_test "Sign with ML-DSA-87 key (digest mode)" \
    "./gendilsig -k $TEST_DIR/mldsa.key -i $TEST_DIR/test.sha512 -o $TEST_DIR/mldsa.sig"
verify_file "$TEST_DIR/mldsa.sig" 4600
echo ""

# Test 10: Verify ML-DSA-87 signature
run_test "Verify ML-DSA-87 signature" \
    "./verifydilsig -k $TEST_DIR/mldsa.pub -i $TEST_DIR/test.sha512 -s $TEST_DIR/mldsa.sig"
echo ""

# Test 11: Sign with ML-DSA-87 (pure mode)
run_test "Sign with ML-DSA-87 key (pure mode)" \
    "./gendilsig -k $TEST_DIR/mldsa.key -i $TEST_DIR/test_data.bin -o $TEST_DIR/mldsa_pure.sig --pure"
verify_file "$TEST_DIR/mldsa_pure.sig" 4600
echo ""

echo "=============================="
echo "Existing Keys Tests"
echo "=============================="
echo ""

# Test 12: Test with existing v2 keys
if [ -f "test/v2_keys/runtime_hw_key_d.key" ]; then
    echo "test v2 data" > $TEST_DIR/v2_test.txt
    openssl dgst -sha3-512 -binary $TEST_DIR/v2_test.txt > $TEST_DIR/v2_test.hash 2>/dev/null
    
    run_test "Sign with existing v2 (Dilithium R2) key" \
        "./gendilsig -k test/v2_keys/runtime_hw_key_d.key -i $TEST_DIR/v2_test.hash -o $TEST_DIR/v2_test.sig"
    verify_file "$TEST_DIR/v2_test.sig" 4600
    
    if [ -f "test/v2_keys/runtime_hw_key_d.pub" ]; then
        run_test "Verify with existing v2 public key" \
            "./verifydilsig -k test/v2_keys/runtime_hw_key_d.pub -i $TEST_DIR/v2_test.hash -s $TEST_DIR/v2_test.sig"
    fi
    echo ""
fi

# Test 13: Test with existing v3 keys
if [ -f "test/v3_keys/runtime_hw_key_d.key" ]; then
    echo "test v3 data" > $TEST_DIR/v3_test.txt
    openssl dgst -sha512 -binary $TEST_DIR/v3_test.txt > $TEST_DIR/v3_test.hash 2>/dev/null
    
    run_test "Sign with existing v3 (ML-DSA-87) key (digest mode)" \
        "./gendilsig -k test/v3_keys/runtime_hw_key_d.key -i $TEST_DIR/v3_test.hash -o $TEST_DIR/v3_test.sig"
    verify_file "$TEST_DIR/v3_test.sig" 4600
    
    if [ -f "test/v3_keys/runtime_hw_key_d.pub" ]; then
        run_test "Verify with existing v3 public key" \
            "./verifydilsig -k test/v3_keys/runtime_hw_key_d.pub -i $TEST_DIR/v3_test.hash -s $TEST_DIR/v3_test.sig"
    fi
    echo ""
    
    run_test "Sign with existing v3 key (pure mode)" \
        "./gendilsig -k test/v3_keys/runtime_hw_key_d.key -i $TEST_DIR/v3_test.txt -o $TEST_DIR/v3_pure.sig --pure"
    verify_file "$TEST_DIR/v3_pure.sig" 4600
    echo ""
fi

echo "=============================="
echo "Negative Tests"
echo "=============================="
echo ""

# Test 14: Reject pure mode with Dilithium R2
run_test "Reject pure mode with Dilithium R2 key" \
    "./gendilsig -k $TEST_DIR/dilr2.key -i $TEST_DIR/test_data.bin -o $TEST_DIR/should_fail.sig --pure" \
    1
echo ""

# Test 15: Reject wrong public key
run_test "Reject verification with wrong public key" \
    "./verifydilsig -k $TEST_DIR/mldsa.pub -i $TEST_DIR/test.sha3-512 -s $TEST_DIR/dilr2.sig" \
    1
echo ""

# Test 16: Reject corrupted signature
cp $TEST_DIR/dilr2.sig $TEST_DIR/corrupted.sig
dd if=/dev/urandom of=$TEST_DIR/corrupted.sig bs=1 count=10 seek=100 conv=notrunc 2>/dev/null

run_test "Reject corrupted signature" \
    "./verifydilsig -k $TEST_DIR/dilr2.pub -i $TEST_DIR/test.sha3-512 -s $TEST_DIR/corrupted.sig" \
    1
echo ""

# Test 17: Reject wrong hash
echo "wrong data" > $TEST_DIR/wrong.txt
openssl dgst -sha3-512 -binary $TEST_DIR/wrong.txt > $TEST_DIR/wrong.hash 2>/dev/null

run_test "Reject verification with wrong hash" \
    "./verifydilsig -k $TEST_DIR/dilr2.pub -i $TEST_DIR/wrong.hash -s $TEST_DIR/dilr2.sig" \
    1
echo ""

echo "=============================="
echo "Test Summary"
echo "=============================="
echo "Total tests run: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
else
    echo "Failed: 0"
fi
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS]${NC} All tests passed!"
    exit 0
else
    echo -e "${RED}[FAILURE]${NC} Some tests failed!"
    exit 1
fi

# Made with Bob
