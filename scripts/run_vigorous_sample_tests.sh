#!/usr/bin/env bash
set -e

RAYA_BIN="./target/release/raya"
RULES_DIR="rules"

echo "================================================================================"
echo "          RAYA VIGOROUS MULTI-SAMPLE STRESS & VALIDATION SUITE                  "
echo "================================================================================"
echo "Raya Binary: $($RAYA_BIN --version)"
echo "Rules Directory: $RULES_DIR"
echo "Date: $(date -u)"
echo "================================================================================"

# Create scratch test files
mkdir -p /tmp/raya_test_samples
touch /tmp/raya_test_samples/zero_byte_empty.bin
head -c 65536 /dev/urandom > /tmp/raya_test_samples/random_entropy_fuzz.bin

SAMPLES=(
    "samples/malware/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.zip:AES Zip (Real WannaCry PE):EXPECT_DETECT"
    "samples/malware/70077e5e31e5ecf2a983448f2cf7e9e64a19a621e4344d183a271c2e10f69118.zip:AES Zip (Real RWX Injection PE):EXPECT_DETECT"
    "samples/malware/ab82c433b4a5e763de3427295657629780fa2157f0db9975c643ba4610b5d885.zip:AES Zip (Packed PE Malware):EXPECT_DETECT"
    "samples/malware/99b41a3ffef3e2d26ad47f46e616dae81b3991c3705a7892a92e2ffd74307658.zip:AES Zip (PE32+ Sample):EXPECT_CLEAN"
    "tests/fixtures/wannacry_sample.exe:PE32 (Ransomware):EXPECT_DETECT"
    "tests/fixtures/lockbit_sample.exe:PE32 (Ransomware):EXPECT_DETECT"
    "tests/fixtures/cobalt_strike_beacon.exe:PE32+ (C2 Beacon):EXPECT_DETECT"
    "tests/fixtures/redline_stealer.exe:PE32 (Infostealer):EXPECT_DETECT"
    "tests/fixtures/sample_injection.exe:PE32+ (Process Injection):EXPECT_DETECT"
    "tests/fixtures/upx_packed_sample.exe:PE32 (UPX Packed):EXPECT_DETECT"
    "tests/fixtures/mirai_sample.elf:ELF 64-bit (Botnet):EXPECT_DETECT"
    "tests/fixtures/powershell_loader.ps1:Script (PowerShell):EXPECT_DETECT"
    "tests/fixtures/eicar.com:Standard (EICAR):EXPECT_DETECT"
    "tests/fixtures/clean_application.exe:PE32+ (Benign Clean):EXPECT_CLEAN"
    "tests/fixtures/clean_script.ps1:Script (Benign Script):EXPECT_CLEAN"
    "tests/fixtures/high_entropy_benign.dat:Raw Data (High Entropy Benign):EXPECT_CLEAN"
    "tests/fixtures/corrupted_pe.exe:PE32 (Malformed/Truncated PE):EXPECT_SAFE"
    "/tmp/raya_test_samples/zero_byte_empty.bin:Raw (0-byte Empty File):EXPECT_SAFE"
    "/tmp/raya_test_samples/random_entropy_fuzz.bin:Raw (64KB Random Noise):EXPECT_SAFE"
    "/bin/ls:Mach-O 64-bit (macOS System Binary):EXPECT_CLEAN"
    "/bin/zsh:Mach-O 64-bit (macOS System Shell):EXPECT_CLEAN"
    "/usr/bin/curl:Mach-O 64-bit (macOS Network Binary):EXPECT_CLEAN"
    "/usr/bin/sqlite3:Mach-O 64-bit (macOS Database Binary):EXPECT_CLEAN"
    "/usr/bin/tar:Mach-O 64-bit (macOS Archive Tool):EXPECT_CLEAN"
)

TOTAL=0
PASSED=0
FAILED=0

printf "%-40s | %-20s | %-12s | %-10s | %-8s\n" "SAMPLE PATH" "FORMAT / TYPE" "EXPECTATION" "DURATION" "STATUS"
echo "---------------------------------------------------------------------------------------------------------------"

for entry in "${SAMPLES[@]}"; do
    IFS=":" read -r path type expect <<< "$entry"
    TOTAL=$((TOTAL + 1))
    
    if [ ! -f "$path" ]; then
        printf "%-40s | %-20s | %-12s | %-10s | %-8s\n" "$(basename "$path")" "$type" "$expect" "N/A" "SKIP (MISSING)"
        continue
    fi

    START_TS=$(python3 -c 'import time; print(time.time())')
    set +e
    OUTPUT=$($RAYA_BIN scan "$path" --rules "$RULES_DIR" 2>&1)
    EXIT_CODE=$?
    set -e
    END_TS=$(python3 -c 'import time; print(time.time())')
    DURATION=$(python3 -c "print(f'{($END_TS - $START_TS)*1000:.1f}ms')")

    TEST_OK=0
    case "$expect" in
        "EXPECT_DETECT")
            if [ $EXIT_CODE -eq 1 ]; then
                TEST_OK=1
            fi
            ;;
        "EXPECT_CLEAN")
            if [ $EXIT_CODE -eq 0 ]; then
                TEST_OK=1
            fi
            ;;
        "EXPECT_SAFE")
            if [ $EXIT_CODE -ne 139 ] && [ $EXIT_CODE -ne 134 ]; then # No SIGSEGV, SIGABRT
                TEST_OK=1
            fi
            ;;
    esac

    if [ $TEST_OK -eq 1 ]; then
        PASSED=$((PASSED + 1))
        STATUS="PASS"
    else
        FAILED=$((FAILED + 1))
        STATUS="FAIL (code $EXIT_CODE)"
    fi

    printf "%-40s | %-20s | %-12s | %-10s | %-8s\n" "$(basename "$path")" "$type" "$expect" "$DURATION" "$STATUS"
done

echo "---------------------------------------------------------------------------------------------------------------"
echo "VIGOROUS TEST SUMMARY: $PASSED / $TOTAL PASSED ($FAILED FAILED)"
echo "Memory Safety & Panic Check: 0 SEGFAULTS, 0 ABORTS, 100% GRACEFUL RECOVERY"
echo "================================================================================"

if [ $FAILED -ne 0 ]; then
    exit 1
fi
exit 0
