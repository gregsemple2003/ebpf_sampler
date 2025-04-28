#!/bin/bash

# set -e # Commenting out set -e for investigation
set -u

echo "===== Perf SymFS Investigation Script ====="
echo "Timestamp: $(date)"
echo ""

# --- Configuration ---
PERF_SYM_DIR="perf_syms"        # The directory where push_symbols.sh placed files
PERF_DATA_FILE="perf.data"      # Assumed name of the perf data file
# Resolve custom perf path carefully
EFFECTIVE_HOME="$HOME"
if [ "$(id -u)" -eq 0 ]; then EFFECTIVE_HOME="/root"; fi
CUSTOM_PERF_PATH="$EFFECTIVE_HOME/WSL2-Linux-Kernel/tools/perf/perf"

ASSEMBLY_SO="GameAssembly.so"

# --- Prerequisite Checks ---
echo "--- Prerequisite Checks ---"
echo "Current Directory: $(pwd)"
echo "Checking for custom perf: $CUSTOM_PERF_PATH"
if [ ! -x "$CUSTOM_PERF_PATH" ]; then
    echo "ERROR: Custom perf executable not found or not executable at '$CUSTOM_PERF_PATH'"
    exit 1
else
    echo "Custom perf found."
fi

echo "Checking for '$PERF_DATA_FILE':"
if [ ! -f "$PERF_DATA_FILE" ]; then
    echo "ERROR: '$PERF_DATA_FILE' not found. Cannot proceed with report checks."
    exit 1
else
    echo "'$PERF_DATA_FILE' found."
fi

echo "Checking for symbol directory '$PERF_SYM_DIR':"
if [ ! -d "$PERF_SYM_DIR" ]; then
    echo "ERROR: Symbol directory '$PERF_SYM_DIR' not found."
    exit 1
else
    echo "Symbol directory '$PERF_SYM_DIR' found."
fi
echo "---------------------------"
echo ""

# --- Permissions Check ---
echo "--- Permissions of '$PERF_SYM_DIR' and contents ---"
echo "Directory Permissions:"
ls -ld "$PERF_SYM_DIR"
echo "Recursive File Permissions (limited depth for brevity):"
ls -lR "$PERF_SYM_DIR" | head -n 30 # Show first few files/permissions recursively
echo "---------------------------"
echo ""

# --- Recorded Path Check ---
echo "--- Checking Recorded Path for $ASSEMBLY_SO in $PERF_DATA_FILE ---"
# Use buildid-list again as it shows the path
"$CUSTOM_PERF_PATH" buildid-list -i "$PERF_DATA_FILE" | grep "$ASSEMBLY_SO" || echo "  ($ASSEMBLY_SO not found in buildid-list for $PERF_DATA_FILE)"
echo "---------------------------"
echo ""

# --- Attempt 1: Perf Report with Sudo + Max Verbosity + Absolute Path ---
echo "--- Running Perf Report with sudo, -vvv, --stdio, Absolute --symfs (First 150 Lines) ---"
ABS_SYMFS_PATH=$(readlink -f "./$PERF_SYM_DIR")
echo "Using Absolute Path: $ABS_SYMFS_PATH"
sudo "$CUSTOM_PERF_PATH" report --stdio --symfs="$ABS_SYMFS_PATH" -vvv | head -n 150
echo ""
echo "(End of sudo verbose attempt)"
echo "---------------------------"
echo ""

# --- Attempt 2: Perf Report WITHOUT Sudo (if possible) ---
echo "--- Running Perf Report WITHOUT sudo, -vvv, --stdio, Absolute --symfs (First 150 Lines) ---"
# Check if current user can read perf.data
if [ -r "$PERF_DATA_FILE" ]; then
    echo "Attempting run without sudo (perf.data is readable)..."
    "$CUSTOM_PERF_PATH" report --stdio --symfs="$ABS_SYMFS_PATH" -vvv | head -n 150
    echo ""
    echo "(End of non-sudo verbose attempt)"
else
    echo "Skipping non-sudo run because '$PERF_DATA_FILE' is not readable by current user ($(whoami))."
fi
echo "---------------------------"
echo ""

# --- Attempt 3: Perf Debug Info Dump (Optional - VERY VERBOSE) ---
# This command dumps *all* debug info perf can find, potentially very large.
# echo "--- Running Perf Report --dump-debug-info (First 200 Lines) ---"
# sudo "$CUSTOM_PERF_PATH" report --dump-debug-info --symfs="$ABS_SYMFS_PATH" | head -n 200
# echo ""
# echo "(End of debug info dump attempt)"
# echo "---------------------------"
# echo ""


echo "===== Investigation Script Finished ====="

exit 0