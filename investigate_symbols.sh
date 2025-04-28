#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
# set -e # Commenting out set -e as some commands might fail intentionally during investigation
# Treat unset variables as an error when substituting.
set -u

echo "===== Perf Symbol Investigation Script ====="
echo "Timestamp: $(date)"
echo ""

# --- Configuration ---
PERF_SYM_DIR="perf_syms"        # The directory where push_symbols.sh placed files
PERF_DATA_FILE="perf.data"      # Assumed name of the perf data file

# --- Path to your custom perf (Adjust if necessary) ---
# Determine the likely home directory of the user who built perf
# If running as root, HOME is usually /root. Otherwise, use the current HOME.
EFFECTIVE_HOME="$HOME"
if [ "$(id -u)" -eq 0 ]; then
  EFFECTIVE_HOME="/root"
fi
CUSTOM_PERF_PATH="$EFFECTIVE_HOME/WSL2-Linux-Kernel/tools/perf/perf"
# --- End Custom Perf Path ---

EXE_FILE="LastEpoch.x86_64"
ASSEMBLY_SO="GameAssembly.so"
PLAYER_SO="UnityPlayer.so"

DEBUG_DIR_RELATIVE="LastEpoch_BackUpThisFolder_ButDontShipItWithYourGame"
EXE_DEBUG="LastEpoch_s.debug"
ASSEMBLY_DEBUG="GameAssembly.debug"
PLAYER_DEBUG="UnityPlayer_s.debug"

# --- Check Environment ---
echo "--- Environment Checks ---"
echo "Current Directory (should be /mnt/c/LE_Server_Linux): $(pwd)"
echo "Checking for custom perf at resolved path: $CUSTOM_PERF_PATH"
if [ ! -x "$CUSTOM_PERF_PATH" ]; then
    echo "ERROR: Custom perf executable not found or not executable at '$CUSTOM_PERF_PATH'"
    # Try finding perf in PATH as fallback? Might be wrong version.
    if command -v perf > /dev/null; then
        echo "Warning: Falling back to 'perf' found in PATH ($(which perf)). This might be the wrong version."
        CUSTOM_PERF_PATH="perf"
    else
        echo "Cannot proceed without a perf executable."
        exit 1
    fi
else
    echo "Custom perf found."
fi

echo "Checking for '$PERF_DATA_FILE':"
if [ ! -f "$PERF_DATA_FILE" ]; then
    echo "WARNING: '$PERF_DATA_FILE' not found in current directory. Will skip report check."
    # exit 1 # Allow script to continue to check symbols even if perf.data is missing
else
    echo "'$PERF_DATA_FILE' found."
fi

echo "Checking for symbol directory '$PERF_SYM_DIR' (relative to CWD):"
if [ ! -d "$PERF_SYM_DIR" ]; then
    echo "ERROR: Symbol directory '$PERF_SYM_DIR' not found. Did push_symbols.sh run correctly?"
    exit 1
else
    echo "Symbol directory '$PERF_SYM_DIR' found."
fi

echo "Checking for debug source directory '$DEBUG_DIR_RELATIVE' (relative to CWD):"
if [ ! -d "$DEBUG_DIR_RELATIVE" ]; then
    echo "ERROR: Debug source directory '$DEBUG_DIR_RELATIVE' not found. Cannot check debug file contents."
    # We can still check build IDs in perf_syms though
else
    echo "Debug source directory '$DEBUG_DIR_RELATIVE' found."
fi
echo "---------------------------"
echo ""

# --- Check Contents of Symbol Directory ---
echo "--- Contents of '$PERF_SYM_DIR' ---"
ls -l "$PERF_SYM_DIR"
echo "---------------------------"
echo ""

# --- Verify Build IDs in Symbol Directory ---
echo "--- Build ID Checks (in $PERF_SYM_DIR) ---"
echo "Checking $EXE_FILE:"
readelf -n "$PERF_SYM_DIR/$EXE_FILE" 2>/dev/null | grep "Build ID" || echo "  (Build ID not found or readelf error)"
echo "Checking $ASSEMBLY_SO:"
readelf -n "$PERF_SYM_DIR/$ASSEMBLY_SO" 2>/dev/null | grep "Build ID" || echo "  (Build ID not found or readelf error)"
echo "Checking $PLAYER_SO:"
readelf -n "$PERF_SYM_DIR/$PLAYER_SO" 2>/dev/null | grep "Build ID" || echo "  (Build ID not found or readelf error)"
echo "---------------------------"
echo ""

# --- Verify Debug File Contents ---
echo "--- Debug File Content Checks (in $PERF_SYM_DIR) ---"
echo "Checking $ASSEMBLY_DEBUG sections:"
readelf -S "$PERF_SYM_DIR/$ASSEMBLY_DEBUG" 2>/dev/null | grep '\.debug_' || echo "  (No .debug sections found or readelf error)"
echo ""
echo "Checking $PLAYER_DEBUG sections:"
readelf -S "$PERF_SYM_DIR/$PLAYER_DEBUG" 2>/dev/null | grep '\.debug_' || echo "  (No .debug sections found or readelf error)"
echo ""
echo "Checking $ASSEMBLY_DEBUG symbols (first 20):"
nm "$PERF_SYM_DIR/$ASSEMBLY_DEBUG" 2>/dev/null | head -n 20 || echo "  (nm error or no symbols found)"
echo ""
echo "Checking $PLAYER_DEBUG symbols (first 20):"
nm "$PERF_SYM_DIR/$PLAYER_DEBUG" 2>/dev/null | head -n 20 || echo "  (nm error or no symbols found)"
echo "---------------------------"
echo ""

# --- Get Absolute Path ---
echo "--- Absolute Path for --symfs ---"
ABS_SYMFS_PATH=$(readlink -f "./$PERF_SYM_DIR")
echo "Absolute path: $ABS_SYMFS_PATH"
echo "---------------------------"
echo ""

# --- Run Perf Report with High Verbosity ---
echo "--- Running Perf Report (Very Verbose, Non-Interactive, First 100 Lines) ---"
# Check if perf.data exists before running
if [ -f "$PERF_DATA_FILE" ]; then
    # Using --stdio to avoid interactive TUI and capture initial output easily
    # Limiting lines with head to focus on symbol loading messages
    # Using the absolute path for --symfs just to be certain
    sudo "$CUSTOM_PERF_PATH" report --stdio --symfs="$ABS_SYMFS_PATH" -vvv | head -n 100
    echo ""
    echo "(Above lines show the beginning of the verbose report output)"
else
    echo "Skipping perf report run because '$PERF_DATA_FILE' was not found."
fi
echo "---------------------------"
echo ""
echo "===== Investigation Script Finished ====="

exit 0