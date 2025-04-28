#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u

# --- Configuration (Hardcoded Relative Paths & Target Dir) ---

# Fixed relative path from CWD to the directory containing the .debug files
# IMPORTANT: Adjust this line if the directory name ever changes!
DEBUG_DIR_RELATIVE="LastEpoch_BackUpThisFolder_ButDontShipItWithYourGame"

# Fixed name for the directory where symbols will be staged (relative to CWD)
PERF_SYM_DIR="perf_syms"

# Names of the main binaries (expected in the current directory)
EXE_FILE="LastEpoch.x86_64"
ASSEMBLY_SO="GameAssembly.so"
PLAYER_SO="UnityPlayer.so"

# Names of the corresponding debug files (expected within DEBUG_DIR_RELATIVE)
# Adjust these if your naming convention is different
EXE_DEBUG="LastEpoch_s.debug"
ASSEMBLY_DEBUG="GameAssembly.debug"
PLAYER_DEBUG="UnityPlayer_s.debug"

# --- Validate Inputs ---
echo "--> Validating expected file structure..."
CURRENT_DIR=$(pwd)
echo "    Running from: $CURRENT_DIR"
echo "    Expecting debug files in: $CURRENT_DIR/$DEBUG_DIR_RELATIVE"
echo "    Will stage symbols in: $CURRENT_DIR/$PERF_SYM_DIR"

# Check main binaries in current directory
if [ ! -f "$EXE_FILE" ]; then echo "Error: Executable '$EXE_FILE' not found in current directory ('$CURRENT_DIR')."; exit 1; fi
if [ ! -f "$ASSEMBLY_SO" ]; then echo "Error: Assembly '$ASSEMBLY_SO' not found in current directory ('$CURRENT_DIR')."; exit 1; fi
if [ ! -f "$PLAYER_SO" ]; then echo "Error: Player '$PLAYER_SO' not found in current directory ('$CURRENT_DIR')."; exit 1; fi
echo "    [OK] Found main binaries in CWD."

# Check if the relative debug directory exists
if [ ! -d "$DEBUG_DIR_RELATIVE" ]; then
  echo "Error: Expected debug directory '$DEBUG_DIR_RELATIVE' not found relative to current path."
  exit 1
fi
echo "    [OK] Found relative debug directory: $DEBUG_DIR_RELATIVE"

# Construct full paths to debug files
FULL_EXE_DEBUG_PATH="$DEBUG_DIR_RELATIVE/$EXE_DEBUG"
FULL_ASSEMBLY_DEBUG_PATH="$DEBUG_DIR_RELATIVE/$ASSEMBLY_DEBUG"
FULL_PLAYER_DEBUG_PATH="$DEBUG_DIR_RELATIVE/$PLAYER_DEBUG"

# Check debug files relative to the debug directory
if [ ! -f "$FULL_EXE_DEBUG_PATH" ]; then echo "Error: Debug file '$FULL_EXE_DEBUG_PATH' not found."; exit 1; fi
if [ ! -f "$FULL_ASSEMBLY_DEBUG_PATH" ]; then echo "Error: Debug file '$FULL_ASSEMBLY_DEBUG_PATH' not found."; exit 1; fi
if [ ! -f "$FULL_PLAYER_DEBUG_PATH" ]; then echo "Error: Debug file '$FULL_PLAYER_DEBUG_PATH' not found."; exit 1; fi
echo "    [OK] Found debug files within relative directory."

echo "--> All structure checks passed."

# --- Ensure Target Symbol Directory Exists ---
echo "--> Ensuring target symbol directory exists: $PERF_SYM_DIR"
mkdir -p "$PERF_SYM_DIR"

if [ ! -d "$PERF_SYM_DIR" ]; then
    echo "Error: Failed to create target symbol directory '$PERF_SYM_DIR'."
    exit 1
fi
echo "    [OK] Target directory '$PERF_SYM_DIR' is ready."

# --- Copy Files (Overwriting) ---
echo "--> Copying files to target symbol directory (overwriting if present)..."

echo "    Copying $EXE_FILE..."
cp "$EXE_FILE" "$PERF_SYM_DIR/"
echo "    Copying $ASSEMBLY_SO..."
cp "$ASSEMBLY_SO" "$PERF_SYM_DIR/"
echo "    Copying $PLAYER_SO..."
cp "$PLAYER_SO" "$PERF_SYM_DIR/"

echo "    Copying $FULL_EXE_DEBUG_PATH..."
cp "$FULL_EXE_DEBUG_PATH" "$PERF_SYM_DIR/"
echo "    Copying $FULL_ASSEMBLY_DEBUG_PATH..."
cp "$FULL_ASSEMBLY_DEBUG_PATH" "$PERF_SYM_DIR/"
echo "    Copying $FULL_PLAYER_DEBUG_PATH..."
cp "$FULL_PLAYER_DEBUG_PATH" "$PERF_SYM_DIR/"

echo "--> Successfully copied all files."

# --- Output Next Step ---
echo ""
echo "---------------------------------------------------------------------"
echo "Symbol directory prepared successfully in './$PERF_SYM_DIR/' !"
echo "To run perf report with these symbols, use the following command:"
echo ""
# Using ./ ensures it uses the relative path from CWD, even if PERF_SYM_DIR was an absolute path
echo "perf report --symfs=\"./$PERF_SYM_DIR\""
echo ""
echo "(Note: This directory '$PERF_SYM_DIR' will persist until manually deleted.)"
echo "---------------------------------------------------------------------"

exit 0