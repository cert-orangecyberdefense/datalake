#!/bin/bash

HOOK_NAME="pre-push"
HOOK_DIR=".git/hooks"
HOOK_PATH="$HOOK_DIR/$HOOK_NAME"
HOOK_SCRIPT_FIRST_LINE='#!/bin/sh'
HOOK_SCRIPT_SECOND_LINE='make lint_check && echo "Black check passed." || { echo "Black check failed. Please fix the formatting before pushing."; exit 1; }'

# Write the hook script to the pre-push file
echo $HOOK_SCRIPT_FIRST_LINE > $HOOK_PATH
echo $HOOK_SCRIPT_SECOND_LINE >> $HOOK_PATH

# Make the pre-push hook executable
chmod +x $HOOK_PATH

echo "Pre-push hook installed successfully."