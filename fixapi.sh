#!/bin/bash

# Define the old and new URLs
OLD_URL="https://notes.canary.hectabit.org/api"
NEW_URL="https://notes.canary.hectabit.org/api"

# Recursively search and replace in files under the current directory
find . -type f -exec sed -i "s|$OLD_URL|$NEW_URL|g" {} +
