#!/bin/bash
# Git Push Script for FWF Site

echo "=== FWF Site Git Push Script ==="
echo "Current directory: $(pwd)"

# Check if we're in the right directory
if [ ! -d ".git" ]; then
    echo "Error: Not in a git repository!"
    cd "d:/fwf-site_0.2_vercel/fwf-site"
    echo "Changed to: $(pwd)"
fi

# Show current status
echo "=== Checking Git Status ==="
git status

# Add all changes
echo "=== Adding all changes ==="
git add .

# Show what's staged
echo "=== Changes to be committed ==="
git status --short

# Ask for commit message
echo "Enter commit message (or press Enter for default):"
read -r commit_message

if [ -z "$commit_message" ]; then
    commit_message="Update files - $(date '+%Y-%m-%d %H:%M:%S')"
fi

# Commit changes
echo "=== Committing with message: $commit_message ==="
git commit -m "$commit_message"

# Push to remote
echo "=== Pushing to remote repository ==="
git push

echo "=== Push completed! ==="