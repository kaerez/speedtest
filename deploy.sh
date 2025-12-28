#!/bin/bash
set -e # Exit on error

echo "Generating HMAC_SECRET (UUIDv4)..."
SECRET=$(uuidgen | tr '[:upper:]' '[:lower:]')

if [ -z "$SECRET" ]; then
    echo "Error: Failed to generate UUID."
    exit 1
fi

echo "Generated Secret: $SECRET"

echo "Setting HMAC_SECRET in Cloudflare..."
# Use printf to ensure no extra whitespace/newlines
# Use npx -y to suppress install prompts
if printf "$SECRET" | npx -y wrangler secret put HMAC_SECRET; then
    echo "Successfully set HMAC_SECRET."
else
    echo "WARNING: Failed to set HMAC_SECRET. This is expected if running in a CI environment without 'Edit Secrets' permission."
fi

# Check for setup-only flag
if [ "$1" == "--setup-only" ]; then
    echo "Setup complete. Skipping deployment."
    exit 0
fi

echo "Deploying Worker..."
npx -y wrangler deploy
