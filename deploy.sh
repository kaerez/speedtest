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
printf "$SECRET" | npx -y wrangler secret put HMAC_SECRET

echo "Deploying Worker..."
npx -y wrangler deploy
