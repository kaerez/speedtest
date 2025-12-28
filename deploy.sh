#!/bin/bash

echo "Generating HMAC_SECRET (UUIDv4)..."
SECRET=$(uuidgen | tr '[:upper:]' '[:lower:]')

if [ -z "$SECRET" ]; then
    echo "Error: Failed to generate UUID. Check if 'uuidgen' is installed."
    exit 1
fi

echo "Generated Secret: $SECRET"

echo "Setting HMAC_SECRET in Cloudflare..."
echo "$SECRET" | npx wrangler secret put HMAC_SECRET

echo "Deploying Worker..."
npx wrangler deploy
