#!/bin/bash

echo "Generating HMAC_SECRET (UUIDv4)..."
# Generate UUIDv4 and lowercase it
SECRET=$(uuidgen | tr '[:upper:]' '[:lower:]')

echo "Setting HMAC_SECRET in Cloudflare..."
# Pipe the secret to wrangler secret put
echo $SECRET | npx wrangler secret put HMAC_SECRET

echo "Deploying Worker..."
npx wrangler deploy
