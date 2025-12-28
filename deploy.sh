#!/bin/bash
set -e # Exit on error

echo "Deploying Worker..."
npx -y wrangler deploy
