#!/bin/bash

# Full passport workflow script
# This script runs the complete passport generation, registration, and query proof workflow

set -e  # Exit on error

# Address for query proof
ADDRESS="${1:-0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266}"

echo "=== Starting full passport workflow ==="
echo "Target address: $ADDRESS"
echo ""

echo "[1/6] Generating passport..."
npm run generate-passport
echo "✓ Passport generated"
echo ""

echo "[2/6] Generating register proof..."
npm run generate-register-proof
echo "✓ Register proof generated"
echo ""

echo "[3/6] Updating AA signature..."
npm run update-aa-sig
echo "✓ AA signature updated"
echo ""

echo "[4/6] Registering passport..."
npm run register-passport
echo "✓ Passport registered"
echo ""

echo "[5/6] Generating query proof (Noir) for address $ADDRESS..."
npm run generate-query-proof-noir "$ADDRESS"
echo "✓ Query proof generated"
echo ""

echo "[6/6] Executing query proof (Noir) for address $ADDRESS..."
npm run execute-query-proof-noir "$ADDRESS"
echo "✓ Query proof executed"
echo ""

echo "=== Workflow completed successfully ==="
