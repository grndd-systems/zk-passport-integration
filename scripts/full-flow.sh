#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     RARIMO PASSPORT REGISTRATION - FULL FLOW                   ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step counter
STEP=1

print_step() {
  echo ""
  echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║${NC} ${GREEN}Step $STEP: $1${NC}"
  echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  STEP=$((STEP + 1))
}

print_step "Generate RSA-PSS Certificate"
bash scripts/generate-cert-rsapss.sh

print_step "Update ICAO Master Tree Root on Blockchain"
npm run setup

print_step "Register Certificate in PoseidonSMT"
npm run register-cert-rsapss

print_step "Generate Biometric Passport Data"
node dist/index.js generate-passport

print_step "Generate ZK Proof for Passport"
node dist/index.js generate-proof

print_step "Update Active Authentication Signature"
npm run update-aa-sig

print_step "Register Passport on Blockchain"
npm run register-passport

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     ✅ FULL FLOW COMPLETED SUCCESSFULLY!                      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Summary of completed steps:"
echo "  1. ✅ Generated RSA-PSS certificate"
echo "  2. ✅ Updated ICAO root on blockchain"
echo "  3. ✅ Registered certificate in PoseidonSMT"
echo "  4. ✅ Generated biometric passport data"
echo "  5. ✅ Generated ZK proof"
echo "  6. ✅ Updated AA signature"
echo "  7. ✅ Registered passport on blockchain"
echo ""
echo "Files created:"
echo "  - Certificate: data/out_cert/cert.pem"
echo "  - Passport: data/out_passport/passport_*.json"
echo "  - Proof: data/circuit/proof"
echo "  - Public inputs: data/circuit/public-inputs"
echo ""
