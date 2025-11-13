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

print_step "Generate CSCA Certificate (Root CA, goes to masterlist)"
bash scripts/generate-csca-rsapss.sh

print_step "Generate DSC Certificate (signed by CSCA)"
bash scripts/generate-dsc-rsapss.sh

print_step "Update ICAO Root on Blockchain (from CSCA masterlist)"
npm run setup

print_step "Register DSC in PoseidonSMT (prove DSC signed by CSCA)"
npm run register-cert-rsapss

print_step "Generate Biometric Passport Data"
node dist/index.js generate-passport

print_step "Generate ZK Proof for Passport"
node dist/index.js generate-register-proof

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
echo "  1. ✅ Generated CSCA certificate (root CA, added to masterlist)"
echo "  2. ✅ Generated DSC certificate (signed by CSCA)"
echo "  3. ✅ Updated ICAO root on blockchain (from CSCA masterlist)"
echo "  4. ✅ Registered DSC in PoseidonSMT (proved DSC signed by CSCA)"
echo "  5. ✅ Generated biometric passport data (with unique AA key)"
echo "  6. ✅ Generated ZK proof"
echo "  7. ✅ Updated AA signature"
echo "  8. ✅ Registered passport on blockchain"
echo ""
echo "Files created:"
echo "  - CSCA cert: data/rsapss/csca_cert.pem (in masterlist.pem)"
echo "  - DSC cert: data/rsapss/dsc_cert.pem (registered in PoseidonSMT)"
echo "  - Passport: data/out_passport/passport_*.json"
echo "  - Proof: data/circuit/proof"
echo "  - Public inputs: data/circuit/public-inputs"
echo ""
echo "Architecture:"
echo "  - CSCA (in masterlist.pem) → ICAO root on blockchain"
echo "  - CSCA signs DSC → DSC registered in PoseidonSMT"
echo "  - DSC signs SOD for each passport"
echo "  - Each passport has unique AA key in DG15"
echo "  - One DSC can sign multiple passports"
echo ""
