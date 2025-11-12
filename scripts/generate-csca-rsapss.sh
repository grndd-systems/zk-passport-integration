#!/bin/bash
set -e

# Script to generate CSCA (Country Signing Certificate Authority)
# This is a self-signed root certificate that will sign DSC certificates
# Certificate valid for 10 years

RSAPSS_DIR="data/rsapss"
CSCA_KEY="$RSAPSS_DIR/csca_key.pem"
CSCA_CERT="$RSAPSS_DIR/csca_cert.pem"
MASTERLIST_FILE="$RSAPSS_DIR/masterlist.pem"

# Create output directory if it doesn't exist
mkdir -p "$RSAPSS_DIR"

echo "=== Generating CSCA (Country Signing CA) Certificate ==="
echo "Target directory: $RSAPSS_DIR"
echo ""

# Generate 2048-bit RSA private key for CSCA
echo "1. Generating CSCA RSA private key (2048-bit)..."
openssl genrsa -out "$CSCA_KEY" 2048

# Generate self-signed CSCA certificate with RSA-PSS signature
# This cert has CA:TRUE and can sign other certificates (DSC)
echo "2. Generating self-signed CSCA certificate with RSA-PSS signature (10 years)..."
openssl req -new -x509 \
  -key "$CSCA_KEY" \
  -out "$CSCA_CERT" \
  -days 3650 \
  -sha256 \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 \
  -subj "/C=TS/O=Test Country/OU=CSCA/CN=Test Country CSCA" \
  -extensions v3_ca \
  -config <(cat <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[ req_distinguished_name ]

[ v3_ca ]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

echo ""
echo "=== CSCA Generation Complete ==="
echo ""

# Display certificate information
echo "=== CSCA Information ==="
openssl x509 -in "$CSCA_CERT" -noout -text | grep -A 2 "Validity"
openssl x509 -in "$CSCA_CERT" -noout -text | grep -A 1 "Signature Algorithm"
openssl x509 -in "$CSCA_CERT" -noout -text | grep "Subject:"
openssl x509 -in "$CSCA_CERT" -noout -text | grep "CA:TRUE"
echo ""

# Verify the certificate
echo "=== Verifying CSCA ==="
if openssl verify -CAfile "$CSCA_CERT" "$CSCA_CERT" > /dev/null 2>&1; then
  echo "✅ CSCA is valid and self-signed"
else
  echo "❌ CSCA verification failed"
  exit 1
fi

echo ""
echo "=== Updating Masterlist ==="
# Append CSCA certificate to masterlist (don't overwrite)
if [ -f "$MASTERLIST_FILE" ]; then
  echo "  Appending CSCA certificate to existing masterlist"
  echo "" >> "$MASTERLIST_FILE"  # Add newline before certificate
  cat "$CSCA_CERT" >> "$MASTERLIST_FILE"
else
  echo "  Creating new masterlist with CSCA"
  cp "$CSCA_CERT" "$MASTERLIST_FILE"
fi
echo "  Updated: $MASTERLIST_FILE"

echo ""
echo "=== Files Created ==="
echo "  CSCA Private key:  $CSCA_KEY"
echo "  CSCA Certificate:  $CSCA_CERT"
echo "  Masterlist:        $MASTERLIST_FILE"
echo "  Registration cert: $CERT_FILE"
echo "  Registration key:  $KEY_FILE"

echo ""
echo "✅ Done! CSCA ready for signing DSC certificates."
echo ""
echo "Next steps:"
echo "  1. Run: npm run setup           (Update ICAO root with CSCA)"
echo "  2. Generate passports - each will create its own DSC signed by this CSCA"
