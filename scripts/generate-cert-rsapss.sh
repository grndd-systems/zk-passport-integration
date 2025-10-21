#!/bin/bash
set -e

# Script to generate RSA key pair and self-signed certificate with RSA-PSS signature
# Certificate valid for 10 years
# Generates directly into data/rsapss directory for ICAO setup

RSAPSS_DIR="data/rsapss"
KEY_FILE="$RSAPSS_DIR/key.pem"
CERT_FILE="$RSAPSS_DIR/cert.pem"
PUBKEY_FILE="$RSAPSS_DIR/pubkey.pem"
MASTERLIST_FILE="$RSAPSS_DIR/masterlist.pem"

# Create output directory if it doesn't exist
mkdir -p "$RSAPSS_DIR"

echo "=== Generating RSA-PSS Certificate and Key ==="
echo "Target directory: $RSAPSS_DIR"
echo ""

# Generate 2048-bit RSA private key
echo "1. Generating RSA private key (2048-bit)..."
openssl genrsa -out "$KEY_FILE" 2048

# Extract public key from private key
echo "2. Extracting public key..."
openssl rsa -in "$KEY_FILE" -pubout -out "$PUBKEY_FILE"

# Generate self-signed certificate with RSA-PSS signature
# Valid for 10 years (3650 days)
echo "3. Generating self-signed certificate with RSA-PSS signature (10 years)..."
openssl req -new -x509 \
  -key "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 3650 \
  -sha256 \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 \
  -subj "/CN=Test SelfSigned Cert" \
  -extensions v3_ca \
  -config <(cat <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[ req_distinguished_name ]

[ v3_ca ]
basicConstraints = critical,CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

echo ""
echo "=== Certificate Generation Complete ==="
echo ""

# Display certificate information
echo "=== Certificate Information ==="
openssl x509 -in "$CERT_FILE" -noout -text | grep -A 2 "Validity"
openssl x509 -in "$CERT_FILE" -noout -text | grep -A 1 "Signature Algorithm"
openssl x509 -in "$CERT_FILE" -noout -text | grep "Subject:"
echo ""

# Verify the certificate
echo "=== Verifying Certificate ==="
if openssl verify -CAfile "$CERT_FILE" "$CERT_FILE" > /dev/null 2>&1; then
  echo "✅ Certificate is valid and self-signed"
else
  echo "❌ Certificate verification failed"
  exit 1
fi

echo ""
echo "=== Updating Masterlist ==="
# Append the generated certificate to masterlist.pem
# This will be used by ICAO root calculation
if [ -f "$MASTERLIST_FILE" ]; then
  echo "  Appending certificate to existing masterlist"
  echo "" >> "$MASTERLIST_FILE"  # Add newline before certificate
  cat "$CERT_FILE" >> "$MASTERLIST_FILE"
else
  echo "  Creating new masterlist"
  cp "$CERT_FILE" "$MASTERLIST_FILE"
fi
echo "  Updated: $MASTERLIST_FILE"

echo ""
echo "=== Files Created ==="
echo "  Private key:  $KEY_FILE"
echo "  Certificate:  $CERT_FILE"
echo "  Public key:   $PUBKEY_FILE"
echo "  Masterlist:   $MASTERLIST_FILE"

echo ""
echo "✅ Done! Certificate ready for ICAO setup and registration."
echo ""
echo "Next steps:"
echo "  1. Run: npm run setup           (Update ICAO root)"
echo "  2. Run: npm run register-cert-rsapss  (Register certificate)"
