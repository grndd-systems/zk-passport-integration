#!/bin/bash

# Generate RSA certificate with standard PKCS#1 v1.5 signature (not PSS)
# Valid for 10 years

set -e

CERT_DIR="./data/out_cert"
KEY_FILE="$CERT_DIR/key.pem"
CERT_FILE="$CERT_DIR/cert.pem"

echo "Generating RSA-2048 certificate with PKCS#1 v1.5 signature..."

# Generate RSA-2048 private key (if doesn't exist)
if [ ! -f "$KEY_FILE" ]; then
    openssl genrsa -out "$KEY_FILE" 2048
    echo "✅ Generated private key: $KEY_FILE"
else
    echo "Using existing private key: $KEY_FILE"
fi

# Generate self-signed certificate with standard RSA signature
# Note: No -sigopt flags = PKCS#1 v1.5 (not PSS)
openssl req -new -x509 \
    -key "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 3650 \
    -sha256 \
    -subj "/CN=Test SelfSigned Cert"

echo "✅ Generated certificate: $CERT_FILE"
echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_FILE" -noout -text | grep -A 2 "Signature Algorithm"
echo ""
echo "✅ Certificate generated successfully!"
echo "   Valid for: 10 years"
echo "   Signature: RSA with SHA-256 (PKCS#1 v1.5)"
