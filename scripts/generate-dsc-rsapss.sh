#!/bin/bash
set -e

# Script to generate DSC (Document Signer Certificate) signed by CSCA
# DSC is used to sign multiple passport SODs
# Each passport will have unique AA key in DG15, but all share the same DSC

RSAPSS_DIR="data/rsapss"
CSCA_KEY="$RSAPSS_DIR/csca_key.pem"
CSCA_CERT="$RSAPSS_DIR/csca_cert.pem"
DSC_KEY="$RSAPSS_DIR/dsc_key.pem"
DSC_CERT="$RSAPSS_DIR/dsc_cert.pem"
DSC_CSR="$RSAPSS_DIR/dsc.csr"

# Check if CSCA exists
if [ ! -f "$CSCA_KEY" ] || [ ! -f "$CSCA_CERT" ]; then
  echo "❌ CSCA certificate not found. Please run scripts/generate-cert-rsapss.sh first."
  exit 1
fi

echo "=== Generating DSC (Document Signer Certificate) ==="
echo "Target directory: $RSAPSS_DIR"
echo "CSCA cert: $CSCA_CERT"
echo ""

# Generate 2048-bit RSA private key for DSC
echo "1. Generating DSC private key (2048-bit)..."
openssl genrsa -out "$DSC_KEY" 2048

# Generate Certificate Signing Request (CSR)
echo "2. Generating certificate signing request..."
openssl req -new \
  -key "$DSC_KEY" \
  -out "$DSC_CSR" \
  -subj "/CN=Document Signer Certificate"

# Sign DSC with CSCA to create the DSC certificate
# Valid for 5 years (1825 days)
echo "3. Signing DSC with CSCA (RSA-PSS, 5 years)..."
openssl x509 -req \
  -in "$DSC_CSR" \
  -CA "$CSCA_CERT" \
  -CAkey "$CSCA_KEY" \
  -CAcreateserial \
  -out "$DSC_CERT" \
  -days 1825 \
  -sha256 \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 \
  -extensions v3_dsc \
  -extfile <(cat <<EOF
[ v3_dsc ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,1.3.6.1.5.5.7.3.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

# Clean up CSR
rm -f "$DSC_CSR"

echo ""
echo "=== DSC Generation Complete ==="
echo ""

# Display certificate information
echo "=== DSC Certificate Information ==="
openssl x509 -in "$DSC_CERT" -noout -text | grep -A 2 "Validity"
openssl x509 -in "$DSC_CERT" -noout -text | grep -A 1 "Signature Algorithm"
openssl x509 -in "$DSC_CERT" -noout -text | grep "Subject:"
openssl x509 -in "$DSC_CERT" -noout -text | grep "Issuer:"
echo ""

# Verify the DSC certificate chain
echo "=== Verifying DSC Certificate Chain ==="
if openssl verify -CAfile "$CSCA_CERT" "$DSC_CERT" > /dev/null 2>&1; then
  echo "✅ DSC certificate is valid and signed by CSCA"
else
  echo "❌ DSC certificate verification failed"
  exit 1
fi

echo ""
echo "=== Files Created ==="
echo "  DSC private key:  $DSC_KEY"
echo "  DSC certificate:  $DSC_CERT"
echo ""
echo "✅ Done! DSC ready to sign passport SODs."
echo ""
echo "Architecture:"
echo "  CSCA (in masterlist) -> DSC (to be registered) -> SOD (passport data)"
echo "  Each passport has unique AA key in DG15, but shares DSC for SOD signing"
echo "  Masterlist contains CSCA, DSC is registered via register-certificate"
echo ""
