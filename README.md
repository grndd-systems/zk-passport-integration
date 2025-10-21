# Rarimo Passport ZK Verification

A project for generating and verifying biometric passports using zero-knowledge proofs based on Noir circuits and zkSync smart contracts.

## Architecture

### System Components

1. **ICAO Master Tree (Poseidon SMT)** - Merkle tree based on Poseidon hash containing passport issuing country certificates
2. **Passport ZK Circuits (Noir)** - Zero-knowledge schemes for proving passport validity without revealing personal data
3. **Smart Contracts (zkSync)** - Contracts for storing ICAO root and verifying ZK proofs
4. **Biometric Data Generator** - Generator for test biometric passports with digital signatures

### Project Structure

```
rarimo-test/
├── src/
│   ├── blockchain/          # Smart contract interactions
│   │   ├── contracts.ts     # Contract initialization
│   │   └── tx.ts           # Transactions and contract calls
│   ├── passport/           # Passport data generation
│   │   ├── biometric-passport-generator.ts  # Main generator
│   │   ├── dg15-generator.ts               # DG15 generation (public key)
│   │   ├── generate-aa-signature.ts        # Active Authentication signature
│   │   └── random-passport-data.ts         # Random personal data
│   ├── workflows/          # Main workflows
│   │   ├── setup.ts                    # ICAO root initialization
│   │   ├── register-certificate.ts     # Country certificate registration
│   │   ├── register-passport.ts        # Passport registration via ZK proof
│   │   └── generate-proof.ts          # ZK proof generation
│   └── index.ts            # CLI entry point
├── data/
│   ├── rsapss/             # RSA-PSS certificates and keys
│   │   ├── masterlist.pem         # List of trusted certificates
│   │   ├── cert_rsapss.pem        # Document Signer Certificate
│   │   ├── private_key.pem        # Private key for signing
│   │   └── merkle_output.txt      # Merkle proof for certificate
│   └── out_passport/       # Generated passports (JSON)
├── circuits/               # Noir ZK circuits
└── scripts/               # Helper scripts
    └── full-flow.sh       # Full flow from setup to proof
```

## How It Works

### 1. ICAO PKI Infrastructure

Country passports contain a digital signature from a **Document Signer Certificate** (DSC), which in turn is signed by a **Country Signing CA Certificate** (CSCA).

In our system:

- CSCA certificates are stored in `masterlist.pem`
- A **Poseidon Sparse Merkle Tree** is built from this list
- The **tree root hash** is published to the `StateKeeper` smart contract
- For each certificate, a **Merkle proof** (path from leaf to root) is generated

### 2. Zero-Knowledge Proof

When a user wants to verify passport validity:

1. Passport data groups (DG1, DG15) and SOD signature are fed to the Noir circuit
2. The circuit verifies:
   - Digital signature of SOD from Document Signer Certificate
   - Data group hashes match signed values
   - Certificate belongs to ICAO Master Tree (via Merkle proof)
3. ZK proof is generated and can be verified on-chain

### 3. Passport Data Structure

A passport contains the following data groups:

- **DG1** - MRZ (Machine Readable Zone): name, passport number, date of birth, gender, nationality
- **DG15** - Public key for Active Authentication
- **SOD** (Security Object Document) - Digital signature of all data groups

## Step-by-Step Guide

### Step 1: Install Dependencies

```bash
npm install
```

### Step 2: Environment Setup

Create a `.env` file:

```env
PRIVATE_KEY=your_private_key_here
RPC_URL=network_with_deployed_rarimo_infra
```

### Step 3: Prepare Certificates

Place your certificates in `data/rsapss/`:

- `masterlist.pem` - List of CSCA certificates (can contain multiple certificates)
- `cert_rsapss.pem` - Document Signer Certificate (must be signed by one of the CSCAs)
- `private_key.pem` - Private key for Document Signer Certificate

**Important**: Certificate must use **RSA-PSS** algorithm with parameters:

- Hash: SHA-256
- MGF: MGF1 with SHA-256
- Salt length: 32 bytes

### Step 4: Generate Merkle Tree and Get Proof

```bash
# Generates Poseidon SMT from masterlist.pem and saves root + proof to merkle_output.txt
npm run icao-root
```

This creates a `data/rsapss/merkle_output.txt` file with:

- `root` - Tree root hash (will be published to contract)
- `proofs` - Array of siblings for our certificate's Merkle proof

### Step 5: Deploy and Initialize Contracts

```bash
# Publishes ICAO root to StateKeeper contract
npm start setup
```

This command:

1. Reads root from `merkle_output.txt`
2. Calls `StateKeeper.updateICAOMasterTreeMerkleRoot(root)`
3. Saves root to blockchain

### Step 6: Register Certificate in Poseidon SMT Contract

```bash
# Registers our Document Signer Certificate with Merkle proof
npm start register-certificate-rsapss
```

This command:

1. Extracts public key from `cert_rsapss.pem`
2. Calculates `pk_hash = poseidon([modulus, exponent])`
3. Reads Merkle proof from `merkle_output.txt`
4. Calls `PoseidonSMT.add(pk_hash, pk_hash, siblings[])`

### Step 7: Generate Test Passport

```bash
# Generates random passport with famous Roman name
npm start generate-passport
```

This command:

1. Generates random personal data (name from list of Roman figures, random number, date of birth, etc.)
2. Forms DG1 (MRZ string)
3. Generates RSA key pair for Active Authentication
4. Forms DG15 with public key
5. Creates SOD with hashes of DG1 and DG15
6. Signs SOD with private key from `private_key.pem`
7. Saves result to `data/out_passport/passport_TIMESTAMP.json`

Example output:

```
=== Generating passport for PUBLIUS AELIUS HADRIAN ===
  Passport Number: GX7509547
  Date of Birth: 890215
  Sex: M
  Nationality: ROM

✅ Passport data generated and saved to: data/out_passport/passport_2025-10-21T12-48-27.json
```

### Step 8: Generate ZK Proof

```bash
# Generates Noir proof for the last created passport
npm start generate-proof
```

This command:

1. Reads the latest passport from `data/out_passport/`
2. Converts passport data to Noir circuit format using `@rarimo/passport-zk-circuits-noir-js`
3. Gets ICAO root from contract (`getCertificatesRoot()`)
4. Gets Merkle proof from contract (`getProofFromContract()`)
5. Forms inputs for Noir:
   - `dg1`, `dg15` - data groups
   - `ec`, `sa` - elliptic curve and signature parameters
   - `pk` - Document Signer public key
   - `reduction_pk` - reduction parameters
   - `sig` - RSA-PSS signature
   - `sk_identity` - private key for identity
   - `icao_root` - ICAO tree root
   - `inclusion_branches` - Merkle proof siblings
6. Executes `noir.execute(inputs)` and generates witness
7. Creates proof using `noir.generateProof(witness)`
8. Verifies proof locally
9. Saves proof to file

### Step 9: Register Passport in Contract

```bash
# Sends ZK proof to smart contract for verification
npm start register-passport
```

This command:

1. Reads generated proof
2. Formats it for Solidity contract
3. Calls `PassportVerifier.verify(proof, publicInputs)`
4. If verification succeeds - passport is registered

### Full Flow Automatically

```bash
# Executes all steps sequentially
./scripts/full-flow.sh
```

## CLI Commands

```bash
# Show help
npm start

# Initialize ICAO root
npm start setup

# Register RSA-PSS certificate
npm start register-certificate-rsapss

# Generate test passport
npm start generate-passport

# Generate ZK proof
npm start generate-proof

# Register passport via ZK proof
npm start register-passport

# Update Active Authentication signature
npm start update-aa-sig
```

## Passport Data Structure

File `data/out_passport/passport_*.json` contains:

```json
{
  "dg1": "base64_encoded_mrz", // Machine Readable Zone
  "dg15": "base64_encoded_public_key", // AA public key (RSA-2048)
  "sod": "base64_encoded_signed_data", // Security Object Document
  "documentNumber": "AB1234567", // Passport number
  "dateOfBirth": "1989-02-15", // Date of birth
  "documentExpiryDate": "2035-12-31", // Expiration date
  "nationality": "ROM", // Nationality
  "gender": "M", // Gender
  "firstName": "PUBLIUS AELIUS", // First name
  "lastName": "HADRIAN", // Last name
  "documentType": "P", // Document type (Passport)
  "issuingAuthority": "UTO", // Issuing authority
  "signature": "hex_aa_signature" // AA signature
}
```

## Technical Details

### Poseidon Sparse Merkle Tree

- Used for storing certificates in compact form
- Key: `pk_hash = poseidon([modulus, exponent])`
- Value: same `pk_hash`
- Siblings: array of 80 elements (tree depth = 80)
- Empty levels: `poseidon([0, 0, 1])`

### Noir Circuit Inputs

- All inputs must be within Noir field modulus (~254 bits)
- BigInt values are passed as strings
- Arrays are passed as arrays of strings
- Field names must exactly match circuit ABI

### RSA-PSS Parameters

```
Algorithm: RSA-PSS
Key size: 2048 bits
Hash: SHA-256
MGF: MGF1 with SHA-256
Salt length: 32 bytes
```

## Troubleshooting

### Input exceeds field modulus

Value exceeds maximum for Noir field. Make sure:

- Poseidon hash is used instead of SHA256 for Merkle tree
- Values are converted to strings for large numbers

### Merkle tree verification failure

Check that:

- ICAO root in contract matches root from `merkle_output.txt`
- Certificate is actually in `masterlist.pem`
- Siblings are correctly obtained from contract via `getProofFromContract()`

### Certificate signature invalid

Make sure:

- `cert_rsapss.pem` is signed by one of the CAs from `masterlist.pem`
- Private key matches public key in certificate
- Correct algorithm is used (RSA-PSS, not RSA-PKCS1)

## Links

- [Noir Documentation](https://noir-lang.org/)
- [ICAO Doc 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303) - Biometric passport specification
- [Rarimo Documentation](https://docs.rarimo.com/)

## License

MIT
