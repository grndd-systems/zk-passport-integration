# Rarimo Passport ZK Verification

A complete implementation for generating and verifying biometric passports using zero-knowledge proofs with Noir circuits and Rarimo smart contracts.

## Features

- **Passport Generation**: Create test biometric passports with realistic data (DG1, DG15, SOD)
- **ICAO PKI Integration**: Certificate management with Poseidon Sparse Merkle Tree
- **ZK Proof Systems**: Support for both Noir/UltraPlonk and Circom/Groth16
- **Registration Proofs**: Verify passport authenticity without revealing personal data
- **Query Proofs**: Prove age, citizenship, and validity without exposing full passport
- **KYC Verification**: On-chain identity verification with nullifier-based fraud prevention
- **Identity Management**: Revoke and reissue identities with new cryptographic keys
- **Full Automation**: End-to-end workflow scripts for rapid testing and deployment

## Architecture

### System Components

1. **ICAO Master Tree (Poseidon SMT)** - Merkle tree based on Poseidon hash containing passport issuing country certificates
2. **Passport ZK Circuits (Noir)** - Zero-knowledge schemes for proving passport validity without revealing personal data
3. **Smart Contracts (Rarimo)** - Contracts for storing ICAO root and verifying ZK proofs
4. **Biometric Data Generator** - Generator for test biometric passports with digital signatures

### Project Structure

```
zk-passport-integration/
├── src/
│   ├── blockchain/          # Smart contract interactions
│   │   ├── contracts.ts     # Contract initialization
│   │   ├── eth.ts          # Ethers provider and wallet setup
│   │   └── tx.ts           # Transactions and contract calls
│   ├── passport/           # Passport data generation
│   │   ├── biometric-passport-generator.ts  # Main generator
│   │   ├── dg15-generator.ts               # DG15 generation (public key)
│   │   ├── generate-aa-signature.ts        # Active Authentication signature
│   │   └── random-passport-data.ts         # Random personal data
│   ├── crypto/             # Cryptographic utilities
│   │   ├── certificate-key.ts      # Certificate key extraction
│   │   ├── extract-from-cert.ts    # Certificate parsing
│   │   ├── hash-packed.ts          # Hash utilities
│   │   └── query-circuit-input.ts  # Query circuit input preparation
│   ├── utils/              # Helper utilities
│   │   ├── bjj-key.ts             # Baby Jubjub key management
│   │   ├── file-loaders.ts        # File loading utilities
│   │   └── sod.ts                 # SOD parsing
│   ├── workflows/          # Main workflows
│   │   ├── setup.ts                              # ICAO root initialization
│   │   ├── register-certificate.ts               # Certificate registration
│   │   ├── generate-register-proof.ts            # Register ZK proof generation
│   │   ├── register-passport.ts                  # Passport registration via ZK proof
│   │   ├── generate-query-proof.ts               # Query proof (Circom/Groth16)
│   │   ├── generate-query-proof-noir.ts          # Query proof (Noir/UltraPlonk)
│   │   ├── generate-query-proof-from-contract.ts # Query proof from contract params
│   │   ├── execute-query-proof.ts                # Execute Circom query proof
│   │   ├── execute-query-proof-noir.ts           # Execute Noir query proof
│   │   ├── revoke-passport.ts                    # Revoke passport identity
│   │   └── reissue-identity.ts                   # Reissue identity with new key
│   └── index.ts            # CLI entry point
├── data/
│   ├── rsapss/             # RSA-PSS certificates and keys
│   │   ├── masterlist.pem         # List of trusted CSCA certificates
│   │   ├── cert_rsapss.pem        # Document Signer Certificate (DSC)
│   │   ├── private_key.pem        # Private key for signing
│   │   └── merkle_output.txt      # Merkle proof for certificate
│   ├── circuit/            # Noir circuits and trusted setup
│   │   ├── query_identity.json    # Query circuit (standard passports)
│   │   ├── query_identity_td1.json # Query circuit (TD1 passports)
│   │   ├── registerIdentity_*.json # Registration circuit
│   │   ├── bn254_g1.dat           # Trusted setup G1 points
│   │   └── bn254_g2.dat           # Trusted setup G2 points
│   ├── abi/                # Smart contract ABIs
│   ├── out_passport/       # Generated passports (JSON)
│   ├── proof/              # Generated registration proofs
│   ├── query-proof-noir/   # Generated Noir query proofs
│   └── sk_identity         # Baby Jubjub secret key
└── full-workflow.sh        # Complete workflow automation script
```

## How It Works

### 1. ICAO PKI Infrastructure

Country passports contain a digital signature from a **Document Signer Certificate** (DSC), which in turn is signed by a **Country Signing CA Certificate** (CSCA).

In our system:

- CSCA certificates are stored in `masterlist.pem`
- A **Poseidon Sparse Merkle Tree** is built from this list
- The **tree root hash** is published to the `StateKeeper` smart contract
- For each certificate, a **Merkle proof** (path from leaf to root) is generated

### 2. Zero-Knowledge Proofs

The project supports two types of ZK proofs:

#### Registration Proof (Noir/UltraPlonk)

When registering a passport:

1. Passport data groups (DG1, DG15) and SOD signature are fed to the Noir registration circuit
2. The circuit verifies:
   - Digital signature of SOD from Document Signer Certificate
   - Data group hashes match signed values
   - Certificate belongs to ICAO Master Tree (via Merkle proof)
3. ZK proof is generated and verified on-chain
4. Passport identity is registered in the smart contract

#### Query Proof (Noir/UltraPlonk or Circom/Groth16)

When proving attributes (age, citizenship, etc.) without revealing passport details:

1. User generates a query proof using:
   - Registered passport identity (from DG1)
   - Query parameters from smart contract (date ranges, citizenship mask, etc.)
   - Baby Jubjub secret key (sk_identity)
2. The circuit verifies:
   - User possesses valid passport data matching the registered identity
   - Attributes meet the query requirements (e.g., age > 18, valid expiration)
   - Generates a unique nullifier to prevent double-use
3. ZK proof is submitted on-chain for KYC verification

**Supported backends:**

- **Noir/UltraPlonk** - Faster proof generation, larger proof size (~2KB)
- **Circom/Groth16** - Slower proof generation, smaller proof size (~300B)

### 3. Passport Data Structure

A passport contains the following data groups:

- **DG1** - MRZ (Machine Readable Zone): name, passport number, date of birth, gender, nationality
- **DG15** - Public key for Active Authentication
- **SOD** (Security Object Document) - Digital signature of all data groups

## Quick Start

For a complete end-to-end workflow, use the automation script:

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Setup environment (create .env file with PRIVATE_KEY and RPC_URL)
cp .env.example .env
# Edit .env with your values

# Run complete workflow (setup → generate → register → query → verify)
./full-workflow.sh
```

## Step-by-Step Guide

### Step 1: Install Dependencies

```bash
npm install
npm run build
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

### Step 8: Generate BJJ Identity Key

Before generating the proof, you need to create a Baby Jubjub identity key:

```bash
# Generates BJJ secret key to data/sk_identity
./BJJKeygen data/sk_identity
```

### Step 9: Generate ZK Proof for Registration

```bash
# Generates Noir proof for the last created passport
npm start generate-register-proof
```

This command:

1. Generates BJJ secret key using BJJKeygen binary (if not exists)
2. Reads the latest passport from `data/out_passport/`
3. Converts passport data to Noir circuit format using `@rarimo/passport-zk-circuits-noir-js`
4. Gets ICAO root from contract (`getCertificatesRoot()`)
5. Gets Merkle proof from contract (`getProofFromContract()`)
6. Forms inputs for Noir:
   - `dg1`, `dg15` - data groups
   - `ec`, `sa` - elliptic curve and signature parameters
   - `pk` - Document Signer public key
   - `reduction_pk` - reduction parameters
   - `sig` - RSA-PSS signature
   - `sk_identity` - private key for identity
   - `icao_root` - ICAO tree root
   - `inclusion_branches` - Merkle proof siblings
7. Executes `noir.execute(inputs)` and generates witness
8. Creates proof using `noir.generateProof(witness)`
9. Verifies proof locally
10. Saves proof to file

### Step 10: Register Passport in Contract

```bash
# Sends ZK proof to smart contract for verification
npm start register-passport
```

This command:

1. Reads generated proof
2. Formats it for Solidity contract
3. Calls `PassportVerifier.verify(proof, publicInputs)`
4. If verification succeeds - passport is registered

### Step 11: Generate Query Proof (Noir)

```bash
# Generate Noir query proof for KYC verification
npm run generate-query-proof-noir <userAddress>

# Example:
npm run generate-query-proof-noir 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
```

This command:

1. Loads registered passport data (DG1, identity key)
2. Fetches query parameters from smart contract (`getPublicSignals`)
3. Generates Noir proof using UltraPlonk backend
4. Saves proof to `data/query-proof-noir/`
5. Verifies all public signals match contract expectations

### Step 12: Execute Query Proof (Noir)

```bash
# Submit Noir query proof to contract for KYC verification
npm run execute-query-proof-noir <userAddress>

# Example:
npm run execute-query-proof-noir 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
```

This command:

1. Loads generated Noir query proof
2. Extracts nullifier from public signals
3. Calls `QueryProofExecutor.executeNoir(currentDate, userPayload, proof)`
4. Verifies the transaction and displays KYC status

### Step 13: Check KYC Status

```bash
# Check KYC verification status for an address
npm run check-kyc-status <address>

# Check your own address (from .env)
npm run check-kyc-status
```

### Full Workflow Automation

```bash
# Executes complete workflow: generate passport → register → query proof → execute
./full-workflow.sh

# Or with custom address:
./full-workflow.sh 0xYourAddressHere
```

This script runs:

1. `generate-passport` - Create test passport
2. `generate-register-proof` - Generate registration proof
3. `update-aa-sig` - Update Active Authentication signature
4. `register-passport` - Register on blockchain
5. `generate-query-proof-noir` - Generate Noir query proof
6. `execute-query-proof-noir` - Submit proof and verify KYC

## CLI Commands

### Setup and Registration

```bash
# Show help with all available commands
npm start

# Initialize ICAO root on blockchain
npm start setup

# Register RSA-PSS certificate with Merkle proof
npm start register-certificate-rsapss

# Generate random biometric passport
npm start generate-passport

# Update Active Authentication signature for last passport
npm start update-aa-sig

# Generate ZK proof for passport registration
npm start generate-register-proof

# Register passport on blockchain via ZK proof
npm start register-passport
```

### Query Proofs (KYC Verification)

```bash
# Generate query proof using Noir/UltraPlonk (recommended)
npm run generate-query-proof-noir <userAddress>

# Execute Noir query proof and verify KYC
npm run execute-query-proof-noir <userAddress>

# Generate query proof using Circom/Groth16 (alternative)
npm run generate-query-proof <userAddress>

# Execute Circom query proof and verify KYC
npm run execute-query-proof [userAddress]

# Check KYC status for an address
npm run check-kyc-status [address]
```

### Identity Management

```bash
# Revoke passport identity (invalidate registration)
npm start revoke-passport

# Reissue identity with new BJJ key (same passport)
npm start reissue-identity
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

### ZK Proof Systems Comparison

| Feature               | Noir/UltraPlonk         | Circom/Groth16             |
| --------------------- | ----------------------- | -------------------------- |
| **Proof Generation**  | ~5-10 seconds           | ~30-60 seconds             |
| **Proof Size**        | ~2KB                    | ~300 bytes                 |
| **Verification Cost** | Higher gas              | Lower gas                  |
| **Trusted Setup**     | Universal (reusable)    | Circuit-specific           |
| **Use Case**          | Fast iteration, testing | Production, cost-sensitive |

### Noir Circuit Details

#### Registration Circuit

- **Purpose**: Verify passport authenticity and register identity
- **Inputs**: DG1, DG15, SOD, DSC public key, Merkle proof, BJJ identity key
- **Outputs**: Passport hash, identity hash, identity counter
- **Backend**: UltraPlonk with BN254 curve
- **Circuit file**: `data/circuit/registerIdentity_*.json`

#### Query Circuit

- **Purpose**: Prove passport attributes without revealing data
- **Inputs**: DG1 (93 bytes), identity key, query parameters (date ranges, citizenship)
- **Outputs**: Nullifier, event data, verification flags
- **Variants**:
  - `query_identity.json` - Standard TD3 passports (88 bytes MRZ)
  - `query_identity_td1.json` - TD1 passports (90 bytes MRZ)
- **Backend**: UltraPlonk with BN254 curve

### Circuit Input Requirements

- All inputs must be within Noir field modulus (~254 bits)
- BigInt values are passed as strings
- Arrays are passed as arrays of numbers
- Field names must exactly match circuit ABI
- Date encoding: YYMMDD in hex converted to decimal (e.g., "251030" → 0x323531303330 → bigint)

### RSA-PSS Parameters

```
Algorithm: RSA-PSS
Key size: 2048 bits
Hash: SHA-256
MGF: MGF1 with SHA-256
Salt length: 32 bytes
```

### Baby Jubjub Identity Key

- Used for generating unique identity commitment
- Generated once and stored in `data/sk_identity`
- Public key hash becomes part of passport registration
- Same key used for all query proofs from same identity
- Generated using `BJJKeygen` binary

## Troubleshooting

### Input exceeds field modulus

**Error**: Value exceeds maximum for Noir field

**Solutions**:

- Poseidon hash is used instead of SHA256 for Merkle tree
- Values are converted to strings for large numbers
- Date values are properly encoded as hex → decimal

### Merkle tree verification failure

**Error**: Proof verification failed / Invalid Merkle proof

**Check**:

- ICAO root in contract matches root from `merkle_output.txt`
- Certificate is actually in `masterlist.pem`
- Siblings are correctly obtained from contract via `getProofFromContract()`

### Certificate signature invalid

**Error**: Invalid SOD signature / RSA verification failed

**Make sure**:

- `cert_rsapss.pem` is signed by one of the CAs from `masterlist.pem`
- Private key matches public key in certificate
- Correct algorithm is used (RSA-PSS, not RSA-PKCS1)
- Salt length is 32 bytes

### Query proof public signals mismatch

**Error**: Public signals do not match contract expectations

**Check**:

- Circuit is using the latest version (`query_identity.json`)
- Query parameters are fetched from contract via `getPublicSignals()`
- Date encoding matches contract format (YYMMDD hex → decimal)
- Passport data (DG1) has correct length (93 bytes for circuit)

### Query proof execution fails

**Error**: Transaction reverted / Proof verification failed on-chain

**Verify**:

- Passport is registered on-chain (`check-kyc-status`)
- Query proof was generated with correct userAddress
- Nullifier hasn't been used before (each proof generates unique nullifier)
- Current date is within valid range
- Passport hasn't expired

### BJJKeygen not found

**Error**: Cannot find BJJKeygen binary

**Solution**:

- Make sure `BJJKeygen` binary is in project root
- Check execution permissions: `chmod +x BJJKeygen`
- Binary should be compatible with your system (Linux/macOS)

### Worker threads not exiting

**Issue**: Node.js process hangs after proof generation

**Explanation**: This is normal behavior - the process explicitly calls `process.exit(0)` after completion to terminate worker threads created by snarkjs/bb.js

## Links

### Documentation

- [Noir Documentation](https://noir-lang.org/) - Noir programming language and circuits
- [Aztec bb.js](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg/ts) - UltraPlonk backend
- [Rarimo Documentation](https://docs.rarimo.com/) - Rarimo protocol and smart contracts
- [ICAO Doc 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303) - Biometric passport specification

### Related Projects

- [passport-zk-circuits-noir](https://github.com/grndd-systems/passport-zk-circuits-noir) - Noir circuits for passport verification
- [Rarimo Core](https://github.com/rarimo/rarimo-core) - Rarimo blockchain protocol
- [zkPassport](https://github.com/zk-passport) - ZK passport ecosystem

### Standards

- [RFC 3447](https://www.rfc-editor.org/rfc/rfc3447) - RSA-PSS specification
- [Poseidon Hash](https://www.poseidon-hash.info/) - ZK-friendly hash function
- [Baby Jubjub](https://eips.ethereum.org/EIPS/eip-2494) - Elliptic curve for ZK proofs

## License

MIT
