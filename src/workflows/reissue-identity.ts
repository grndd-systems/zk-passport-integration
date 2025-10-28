import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { reissueIdentityViaNoir, getCertificatesRoot } from '../blockchain/tx';
import { P_RSA_SHA256_2688, Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296 } from '../blockchain/eth';

interface Passport {
  dataType: string;
  zkType: string;
  signature: string;
  publicKey: string;
  passportHash: string;
}

export async function reissuePassport() {
  console.log('Reissuing passport identity via Noir proof...');

  // Load the generated passport data
  // The passport can be the SAME as original registration
  // What changes is the identityKey (derived from NEW sk_identity)
  const passportFiles = fs.readdirSync(path.join(__dirname, '../../data/out_passport'));
  const latestPassportFile = passportFiles.sort().reverse()[0];
  const passportPath = path.join(__dirname, '../../data/out_passport', latestPassportFile);
  const passportData = JSON.parse(fs.readFileSync(passportPath, 'utf-8'));

  console.log('Using passport file:', latestPassportFile);

  // Extract circuit output values from the public-inputs file
  // NOTE: The proof must be generated with a NEW sk_identity (different from original registration)
  // This generates a NEW identityKey while proving ownership of the same passport
  const publicInputsPath = path.join(__dirname, '../../data/proof/public-inputs');
  const publicInputsContent = fs.readFileSync(publicInputsPath, 'utf-8');
  const circuitOutputs = publicInputsContent
    .trim()
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => BigInt(line.trim()));

  console.log(
    'Circuit outputs extracted from public-inputs:',
    circuitOutputs.map((o) => ethers.toBeHex(o, 32)),
  );

  // The circuit public inputs/outputs are:
  // [0] = passportKey (OUTPUT - passport key) extract_dg15_pk_hash::<DG15_LEN, AA_SHIFT, AA_SIG_TYPE>(dg15)
  // [1] = passportHash (OUTPUT - hash of the passport data) extract_passport_hash::<HASH_ALGO>(sa_hash)
  // [2] = dgCommit (OUTPUT - commitment to DG1) extract_dg1_commitment::<DG1_LEN>(dg1, sk_identity)
  // [3] = identityKey (OUTPUT - hashed identity key) extract_pk_identity_hash(sk_identity)
  // [4] = certificatesRoot (INPUT - passed to circuit for verification)

  const passportKey = circuitOutputs[0];
  const passportHash = circuitOutputs[1];
  const dgCommit = circuitOutputs[2];
  const identityKey = circuitOutputs[3];
  const circuitCertificatesRoot = circuitOutputs[4];

  // Get the current certificates root from the blockchain
  console.log('Reading certificates root from blockchain...');
  const certificatesRoot = await getCertificatesRoot();
  console.log('Certificates root:', certificatesRoot);

  // Verify that the circuit's certificatesRoot matches the blockchain's current root
  if (ethers.toBeHex(circuitCertificatesRoot, 32) !== certificatesRoot) {
    console.warn(
      '\n⚠️  WARNING: Circuit certificatesRoot does not match blockchain certificatesRoot!',
    );
    console.warn('  Circuit:    ', ethers.toBeHex(circuitCertificatesRoot, 32));
    console.warn('  Blockchain: ', certificatesRoot);
    console.warn('  The proof was generated with a different certificates tree state.');
    console.warn('  Transaction will likely fail with frontrunning protection.\n');
  }

  // Extract modulus from DG15 for RSA operations
  const dg15Buffer = Buffer.from(passportData.dg15, 'base64');

  // Parse DG15 to extract the modulus
  let offset = 0;
  if (dg15Buffer[offset] === 0x6f) {
    offset++;
    if (dg15Buffer[offset] & 0x80) {
      const lengthBytes = dg15Buffer[offset] & 0x7f;
      offset += 1 + lengthBytes;
    } else {
      offset += 1;
    }
  }
  const spki = dg15Buffer.slice(offset);

  const publicKey = crypto.createPublicKey({
    key: spki,
    format: 'der',
    type: 'spki',
  });

  const jwk = publicKey.export({ format: 'jwk' }) as crypto.JsonWebKey;
  const modulusBytes = Buffer.from(jwk.n!, 'base64');

  console.log('Using modulus as publicKey:', modulusBytes.length, 'bytes');

  const passport: Passport = {
    dataType: P_RSA_SHA256_2688, // RSA 2048-bit with SHA-256 (our certificate type)
    zkType: Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296, // Noir verifier type
    signature: '0x' + passportData.signature,
    publicKey: '0x' + modulusBytes.toString('hex'), // Send modulus only (256 bytes)
    passportHash: ethers.toBeHex(passportHash, 32),
  };

  // Load the ZK proof
  const proofPath = path.join(__dirname, '../../data/proof/proof');

  if (!fs.existsSync(proofPath)) {
    throw new Error(
      '\n❌ Proof file not found!\n\n' +
        'The witness file (noir_dl.gz) is 566KB and contains circuit execution trace.\n' +
        'You need to generate the actual cryptographic proof (~2KB) using Barretenberg:\n\n' +
        'Steps:\n' +
        '  1. cd /home/horacio/Projects/passport-zk-circuits-noir\n' +
        '  2. bb prove -b ./target/noir_dl.json -w ./target/noir_dl.gz -o ./target/proof\n' +
        '  3. Copy the proof: cp ./target/proof ' +
        proofPath +
        '\n\n' +
        'Requirements:\n' +
        '  - bb version 0.66.0 (install: npm install -g @aztec/bb)\n',
    );
  }

  // Read proof as binary
  let zkPoints: Buffer;
  zkPoints = fs.readFileSync(proofPath);

  console.log('\nTransaction parameters:');
  console.log('  certificatesRoot:', certificatesRoot);
  console.log('  identityKey:', ethers.toBeHex(identityKey, 32));
  console.log('  dgCommit:', ethers.toBeHex(dgCommit, 32));
  console.log('  passport.dataType:', passport.dataType);
  console.log('  passport.zkType:', passport.zkType);
  console.log('  passport.signature:', passport.signature);
  console.log('  passport.publicKey:', passport.publicKey);
  console.log('  passport.passportHash:', passport.passportHash);
  console.log('  zkPoints length:', zkPoints.length, 'bytes');
  console.log(
    '\nNOTE: This is a NEW identityKey (from new sk_identity) for the same passport',
  );
  console.log('  New identityKey:', ethers.toBeHex(identityKey, 32));

  // Use the tx.ts function for reissuing
  const tx = await reissueIdentityViaNoir(
    certificatesRoot,
    identityKey,
    dgCommit,
    passport,
    zkPoints,
  );

  console.log('Passport reissued successfully!');

  return {
    transactionHash: tx.hash,
  };
}
