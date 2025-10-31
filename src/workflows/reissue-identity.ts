import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { reissueIdentityViaNoir, getCertificatesRoot } from '../blockchain/tx';
import {
  P_RSA_SHA256_2688,
  Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296,
} from '../blockchain/eth';
import {
  loadLatestPassportData,
  loadRegistrationProofOutputs,
  extractModulusFromDG15,
} from '../crypto/query-circuit-input';

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
  const { data: passportData, filename } = loadLatestPassportData();
  console.log('Using passport file:', filename);

  // Load registration proof outputs
  // NOTE: The proof must be generated with a NEW sk_identity (different from original registration)
  // This generates a NEW identityKey while proving ownership of the same passport
  const {
    passportKey,
    passportHash,
    dgCommit,
    identityKey,
    certificatesRoot: circuitCertificatesRoot,
  } = loadRegistrationProofOutputs();

  console.log('Circuit outputs from registration proof:');
  console.log('  passportKey:', ethers.toBeHex(passportKey, 32));
  console.log('  passportHash:', ethers.toBeHex(passportHash, 32));
  console.log('  dgCommit:', ethers.toBeHex(dgCommit, 32));
  console.log('  identityKey:', ethers.toBeHex(identityKey, 32));
  console.log('  certificatesRoot:', ethers.toBeHex(circuitCertificatesRoot, 32));

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
  const modulusBytes = extractModulusFromDG15(passportData.dg15);

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
  console.log('\nNOTE: This is a NEW identityKey (from new sk_identity) for the same passport');
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
