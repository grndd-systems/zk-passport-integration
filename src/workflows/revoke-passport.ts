import { ethers } from 'ethers';
import { revokePassport } from '../blockchain/tx';
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

export async function revokePassportIdentity() {
  console.log('Revoking passport identity...');

  // Load the generated passport data
  const { data: passportData, filename } = loadLatestPassportData();
  console.log('Using passport file:', filename);

  // Load registration proof outputs
  const { passportHash, identityKey } = loadRegistrationProofOutputs();

  console.log('Circuit outputs from registration proof:');
  console.log('  passportHash:', ethers.toBeHex(passportHash, 32));
  console.log('  identityKey:', ethers.toBeHex(identityKey, 32));

  // Extract modulus from DG15 for RSA operations
  const modulusBytes = extractModulusFromDG15(passportData.dg15);

  console.log('Using modulus as publicKey:', modulusBytes.length, 'bytes');

  const passport: Passport = {
    dataType: P_RSA_SHA256_2688, // RSA 2048-bit with SHA-256
    zkType: Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296, // Noir verifier type
    signature: '0x' + passportData.signature,
    publicKey: '0x' + modulusBytes.toString('hex'), // Send modulus only (256 bytes)
    passportHash: ethers.toBeHex(passportHash, 32),
  };

  console.log('\nTransaction parameters:');
  console.log('  identityKey:', ethers.toBeHex(identityKey, 32));
  console.log('  passport.dataType:', passport.dataType);
  console.log('  passport.zkType:', passport.zkType);
  console.log('  passport.signature:', passport.signature);
  console.log('  passport.publicKey:', passport.publicKey);
  console.log('  passport.passportHash:', passport.passportHash);

  // Use the tx.ts function to revoke the passport
  const tx = await revokePassport(identityKey, passport);

  console.log('Passport identity revoked successfully!');

  return {
    transactionHash: tx.hash,
  };
}
