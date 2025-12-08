import { ethers } from 'ethers';
import {
  revokeSession,
  revokeAllSessions,
  revokeOtherSessions,
  getPassportInfo,
} from '../blockchain/tx';
import {
  P_RSA_SHA256_2688,
  Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296,
  getProviderAndWallet,
} from '../blockchain/eth';
import {
  loadLatestPassportData,
  loadRegistrationProofOutputs,
  loadPkPassportHash,
  extractModulusFromDG15,
} from '../crypto/query-circuit-input';

interface Passport {
  dataType: string;
  zkType: string;
  signature: string;
  publicKey: string;
  passportHash: string;
}

/**
 * Revoke a single session
 */
export async function revokeSingleSession() {
  console.log('=== Revoking Single Session ===\n');

  // Load the generated passport data
  const { data: passportData, filename } = loadLatestPassportData();
  console.log('Using passport file:', filename);

  // Load registration proof outputs
  const { passportHash, identityKey: sessionKey } = loadRegistrationProofOutputs();

  console.log('\nCircuit outputs from registration proof:');
  console.log('  passportHash:', ethers.toBeHex(passportHash, 32));
  console.log('  sessionKey:', ethers.toBeHex(sessionKey, 32));

  // Extract modulus from DG15 for RSA operations
  const modulusBytes = extractModulusFromDG15(passportData.dg15);

  const passport: Passport = {
    dataType: P_RSA_SHA256_2688,
    zkType: Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296,
    signature: '0x' + passportData.signature,
    publicKey: '0x' + modulusBytes.toString('hex'),
    passportHash: ethers.toBeHex(passportHash, 32),
  };

  console.log('\n=== Transaction Parameters ===');
  console.log('  sessionKey:', ethers.toBeHex(sessionKey, 32));
  console.log('  passport.passportHash:', passport.passportHash);

  // Revoke the session
  const tx = await revokeSession(sessionKey, passport);

  console.log('\n✅ Session revoked successfully!');

  return {
    transactionHash: tx.hash,
    sessionKey: ethers.toBeHex(sessionKey, 32),
  };
}

/**
 * Revoke all sessions for a passport
 */
export async function revokeAllPassportSessions() {
  console.log('=== Revoking All Sessions ===\n');

  // Load the generated passport data
  const { data: passportData, filename } = loadLatestPassportData();
  console.log('Using passport file:', filename);

  // Load registration proof outputs
  const { passportHash, identityKey: sessionKey } = loadRegistrationProofOutputs();
  const passportKey = loadPkPassportHash();

  console.log('\nCircuit outputs from registration proof:');
  console.log('  passportKey:', ethers.toBeHex(passportKey, 32));
  console.log('  passportHash:', ethers.toBeHex(passportHash, 32));
  console.log('  sessionKey:', ethers.toBeHex(sessionKey, 32));

  // Get current sessions before revoking
  console.log('\n=== Current Sessions ===');
  const { wallet } = getProviderAndWallet();
  await getPassportInfo(ethers.toBeHex(passportKey, 32));

  // Extract modulus from DG15 for RSA operations
  const modulusBytes = extractModulusFromDG15(passportData.dg15);

  const passport: Passport = {
    dataType: P_RSA_SHA256_2688,
    zkType: Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296,
    signature: '0x' + passportData.signature,
    publicKey: '0x' + modulusBytes.toString('hex'),
    passportHash: ethers.toBeHex(passportHash, 32),
  };

  console.log('\n=== Transaction Parameters ===');
  console.log('  sessionKey (for proof):', ethers.toBeHex(sessionKey, 32));
  console.log('  passport.passportHash:', passport.passportHash);

  // Revoke all sessions
  const tx = await revokeAllSessions(sessionKey, passport);

  console.log('\n✅ All sessions revoked successfully!');

  return {
    transactionHash: tx.hash,
  };
}

/**
 * Revoke other sessions (keep current one)
 *
 * @param keepSessionKey - Optional session key to keep. If not provided, uses current session from proof
 */
export async function revokeOtherPassportSessions(keepSessionKey?: bigint) {
  console.log('=== Revoking Other Sessions (Keep Current) ===\n');

  // Load the generated passport data
  const { data: passportData, filename } = loadLatestPassportData();
  console.log('Using passport file:', filename);

  // Load registration proof outputs
  const { passportHash, identityKey: currentSessionKey } = loadRegistrationProofOutputs();
  const passportKey = loadPkPassportHash();
  const sessionToKeep = keepSessionKey || currentSessionKey;

  console.log('\nCircuit outputs from registration proof:');
  console.log('  passportKey:', ethers.toBeHex(passportKey, 32));
  console.log('  passportHash:', ethers.toBeHex(passportHash, 32));
  console.log('  currentSessionKey:', ethers.toBeHex(currentSessionKey, 32));
  console.log('  sessionToKeep:', ethers.toBeHex(sessionToKeep, 32));

  // Get current sessions before revoking
  console.log('\n=== Current Sessions ===');
  const { wallet } = getProviderAndWallet();
  await getPassportInfo(ethers.toBeHex(passportKey, 32));

  // Extract modulus from DG15 for RSA operations
  const modulusBytes = extractModulusFromDG15(passportData.dg15);

  const passport: Passport = {
    dataType: P_RSA_SHA256_2688,
    zkType: Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296,
    signature: '0x' + passportData.signature,
    publicKey: '0x' + modulusBytes.toString('hex'),
    passportHash: ethers.toBeHex(passportHash, 32),
  };

  console.log('\n=== Transaction Parameters ===');
  console.log('  keepSessionKey:', ethers.toBeHex(sessionToKeep, 32));
  console.log('  passport.passportHash:', passport.passportHash);

  // Revoke other sessions
  const tx = await revokeOtherSessions(sessionToKeep, passport);

  console.log('\n✅ Other sessions revoked successfully!');

  return {
    transactionHash: tx.hash,
    keptSession: ethers.toBeHex(sessionToKeep, 32),
  };
}
