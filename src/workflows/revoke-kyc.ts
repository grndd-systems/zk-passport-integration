import { ethers } from 'ethers';
import { revokeZKKYC, getZKKYCStatus, getUserPassports } from '../blockchain/tx';
import { getProviderAndWallet } from '../blockchain/eth';

/**
 * Revoke ZK KYC for a specific user and passport
 *
 * @param userAddress - Address of the user
 * @param passportHash - Hash of the passport to revoke KYC for
 */
export async function revokeUserKYC(userAddress: string, passportHash: string) {
  console.log('=== Revoking ZK KYC ===\n');

  // Verify passport hash format
  if (!passportHash.startsWith('0x') || passportHash.length !== 66) {
    throw new Error('Invalid passport hash format. Expected 32-byte hex string with 0x prefix.');
  }

  console.log('User Address:', userAddress);
  console.log('Passport Hash:', passportHash);

  // Check current KYC status
  console.log('\n=== Current KYC Status ===');
  await getZKKYCStatus(userAddress);

  // Revoke the KYC
  const tx = await revokeZKKYC(userAddress, passportHash);

  // Check updated KYC status
  console.log('\n=== Updated KYC Status ===');
  await getZKKYCStatus(userAddress);

  console.log('\n✅ ZK KYC revoked successfully!');

  return {
    transactionHash: tx.hash,
    userAddress,
    passportHash,
  };
}

/**
 * Revoke all ZK KYC verifications for a user
 *
 * @param userAddress - Address of the user
 */
export async function revokeAllUserKYC(userAddress: string) {
  console.log('=== Revoking All ZK KYC for User ===\n');
  console.log('User Address:', userAddress);

  // Get all passport hashes for the user
  console.log('\n=== Fetching User Passports ===');
  const passportHashes = await getUserPassports(userAddress);

  if (passportHashes.length === 0) {
    console.log('\n❌ No passports found for this user.');
    return {
      transactionHashes: [],
      userAddress,
      revokedCount: 0,
    };
  }

  console.log(`\nFound ${passportHashes.length} passport(s). Revoking all...`);

  const transactionHashes: string[] = [];

  // Revoke each passport
  for (let i = 0; i < passportHashes.length; i++) {
    const passportHash = passportHashes[i];
    console.log(`\n--- Revoking Passport ${i + 1}/${passportHashes.length} ---`);
    console.log('Passport Hash:', passportHash);

    const tx = await revokeZKKYC(userAddress, passportHash);
    transactionHashes.push(tx.hash);

    console.log('✓ Revoked. TX:', tx.hash);
  }

  // Check final status
  console.log('\n=== Final KYC Status ===');
  await getZKKYCStatus(userAddress);

  console.log(`\n✅ All ${passportHashes.length} ZK KYC(s) revoked successfully!`);

  return {
    transactionHashes,
    userAddress,
    revokedCount: passportHashes.length,
  };
}

/**
 * Revoke own KYC using current wallet address
 *
 * @param passportHash - Optional specific passport hash. If not provided, revokes all.
 */
export async function revokeSelfKYC(passportHash?: string) {
  const { wallet } = getProviderAndWallet();
  const userAddress = wallet.address;

  console.log('=== Revoking Self KYC ===\n');
  console.log('Your Address:', userAddress);

  if (passportHash) {
    // Revoke specific passport
    return revokeUserKYC(userAddress, passportHash);
  } else {
    // Revoke all passports
    return revokeAllUserKYC(userAddress);
  }
}
