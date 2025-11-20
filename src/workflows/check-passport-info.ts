import { ethers } from 'ethers';
import { getPassportInfo } from '../blockchain/tx';
import { loadPkPassportHash } from '../crypto/query-circuit-input';
import { getProviderAndWallet } from '../blockchain/eth';

/**
 * Check passport info for the passport from registration proof
 *
 * Loads the passportKey from the generated registration proof
 * and displays all sessions associated with this passport.
 */
export async function checkPassportInfoFromProof() {
  console.log('=== Checking Passport Info ===\n');

  try {
    // Load passportKey from registration proof
    const passportKey = loadPkPassportHash();
    const passportKeyHex = ethers.toBeHex(passportKey, 32);

    console.log('Passport Key (from proof):', passportKeyHex);

    // Get passport info from blockchain
    const { wallet, provider } = getProviderAndWallet();
    const result = await getPassportInfo(passportKeyHex);

    // Close provider connection
    provider.destroy();

    return {
      passportKey: passportKeyHex,
      activeSessionCount: result.passportInfo.activeSessionCount,
      totalSessionCount: result.passportInfo.totalSessionCount,
      sessions: result.sessionKeys.map((key: string, i: number) => ({
        sessionKey: key,
        activePassport: result.sessionInfos[i].activePassport,
        issueTimestamp: result.sessionInfos[i].issueTimestamp,
      })),
    };
  } catch (error: any) {
    console.error('\n❌ Error:', error.message);

    if (error.message.includes('Registration proof public-inputs not found')) {
      console.log('\nPlease run generate-register-proof first to create the proof.');
    }

    throw error;
  }
}
