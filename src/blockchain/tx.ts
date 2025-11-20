import {
  getProviderAndWallet,
  getStateKeeperContract,
  getRegistration2Contract,
  getQueryProofExecutorContract,
  getCertificateSMTContract,
} from './eth.js';
import { BigNumberish, BytesLike, Overrides } from 'ethers';

type CertificateStruct = {
  dataType: BytesLike;
  signedAttributes: BytesLike;
  keyOffset: BigNumberish;
  expirationOffset: BigNumberish;
};

type IcaoMemberStruct = {
  signature: BytesLike;
  publicKey: BytesLike;
};

type PassportStruct = {
  dataType: BytesLike;
  zkType: BytesLike;
  signature: BytesLike;
  publicKey: BytesLike;
  passportHash: BytesLike;
};

export async function getCertificatesRoot(): Promise<string> {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);
  const certificatesSmtAddress = await sk.certificatesSmt();

  // Get the SMT contract and read root
  const smtAbi = ['function getRoot() external view returns (bytes32)'];
  const smt = new (await import('ethers')).ethers.Contract(certificatesSmtAddress, smtAbi, wallet);
  const root = await smt.getRoot();

  return root;
}

export async function getICAOMasterTreeRoot(): Promise<string> {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);
  const root = await sk.icaoMasterTreeMerkleRoot();
  return root;
}

export async function changeICAOMasterTreeRoot(newRoot: string): Promise<void> {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);
  const tx = await sk.changeICAOMasterTreeRoot(newRoot, {
    gasLimit: 20000000,
  } as Overrides);
  console.log('Sent changeICAOMasterTreeRoot tx hash:', tx.hash);
  await tx.wait();
  console.log('Confirmed');
}

export async function registerCertificate(
  certificate: CertificateStruct,
  icaoMember: IcaoMemberStruct,
  merkleProof: BytesLike[],
) {
  const { wallet } = getProviderAndWallet();
  const reg = getRegistration2Contract(wallet);
  const sk = getStateKeeperContract(wallet);

  // solidity expects types: bytes32, bytes, uint256, etc. Convert as needed.
  const tx = await reg.registerCertificate(certificate, icaoMember, merkleProof, {
    gasLimit: 20000000,
  } as Overrides);
  console.log('Sent registerCertificate tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed registerCertificate');

  // Parse events from receipt
  if (receipt) {
    for (const log of receipt.logs) {
      try {
        const parsed = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'CertificateAdded') {
          const certificateKey = parsed.args.certificateKey;
          const expirationTimestamp = parsed.args.expirationTimestamp;

          console.log('\n=== StateKeeper.CertificateAdded Event ===');
          console.log('certificateKey:', certificateKey);
          console.log('expirationTimestamp:', expirationTimestamp.toString());

          // Call getCertificateInfo
          await getCertificateInfo(certificateKey);
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
  }
}

export async function getPassportInfo(passportKey: BytesLike) {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);

  const passportInfo = await sk.getPassportInfo(passportKey);

  console.log('\n=== Passport Info ===');
  console.log('PassportInfo.activeSessionCount:', passportInfo.activeSessionCount.toString());

  // Get detailed session information
  const [sessionKeys, sessionInfos] = await sk.getPassportSessionsInfo(passportKey);

  if (sessionKeys.length > 0) {
    console.log('\n=== Sessions ===');
    for (let i = 0; i < sessionKeys.length; i++) {
      console.log(`\nSession ${i + 1}:`);
      console.log('  sessionKey:', sessionKeys[i]);
      console.log('  activePassport:', sessionInfos[i].activePassport);
      console.log('  issueTimestamp:', sessionInfos[i].issueTimestamp.toString());
    }
  } else {
    console.log('No sessions found for this passport.');
  }

  return { passportInfo, sessionKeys, sessionInfos };
}

export async function getCertificateInfo(certificateKey: BytesLike) {
  const { wallet } = getProviderAndWallet();
  const sk = getStateKeeperContract(wallet);

  const result = await sk.getCertificateInfo(certificateKey);

  console.log('\n=== Certificate Info ===');
  console.log('expirationTimestamp:', result[0].toString());

  return result;
}

export async function registerPassportViaNoir(
  certificatesRoot: BytesLike,
  identityKey: BigNumberish,
  dgCommit: BigNumberish,
  passport: PassportStruct,
  zkPoints: BytesLike,
) {
  const { wallet } = getProviderAndWallet();
  const reg = getRegistration2Contract(wallet);
  const sk = getStateKeeperContract(wallet);

  const tx = await reg.registerViaNoir(
    certificatesRoot,
    identityKey,
    dgCommit,
    passport,
    zkPoints,
    { gasLimit: 20000000 } as Overrides,
  );
  console.log('Sent registerViaNoir tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed registerViaNoir');

  // Parse events from receipt
  if (receipt) {
    for (const log of receipt.logs) {
      try {
        const parsed = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'BondAdded') {
          const passportKey = parsed.args.passportKey;
          const sessionKey = parsed.args.sessionKey;

          console.log('\n=== StateKeeper.BondAdded Event ===');
          console.log('passportKey:', passportKey);
          console.log('sessionKey:', sessionKey);

          // Call getPassportInfo
          await getPassportInfo(passportKey);
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
  }

  return tx;
}

/**
 * Revoke a single passport session
 *
 * Revokes a specific session by proving ownership of the passport's private key.
 * This allows users to invalidate a single session on-chain.
 *
 * @param sessionKey - The session key to revoke (hashed identity key from proof)
 * @param passport - Passport data structure containing signature and public key
 * @returns Transaction object
 */
export async function revokeSession(sessionKey: BigNumberish, passport: PassportStruct) {
  const { wallet } = getProviderAndWallet();
  const reg = getRegistration2Contract(wallet);
  const sk = getStateKeeperContract(wallet);

  const tx = await reg.revoke(sessionKey, passport, { gasLimit: 20000000 } as Overrides);
  console.log('Sent revoke session tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed revoke session');

  // Parse events from receipt
  if (receipt) {
    for (const log of receipt.logs) {
      try {
        const parsed = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'BondRevoked') {
          const revokedSessionKey = parsed.args.sessionKey;

          console.log('\n=== StateKeeper.BondRevoked Event ===');
          console.log('sessionKey:', revokedSessionKey);
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
  }

  return tx;
}

/**
 * Revoke all sessions for a passport
 *
 * Revokes ALL sessions associated with a passport by proving ownership.
 * This completely invalidates the passport registration on-chain.
 *
 * @param sessionKey - Any valid session key for this passport (used for proof)
 * @param passport - Passport data structure containing signature and public key
 * @returns Transaction object
 */
export async function revokeAllSessions(sessionKey: BigNumberish, passport: PassportStruct) {
  const { wallet } = getProviderAndWallet();
  const reg = getRegistration2Contract(wallet);
  const sk = getStateKeeperContract(wallet);

  const tx = await reg.revokeAllSessions(sessionKey, passport, {
    gasLimit: 20000000,
  } as Overrides);
  console.log('Sent revoke all sessions tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed revoke all sessions');

  // Parse events from receipt
  if (receipt) {
    let revokedCount = 0;
    for (const log of receipt.logs) {
      try {
        const parsed = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'BondRevoked') {
          revokedCount++;
          const revokedSessionKey = parsed.args.sessionKey;
          console.log(`\n=== Session ${revokedCount} Revoked ===`);
          console.log('sessionKey:', revokedSessionKey);
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
    console.log(`\n✅ Total sessions revoked: ${revokedCount}`);
  }

  return tx;
}

/**
 * Revoke all sessions except one for a passport
 *
 * Revokes all sessions EXCEPT the specified one. Useful for rotating sessions
 * while keeping one active session.
 *
 * @param keepSessionKey - The session key to keep active
 * @param passport - Passport data structure containing signature and public key
 * @returns Transaction object
 */
export async function revokeOtherSessions(keepSessionKey: BigNumberish, passport: PassportStruct) {
  const { wallet } = getProviderAndWallet();
  const reg = getRegistration2Contract(wallet);
  const sk = getStateKeeperContract(wallet);

  const tx = await reg.revokeOtherSessions(keepSessionKey, passport, {
    gasLimit: 20000000,
  } as Overrides);
  console.log('Sent revoke other sessions tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed revoke other sessions');

  // Parse events from receipt
  if (receipt) {
    let revokedCount = 0;
    for (const log of receipt.logs) {
      try {
        const parsed = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'BondRevoked') {
          revokedCount++;
          const revokedSessionKey = parsed.args.sessionKey;
          console.log(`\n=== Session ${revokedCount} Revoked ===`);
          console.log('sessionKey:', revokedSessionKey);
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
    console.log(`\n✅ Total sessions revoked: ${revokedCount}`);
    console.log(`✅ Kept session: ${keepSessionKey}`);
  }

  return tx;
}

/**
 * Revoke passport identity (alias for revokeSession for backward compatibility)
 *
 * @deprecated Use revokeSession, revokeAllSessions, or revokeOtherSessions instead
 */
export async function revokePassport(sessionKey: BigNumberish, passport: PassportStruct) {
  console.warn(
    'Warning: revokePassport is deprecated. Use revokeSession, revokeAllSessions, or revokeOtherSessions instead.',
  );
  return revokeSession(sessionKey, passport);
}

/**
 * Revoke ZK KYC verification for a user and passport
 *
 * Admin function to revoke KYC verification status.
 * This removes the KYC data from the QueryProofExecutor contract.
 *
 * @param userAddress - Address of the user
 * @param passportHash - Hash of the passport to revoke KYC for
 * @returns Transaction object
 */
export async function revokeZKKYC(userAddress: string, passportHash: BytesLike) {
  const { wallet } = getProviderAndWallet();
  const executorContract = getQueryProofExecutorContract(wallet);

  console.log('\n=== Revoking ZK KYC ===');
  console.log('User Address:', userAddress);
  console.log('Passport Hash:', passportHash);

  const tx = await executorContract.revokeZKKYC(userAddress, passportHash, {
    gasLimit: 20000000,
  } as Overrides);

  console.log('Sent revokeZKKYC tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed revokeZKKYC');

  console.log('\n✅ ZK KYC revoked successfully!');

  return tx;
}

/**
 * ProofPoints structure for Circom/Groth16 proofs
 * Matches the ProofPoints struct in AQueryProofExecutor.sol
 */
export type ProofPoints = {
  a: [BigNumberish, BigNumberish];
  b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]];
  c: [BigNumberish, BigNumberish];
};

/**
 * Execute query proof via QueryProofExecutor contract
 *
 * This function calls the execute() function from AQueryProofExecutor.
 *
 * The userPayload structure is:
 * (address user, bytes32 sessionKey, bytes32 passportHash, uint256 minExpirationDate)
 *
 * @param currentDate - Current date in YYMMDD format (e.g., "251030" for Oct 30, 2025)
 * @param userAddress - Address of the user being verified
 * @param sessionKey - Session key associated with the identity
 * @param passportHash - Passport hash (DG15 hash)
 * @param minExpirationDate - Minimum passport expiration date (0 for no restriction)
 * @param zkPoints - Groth16 proof points
 * @returns Transaction object
 */
export async function executeQueryProof(
  currentDate: BigNumberish,
  userAddress: string,
  sessionKey: BytesLike,
  passportHash: BytesLike,
  minExpirationDate: BigNumberish,
  zkPoints: ProofPoints,
) {
  const { wallet } = getProviderAndWallet();
  const executorContract = getQueryProofExecutorContract(wallet);
  const ethers = await import('ethers');

  // Encode userPayload
  // (address user, bytes32 sessionKey, bytes32 passportHash, uint256 minExpirationDate)
  const userPayload = ethers.ethers.AbiCoder.defaultAbiCoder().encode(
    ['address', 'bytes32', 'bytes32', 'uint256'],
    [userAddress, sessionKey, passportHash, minExpirationDate],
  );

  console.log('\n=== Executing Query Proof ===');
  console.log('currentDate:', currentDate.toString());
  console.log('userAddress:', userAddress);
  console.log('sessionKey:', sessionKey);
  console.log('passportHash:', passportHash);
  console.log('minExpirationDate:', minExpirationDate.toString());
  console.log('userPayload:', userPayload);

  const tx = await executorContract.execute(currentDate, userPayload, zkPoints, {
    gasLimit: 20000000,
  } as Overrides);

  console.log('Sent execute tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed execute transaction');

  // Parse events from receipt
  if (receipt) {
    for (const log of receipt.logs) {
      try {
        const parsed = executorContract.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'ZKKYCVerified') {
          const userEvent = parsed.args.user;
          const timestamp = parsed.args.timestamp;

          console.log('\n=== QueryProofExecutor.ZKKYCVerified Event ===');
          console.log('user:', userEvent);
          console.log('timestamp:', timestamp.toString());
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
  }

  return tx;
}

/**
 * Execute Noir query proof via QueryProofExecutor contract
 *
 * This function calls the executeNoir() function from AQueryProofExecutor.
 * Unlike executeQueryProof which uses Groth16 ProofPoints, this accepts raw proof bytes.
 *
 * @param currentDate - Current date in YYMMDD format (e.g., "251030" for Oct 30, 2025)
 * @param userPayload - ABI-encoded user data (address, sessionKey, passportHash, minExpirationDate)
 * @param zkPoints - UltraPlonk proof bytes (from Noir circuit)
 * @returns Transaction object
 */
export async function executeQueryProofNoir(
  currentDate: BigNumberish,
  userPayload: BytesLike,
  zkPoints: BytesLike,
) {
  const { wallet } = getProviderAndWallet();
  const executorContract = getQueryProofExecutorContract(wallet);

  console.log('\n=== Executing Noir Query Proof ===');
  console.log('currentDate:', currentDate.toString());
  console.log('userPayload:', userPayload);
  console.log('zkPoints length:', zkPoints.length, 'bytes');

  const tx = await executorContract.executeNoir(currentDate, userPayload, zkPoints, {
    gasLimit: 20000000,
  } as Overrides);

  console.log('Sent executeNoir tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed executeNoir transaction');

  // Parse events from receipt
  if (receipt) {
    for (const log of receipt.logs) {
      try {
        const parsed = executorContract.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'ZKKYCVerified') {
          const userEvent = parsed.args.user;
          const timestamp = parsed.args.timestamp;

          console.log('\n=== QueryProofExecutor.ZKKYCVerified Event ===');
          console.log('user:', userEvent);
          console.log('timestamp:', timestamp.toString());
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
  }

  return tx;
}

/**
 * Get ZK KYC status for an address
 *
 * @param userAddress - Address to check
 * @returns Object with verification status and all KYC data
 */
export async function getZKKYCStatus(userAddress: string) {
  const { wallet } = getProviderAndWallet();
  const executorContract = getQueryProofExecutorContract(wallet);

  // Check if user has any verified passport
  const hasKYC = await executorContract.hasAnyVerifiedKYC(userAddress);

  console.log('\n=== ZK KYC Status ===');
  console.log('Address:', userAddress);
  console.log('Has Verified KYC:', hasKYC);

  if (!hasKYC) {
    return { isVerified: false, passports: [] };
  }

  // Get all passport hashes and KYC data
  const [passportHashes, kycDataArray] = await executorContract.getAllZKKYCData(userAddress);

  console.log('\nTotal Verified Passports:', passportHashes.length);

  const passports = [];
  for (let i = 0; i < passportHashes.length; i++) {
    console.log(`\n--- Passport ${i + 1} ---`);
    console.log('Passport Hash:', passportHashes[i]);
    console.log('Min Expiration Date:', kycDataArray[i].minExpirationDate?.toString() || '0');
    console.log('Verified At:', kycDataArray[i].verifiedAt.toString());

    passports.push({
      passportHash: passportHashes[i],
      minExpirationDate: kycDataArray[i].minExpirationDate,
      verifiedAt: kycDataArray[i].verifiedAt,
    });
  }

  return { isVerified: true, passports };
}

/**
 * Get user's verified passport hashes
 *
 * @param userAddress - Address to check
 * @returns Array of passport hashes
 */
export async function getUserPassports(userAddress: string) {
  const { wallet } = getProviderAndWallet();
  const executorContract = getQueryProofExecutorContract(wallet);

  const passportHashes = await executorContract.getUserPassports(userAddress);

  console.log('\n=== User Passports ===');
  console.log('Address:', userAddress);
  console.log('Total Passports:', passportHashes.length);

  passportHashes.forEach((hash: string, index: number) => {
    console.log(`${index + 1}. ${hash}`);
  });

  return passportHashes;
}
