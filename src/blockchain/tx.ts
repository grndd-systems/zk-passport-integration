import {
  getProviderAndWallet,
  getStateKeeperContract,
  getRegistration2Contract,
  getQueryProofExecutorContract,
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

  const result = await sk.getPassportInfo(passportKey);

  console.log('\n=== Passport Info ===');
  console.log('PassportInfo.activeIdentity:', result[0][0]);
  console.log('PassportInfo.identityReissueCounter:', result[0][1].toString());
  console.log('IdentityInfo.activePassport:', result[1][0]);
  console.log('IdentityInfo.issueTimestamp:', result[1][1].toString());

  return result;
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
          const identityKey = parsed.args.identityKey;

          console.log('\n=== StateKeeper.BondAdded Event ===');
          console.log('passportKey:', passportKey);
          console.log('identityKey:', identityKey);

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
 * Revoke passport identity
 *
 * Revokes an identity by proving ownership of the passport's private key.
 * This allows users to invalidate their identity on-chain.
 *
 * @param identityKey - The identity key to revoke (hashed identity key from proof)
 * @param passport - Passport data structure containing signature and public key
 * @returns Transaction object
 */
export async function revokePassport(identityKey: BigNumberish, passport: PassportStruct) {
  const { wallet } = getProviderAndWallet();
  const reg = getRegistration2Contract(wallet);
  const sk = getStateKeeperContract(wallet);

  const tx = await reg.revoke(identityKey, passport, { gasLimit: 20000000 } as Overrides);
  console.log('Sent revoke tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed revoke');

  // Parse events from receipt
  if (receipt) {
    for (const log of receipt.logs) {
      try {
        const parsed = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'BondRevoked') {
          const identityKey = parsed.args.identityKey;

          console.log('\n=== StateKeeper.BondRevoked Event ===');
          console.log('identityKey:', identityKey);
        }
      } catch (e) {
        // Skip logs that don't match
      }
    }
  }

  return tx;
}

/**
 * Reissue identity via Noir proof
 *
 * Reissues an identity with a new identityKey while using the same passport.
 * This allows rotating the BJJ identity key pair without changing the passport.
 * Common use cases:
 * - Identity key rotation for security
 * - Switching to new sk_identity while keeping same passport
 * - Moving identity to new device/wallet
 *
 * @param certificatesRoot - Root of certificates SMT (for frontrunning protection)
 * @param identityKey - The NEW identity key (from new sk_identity)
 * @param dgCommit - Commitment to DG1 data (with new sk_identity)
 * @param passport - Passport data structure (can be same passport)
 * @param zkPoints - Noir proof (bytes)
 * @returns Transaction object
 */
export async function reissueIdentityViaNoir(
  certificatesRoot: BytesLike,
  identityKey: BigNumberish,
  dgCommit: BigNumberish,
  passport: PassportStruct,
  zkPoints: BytesLike,
) {
  const { wallet } = getProviderAndWallet();
  const reg = getRegistration2Contract(wallet);
  const sk = getStateKeeperContract(wallet);

  const tx = await reg.reissueIdentityViaNoir(
    certificatesRoot,
    identityKey,
    dgCommit,
    passport,
    zkPoints,
    { gasLimit: 20000000 } as Overrides,
  );
  console.log('Sent reissueIdentityViaNoir tx hash:', tx.hash);

  const receipt = await tx.wait();
  console.log('Confirmed reissueIdentityViaNoir');

  // Parse events from receipt
  if (receipt) {
    for (const log of receipt.logs) {
      try {
        const parsed = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (parsed && parsed.name === 'BondReissued') {
          const passportKey = parsed.args.passportKey;
          const identityKey = parsed.args.identityKey;

          console.log('\n=== StateKeeper.BondReissued Event ===');
          console.log('passportKey:', passportKey);
          console.log('identityKey:', identityKey);

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
 * (address user, string requestId, uint256 nullifier, bytes32 passportHash, uint256 identityCreationTimestamp)
 *
 * @param currentDate - Current date in YYMMDD format (e.g., "251030" for Oct 30, 2025)
 * @param userAddress - Address of the user being verified
 * @param requestId - Request ID string
 * @param nullifier - Nullifier from the query proof
 * @param passportHash - Passport hash (DG15 hash)
 * @param identityCreationTimestamp - Timestamp of identity creation (0 for no restriction)
 * @param zkPoints - Groth16 proof points
 * @returns Transaction object
 */
export async function executeQueryProof(
  currentDate: BigNumberish,
  userAddress: string,
  requestId: string,
  nullifier: BigNumberish,
  passportHash: BytesLike,
  identityCreationTimestamp: BigNumberish,
  zkPoints: ProofPoints,
) {
  const { wallet } = getProviderAndWallet();
  const executorContract = getQueryProofExecutorContract(wallet);
  const ethers = await import('ethers');

  // Encode userPayload
  // (address user, string requestId, uint256 nullifier, bytes32 passportHash, uint256 identityCreationTimestamp)
  const userPayload = ethers.ethers.AbiCoder.defaultAbiCoder().encode(
    ['address', 'string', 'uint256', 'bytes32', 'uint256'],
    [userAddress, requestId, nullifier, passportHash, identityCreationTimestamp],
  );

  console.log('\n=== Executing Query Proof ===');
  console.log('currentDate:', currentDate.toString());
  console.log('userAddress:', userAddress);
  console.log('requestId:', requestId);
  console.log('nullifier:', nullifier.toString());
  console.log('passportHash:', passportHash);
  console.log('identityCreationTimestamp:', identityCreationTimestamp.toString());
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
          const requestIdEvent = parsed.args.celestialId || parsed.args.requestId;
          const userEvent = parsed.args.user;
          const nullifierEvent = parsed.args.nullifier;
          const timestamp = parsed.args.timestamp;

          console.log('\n=== QueryProofExecutor.ZKKYCVerified Event ===');
          console.log('requestId:', requestIdEvent);
          console.log('user:', userEvent);
          console.log('nullifier:', nullifierEvent.toString());
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
 * @returns Object with isVerified flag and ZKKYCData
 */
export async function getZKKYCStatus(userAddress: string) {
  const { wallet } = getProviderAndWallet();
  const executorContract = getQueryProofExecutorContract(wallet);

  const result = await executorContract.getZKKYCStatus(userAddress);

  console.log('\n=== ZK KYC Status ===');
  console.log('Address:', userAddress);
  console.log('Is Verified:', result[0]);
  if (result[0]) {
    const requestId = result[1].celestialId || result[1].requestId;
    console.log('Request ID:', requestId);
    console.log('Nullifier:', result[1].nullifier.toString());
    console.log('Passport Hash:', result[1].passportHash);
    console.log('Identity Creation Timestamp:', result[1].identityCreationTimestamp.toString());
    console.log('Verified At:', result[1].verifiedAt.toString());
  }

  return result;
}
