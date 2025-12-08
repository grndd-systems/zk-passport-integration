import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { getCertificatesRoot, getZKKYCStatus, getPassportInfo } from '../blockchain/tx';
import {
  P_RSA_SHA256_2688,
  Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296,
  getProviderAndWallet,
  getQueryProofExecutorContract,
  getStateKeeperContract,
} from '../blockchain/eth';
import {
  loadLatestPassportData,
  loadRegistrationProofOutputs,
  extractModulusFromDG15,
  getCurrentDateFromBlockchain,
  calculateMinExpirationDate,
} from '../crypto/query-circuit-input';

/**
 * Parameters for EIP-7702 registration and KYC verification
 */
export interface RegisterAndVerifyKYCEIP7702Params {
  // User parameters
  userAddress?: string; // If not provided, uses wallet address from env

  // Identity parameters
  minExpirationDate?: number; // Optional: minimum passport expiration date (0 = no restriction)

  // Registration proof path
  registrationProofPath?: string; // Path to registration proof binary (default: data/proof/proof)

  // Query proof paths
  queryProofPath?: string; // Path to query proof binary (default: data/query-proof-noir/query_proof)
  queryPublicPath?: string; // Path to public signals (default: data/query-proof-noir/public-inputs)

  // Date parameter
  currentDate?: bigint; // Current date, auto-calculated if not provided
}

interface Passport {
  dataType: string;
  zkType: string;
  signature: string;
  publicKey: string;
  passportHash: string;
}

/**
 * Load public inputs from file (one value per line)
 */
function loadPublicInputs(filePath: string): string[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  return content
    .trim()
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/**
 * Register passport and verify KYC using simplified workflow
 *
 * This workflow calls QueryProofExecutor.executeNoir() with extended userPayload
 * that includes registration data. The contract handles registration internally if needed.
 *
 * Flow:
 * 1. Load registration proof and query proof data
 * 2. Create extended userPayload with all registration parameters
 * 3. Call executeNoir() which internally calls registerViaNoir if not registered
 * 4. Verify KYC status
 *
 * Prerequisites:
 * - Registration proof must be generated
 * - Query proof must be generated
 *
 * @param params - Workflow parameters
 */
export async function registerAndVerifyKYCWorkflow(params: RegisterAndVerifyKYCEIP7702Params = {}) {
  console.log('=== Register & Verify KYC (Simplified Workflow) ===\n');

  // ============================================================================
  // STEP 1: Load Registration Data
  // ============================================================================
  console.log('--- Step 1: Loading Registration Data ---');

  const { data: passportData, filename } = loadLatestPassportData();
  console.log('✓ Using passport file:', filename);

  const {
    passportKey,
    passportHash,
    dgCommit,
    identityKey,
    certificatesRoot: circuitCertificatesRoot,
  } = loadRegistrationProofOutputs();

  console.log('✓ Registration proof outputs loaded');

  const certificatesRoot = await getCertificatesRoot();
  console.log('✓ Blockchain certificatesRoot:', certificatesRoot);

  if (ethers.toBeHex(circuitCertificatesRoot, 32) !== certificatesRoot) {
    console.warn('⚠️  WARNING: Circuit certificatesRoot mismatch!');
  }

  const modulusBytes = extractModulusFromDG15(passportData.dg15);

  const passport: Passport = {
    dataType: P_RSA_SHA256_2688,
    zkType: Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296,
    signature: '0x' + passportData.signature,
    publicKey: '0x' + modulusBytes.toString('hex'),
    passportHash: ethers.toBeHex(passportHash, 32),
  };

  const registrationProofPath =
    params.registrationProofPath || path.join(process.cwd(), 'data', 'proof', 'proof');

  if (!fs.existsSync(registrationProofPath)) {
    throw new Error(`Registration proof not found at ${registrationProofPath}`);
  }

  const registrationZkPoints = fs.readFileSync(registrationProofPath);
  console.log('✓ Loaded registration proof:', registrationZkPoints.length, 'bytes');

  // ============================================================================
  // STEP 2: Load Query Proof Data
  // ============================================================================
  console.log('\n--- Step 2: Loading Query Proof Data ---');

  const queryProofPath =
    params.queryProofPath || path.join(process.cwd(), 'data', 'query-proof-noir', 'query_proof');
  const queryPublicPath =
    params.queryPublicPath || path.join(process.cwd(), 'data', 'query-proof-noir', 'public-inputs');

  if (!fs.existsSync(queryProofPath) || !fs.existsSync(queryPublicPath)) {
    throw new Error('Query proof files not found. Run generate-query-proof-noir first.');
  }

  const kycZkPoints = fs.readFileSync(queryProofPath);
  const publicSignals = loadPublicInputs(queryPublicPath);

  console.log('✓ Loaded query proof:', kycZkPoints.length, 'bytes');
  console.log('✓ Nullifier:', publicSignals[0]);

  // ============================================================================
  // STEP 3: Prepare Parameters
  // ============================================================================
  console.log('\n--- Step 3: Preparing Transaction Parameters ---');

  const { wallet, provider } = getProviderAndWallet();
  const userAddress = params.userAddress || wallet.address;
  console.log('✓ User address:', userAddress);

  const block = await provider.getBlock('latest');
  if (!block) throw new Error('Failed to get latest block');

  const blockDate = new Date(block.timestamp * 1000);
  const currentDate = params.currentDate || (await getCurrentDateFromBlockchain(provider));
  const minExpirationDate =
    params.minExpirationDate !== undefined
      ? params.minExpirationDate
      : calculateMinExpirationDate(blockDate, 6);

  console.log('✓ Current Date:', currentDate);
  console.log('✓ Min Expiration Date:', minExpirationDate);

  const sessionKey = ethers.toBeHex(identityKey, 32);
  const passportKeyHash = ethers.toBeHex(passportKey, 32);

  // ============================================================================
  // STEP 4: Check if Passport is Already Registered
  // ============================================================================
  console.log('\n--- Step 4: Checking Passport Registration Status ---');

  let isPassportRegistered = false;
  try {
    const { passportInfo } = await getPassportInfo(passportKeyHash);
    isPassportRegistered = passportInfo.activeSessionCount > 0;
    console.log('✓ Passport is already registered, will skip registration proof');
  } catch (e) {
    console.log('✓ Passport not yet registered, will include registration proof');
  }

  // Use empty bytes if already registered, otherwise use actual proof
  const registrationProof = isPassportRegistered ? '0x' : registrationZkPoints;

  // ============================================================================
  // STEP 5: Prepare Extended User Payload
  // ============================================================================
  console.log('\n--- Step 5: Preparing Extended User Payload ---');

  // Extended userPayload includes registration data so QueryProofExecutor
  // can handle registration internally if needed
  const userPayload = ethers.AbiCoder.defaultAbiCoder().encode(
    [
      'address',
      'bytes32',
      'bytes32',
      'uint256',
      'bytes32',
      'uint256',
      'tuple(bytes32,bytes32,bytes,bytes,bytes32)',
      'bytes',
    ],
    [
      userAddress, // user
      sessionKey, // sessionKey
      passportKeyHash, // passportKey
      minExpirationDate, // minExpirationDate
      certificatesRoot, // certificatesRoot (for registration)
      dgCommit, // dgCommit (for registration)
      [
        passport.dataType, // passport.dataType (bytes32)
        passport.zkType, // passport.zkType (bytes32)
        passport.signature, // passport.signature
        passport.publicKey, // passport.publicKey
        passport.passportHash, // passport.passportHash
      ], // passport struct (for registration)
      registrationProof, // ZK proof for registration (or empty bytes if already registered)
    ],
  );

  console.log('✓ Extended userPayload prepared with registration data');
  console.log('✓ Registration proof included:', !isPassportRegistered);

  // ============================================================================
  // STEP 6: Send executeNoir Transaction
  // ============================================================================
  console.log('\n--- Step 6: Sending executeNoir Transaction ---');

  const queryExecutor = getQueryProofExecutorContract(wallet);

  // Call executeNoir with extended userPayload
  const tx = await queryExecutor.executeNoir(currentDate, userPayload, kycZkPoints, {
    gasLimit: 30000000,
  });

  console.log('✓ Transaction sent:', tx.hash);
  console.log('✓ Waiting for confirmation...');

  const receipt = await tx.wait();
  console.log('✅ Transaction confirmed in block:', receipt?.blockNumber);
  console.log('Gas used:', receipt?.gasUsed.toString());

  // ============================================================================
  // STEP 7: Parse Events
  // ============================================================================
  console.log('\n--- Step 7: Parsing Transaction Events ---');

  // Parse events to check execution status
  if (receipt) {
    let bondAdded = false;
    let kycVerified = false;

    console.log('\n=== Parsing Transaction Events ===');
    console.log('Total logs:', receipt.logs.length);

    const sk = getStateKeeperContract(wallet);

    for (const log of receipt.logs) {
      // Try to parse as StateKeeper events (registration)
      try {
        const parsedSK = sk.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });

        if (parsedSK && parsedSK.name === 'BondAdded') {
          bondAdded = true;
          console.log('\n=== StateKeeper.BondAdded (Registration) ===');
          console.log('Passport Key:', parsedSK.args.passportKey);
          console.log('Session Key:', parsedSK.args.sessionKey);
          console.log('✅ Passport registered successfully');
        }
      } catch (e) {
        // Not a StateKeeper event
      }

      // Try to parse as QueryProofExecutor events (KYC)
      try {
        const parsedExecutor = queryExecutor.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });

        if (parsedExecutor && parsedExecutor.name === 'ZKKYCVerified') {
          kycVerified = true;
          console.log('\n=== QueryProofExecutor.ZKKYCVerified ===');
          console.log('User:', parsedExecutor.args.user);
          console.log('Timestamp:', parsedExecutor.args.timestamp.toString());
          console.log('✅ KYC verified successfully');
        }
      } catch (e) {
        // Not a QueryProofExecutor event
      }
    }

    // Summary
    console.log('\n=== Transaction Summary ===');
    if (bondAdded) {
      console.log('✅ Passport registration: SUCCESS');
    } else {
      console.log('ℹ️  Passport registration: SKIPPED (already registered)');
    }
    if (kycVerified) {
      console.log('✅ KYC verification: SUCCESS');
    } else {
      console.warn('⚠️  KYC verification: NOT FOUND');
    }
  }

  // ============================================================================
  // STEP 8: Verify Result
  // ============================================================================
  console.log('\n--- Step 8: Verifying KYC Status ---');
  await getZKKYCStatus(userAddress);

  provider.destroy();

  return {
    transactionHash: tx.hash,
    userAddress,
    passportHash: passportKeyHash,
  };
}
