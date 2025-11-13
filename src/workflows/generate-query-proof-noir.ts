import { UltraPlonkBackend, BackendOptions } from '@aztec/bb.js';
import { Noir, CompiledCircuit } from '@noir-lang/noir_js';
import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';
import {
  loadLatestPassportData,
  loadPkPassportHash,
  loadPkIdentityHash,
  encodePassportDate,
  calculateMinExpirationDate,
} from '../crypto/query-circuit-input';
import { readSkIdentity } from '../utils/bjj-key';
import { getProviderAndWallet, getQueryProofExecutorContract } from '../blockchain/eth';
import circuitData from '../../data/circuit/query_identity.json';

const circuit = circuitData as unknown as CompiledCircuit;

export interface GenerateNoirQueryProofParams {
  userAddress: string;
  identityCreationTimestamp?: number;
  minExpirationDate?: number;
}

/**
 * Generate Noir query proof using parameters from contract's getPublicSignals
 * Uses UltraPlonk backend instead of Groth16
 *
 * @param params - Parameters for proof generation
 * @returns Generated proof with public inputs
 */
export async function generateNoirQueryProofFromContract(params: GenerateNoirQueryProofParams) {
  console.log('\n=== Generating Noir Query Proof from Contract Parameters ===\n');

  // Load passport data
  const { dg1Array, filename } = loadLatestPassportData();
  console.log('Loaded passport:', filename);

  // Load sk_identity
  const skIdentity = readSkIdentity();

  // User parameters
  const { userAddress, identityCreationTimestamp = 0 } = params;

  // Get blockchain state
  const { provider, wallet } = getProviderAndWallet();
  const contract = getQueryProofExecutorContract(wallet);
  const block = await provider.getBlock('latest');

  if (!block) {
    throw new Error('Failed to get latest block');
  }

  const blockDate = new Date(block.timestamp * 1000);
  const currentDateEncoded = encodePassportDate(blockDate);
  const currentDateDecimal = BigInt(currentDateEncoded);
  const minExpirationDate = calculateMinExpirationDate(blockDate, 6); // 6 months from current date
  console.log('Block timestamp:', block.timestamp);
  console.log('Block date:', blockDate.toISOString());
  console.log('Current Date (encoded):', currentDateEncoded);
  console.log('Current Date (decimal):', currentDateDecimal.toString());

  // Get passport hash
  const pkPassportHash = loadPkPassportHash();
  const passportHash = ethers.toBeHex(pkPassportHash, 32);

  console.log('\nPassport hash:', passportHash);
  console.log('User address:', userAddress);
  console.log('Identity Creation Timestamp:', identityCreationTimestamp);
  console.log('Min Expiration Date:', minExpirationDate);

  // Prepare userPayload for getPublicSignals call
  // Format: (address user, uint256 nullifier, bytes32 passportHash, uint256 identityCreationTimestamp, uint256 minExpirationDate)
  const nullifierPlaceholder = 0;

  const userPayload = ethers.AbiCoder.defaultAbiCoder().encode(
    ['address', 'uint256', 'bytes32', 'uint256', 'uint256'],
    [userAddress, nullifierPlaceholder, passportHash, identityCreationTimestamp, minExpirationDate],
  );

  console.log('\n=== Calling contract.getPublicSignals ===');

  // Call getPublicSignals to get expected parameters
  const expectedSignals = await contract.getPublicSignals(currentDateDecimal, userPayload);

  console.log('\n=== Expected Public Signals from Contract ===');
  console.log('Total signals:', expectedSignals.length);

  // Extract key parameters from expected signals
  const eventID = expectedSignals[9].toString();
  const eventData = expectedSignals[10].toString();
  const selector = Number(expectedSignals[12]);
  const timestampLowerbound = expectedSignals[14].toString();
  const timestampUpperbound = expectedSignals[15].toString();
  const identityCounterLowerbound = expectedSignals[16].toString();
  const identityCounterUpperbound = expectedSignals[17].toString();

  // Convert date bounds back to hex format
  const toHex = (val: bigint) => {
    const hex = val.toString(16).padStart(12, '0');
    return hex.startsWith('0x') ? hex : '0x' + hex;
  };

  const birthDateLowerbound = toHex(expectedSignals[18]);
  const birthDateUpperbound = toHex(expectedSignals[19]);
  const expirationDateLowerbound = toHex(expectedSignals[20]);
  const expirationDateUpperbound = toHex(expectedSignals[21]);

  const citizenshipMask = expectedSignals[22].toString();

  console.log('\n=== Extracted Parameters ===');
  console.log('Event ID:', eventID);
  console.log('Event Data:', eventData);
  console.log('Selector:', selector);
  console.log('Current Date:', currentDateEncoded);
  console.log('Timestamp bounds:', timestampLowerbound, '-', timestampUpperbound);
  console.log(
    'Identity counter bounds:',
    identityCounterLowerbound,
    '-',
    identityCounterUpperbound,
  );
  console.log('Birth date bounds:', birthDateLowerbound, '-', birthDateUpperbound);
  console.log('Expiration date bounds:', expirationDateLowerbound, '-', expirationDateUpperbound);
  console.log('Citizenship mask:', citizenshipMask);

  // Circuit expects 93 bytes of DG1
  const dg1Bytes = dg1Array.slice(0, 93);

  console.log('\n=== Preparing Noir Circuit Inputs ===');

  // Prepare inputs matching Noir circuit signature:
  // pub fn query_identity(
  //   event_id, event_data, selector, current_date,
  //   timestamp_lowerbound, timestamp_upperbound,
  //   identity_count_lowerbound, identity_count_upperbound,
  //   birth_date_lowerbound, birth_date_upperbound,
  //   expiration_date_lowerbound, expiration_date_upperbound,
  //   citizenship_mask, pk_identity, sk_identity,
  //   dg1: [u8; 93], timestamp, identity_counter
  // )
  const noirInputs = {
    event_id: eventID,
    event_data: eventData,
    selector: selector.toString(),
    current_date: BigInt(currentDateEncoded).toString(),
    timestamp_lowerbound: timestampLowerbound,
    timestamp_upperbound: timestampUpperbound,
    identity_count_lowerbound: identityCounterLowerbound,
    identity_count_upperbound: identityCounterUpperbound,
    birth_date_lowerbound: BigInt(birthDateLowerbound).toString(),
    birth_date_upperbound: BigInt(birthDateUpperbound).toString(),
    expiration_date_lowerbound: BigInt(expirationDateLowerbound).toString(),
    expiration_date_upperbound: BigInt(expirationDateUpperbound).toString(),
    citizenship_mask: citizenshipMask,
    pk_identity: loadPkIdentityHash().toString(), // Hash of sk_identity (renamed from sk_hash)
    sk_identity: skIdentity.toString(),
    dg1: Array.from(dg1Bytes), // Convert to array of numbers
    timestamp: block.timestamp.toString(),
    identity_counter: '1',
  };

  console.log('Initializing Noir...');
  const noir = new Noir(circuit);

  console.log('Generating witness...');
  const { witness } = await noir.execute(noirInputs as any);

  console.log('Initializing UltraPlonk backend...');
  const trustedSetupPath = path.join(__dirname, '../../data/circuit/');
  const backendOptions: BackendOptions = { crsPath: trustedSetupPath };
  const backend = new UltraPlonkBackend(circuit.bytecode, backendOptions);

  console.log('Generating verification key...');
  const vk = await backend.getVerificationKey();

  console.log('Generating proof...');
  const proof = await backend.generateProof(witness);

  console.log('Proof generated successfully!');
  console.log('Proof length:', proof.proof.length, 'bytes');

  // Save proof and verification key
  const proofDir = path.join(__dirname, '../../data/query-proof-noir');
  if (!fs.existsSync(proofDir)) {
    fs.mkdirSync(proofDir, { recursive: true });
  }

  const vkPath = path.join(proofDir, 'vk');
  fs.writeFileSync(vkPath, vk);
  console.log('Verification key saved to:', vkPath);

  const proofPath = path.join(proofDir, 'query_proof');
  fs.writeFileSync(proofPath, proof.proof);
  console.log('Proof saved to:', proofPath);

  const publicInputsPath = path.join(proofDir, 'public-inputs');
  fs.writeFileSync(publicInputsPath, proof.publicInputs.join('\n'));
  console.log('Public inputs saved to:', publicInputsPath);

  console.log('Verifying proof...');
  const isValid = await backend.verifyProof(proof);
  console.log('Proof is valid:', isValid);

  if (!isValid) {
    throw new Error('Generated proof is invalid');
  }

  // Verify all signals match (except nullifier at [0])
  console.log('\n=== Verification: Comparing Generated vs Expected ===');
  let allMatch = true;
  for (let i = 1; i < proof.publicInputs.length; i++) {
    // Convert both to BigInt for proper comparison
    const generated = BigInt(proof.publicInputs[i]);
    const expected = BigInt(expectedSignals[i]);
    const match = generated === expected;
    if (!match) {
      console.log(`[${i}]: ✗ Generated: ${generated.toString()}, Expected: ${expected.toString()}`);
      allMatch = false;
    } else {
      console.log(`[${i}]: ✓ Match`);
    }
  }

  if (allMatch) {
    console.log('\n✅ All public signals match (except nullifier)!');
  } else {
    console.log('\n❌ Some public signals do not match!');
    console.log('Check the differences above.');
    throw new Error('Public signals do not match contract expectations');
  }

  // Destroy backend to clean up workers
  await backend.destroy();

  // Close provider connection
  provider.destroy();

  console.log('\n✅ All verifications passed! Noir query proof is ready to be submitted.');

  return {
    proof: proof.proof,
    publicInputs: proof.publicInputs,
  };
}
