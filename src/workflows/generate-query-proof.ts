import * as snarkjs from 'snarkjs';
import * as fs from 'fs';
import * as path from 'path';
import {
  buildQueryCircuitInput,
  QueryInputBuilder,
  QueryCircuitInput
} from '../crypto/query-circuit-input';

const CIRCUIT_DIR = path.join(__dirname, '../../data/circuit/queryIdentity');
const WASM_FILE = path.join(CIRCUIT_DIR, 'queryIdentity.wasm');
const ZKEY_FILE = path.join(CIRCUIT_DIR, 'queryIdentity_0000.zkey');
const VKEY_FILE = path.join(CIRCUIT_DIR, 'verification_key.json');

export interface QueryProofParams extends QueryInputBuilder {
  outputDir?: string;
}

export interface QueryProofResult {
  proof: any;
  publicSignals: string[];
  proofJson: string;
}

/**
 * Generate a query identity proof
 *
 * This is the main function for generating query proofs.
 * It accepts explicit circuit inputs and generates a proof.
 *
 * Example usage:
 * ```typescript
 * const result = await generateQueryProof({
 *   dg1Bytes: inputs.dg1,
 *   skIdentity: BigInt(inputs.sk_identity),
 *   pkPassportHash: loadPkPassportHash(),
 *   eventID: '0x...',
 *   eventData: '0x...',
 *   timestamp: '1760152656',
 *   currentDate: '0x323531303131',
 *   identityCounter: '1',
 *   selector: 0x1,  // Only nullifier
 *   citizenshipMask: '288230376151711744',
 *   timestampUpperbound: '0',
 *   identityCounterUpperbound: '0',
 *   expirationDateUpperbound: '0x303030303030'
 * });
 * ```
 */
export async function generateQueryProof(params: QueryProofParams): Promise<QueryProofResult> {
  console.log('Building circuit input...');

  // Build circuit input
  const circuitInput = buildQueryCircuitInput(params);

  // Save input to file for debugging
  const outputDir = params.outputDir || path.join(process.cwd(), 'data', 'query-proof');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const inputPath = path.join(outputDir, 'query_input.json');
  fs.writeFileSync(inputPath, JSON.stringify(circuitInput, null, 2));
  console.log('Input saved to:', inputPath);

  console.log('Generating witness and proof...');

  // Generate witness and proof
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_FILE,
    ZKEY_FILE
  );

  console.log('Proof generated');

  // Save proof
  const proofPath = path.join(outputDir, 'query_proof.json');
  fs.writeFileSync(proofPath, JSON.stringify(proof, null, 2));
  console.log('Proof saved to:', proofPath);

  // Save public signals
  const publicPath = path.join(outputDir, 'query_public.json');
  fs.writeFileSync(publicPath, JSON.stringify(publicSignals, null, 2));
  console.log('Public signals saved to:', publicPath);

  // Verify proof
  console.log('Verifying proof...');
  const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, 'utf8'));
  const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);

  if (isValid) {
    console.log('Proof is valid!');
  } else {
    throw new Error('Generated proof is invalid');
  }

  // Generate Solidity calldata
  const calldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const calldataPath = path.join(outputDir, 'query_calldata.txt');
  fs.writeFileSync(calldataPath, calldata);
  console.log(`Solidity calldata saved to: ${calldataPath}`);

  return {
    proof,
    publicSignals,
    proofJson: JSON.stringify(proof, null, 2)
  };
}

/**
 * Verify an existing query proof
 */
export async function verifyQueryProof(
  proof: any,
  publicSignals: string[]
): Promise<boolean> {
  const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, 'utf8'));
  return await snarkjs.groth16.verify(vkey, publicSignals, proof);
}
