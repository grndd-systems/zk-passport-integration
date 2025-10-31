import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

/**
 * Passport data structure
 */
export interface PassportData {
  dg1: number[] | string; // Can be array or base64 string
  dg15: string; // DG15 public key (base64)
  signature: string; // AA signature (hex)
  [key: string]: any;
}

/**
 * Registration proof public outputs structure
 * The registration proof generates 5 public outputs in this order:
 */
export interface RegistrationProofOutputs {
  passportKey: bigint; // [0] - Used as passportHash in StateKeeper
  passportHash: bigint; // [1] - Hash of the passport data
  dgCommit: bigint; // [2] - Commitment to DG1
  identityKey: bigint; // [3] - Hashed identity key (pkIdentityHash)
  certificatesRoot: bigint; // [4] - Certificates root (INPUT to circuit)
}

/**
 * Load all registration proof public outputs
 *
 * @returns Object with all 5 outputs from the registration proof
 * @throws Error if registration proof not found
 */
export function loadRegistrationProofOutputs(): RegistrationProofOutputs {
  const publicInputsPath = path.join(process.cwd(), 'data', 'proof', 'public-inputs');

  if (!fs.existsSync(publicInputsPath)) {
    throw new Error(
      'Registration proof public-inputs not found. Please run register-passport first.',
    );
  }

  const publicInputsContent = fs.readFileSync(publicInputsPath, 'utf-8');
  const circuitOutputs = publicInputsContent
    .trim()
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => BigInt(line.trim()));

  if (circuitOutputs.length < 5) {
    throw new Error(`Invalid registration proof: expected 5 outputs, got ${circuitOutputs.length}`);
  }

  return {
    passportKey: circuitOutputs[0],
    passportHash: circuitOutputs[1],
    dgCommit: circuitOutputs[2],
    identityKey: circuitOutputs[3],
    certificatesRoot: circuitOutputs[4],
  };
}

/**
 * Load pkPassportHash from registration proof public outputs
 * @returns The passportKey (index [0]) which is used as passportHash in StateKeeper
 */
export function loadPkPassportHash(): bigint {
  return loadRegistrationProofOutputs().passportKey;
}

/**
 * Load pkIdentityHash from registration proof public outputs
 * @returns The identityKey (public key identity hash) from the registration proof
 */
export function loadPkIdentityHash(): bigint {
  return loadRegistrationProofOutputs().identityKey;
}

/**
 * Load the latest passport data from the out_passport directory
 *
 * @returns Passport data with dg1 as number array
 */
export function loadLatestPassportData(): {
  data: PassportData;
  dg1Array: number[];
  filename: string;
} {
  const passportDir = path.join(process.cwd(), 'data', 'out_passport');
  const passportFiles = fs.readdirSync(passportDir);
  const latestFile = passportFiles.sort().reverse()[0];
  const passportPath = path.join(passportDir, latestFile);
  const passportData = JSON.parse(fs.readFileSync(passportPath, 'utf-8'));

  // Decode dg1 from base64 if needed
  let dg1Array: number[];
  if (typeof passportData.dg1 === 'string') {
    const dg1Buffer = Buffer.from(passportData.dg1, 'base64');
    dg1Array = Array.from(dg1Buffer);
  } else {
    dg1Array = passportData.dg1;
  }

  return {
    data: passportData,
    dg1Array,
    filename: latestFile,
  };
}

/**
 * Extract RSA modulus from DG15 data
 *
 * DG15 contains the public key in SPKI format wrapped in TLV structure.
 * This function parses the TLV header and extracts the modulus.
 *
 * @param dg15Base64 - DG15 data encoded as base64 string
 * @returns RSA modulus as Buffer
 */
export function extractModulusFromDG15(dg15Base64: string): Buffer {
  const dg15Buffer = Buffer.from(dg15Base64, 'base64');

  // Parse DG15 TLV structure to extract SPKI
  let offset = 0;
  if (dg15Buffer[offset] === 0x6f) {
    offset++;
    if (dg15Buffer[offset] & 0x80) {
      const lengthBytes = dg15Buffer[offset] & 0x7f;
      offset += 1 + lengthBytes;
    } else {
      offset += 1;
    }
  }
  const spki = dg15Buffer.slice(offset);

  // Extract modulus from SPKI using Node.js crypto
  const publicKey = crypto.createPublicKey({
    key: spki,
    format: 'der',
    type: 'spki',
  });

  const jwk = publicKey.export({ format: 'jwk' }) as crypto.JsonWebKey;
  const modulusBytes = Buffer.from(jwk.n!, 'base64');

  return modulusBytes;
}
