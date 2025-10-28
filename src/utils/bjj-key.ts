import * as fs from 'fs';
import * as path from 'path';

/**
 * Read BJJ secret key from file and interpret as little-endian
 *
 * The BJJKeygen binary generates a secret key in little-endian format.
 * This function reads the binary file and correctly interprets the bytes.
 *
 * @param skIdentityPath - Optional path to sk_identity file (defaults to data/sk_identity)
 * @returns BigInt representation of the secret key
 * @throws Error if file not found
 */
export function readSkIdentity(skIdentityPath?: string): bigint {
  // Use provided path or default to data/sk_identity
  const filePath = skIdentityPath || path.join(process.cwd(), 'data', 'sk_identity');

  if (!fs.existsSync(filePath)) {
    throw new Error(
      `BJJ secret key file not found at: ${filePath}. Please run BJJKeygen first.`
    );
  }

  // Read as binary buffer
  const skIdentityBuffer = fs.readFileSync(filePath);
  console.log('Read sk_identity from file:', filePath);
  console.log('Buffer length:', skIdentityBuffer.length, 'bytes');

  // Interpret bytes as little-endian: reverse the buffer before converting to BigInt
  const skIdentityReversed = Buffer.from(skIdentityBuffer).reverse();
  const skIdentityHex = '0x' + skIdentityReversed.toString('hex');

  // Convert to BigInt
  const sk_identity = BigInt(skIdentityHex);
  console.log('Using sk_identity (little-endian):', '0x' + sk_identity.toString(16));

  return sk_identity;
}

/**
 * Get default sk_identity file path
 */
export function getDefaultSkIdentityPath(): string {
  return path.join(process.cwd(), 'data', 'sk_identity');
}
