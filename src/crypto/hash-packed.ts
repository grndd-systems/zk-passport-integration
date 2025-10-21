import { poseidon } from 'passport-zk-circuits-noir-js';

/**
 * Implements the hashPacked function from Solidity
 * Converts a byte array (public key modulus) to certificate key using Poseidon hash
 *
 * This replicates the logic from the smart contract:
 * function hashPacked(bytes memory byteArray_) internal pure returns (uint256)
 */
export function hashPacked(byteArray: Buffer): bigint {
  if (byteArray.length < 120) {
    throw new Error('byteArray must be at least 120 bytes');
  }

  const decomposed: bigint[] = new Array(5);

  // Start from the last 32 bytes
  let position = byteArray.length;

  for (let i = 0; i < 5; i++) {
    // Take 32 bytes starting from position - 32
    const element = byteArray.slice(position - 32, position);
    const elementBigInt = BigInt('0x' + element.toString('hex'));

    let reversed = 0n;

    // Split element into 3 chunks of 64 bits and reverse
    for (let j = 0; j < 3; j++) {
      // Extract 64 bits (8 bytes)
      const extracted = (elementBigInt >> BigInt(j * 64)) & 0xffffffffffffffffn;
      reversed = (reversed << 64n) | extracted;
    }

    decomposed[i] = reversed;

    // Move back 24 bytes
    position -= 24;
  }

  // Apply Poseidon hash to the 5 decomposed values
  const hash = poseidon(decomposed);

  return hash;
}

/**
 * Convert bigint certificate key to hex string with 0x prefix and padding
 */
export function certificateKeyToHex(key: bigint): string {
  return '0x' + key.toString(16).padStart(64, '0');
}
