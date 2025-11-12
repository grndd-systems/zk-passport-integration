import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import {
  loadLatestPassportData,
  loadRegistrationProofOutputs,
} from '../crypto/query-circuit-input';
import { extractModulusFromDG15 } from '../utils/file-loaders';

/**
 * Updates only the AA signature in an existing passport JSON
 * This doesn't affect the ZK proof since AA signature is NOT part of circuit inputs
 */

// Verify AA signature using the same logic as PRSASHAAuthenticator.authenticate()
function authenticate(
  challenge: Buffer,
  signature: Buffer,
  publicKeyDER: Buffer,
  isSha1: boolean = false,
): boolean {
  const hashLen = isSha1 ? 20 : 32; // SHA-1: 20 bytes, SHA-256: 32 bytes

  console.log('\n=== Verifying signature (contract logic) ===');
  console.log('challenge:', challenge.toString('hex'));
  console.log('signature length:', signature.length);

  if (signature.length === 0 || publicKeyDER.length === 0) {
    console.log('❌ Empty signature or public key');
    return false;
  }

  // Extract modulus from DG15
  const modulusBytes = extractModulusFromDG15(publicKeyDER.toString('base64'));
  const modulus = bufferToBigInt(modulusBytes);

  // Verify using raw modexp: decipher = signature^e mod modulus
  const e = 65537n;
  const signatureBigInt = bufferToBigInt(signature);
  const decipherBigInt = modPow(signatureBigInt, e, modulus);
  const decipher = bigIntToBuffer(decipherBigInt, modulusBytes.length);

  console.log('decipher (full bytes):', decipher.toString('hex'));

  // Remove suffix (ISO 9796-2: 2 bytes for SHA-256)
  const suffixLen = isSha1 ? 2 : 2; // Both use 2 bytes in ISO 9796-2
  const decipherNoSuffix = decipher.slice(0, decipher.length - suffixLen);

  console.log('decipher after suffix removal:', decipherNoSuffix.length, 'bytes');

  // Extract prepared and digest
  const preparedLen = decipherNoSuffix.length - hashLen - 1;
  const prepared = decipherNoSuffix.slice(1, 1 + preparedLen);
  const digest = decipherNoSuffix.slice(decipherNoSuffix.length - hashLen);

  console.log('prepared length:', preparedLen, 'bytes');
  console.log('digest from signature:', digest.toString('hex'));

  // Hash prepared || challenge
  const dataToHash = Buffer.concat([prepared, challenge]);
  const expectedDigest = isSha1
    ? crypto.createHash('sha1').update(dataToHash).digest()
    : crypto.createHash('sha256').update(dataToHash).digest();

  console.log('expected digest (_hash(prepared || challenge)):', expectedDigest.toString('hex'));

  const isValid = digest.equals(expectedDigest);
  console.log('Match:', isValid ? '✅ VALID' : '❌ INVALID');

  return isValid;
}

// Raw modular exponentiation: base^exp mod modulus
function modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
  let result = 1n;
  base = base % modulus;

  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exp = exp >> 1n;
    base = (base * base) % modulus;
  }

  return result;
}

// Convert Buffer to BigInt
function bufferToBigInt(buf: Buffer): bigint {
  return BigInt('0x' + buf.toString('hex'));
}

// Convert BigInt to Buffer with fixed length
function bigIntToBuffer(value: bigint, length: number): Buffer {
  const hex = value.toString(16).padStart(length * 2, '0');
  return Buffer.from(hex, 'hex');
}

// Generate AA signature using raw RSA modexp
function generateAASignature(
  challengeHex: string,
  dg15Data: Buffer,
  privateKeyPEM: string,
): string {
  const challengeBuffer = Buffer.from(challengeHex.replace('0x', ''), 'hex');

  // Extract the actual modulus from DG15
  const modulusBytes = extractModulusFromDG15(dg15Data.toString('base64'));
  const modulus = bufferToBigInt(modulusBytes);
  const RSA_SIZE = modulusBytes.length;

  console.log('\nGenerating AA signature:');
  console.log('  RSA modulus size:', RSA_SIZE, 'bytes');

  // ISO 9796-2 format with SHA-256
  const HASH_LEN = 32; // SHA-256
  const SUFFIX_LEN = 2; // ISO 9796-2: 2 bytes for trailer (0x34CC)
  const afterSuffixLen = RSA_SIZE - SUFFIX_LEN; // 254
  const preparedLen = afterSuffixLen - HASH_LEN - 1; // 221 bytes

  console.log('  Prepared length:', preparedLen, 'bytes');

  // Generate 221 bytes of prepared data
  const prepared = crypto.randomBytes(preparedLen);

  // Hash: prepared || challenge
  const dataToHash = Buffer.concat([prepared, challengeBuffer]);
  const digest = crypto.createHash('sha256').update(dataToHash).digest();

  console.log('  Challenge:', challengeBuffer.toString('hex'));
  console.log('  Digest:', digest.toString('hex'));

  // Build 256-byte message for RSA signing:
  // [0] = header byte (0x01 for ISO 9796-2)
  // [1..221] = prepared (221 bytes)
  // [222..253] = digest (32 bytes)
  // [254..255] = trailer (0x34CC for SHA-256)
  const message = Buffer.alloc(RSA_SIZE);
  message[0] = 0x01;
  prepared.copy(message, 1);
  digest.copy(message, 1 + preparedLen);
  message[RSA_SIZE - 2] = 0x34; // ISO 9796-2 trailer
  message[RSA_SIZE - 1] = 0xcc;

  console.log('  Structure: [header 1] || [prepared 221] || [digest 32] || [trailer 2]');

  // Get private key components
  const privateKey = crypto.createPrivateKey(privateKeyPEM);
  const privateJwk = privateKey.export({ format: 'jwk' }) as crypto.JsonWebKey;
  const d = bufferToBigInt(Buffer.from(privateJwk.d!, 'base64'));

  // Sign using raw modexp: signature = message^d mod modulus
  const messageBigInt = bufferToBigInt(message);
  const signatureBigInt = modPow(messageBigInt, d, modulus);
  const signature = bigIntToBuffer(signatureBigInt, RSA_SIZE);

  console.log('  Signature generated:', signature.length, 'bytes');

  return signature.toString('hex');
}

export async function updateAASignature() {
  // Load registration proof outputs
  const { passportKey, passportHash, dgCommit, identityKey, certificatesRoot } =
    loadRegistrationProofOutputs();

  console.log('\nCircuit outputs from registration proof:');
  console.log('  passportKey:', '0x' + passportKey.toString(16).padStart(64, '0'));
  console.log('  passportHash:', '0x' + passportHash.toString(16).padStart(64, '0'));
  console.log('  dgCommit:', '0x' + dgCommit.toString(16).padStart(64, '0'));
  console.log('  identityKey:', '0x' + identityKey.toString(16).padStart(64, '0'));
  console.log('  certificatesRoot:', '0x' + certificatesRoot.toString(16).padStart(64, '0'));

  // Challenge is the last 8 bytes of identityKey
  const identityKeyHex = identityKey.toString(16).padStart(64, '0');
  const challenge = '0x' + identityKeyHex.slice(-16); // Last 8 bytes = last 16 hex chars
  console.log('\nChallenge (last 8 bytes of identityKey):', challenge);

  // Load latest passport
  const { data: passport, filename } = loadLatestPassportData();
  console.log('\nLoading passport:', filename);

  const dg15Buffer = Buffer.from(passport.dg15, 'base64');
  console.log('DG15 length:', dg15Buffer.length, 'bytes');

  // Load AA private key from passport (unique per passport)
  if (!passport.aaPrivateKey) {
    console.error('\n❌ ERROR: aaPrivateKey not found in passport data!');
    console.error('   This passport was generated with old code that used CSCA key.');
    console.error('   Please regenerate passport with: npm run generate-passport');
    process.exit(1);
  }

  console.log('\nGenerating AA signature with challenge:', challenge);
  console.log('Using unique AA private key from passport data');
  const newSignature = generateAASignature(challenge, dg15Buffer, passport.aaPrivateKey);

  // Verify the signature using contract logic
  const challengeBuffer = Buffer.from(challenge.replace('0x', ''), 'hex');
  const signatureBuffer = Buffer.from(newSignature, 'hex');

  const isValid = authenticate(challengeBuffer, signatureBuffer, dg15Buffer, false);

  if (!isValid) {
    console.log('\n❌ ERROR: Generated signature failed verification!');
    process.exit(1);
  }

  // Update only the signature field
  passport.signature = newSignature;

  // Save with new name
  const passportDir = path.join(process.cwd(), 'data', 'out_passport');
  const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, '');
  const outputPath = path.join(passportDir, `passport_${timestamp}.json`);
  fs.writeFileSync(outputPath, JSON.stringify(passport, null, 2));

  console.log('\n✅ Updated passport saved:', path.basename(outputPath));
  console.log('   Only "signature" field was changed');
  console.log('   All other data (dg1, dg15, sod) remains the same');
  console.log('   ZK proof will still be valid!');
}

// Run if called directly
if (require.main === module) {
  updateAASignature().catch((error) => {
    console.error('\n❌ Error:', error);
    process.exit(1);
  });
}
