/**
 * Certificate key computation utilities
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { randomBytes } from 'crypto';
import {
  extractTBSFromCert,
  extractPublicKeyFromTBS,
  extractRSAModulus,
} from './extract-from-cert';
import { hashPacked, certificateKeyToHex } from './hash-packed';

/**
 * Compute certificate key from certificate DER data
 * The key is hashPacked(publicKey modulus), using the same logic as the smart contract
 */
export async function computeCertificateKey(certificateDER: Buffer): Promise<string> {
  // Convert DER to PEM format
  const certificatePem =
    '-----BEGIN CERTIFICATE-----\n' +
    certificateDER
      .toString('base64')
      .match(/.{1,64}/g)!
      .join('\n') +
    '\n-----END CERTIFICATE-----\n';

  // Write to temp file for extraction functions
  // Use unique filename to avoid conflicts with parallel executions
  const tmpFileName = `temp_cert_${Date.now()}_${randomBytes(4).toString('hex')}.pem`;
  const tmpPemFile = path.join(os.tmpdir(), tmpFileName);
  fs.writeFileSync(tmpPemFile, certificatePem);

  try {
    const tbs = extractTBSFromCert(tmpPemFile);
    const spkiBuffer = extractPublicKeyFromTBS(tbs);
    const pubkey_modulus = extractRSAModulus(spkiBuffer);

    console.log('Public key modulus length:', pubkey_modulus.length, 'bytes');

    // Compute certificate key using hashPacked (same as smart contract)
    const certificateKeyBigInt = hashPacked(pubkey_modulus);
    const certificateKey = certificateKeyToHex(certificateKeyBigInt);

    console.log('Certificate key (hashPacked of modulus):', certificateKey);

    return certificateKey;
  } finally {
    // Clean up temp file
    if (fs.existsSync(tmpPemFile)) {
      fs.unlinkSync(tmpPemFile);
    }
  }
}
