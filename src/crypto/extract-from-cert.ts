import * as fs from 'fs';
import * as crypto from 'crypto';

/**
 * Parse DER length field
 */
export function parseDERLength(
  buffer: Buffer,
  offset: number,
): { length: number; bytesRead: number } {
  let length = buffer[offset];
  let bytesRead = 1;

  if (length & 0x80) {
    const numLengthBytes = length & 0x7f;
    length = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      length = (length << 8) | buffer[offset + bytesRead];
      bytesRead++;
    }
  }

  return { length, bytesRead };
}

/**
 * Extract RSA modulus (n) from SPKI public key
 */
export function extractRSAModulus(publicKeyDER: Buffer): Buffer {
  let offset = 0;

  // Skip outer SEQUENCE
  if (publicKeyDER[offset] !== 0x30) {
    throw new Error('Invalid public key: expected SEQUENCE');
  }
  offset++;
  const outerLength = parseDERLength(publicKeyDER, offset);
  offset += outerLength.bytesRead;

  // Skip algorithm SEQUENCE
  if (publicKeyDER[offset] !== 0x30) {
    throw new Error('Invalid public key: expected algorithm SEQUENCE');
  }
  offset++;
  const algLength = parseDERLength(publicKeyDER, offset);
  offset += algLength.bytesRead + algLength.length;

  // Now at BIT STRING
  if (publicKeyDER[offset] !== 0x03) {
    throw new Error('Invalid public key: expected BIT STRING');
  }
  offset++;
  const bitStringLength = parseDERLength(publicKeyDER, offset);
  offset += bitStringLength.bytesRead;

  // Skip unused bits byte
  offset++;

  // Now at inner SEQUENCE (modulus and exponent)
  if (publicKeyDER[offset] !== 0x30) {
    throw new Error('Invalid public key: expected inner SEQUENCE');
  }
  offset++;
  const innerSeqLength = parseDERLength(publicKeyDER, offset);
  offset += innerSeqLength.bytesRead;

  // Now at modulus INTEGER
  if (publicKeyDER[offset] !== 0x02) {
    throw new Error('Invalid public key: expected modulus INTEGER');
  }
  offset++;
  const modulusLengthInfo = parseDERLength(publicKeyDER, offset);
  offset += modulusLengthInfo.bytesRead;

  // The modulus might have a leading 0x00 byte if the high bit is set
  let modulusLength = modulusLengthInfo.length;
  if (publicKeyDER[offset] === 0x00) {
    offset++; // Skip leading zero
    modulusLength--;
  }

  // Extract the modulus
  const modulus = publicKeyDER.slice(offset, offset + modulusLength);

  return modulus;
}

/**
 * Extract signature from X.509 certificate DER
 *
 * X.509 Certificate structure (DER):
 * Certificate ::= SEQUENCE {
 *   tbsCertificate       TBSCertificate,
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING
 * }
 */

export function extractSignatureFromCert(certPath: string): Buffer {
  const certPEM = fs.readFileSync(certPath, 'utf8');

  // Parse certificate using Node.js crypto
  const cert = new crypto.X509Certificate(certPEM);

  // Get the raw certificate in DER format
  const certDER = cert.raw;

  // Parse DER to find signature
  // The signature is at the end of the certificate
  // We need to manually parse the DER structure

  let offset = 0;

  // Read the outermost SEQUENCE tag
  if (certDER[offset] !== 0x30) {
    throw new Error('Invalid certificate: expected SEQUENCE tag');
  }
  offset++;

  // Read length of outer SEQUENCE
  let length = certDER[offset];
  offset++;

  if (length & 0x80) {
    // Long form length
    const numLengthBytes = length & 0x7f;
    length = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      length = (length << 8) | certDER[offset];
      offset++;
    }
  }

  // Skip tbsCertificate (first SEQUENCE)
  if (certDER[offset] !== 0x30) {
    throw new Error('Invalid certificate: expected tbsCertificate SEQUENCE');
  }
  offset++;

  let tbsLength = certDER[offset];
  offset++;

  if (tbsLength & 0x80) {
    const numLengthBytes = tbsLength & 0x7f;
    tbsLength = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      tbsLength = (tbsLength << 8) | certDER[offset];
      offset++;
    }
  }

  offset += tbsLength; // Skip tbsCertificate content

  // Skip signatureAlgorithm (SEQUENCE)
  if (certDER[offset] !== 0x30) {
    throw new Error('Invalid certificate: expected signatureAlgorithm SEQUENCE');
  }
  offset++;

  let sigAlgLength = certDER[offset];
  offset++;

  if (sigAlgLength & 0x80) {
    const numLengthBytes = sigAlgLength & 0x7f;
    sigAlgLength = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      sigAlgLength = (sigAlgLength << 8) | certDER[offset];
      offset++;
    }
  }

  offset += sigAlgLength; // Skip signatureAlgorithm content

  // Now we're at the signatureValue (BIT STRING)
  if (certDER[offset] !== 0x03) {
    throw new Error('Invalid certificate: expected signatureValue BIT STRING');
  }
  offset++;

  let sigLength = certDER[offset];
  offset++;

  if (sigLength & 0x80) {
    const numLengthBytes = sigLength & 0x7f;
    sigLength = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      sigLength = (sigLength << 8) | certDER[offset];
      offset++;
    }
  }

  // BIT STRING starts with a byte indicating unused bits (should be 0)
  const unusedBits = certDER[offset];
  offset++;

  if (unusedBits !== 0) {
    console.warn(`Warning: BIT STRING has ${unusedBits} unused bits`);
  }

  // Extract the signature
  const signatureLength = sigLength - 1; // Subtract the unused bits byte
  const signature = certDER.slice(offset, offset + signatureLength);

  return signature;
}

/**
 * Find expiration date (notAfter) offset in certificate DER
 *
 * X.509 Structure:
 * Certificate ::= SEQUENCE {
 *   tbsCertificate SEQUENCE {
 *     version [0] EXPLICIT,
 *     serialNumber,
 *     signature (algorithm),
 *     issuer,
 *     validity SEQUENCE {
 *       notBefore Time,
 *       notAfter Time   <-- We want this offset
 *     },
 *     ...
 *   }
 * }
 */
export function findExpirationOffset(tbsDER: Buffer): number {
  let offset = 0;

  // Now at tbsCertificate SEQUENCE
  if (tbsDER[offset] !== 0x30) {
    throw new Error('Invalid certificate: expected tbsCertificate SEQUENCE');
  }
  offset++;

  // Skip tbsCertificate length
  const tbsLength = parseDERLength(tbsDER, offset);
  offset += tbsLength.bytesRead;

  // Now inside tbsCertificate, need to skip:
  // 1. version (optional, tagged [0])
  // 2. serialNumber
  // 3. signature (algorithm)
  // 4. issuer
  // Then we reach validity

  // Skip version if present (tag 0xA0)
  if (tbsDER[offset] === 0xa0) {
    offset++; // Skip tag
    const versionLength = parseDERLength(tbsDER, offset);
    offset += versionLength.bytesRead + versionLength.length;
  }

  // Skip serialNumber (INTEGER)
  if (tbsDER[offset] === 0x02) {
    offset++; // Skip tag
    const serialLength = parseDERLength(tbsDER, offset);
    offset += serialLength.bytesRead + serialLength.length;
  }

  // Skip signature algorithm (SEQUENCE)
  if (tbsDER[offset] === 0x30) {
    offset++; // Skip tag
    const sigAlgLength = parseDERLength(tbsDER, offset);
    offset += sigAlgLength.bytesRead + sigAlgLength.length;
  }

  // Skip issuer (SEQUENCE)
  if (tbsDER[offset] === 0x30) {
    offset++; // Skip tag
    const issuerLength = parseDERLength(tbsDER, offset);
    offset += issuerLength.bytesRead + issuerLength.length;
  }

  // Now we should be at validity SEQUENCE
  if (tbsDER[offset] !== 0x30) {
    throw new Error(
      `Invalid certificate: expected validity SEQUENCE at offset ${offset}, got 0x${tbsDER[offset].toString(16)}`,
    );
  }
  offset++; // Skip SEQUENCE tag

  const validityLength = parseDERLength(tbsDER, offset);
  offset += validityLength.bytesRead;

  // Inside validity, skip notBefore (first Time)
  // Time can be UTCTime (0x17) or GeneralizedTime (0x18)
  const notBeforeTag = tbsDER[offset];
  if (notBeforeTag !== 0x17 && notBeforeTag !== 0x18) {
    throw new Error(
      `Invalid certificate: expected Time tag for notBefore, got 0x${notBeforeTag.toString(16)}`,
    );
  }
  offset++; // Skip tag

  const notBeforeLength = parseDERLength(tbsDER, offset);
  offset += notBeforeLength.bytesRead + notBeforeLength.length;

  // Now we're at notAfter - this is the expiration offset we want!
  const expirationOffset = offset;

  console.log(`Found expiration (notAfter) at offset: ${expirationOffset}`);
  console.log(
    `  Tag: 0x${tbsDER[offset].toString(16)} (${tbsDER[offset] === 0x17 ? 'UTCTime' : 'GeneralizedTime'})`,
  );

  // Read the expiration date for verification
  const notAfterTag = tbsDER[offset];
  offset++;
  const notAfterLength = parseDERLength(tbsDER, offset);
  offset += notAfterLength.bytesRead;
  const notAfterBytes = tbsDER.slice(offset, offset + notAfterLength.length);
  console.log(`  Expiration date: ${notAfterBytes.toString('ascii')}`);

  return expirationOffset + 2; // +2 to account for tag and length bytes
}

/**
 * Extract TBS (To Be Signed) part from X.509 certificate
 *
 * X.509 Certificate structure (DER):
 * Certificate ::= SEQUENCE {
 *   tbsCertificate       TBSCertificate,  <-- We want to extract this
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING
 * }
 */
export function extractTBSFromCert(certPath: string): Buffer {
  const certPEM = fs.readFileSync(certPath, 'utf8');
  const cert = new crypto.X509Certificate(certPEM);
  const certDER = cert.raw;

  let offset = 0;

  // Read the outermost SEQUENCE tag
  if (certDER[offset] !== 0x30) {
    throw new Error('Invalid certificate: expected SEQUENCE tag');
  }
  offset++;

  // Read length of outer SEQUENCE
  const outerLength = parseDERLength(certDER, offset);
  offset += outerLength.bytesRead;

  // Now at tbsCertificate (SEQUENCE)
  if (certDER[offset] !== 0x30) {
    throw new Error('Invalid certificate: expected tbsCertificate SEQUENCE');
  }

  const tbsStartOffset = offset;
  offset++;

  // Read TBS length
  const tbsLength = parseDERLength(certDER, offset);
  offset += tbsLength.bytesRead;

  // Calculate total TBS size (tag + length bytes + content)
  const tbsTotalLength = 1 + tbsLength.bytesRead + tbsLength.length;

  // Extract TBS
  const tbs = certDER.slice(tbsStartOffset, tbsStartOffset + tbsTotalLength);

  console.log(`Extracted TBS: ${tbs.length} bytes`);

  return tbs;
}

/**
 * Extract public key (SPKI) from TBS certificate
 *
 * TBSCertificate ::= SEQUENCE {
 *   version [0] EXPLICIT,
 *   serialNumber,
 *   signature (algorithm),
 *   issuer,
 *   validity,
 *   subject,
 *   subjectPublicKeyInfo  <-- We want to extract this
 *   ...
 * }
 */
export function extractPublicKeyFromTBS(tbsDER: Buffer): Buffer {
  let offset = 0;

  // Skip outer SEQUENCE tag and length
  if (tbsDER[offset] !== 0x30) {
    throw new Error('Invalid TBS: expected SEQUENCE tag');
  }
  offset++;
  const tbsLength = parseDERLength(tbsDER, offset);
  offset += tbsLength.bytesRead;

  // Skip version if present (tag 0xA0)
  if (tbsDER[offset] === 0xa0) {
    offset++;
    const versionLength = parseDERLength(tbsDER, offset);
    offset += versionLength.bytesRead + versionLength.length;
  }

  // Skip serialNumber (INTEGER)
  if (tbsDER[offset] === 0x02) {
    offset++;
    const serialLength = parseDERLength(tbsDER, offset);
    offset += serialLength.bytesRead + serialLength.length;
  }

  // Skip signature algorithm (SEQUENCE)
  if (tbsDER[offset] === 0x30) {
    offset++;
    const sigAlgLength = parseDERLength(tbsDER, offset);
    offset += sigAlgLength.bytesRead + sigAlgLength.length;
  }

  // Skip issuer (SEQUENCE)
  if (tbsDER[offset] === 0x30) {
    offset++;
    const issuerLength = parseDERLength(tbsDER, offset);
    offset += issuerLength.bytesRead + issuerLength.length;
  }

  // Skip validity (SEQUENCE)
  if (tbsDER[offset] === 0x30) {
    offset++;
    const validityLength = parseDERLength(tbsDER, offset);
    offset += validityLength.bytesRead + validityLength.length;
  }

  // Skip subject (SEQUENCE)
  if (tbsDER[offset] === 0x30) {
    offset++;
    const subjectLength = parseDERLength(tbsDER, offset);
    offset += subjectLength.bytesRead + subjectLength.length;
  }

  // Now we should be at subjectPublicKeyInfo (SEQUENCE)
  if (tbsDER[offset] !== 0x30) {
    throw new Error(
      `Invalid TBS: expected subjectPublicKeyInfo SEQUENCE at offset ${offset}, got 0x${tbsDER[offset].toString(16)}`,
    );
  }

  const spkiStartOffset = offset;
  offset++;

  const spkiLength = parseDERLength(tbsDER, offset);
  offset += spkiLength.bytesRead;

  // Calculate total SPKI size (tag + length bytes + content)
  const spkiTotalLength = 1 + spkiLength.bytesRead + spkiLength.length;

  // Extract SPKI
  const spki = tbsDER.slice(spkiStartOffset, spkiStartOffset + spkiTotalLength);

  console.log(`Extracted SPKI: ${spki.length} bytes`);

  return spki;
}

/**
 * Find RSA modulus offset within TBS certificate
 */
export function findModulusOffsetInTBS(tbsDER: Buffer, modulus: Buffer): number {
  const offset = tbsDER.indexOf(modulus);

  if (offset === -1) {
    throw new Error('Modulus not found in TBS certificate');
  }

  console.log(`Found modulus at offset ${offset} in TBS`);

  return offset;
}
