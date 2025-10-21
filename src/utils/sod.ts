/**
 * SOD (Security Object Document) utilities
 */

/**
 * Parse DER length field
 */
function parseDERLength(buffer: Buffer, offset: number): { length: number; bytesRead: number } {
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
 * Extract certificate from SOD (Security Object Document) data
 * SOD structure: SEQUENCE -> [1] -> SEQUENCE (SignedData) -> [3] certificates [0]
 */
export function extractCertificateFromSOD(sodData: Buffer): Buffer {
  let offset = 0;

  // Skip outer SEQUENCE
  if (sodData[offset] !== 0x30) throw new Error('Invalid SOD: expected SEQUENCE');
  offset++;
  const outerLength = parseDERLength(sodData, offset);
  offset += outerLength.bytesRead;

  // Skip ContentType OID
  if (sodData[offset] !== 0x06) throw new Error('Invalid SOD: expected OID');
  offset++;
  const oidLength = parseDERLength(sodData, offset);
  offset += oidLength.bytesRead + oidLength.length;

  // Now at [0] EXPLICIT tag
  if (sodData[offset] !== 0xa0) throw new Error('Invalid SOD: expected [0] EXPLICIT');
  offset++;
  const explicitLength = parseDERLength(sodData, offset);
  offset += explicitLength.bytesRead;

  // Now at SignedData SEQUENCE
  if (sodData[offset] !== 0x30) throw new Error('Invalid SOD: expected SignedData SEQUENCE');
  offset++;
  const signedDataLength = parseDERLength(sodData, offset);
  offset += signedDataLength.bytesRead;

  // Skip version (INTEGER)
  if (sodData[offset] === 0x02) {
    offset++;
    const versionLength = parseDERLength(sodData, offset);
    offset += versionLength.bytesRead + versionLength.length;
  }

  // Skip digestAlgorithms (SET)
  if (sodData[offset] === 0x31) {
    offset++;
    const digestAlgsLength = parseDERLength(sodData, offset);
    offset += digestAlgsLength.bytesRead + digestAlgsLength.length;
  }

  // Skip encapContentInfo (SEQUENCE)
  if (sodData[offset] === 0x30) {
    offset++;
    const encapLength = parseDERLength(sodData, offset);
    offset += encapLength.bytesRead + encapLength.length;
  }

  // Now at certificates [0] IMPLICIT
  if (sodData[offset] !== 0xa0) throw new Error('Invalid SOD: expected certificates [0]');
  offset++;
  const certsLength = parseDERLength(sodData, offset);
  offset += certsLength.bytesRead;

  // First certificate starts here (SEQUENCE)
  const certStart = offset;
  if (sodData[offset] !== 0x30) throw new Error('Invalid SOD: expected certificate SEQUENCE');
  offset++;
  const certLength = parseDERLength(sodData, offset);
  offset += certLength.bytesRead;

  const certTotalLength = 1 + certLength.bytesRead + certLength.length;
  const certificate = sodData.slice(certStart, certStart + certTotalLength);

  console.log('Extracted certificate from SOD:', certificate.length, 'bytes');
  return certificate;
}
