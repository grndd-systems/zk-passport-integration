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
 *
 * @param sodData - SOD data buffer
 * @param certIndex - Certificate index (0 = DSC, 1 = CSCA, default 0)
 */
export function extractCertificateFromSOD(sodData: Buffer, certIndex: number = 0): Buffer {
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

  // Skip to the requested certificate index
  let currentIndex = 0;
  let certStart = offset;

  while (currentIndex <= certIndex) {
    certStart = offset;

    if (sodData[offset] !== 0x30) {
      throw new Error(
        `Invalid SOD: expected certificate SEQUENCE at index ${currentIndex}, got 0x${sodData[offset].toString(16)}`,
      );
    }
    offset++;
    const certLength = parseDERLength(sodData, offset);
    offset += certLength.bytesRead;

    if (currentIndex === certIndex) {
      // Found the requested certificate
      const certTotalLength = 1 + certLength.bytesRead + certLength.length;
      const certificate = sodData.slice(certStart, certStart + certTotalLength);

      console.log(
        `Extracted certificate ${certIndex} from SOD:`,
        certificate.length,
        'bytes',
        certIndex === 0 ? '(DSC)' : certIndex === 1 ? '(CSCA)' : '',
      );
      return certificate;
    }

    // Skip to next certificate
    offset += certLength.length;
    currentIndex++;
  }

  throw new Error(`Certificate index ${certIndex} not found in SOD`);
}
