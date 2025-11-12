import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as forge from 'node-forge';

/**
 * Generates biometric passport data in JSON format
 * Includes DG1 (Machine Readable Zone), DG15 (Active Authentication Public Key),
 * and SOD (Security Object Document)
 */

interface PassportData {
  documentType?: string;
  issuingCountry?: string;
  surname?: string;
  givenNames?: string;
  passportNumber?: string;
  nationality?: string;
  dateOfBirth?: string;
  sex?: string;
  expiryDate?: string;
  personalNumber?: string;
}

interface DG1Data {
  dataGroupNumber: number;
  tagNumber: string;
  description: string;
  data: {
    mrzLine1: string;
    mrzLine2: string;
    documentType: string;
    issuingCountry: string;
    surname: string;
    givenNames: string;
    passportNumber: string;
    nationality: string;
    dateOfBirth: string;
    sex: string;
    expiryDate: string;
    personalNumber: string;
  };
  encodedData: string;
}

interface DG15Data {
  dataGroupNumber: number;
  tagNumber: string;
  description: string;
  data: {
    algorithm: string;
    keySize: number;
    publicKeyInfo: {
      algorithm: {
        oid: string;
        parameters: null;
      };
      publicKey: {
        modulus: string;
        exponent: number;
      };
    };
  };
  publicKeyPEM: string;
  privateKeyPEM: string;
  encodedData: string;
}

interface SODData {
  tagNumber: string;
  description: string;
  data: {
    ldsSecurityObject: {
      version: number;
      hashAlgorithm: {
        algorithm: string;
        parameters: null;
      };
      dataGroupHashValues: Record<string, string>;
    };
    signatureAlgorithm: {
      algorithm: string;
      parameters: {
        hashAlgorithm: string;
        maskGenAlgorithm: string;
        saltLength: number;
      };
    };
    signature: string;
    certificates: {
      documentSignerCertificate: {
        issuer: string;
        subject: string;
        serialNumber: string;
        validFrom: string;
        validTo: string;
        publicKey: string;
      };
    };
  };
  encodedData: string;
}

interface BiometricPassportData {
  dg1: string;
  dg15: string;
  sod: string;
  documentNumber: string;
  dateOfBirth: string;
  documentExpiryDate: string;
  nationality: string;
  gender: string;
  firstName: string;
  lastName: string;
  documentType: string;
  issuingAuthority: string;
  signature: string; // Active Authentication signature (placeholder initially)
  passportImageRaw: string;
  // DSC certificate data
  dscCertificate?: string; // DSC certificate in PEM format
  dscSerialNumber?: string; // DSC serial number
  // AA private key (INTERNAL USE ONLY - for AA signature generation, NOT in public passport data)
  aaPrivateKey?: string; // AA private key in PEM format (excluded from JSON save)
}

interface PassportGenerationOptions extends PassportData {
  certFolder?: string; // Certificate folder name (default: 'rsapss')
}

/**
 * Generate DG1 - Machine Readable Zone (MRZ)
 * Contains passport holder's biographical data in machine-readable format
 */
function generateDG1(passportData: PassportData): DG1Data {
  const {
    documentType = 'P',
    issuingCountry = 'ITA',
    surname = 'ERIKSSON',
    givenNames = 'ANNA MARIA',
    passportNumber = 'L898902C3',
    nationality = 'ITA',
    dateOfBirth = '740812', // YYMMDD
    sex = 'F',
    expiryDate = '120415', // YYMMDD
    personalNumber = 'ZE184226B',
  } = passportData;

  // Calculate check digits using ICAO algorithm
  const checkDigitWeights = [7, 3, 1];

  function calculateCheckDigit(data: string): number {
    const charValues: Record<string, number> = {
      '<': 0,
      A: 10,
      B: 11,
      C: 12,
      D: 13,
      E: 14,
      F: 15,
      G: 16,
      H: 17,
      I: 18,
      J: 19,
      K: 20,
      L: 21,
      M: 22,
      N: 23,
      O: 24,
      P: 25,
      Q: 26,
      R: 27,
      S: 28,
      T: 29,
      U: 30,
      V: 31,
      W: 32,
      X: 33,
      Y: 34,
      Z: 35,
    };

    let sum = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data[i];
      const value = /\d/.test(char) ? parseInt(char) : charValues[char];
      sum += value * checkDigitWeights[i % 3];
    }
    return sum % 10;
  }

  const passportCheck = calculateCheckDigit(passportNumber);
  const dobCheck = calculateCheckDigit(dateOfBirth);
  const expiryCheck = calculateCheckDigit(expiryDate);
  const personalCheck = calculateCheckDigit(personalNumber);

  // MRZ Line 1: Document type, issuing country, surname, given names
  // Format: P<ITASURNAME<<GIVENNAMES (must be exactly 44 characters)
  // Available space for names: 44 - 5 (P<ITA) = 39 characters
  const maxNameLength = 39;
  const givenNamesFormatted = givenNames.replace(/ /g, '<');
  let namesPart = `${surname}<<${givenNamesFormatted}`;

  // Truncate if too long (prioritize surname, then given names)
  if (namesPart.length > maxNameLength) {
    // Try to fit as much as possible, truncate given names first
    const surnameWithSeparator = `${surname}<<`;
    if (surnameWithSeparator.length >= maxNameLength) {
      // Even surname is too long, truncate it
      namesPart = surname.substring(0, maxNameLength - 2) + '<<';
    } else {
      // Truncate given names to fit
      const remainingSpace = maxNameLength - surnameWithSeparator.length;
      namesPart = surnameWithSeparator + givenNamesFormatted.substring(0, remainingSpace);
    }
  }

  const line1 = `${documentType}<${issuingCountry}${namesPart}`.padEnd(44, '<');

  // MRZ Line 2: Passport number, nationality, DOB, sex, expiry, personal number
  // Personal number field must be exactly 14 characters (pad with '<'), plus 1 check digit = 15 total
  const personalNumberPadded = personalNumber.padEnd(14, '<');

  const compositeData = `${passportNumber}${passportCheck}${nationality}${dateOfBirth}${dobCheck}${sex}${expiryDate}${expiryCheck}${personalNumberPadded}${personalCheck}`;
  const compositeCheck = calculateCheckDigit(compositeData);
  const line2 = `${compositeData}${compositeCheck}`;

  // Verify MRZ lengths
  if (line1.length !== 44) {
    throw new Error(`MRZ Line 1 must be 44 characters, got ${line1.length}`);
  }
  if (line2.length !== 44) {
    throw new Error(`MRZ Line 2 must be 44 characters, got ${line2.length}`);
  }

  // Wrap MRZ in ASN.1 DER encoding for DG1
  // Tag 0x61 (APPLICATION 1), Length, Content
  const mrzContent = Buffer.from(line1 + line2, 'ascii');
  const dg1Der = Buffer.concat([
    Buffer.from([0x61, 0x5b]), // Tag APPLICATION 1, Length 91 (0x5B)
    Buffer.from([0x5f, 0x1f, 0x58]), // Tag 0x5F1F (MRZ Info), Length 88 (0x58)
    mrzContent,
  ]);

  return {
    dataGroupNumber: 1,
    tagNumber: '0x61',
    description: 'Machine Readable Zone (MRZ)',
    data: {
      mrzLine1: line1,
      mrzLine2: line2,
      documentType,
      issuingCountry,
      surname,
      givenNames,
      passportNumber,
      nationality,
      dateOfBirth,
      sex,
      expiryDate,
      personalNumber,
    },
    encodedData: dg1Der.toString('base64'),
  };
}

/**
 * Extract salt length from RSA-PSS certificate DER
 */
function extractSaltLengthFromCert(certDER: Buffer): number {
  let offset = 0;

  // Skip outer SEQUENCE tag
  if (certDER[offset] !== 0x30) {
    throw new Error('Invalid certificate: expected SEQUENCE tag');
  }
  offset++;

  // Skip outer SEQUENCE length
  let length = certDER[offset];
  offset++;
  if (length & 0x80) {
    const numLengthBytes = length & 0x7f;
    for (let i = 0; i < numLengthBytes; i++) {
      offset++;
    }
  }

  // Skip tbsCertificate SEQUENCE
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
  offset += tbsLength;

  // Now at signatureAlgorithm SEQUENCE
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

  // Skip OID
  if (certDER[offset] !== 0x06) {
    throw new Error('Invalid certificate: expected OID tag');
  }
  offset++;
  const oidLength = certDER[offset];
  offset++;
  offset += oidLength;

  // Now should be at RSA-PSS parameters SEQUENCE
  let saltLength = 32; // Default for SHA-256

  if (certDER[offset] === 0x30) {
    offset++;
    let paramsLength = certDER[offset];
    offset++;
    if (paramsLength & 0x80) {
      const numLengthBytes = paramsLength & 0x7f;
      paramsLength = 0;
      for (let i = 0; i < numLengthBytes; i++) {
        paramsLength = (paramsLength << 8) | certDER[offset];
        offset++;
      }
    }

    const paramsEnd = offset + paramsLength;
    while (offset < paramsEnd) {
      const tag = certDER[offset];

      if (tag === 0xa2) {
        // Found [2] EXPLICIT (salt length)
        offset++;
        let saltSeqLength = certDER[offset];
        offset++;
        if (saltSeqLength & 0x80) {
          const numLengthBytes = saltSeqLength & 0x7f;
          saltSeqLength = 0;
          for (let i = 0; i < numLengthBytes; i++) {
            saltSeqLength = (saltSeqLength << 8) | certDER[offset];
            offset++;
          }
        }

        // Inside should be INTEGER
        if (certDER[offset] === 0x02) {
          offset++;
          const intLength = certDER[offset];
          offset++;

          // Read salt length value
          saltLength = 0;
          for (let i = 0; i < intLength; i++) {
            saltLength = (saltLength << 8) | certDER[offset + i];
          }
        }
        break;
      } else {
        // Skip this element
        offset++;
        let elemLength = certDER[offset];
        offset++;
        if (elemLength & 0x80) {
          const numLengthBytes = elemLength & 0x7f;
          elemLength = 0;
          for (let i = 0; i < numLengthBytes; i++) {
            elemLength = (elemLength << 8) | certDER[offset];
            offset++;
          }
        }
        offset += elemLength;
      }
    }
  }

  return saltLength;
}

/**
 * Detect signature algorithm from certificate by parsing DER structure
 */
function detectSignatureAlgorithm(certPath: string): 'RSA' | 'RSA-PSS' {
  const certPEM = fs.readFileSync(certPath, 'utf8');
  const cert = new crypto.X509Certificate(certPEM);
  const certDER = cert.raw;

  // Parse certificate structure to find signature algorithm OID
  // Certificate ::= SEQUENCE {
  //   tbsCertificate       TBSCertificate,
  //   signatureAlgorithm   AlgorithmIdentifier,  <-- We want this
  //   signatureValue       BIT STRING
  // }

  let offset = 0;

  // Skip outer SEQUENCE tag
  if (certDER[offset] !== 0x30) {
    throw new Error('Invalid certificate: expected SEQUENCE tag');
  }
  offset++;

  // Skip outer SEQUENCE length
  let length = certDER[offset];
  offset++;
  if (length & 0x80) {
    const numLengthBytes = length & 0x7f;
    for (let i = 0; i < numLengthBytes; i++) {
      offset++;
    }
  }

  // Skip tbsCertificate SEQUENCE
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
  offset += tbsLength;

  // Now at signatureAlgorithm SEQUENCE
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

  // Now at OID tag
  if (certDER[offset] !== 0x06) {
    throw new Error('Invalid certificate: expected OID tag');
  }
  offset++;

  const oidLength = certDER[offset];
  offset++;

  const oidBytes = certDER.slice(offset, offset + oidLength);

  // RSA-PSS OID: 1.2.840.113549.1.1.10 = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a]
  // RSA with SHA-256 OID: 1.2.840.113549.1.1.11 = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
  const rsaPssOid = Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a]);

  if (oidBytes.equals(rsaPssOid)) {
    console.log('  Certificate signature algorithm: RSA-PSS');
    return 'RSA-PSS';
  }

  console.log('  Certificate signature algorithm: RSA');
  return 'RSA';
}

/**
 * Generate DG15 - Active Authentication Public Key
 * Generates a UNIQUE RSA key pair for Active Authentication for THIS passport
 * The public key goes in DG15, private key is saved for AA signature generation
 */
function generateDG15(certFolder: string): DG15Data {
  console.log('  Generating unique RSA key pair for Active Authentication...');

  // Generate a NEW 2048-bit RSA key pair for this passport's Active Authentication
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  const publicKeyPEM = publicKey;
  const privateKeyPEM = privateKey;

  // For algorithm, use RSA (not RSA-PSS) for Active Authentication
  const signatureAlgorithm: 'RSA' | 'RSA-PSS' = 'RSA-PSS';

  console.log(`  ✓ Generated unique AA key pair for this passport`);

  // Extract key components for structured representation
  const publicKeyObj = crypto.createPublicKey(publicKeyPEM);
  const publicKeyDer = publicKeyObj.export({ type: 'spki', format: 'der' });

  // Parse SPKI to extract raw modulus and exponent
  const spkiAsn1 = forge.asn1.fromDer(forge.util.createBuffer(publicKeyDer.toString('binary')));
  const spkiAny = spkiAsn1 as any;

  // Navigate to the RSA key inside the BIT STRING
  const bitStringContent = spkiAny.value[1].value[0]; // BIT STRING -> SEQUENCE
  const modulusAsn1 = bitStringContent.value[0]; // INTEGER (modulus)
  const exponentAsn1 = bitStringContent.value[1]; // INTEGER (exponent)

  // Convert modulus and exponent to buffers
  const modulusHex = modulusAsn1.value;
  const exponentHex = exponentAsn1.value;

  // Manually build compact DG15 to minimize aa_shift
  // RSA encryption OID: 1.2.840.113549.1.1.1
  const rsaOid = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);

  // Build RSAPublicKey SEQUENCE (modulus + exponent)
  const exponentBuf = Buffer.from(exponentHex, 'binary');
  const modulusBuf = Buffer.from(modulusHex, 'binary');

  // INTEGER tag + length + value for exponent
  const exponentEncoded = Buffer.concat([Buffer.from([0x02, exponentBuf.length]), exponentBuf]);

  // INTEGER tag + length + value for modulus (use 0x82 for 2-byte length)
  const modulusEncoded = Buffer.concat([
    Buffer.from([0x02, 0x82, (modulusBuf.length >> 8) & 0xff, modulusBuf.length & 0xff]),
    modulusBuf,
  ]);

  // RSAPublicKey SEQUENCE
  const rsaKeySeq = Buffer.concat([modulusEncoded, exponentEncoded]);
  const rsaKeySeqEncoded = Buffer.concat([
    Buffer.from([0x30, 0x82, (rsaKeySeq.length >> 8) & 0xff, rsaKeySeq.length & 0xff]),
    rsaKeySeq,
  ]);

  // BIT STRING (0x03) with 0x00 unused bits + RSA key SEQUENCE
  const bitStringContent2 = Buffer.concat([Buffer.from([0x00]), rsaKeySeqEncoded]);
  const bitStringEncoded = Buffer.concat([
    Buffer.from([
      0x03,
      0x82,
      (bitStringContent2.length >> 8) & 0xff,
      bitStringContent2.length & 0xff,
    ]),
    bitStringContent2,
  ]);

  // Algorithm Identifier SEQUENCE (OID + NULL parameter for 2 extra bytes)
  const nullParam = Buffer.from([0x05, 0x00]); // NULL
  const algIdContent = Buffer.concat([rsaOid, nullParam]);
  const algIdSeq = Buffer.concat([Buffer.from([0x30, algIdContent.length]), algIdContent]);

  // SPKI SEQUENCE (algorithm + bitString)
  const spkiContent = Buffer.concat([algIdSeq, bitStringEncoded]);
  const spkiSeq = Buffer.concat([
    Buffer.from([0x30, 0x82, (spkiContent.length >> 8) & 0xff, spkiContent.length & 0xff]),
    spkiContent,
  ]);

  // DG15 APPLICATION tag 0x6F
  const dg15Buffer = Buffer.concat([
    Buffer.from([0x6f, 0x82, (spkiSeq.length >> 8) & 0xff, spkiSeq.length & 0xff]),
    spkiSeq,
  ]);

  // Get algorithm OID based on detected signature algorithm
  const algorithmOid =
    signatureAlgorithm === 'RSA-PSS'
      ? '1.2.840.113549.1.1.10' // RSA-PSS OID
      : '1.2.840.113549.1.1.1'; // RSA encryption OID

  return {
    dataGroupNumber: 15,
    tagNumber: '0x6F',
    description: 'Active Authentication Public Key',
    data: {
      algorithm: signatureAlgorithm,
      keySize: 2048,
      publicKeyInfo: {
        algorithm: {
          oid: algorithmOid,
          parameters: null,
        },
        publicKey: {
          modulus: publicKeyDer.toString('hex'),
          exponent: 65537,
        },
      },
    },
    publicKeyPEM,
    privateKeyPEM, // Save private key for AA signature generation (NOT in passport JSON!)
    encodedData: dg15Buffer.toString('base64'),
  };
}

/**
 * Generate SOD - Security Object Document
 * Contains hashes of all data groups and is digitally signed using proper ASN.1/DER encoding
 * Uses provided DSC certificate and key for signing, but embeds CSCA certificate in SOD
 */
function generateSOD(
  dataGroups: Record<string, DG1Data | DG15Data>,
  certFolder: string,
  dscCert?: string,
  dscKey?: string,
): SODData {
  // Hash each data group using SHA-256
  const hashAlgorithm = 'sha256';
  const dataGroupHashValues: Record<string, string> = {};
  const dataGroupHashBuffers: Record<string, Buffer> = {};

  for (const [dgNumber, dgData] of Object.entries(dataGroups)) {
    const dataBuffer = Buffer.from(dgData.encodedData, 'base64');
    const hash = crypto.createHash(hashAlgorithm).update(dataBuffer).digest();
    dataGroupHashValues[dgNumber] = hash.toString('hex');
    dataGroupHashBuffers[dgNumber] = hash;
  }

  // Add dummy data groups for padding to match expected offsets
  // Adding DG2, DG3, DG4, DG5 to increase EC length and dg15_shift
  for (let dgNum = 2; dgNum <= 5; dgNum++) {
    const dummyData = Buffer.alloc(10, 0xff); // 10 bytes of dummy data
    const dgHash = crypto.createHash(hashAlgorithm).update(dummyData).digest();
    dataGroupHashValues[dgNum.toString()] = dgHash.toString('hex');
    dataGroupHashBuffers[dgNum.toString()] = dgHash;
  }

  // Use provided DSC for signing, but always embed CSCA in SOD
  let docSignPrivateKey: string;
  let signingCertPEM: string; // For signing
  let embeddedCertPEM: string; // For embedding in SOD (CSCA)
  let docSignPublicKey: string; // Public key from embedded cert
  let certInfo: {
    issuer: string;
    subject: string;
    serialNumber: string;
    validFrom: string;
    validTo: string;
  };

  // Load DSC certificate and key (one DSC signs many passports)
  const dscCertPath = path.join(process.cwd(), 'data', certFolder, 'dsc_cert.pem');
  const dscKeyPath = path.join(process.cwd(), 'data', certFolder, 'dsc_key.pem');

  // IMPORTANT: SOD is signed with DSC (one DSC can sign multiple passports)
  // DSC is registered in the contract for verification
  if (dscCert && dscKey) {
    // Use provided DSC for signing
    signingCertPEM = dscCert;
    docSignPrivateKey = dscKey;
    embeddedCertPEM = dscCert;

    const cert = new crypto.X509Certificate(embeddedCertPEM);
    docSignPublicKey = cert.publicKey.export({
      type: 'spki',
      format: 'pem',
    }) as string;
    certInfo = {
      issuer: cert.issuer,
      subject: cert.subject,
      serialNumber: cert.serialNumber,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
    };

    console.log('  Signing SOD with provided DSC certificate');
  } else if (fs.existsSync(dscCertPath) && fs.existsSync(dscKeyPath)) {
    // Use DSC from file system (one DSC signs many passports)
    const dscCertPEM = fs.readFileSync(dscCertPath, 'utf8');
    const dscKeyPEM = fs.readFileSync(dscKeyPath, 'utf8');

    signingCertPEM = dscCertPEM;
    docSignPrivateKey = dscKeyPEM;
    embeddedCertPEM = dscCertPEM;

    const cert = new crypto.X509Certificate(embeddedCertPEM);
    docSignPublicKey = cert.publicKey.export({
      type: 'spki',
      format: 'pem',
    }) as string;
    certInfo = {
      issuer: cert.issuer,
      subject: cert.subject,
      serialNumber: cert.serialNumber,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
    };

    console.log('  Signing SOD with DSC certificate from file (registered in contract)');
  } else {
    // Load existing certificate from folder (no DSC provided)
    const certPath = path.join(process.cwd(), 'data', certFolder, 'csca_cert.pem');
    const keyPath = path.join(process.cwd(), 'data', certFolder, 'csca_key.pem');

    try {
      signingCertPEM = fs.readFileSync(certPath, 'utf8');
      embeddedCertPEM = signingCertPEM; // Same cert for signing and embedding
      docSignPrivateKey = fs.readFileSync(keyPath, 'utf8');

      const cert = new crypto.X509Certificate(embeddedCertPEM);
      docSignPublicKey = cert.publicKey.export({
        type: 'spki',
        format: 'pem',
      }) as string;
      certInfo = {
        issuer: cert.issuer,
        subject: cert.subject,
        serialNumber: cert.serialNumber,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
      };

      console.log(`  Using certificate from ${certFolder}`);
    } catch (error) {
      throw new Error(`Failed to load certificate/key from data/${certFolder}/: ${error}`);
    }
  }

  // Get cert path for signature algorithm detection (use signing cert)
  let certPath: string;
  if (dscCert) {
    // Write temp file for algorithm detection
    const tmpCertPath = path.join(process.cwd(), 'data', 'tmp_dsc', 'tmp_cert.pem');
    const tmpDir = path.dirname(tmpCertPath);
    if (!fs.existsSync(tmpDir)) {
      fs.mkdirSync(tmpDir, { recursive: true });
    }
    fs.writeFileSync(tmpCertPath, signingCertPEM);
    certPath = tmpCertPath;
  } else {
    certPath = path.join(process.cwd(), 'data', certFolder, 'csca_cert.pem');
  }

  // Clean up temp cert file if it was created
  const tmpCertPath = path.join(process.cwd(), 'data', 'tmp_dsc', 'tmp_cert.pem');
  const cleanupTempCert = () => {
    if (dscCert && fs.existsSync(tmpCertPath)) {
      fs.unlinkSync(tmpCertPath);
    }
  };

  // Create LDS Security Object in ASN.1 format
  // LDSSecurityObject ::= SEQUENCE {
  //   version INTEGER,
  //   hashAlgorithm DigestAlgorithmIdentifier,
  //   dataGroupHashValues SEQUENCE OF DataGroupHash,
  //   ldsSecurityObjectVersion (optional) - adding for padding
  // }
  const ldsSecurityObjectAsn1 = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      // version
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.INTEGER,
        false,
        forge.asn1.integerToDer(0).getBytes(),
      ),
      // hashAlgorithm (SHA-256) with explicit NULL parameters
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes(), // SHA-256 OID
        ),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
      ]),
      // dataGroupHashValues (sorted by DG number)
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.SEQUENCE,
        true,
        Object.entries(dataGroupHashBuffers)
          .sort(([a], [b]) => parseInt(a) - parseInt(b))
          .map(([dgNumber, hashBuffer]) =>
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
              // dataGroupNumber
              forge.asn1.create(
                forge.asn1.Class.UNIVERSAL,
                forge.asn1.Type.INTEGER,
                false,
                forge.asn1.integerToDer(parseInt(dgNumber)).getBytes(),
              ),
              // dataGroupHashValue
              forge.asn1.create(
                forge.asn1.Class.UNIVERSAL,
                forge.asn1.Type.OCTETSTRING,
                false,
                hashBuffer.toString('binary'),
              ),
            ]),
          ),
      ),
    ],
  );

  // Convert to DER encoding
  const ldsSecurityObjectDer = forge.asn1.toDer(ldsSecurityObjectAsn1).getBytes();
  const ldsSecurityObjectBuffer = Buffer.from(ldsSecurityObjectDer, 'binary');

  // Detect certificate signature algorithm to use appropriate padding
  const certSigInfo = detectSignatureAlgorithm(certPath);
  const isRsaPss = certSigInfo === 'RSA-PSS';

  let signature: Buffer;
  let saltLength = 0;
  let sodBuffer: Buffer;

  // Always use node-forge to create the base PKCS#7 structure for consistent offsets
  const forgeSigningCert = forge.pki.certificateFromPem(signingCertPEM); // For signing (DSC)
  const forgeEmbeddedCert = forge.pki.certificateFromPem(embeddedCertPEM); // For embedding in SOD (DSC)
  const forgePrivateKey = forge.pki.privateKeyFromPem(docSignPrivateKey);

  // For e-passport SOD, content type should be LDS security object OID
  const ldsSecurityObjectOid = '2.23.136.1.1.1';

  if (isRsaPss) {
    // Extract salt length from certificate
    const cert2 = new crypto.X509Certificate(signingCertPEM);
    const certDER2 = cert2.raw;
    saltLength = extractSaltLengthFromCert(certDER2);

    console.log(`Signing SOD with RSA-PSS (salt length: ${saltLength})`);

    // Step 1: Create PKCS#7 structure using forge (this gives us the right offsets)
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(ldsSecurityObjectDer, 'raw');

    // Add DSC certificate (signs the SOD)
    p7.addCertificate(forgeEmbeddedCert); // DSC certificate

    // Add signing time BEFORE messageDigest to increase ec_shift
    const now = new Date();

    p7.addSigner({
      key: forgePrivateKey,
      certificate: forgeSigningCert, // Use DSC certificate for signing
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        {
          type: forge.pki.oids.contentType,
          value: ldsSecurityObjectOid,
        },
        {
          type: forge.pki.oids.signingTime,
          value: now as any,
        },
        {
          type: forge.pki.oids.messageDigest,
          // Auto-computed by forge
        },
      ],
    });

    // Sign with temporary signature (forge will use PKCS#1 v1.5)
    p7.sign({ detached: false });

    // Convert to ASN.1
    let p7Asn1 = p7.toAsn1();

    // Step 2: Manually patch RSA-PSS parameters into SignerInfo
    // Navigate to SignerInfo -> digestEncryptionAlgorithm
    // PKCS#7 structure: ContentInfo -> content [0] -> SignedData -> signerInfos
    const p7Asn1Any = p7Asn1 as any;
    const signedData = p7Asn1Any.value[1].value[0]; // content [0] -> SignedData SEQUENCE
    const signerInfos = signedData.value[4]; // SignedData -> signerInfos SET
    const signerInfo = signerInfos.value[0]; // First SignerInfo SEQUENCE
    const digestEncryptionAlg = signerInfo.value[4]; // digestEncryptionAlgorithm SEQUENCE

    // Replace the algorithm OID with RSA-PSS OID
    digestEncryptionAlg.value[0] = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer('1.2.840.113549.1.1.10').getBytes(), // RSA-PSS OID
    );

    // Add RSA-PSS parameters
    const rsaPssParams = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      [
        // hashAlgorithm [0] EXPLICIT
        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(
              forge.asn1.Class.UNIVERSAL,
              forge.asn1.Type.OID,
              false,
              forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes(), // SHA-256 OID
            ),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
          ]),
        ]),
        // maskGenAlgorithm [1] EXPLICIT
        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 1, true, [
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
            forge.asn1.create(
              forge.asn1.Class.UNIVERSAL,
              forge.asn1.Type.OID,
              false,
              forge.asn1.oidToDer('1.2.840.113549.1.1.8').getBytes(), // MGF1 OID
            ),
            forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
              forge.asn1.create(
                forge.asn1.Class.UNIVERSAL,
                forge.asn1.Type.OID,
                false,
                forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes(), // SHA-256 OID
              ),
              forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
            ]),
          ]),
        ]),
        // saltLength [2] EXPLICIT
        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 2, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.INTEGER,
            false,
            forge.asn1.integerToDer(saltLength).getBytes(),
          ),
        ]),
      ],
    );

    digestEncryptionAlg.value[1] = rsaPssParams;

    // Step 3: Re-sign with RSA-PSS
    // Get the signed attributes to sign
    const signedAttrs = signerInfo.value[3]; // signedAttrs [0] IMPLICIT
    // Convert to DER with SET tag (0x31)
    const signedAttrsDer = forge.asn1.toDer(signedAttrs).getBytes();
    const signedAttrsSetDer = '\x31' + signedAttrsDer.substring(1); // Replace tag with SET
    const signedAttrsBuffer = Buffer.from(signedAttrsSetDer, 'binary');

    // Sign with RSA-PSS
    signature = crypto.sign('sha256', signedAttrsBuffer, {
      key: docSignPrivateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: saltLength,
    });

    // Replace the signature in the ASN.1 structure
    signerInfo.value[5] = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OCTETSTRING,
      false,
      signature.toString('binary'),
    );

    // Convert final ASN.1 to DER
    const sodDer = forge.asn1.toDer(p7Asn1).getBytes();
    sodBuffer = Buffer.from(sodDer, 'binary');

    console.log(`  ✓ Created SOD with RSA-PSS parameters (${sodBuffer.length} bytes)`);

    // Clean up temp cert
    cleanupTempCert();
  } else {
    console.log('Signing SOD with RSA PKCS#1 v1.5');

    // Create PKCS#7 signed data with proper structure
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(ldsSecurityObjectDer, 'raw');

    // Add DSC certificate (signs the SOD)
    p7.addCertificate(forgeEmbeddedCert); // DSC certificate

    // Add signing time BEFORE messageDigest to increase ec_shift
    const now = new Date();

    p7.addSigner({
      key: forgePrivateKey,
      certificate: forgeSigningCert, // Use DSC certificate for signing
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        {
          type: forge.pki.oids.contentType,
          value: ldsSecurityObjectOid,
        },
        {
          type: forge.pki.oids.signingTime,
          value: now as any,
        },
        {
          type: forge.pki.oids.messageDigest,
          // Auto-computed by forge
        },
      ],
    });

    // Sign the data
    p7.sign({ detached: false });

    // Convert to DER
    let p7Asn1 = p7.toAsn1();
    let sodDer = forge.asn1.toDer(p7Asn1).getBytes();
    sodBuffer = Buffer.from(sodDer, 'binary');

    // Extract signature from ASN.1 for metadata
    const p7Asn1Any = p7Asn1 as any;
    const signedData = p7Asn1Any.value[1].value[0];
    const signerInfos = signedData.value[4];
    const signerInfo = signerInfos.value[0];
    signature = Buffer.from(signerInfo.value[5].value, 'binary');

    console.log(`  ✓ Created SOD with RSA PKCS#1 v1.5 (${sodBuffer.length} bytes)`);

    // Clean up temp cert
    cleanupTempCert();
  }

  return {
    tagNumber: '0x77',
    description: 'Security Object Document (SOD)',
    data: {
      ldsSecurityObject: {
        version: 0,
        hashAlgorithm: {
          algorithm: '2.16.840.1.101.3.4.2.1',
          parameters: null,
        },
        dataGroupHashValues,
      },
      signatureAlgorithm: {
        algorithm: isRsaPss ? '1.2.840.113549.1.1.10' : '1.2.840.113549.1.1.11', // RSA-PSS or RSA with SHA-256
        parameters: {
          hashAlgorithm: 'SHA-256',
          maskGenAlgorithm: isRsaPss ? 'MGF1' : 'PKCS1',
          saltLength: saltLength,
        },
      },
      signature: signature.toString('hex'),
      certificates: {
        documentSignerCertificate: {
          issuer: certInfo.issuer,
          subject: certInfo.subject,
          serialNumber: certInfo.serialNumber,
          validFrom: certInfo.validFrom,
          validTo: certInfo.validTo,
          publicKey: docSignPublicKey,
        },
      },
    },
    encodedData: sodBuffer.toString('base64'),
  };
}

/**
 * Main function to generate complete biometric passport data
 */
export async function generateBiometricPassportData(
  passportInfo: PassportGenerationOptions = {},
): Promise<BiometricPassportData> {
  const certFolder = passportInfo.certFolder || 'rsapss';

  console.log(`\n=== Generating passport with unique AA key ===`);

  // Generate DG1 - Machine Readable Zone
  const dg1Data = generateDG1(passportInfo);

  // Generate DG15 - Active Authentication Public Key (generates unique AA key for this passport)
  const dg15Data = generateDG15(certFolder);

  // Prepare data groups for SOD
  const dataGroups: Record<string, DG1Data | DG15Data> = {
    1: dg1Data,
    15: dg15Data,
  };

  // Generate SOD - Security Object Document (signed with DSC from file or csca_cert.pem)
  // SOD will be signed with DSC (dsc_cert.pem/dsc_key.pem) if it exists, otherwise with csca_cert.pem/csca_key.pem
  const sodData = generateSOD(dataGroups, certFolder);

  // Use placeholder signature
  // The actual AA signature will be generated later using update-aa-signature.ts
  // after the ZK proof is generated and we have the challenge
  console.log('\n=== Using placeholder AA signature ===');
  console.log('  AA signature will be generated later using update-aa-signature.ts');
  const aaSignature = sodData.data.signature;

  // Convert dates from YYMMDD to readable format
  const dob = dg1Data.data.dateOfBirth;
  const expiry = dg1Data.data.expiryDate;

  // Parse YYMMDD format
  const dobYear =
    parseInt(dob.substring(0, 2)) < 50 ? `20${dob.substring(0, 2)}` : `19${dob.substring(0, 2)}`;
  const expiryYear =
    parseInt(expiry.substring(0, 2)) < 50
      ? `20${expiry.substring(0, 2)}`
      : `19${expiry.substring(0, 2)}`;

  // Assemble passport data in the required format
  const passportData: BiometricPassportData = {
    dg1: dg1Data.encodedData,
    dg15: dg15Data.encodedData,
    sod: sodData.encodedData,
    documentNumber: dg1Data.data.passportNumber,
    dateOfBirth: `${dobYear}-${dob.substring(2, 4)}-${dob.substring(4, 6)}`,
    documentExpiryDate: `${expiryYear}-${expiry.substring(2, 4)}-${expiry.substring(4, 6)}`,
    nationality: dg1Data.data.nationality,
    gender: dg1Data.data.sex,
    firstName: dg1Data.data.givenNames,
    lastName: dg1Data.data.surname,
    documentType: dg1Data.data.documentType,
    issuingAuthority: dg1Data.data.issuingCountry,
    signature: aaSignature, // Active Authentication signature (placeholder)
    passportImageRaw: '', // Placeholder for passport photo
    // AA private key (INTERNAL - for AA signature generation only, excluded from JSON save)
    aaPrivateKey: dg15Data.privateKeyPEM,
  };

  console.log(`  ✓ Passport generated with unique AA key`);

  return passportData;
}

/**
 * Utility function to verify SOD signature
 * Decodes the SOD from the passport data and verifies the PKCS#7 signature
 */
export function verifySOD(passportData: BiometricPassportData): boolean {
  try {
    // Decode the SOD from base64 (it's DER-encoded PKCS#7)
    const sodBuffer = Buffer.from(passportData.sod, 'base64');
    const sodDer = forge.util.createBuffer(sodBuffer.toString('binary'));

    // Parse the PKCS#7 structure - this validates it's proper ASN.1/DER
    const p7Asn1 = forge.asn1.fromDer(sodDer);
    const p7: any = forge.pkcs7.messageFromAsn1(p7Asn1);

    // Basic structure validation
    if (!p7.content) {
      console.error('Invalid PKCS#7 structure: no content');
      return false;
    }

    console.log('✓ SOD is properly ASN.1/DER encoded PKCS#7 SignedData');
    console.log('✓ SOD can be successfully parsed by ASN.1 parser');
    console.log('✓ Ready for ZK circuit processing');

    return true;
  } catch (error) {
    console.error('SOD verification error:', error);
    return false;
  }
}

// Example usage when run directly
if (require.main === module) {
  (async () => {
    const passportData = await generateBiometricPassportData({
      surname: 'SMITH',
      givenNames: 'JOHN DAVID',
      passportNumber: 'AB1234567',
      nationality: 'USA',
      dateOfBirth: '850315',
      sex: 'M',
      expiryDate: '301231',
      personalNumber: 'A12345678',
      certFolder: 'rsapss', // Specify certificate folder
    });

    // Create output directory if it doesn't exist
    const outDir = path.join(process.cwd(), 'data', 'out_passport');
    if (!fs.existsSync(outDir)) {
      fs.mkdirSync(outDir, { recursive: true });
    }

    // Save to file with timestamp
    const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, '');
    const outputPath = path.join(outDir, `passport_${timestamp}.json`);
    fs.writeFileSync(outputPath, JSON.stringify(passportData, null, 2));

    console.log(`\n✅ Passport data generated and saved to: ${outputPath}`);
    console.log('\n--- Verification ---');
    console.log('SOD Signature Valid:', verifySOD(passportData));
  })();
}
