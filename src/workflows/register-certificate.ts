import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import * as crypto from 'crypto';
import { registerCertificate } from '../blockchain/tx';
import { C_RSAPSS_SHA2_2048, C_RSA_SHA2_2048 } from '../blockchain/eth';
import {
  extractSignatureFromCert,
  findExpirationOffset,
  extractRSAModulus,
  extractTBSFromCert,
  extractPublicKeyFromTBS,
  findModulusOffsetInTBS,
} from '../crypto/extract-from-cert';

// For CommonJS, use __dirname directly; for ESM, use import.meta.url
const currentDir: string =
  typeof __dirname !== 'undefined'
    ? __dirname
    : path.dirname(fileURLToPath(require.main?.filename || process.argv[1]));

// Signature algorithm types
export type SignatureAlgorithm = 'RSA-PSS' | 'RSA';

/**
 * Register CSCA (Country Signing CA) certificate in PoseidonSMT
 *
 * IMPORTANT: This function registers the CSCA certificate, NOT DSC certificates.
 * - CSCA: Self-signed root CA certificate (CA:TRUE) that is in the ICAO Master Tree
 * - DSC: Document Signer Certificates (CA:FALSE) are generated per passport and NOT registered
 *
 * @param folderName - Folder containing csca_cert.pem (CSCA certificate)
 * @param signatureAlgorithm - Signature algorithm used (RSA-PSS or RSA)
 */
export async function registerCert(
  folderName: string = 'rsapss',
  signatureAlgorithm: SignatureAlgorithm = 'RSA-PSS',
) {
  console.log(
    `Registering certificate from folder: ${folderName} with algorithm: ${signatureAlgorithm}...`,
  );

  // Paths using the provided folder name
  const dataDir = path.join(currentDir, `../../data/${folderName}`);
  const csca_pem = path.join(dataDir, 'csca_cert.pem');
  const dsc_pem = path.join(dataDir, 'dsc_cert.pem');
  const merkle_output = path.join(dataDir, 'merkle_output.txt');

  // Select the appropriate data type constant
  const dataType = signatureAlgorithm === 'RSA-PSS' ? C_RSAPSS_SHA2_2048 : C_RSA_SHA2_2048;

  // Read merkle proof
  const raw = await fs.readFile(merkle_output, 'utf-8');
  const merkleData = JSON.parse(raw);
  const proof = merkleData.proofs || []; // If proofs is null (single cert in tree), use empty array

  // Extract all data from dsc_cert.pem
  console.log('\n=== Extracting data from dsc_cert.pem ===');

  // 1. Extract TBS (To Be Signed) part from DSC certificate
  const dsc_tbs_der_raw = extractTBSFromCert(dsc_pem);
  console.log('✅ TBS extracted:', dsc_tbs_der_raw.length, 'bytes');

  // 2. Extract signature
  const signature_buffer = extractSignatureFromCert(dsc_pem);
  const sig = Uint8Array.from(signature_buffer);
  console.log('✅ Signature extracted:', sig.length, 'bytes');

  // 3. Extract public key (SPKI) from TBS
  const spki = extractPublicKeyFromTBS(dsc_tbs_der_raw);
  console.log('✅ SPKI extracted:', spki.length, 'bytes');

  // 4. Extract RSA modulus from SPKI
  const pubkey_modulus = extractRSAModulus(spki);
  console.log('✅ Public key modulus extracted:', pubkey_modulus.length, 'bytes');

  // 5. Find modulus offset in TBS
  const keyOffset = findModulusOffsetInTBS(dsc_tbs_der_raw, pubkey_modulus);
  console.log('✅ Modulus offset in TBS:', keyOffset);

  // 6. Find expiration offset in TBS
  const expirationOffset = findExpirationOffset(dsc_tbs_der_raw);
  console.log('✅ Expiration offset in TBS:', expirationOffset);

  // Read certificate for verification
  const certPEM = await fs.readFile(dsc_pem, 'utf-8');
  const cert = new crypto.X509Certificate(certPEM);

  // Debug: verify the extraction
  const extractedFromCert = dsc_tbs_der_raw.slice(keyOffset, keyOffset + pubkey_modulus.length);
  console.log('\n=== Debug: Verifying data integrity ===');
  console.log(
    'Modulus from extraction (first 32 bytes):',
    pubkey_modulus.slice(0, 32).toString('hex'),
  );
  console.log(
    'Modulus from TBS at offset (first 32 bytes):',
    extractedFromCert.slice(0, 32).toString('hex'),
  );

  // Extract CSCA public key modulus
  const csca_tbs_der_raw = extractTBSFromCert(csca_pem);
  const csca_spki = extractPublicKeyFromTBS(csca_tbs_der_raw);
  const csca_pubkey_modulus = extractRSAModulus(csca_spki);

  console.log('✅ Public key modulus extracted:', pubkey_modulus.length, 'bytes');
  console.log('Match:', extractedFromCert.equals(pubkey_modulus) ? '✅ YES' : '❌ NO');
  console.log('Signature size:', sig.length, 'bytes');
  console.log('TBS DER size:', dsc_tbs_der_raw.length, 'bytes');

  // Verify signature and modulus match
  console.log('\n=== Verifying icaoMember data ===');
  console.log('icaoMember.signature (first 32):', Buffer.from(sig).slice(0, 32).toString('hex'));
  console.log('icaoMember.publicKey (first 32):', csca_pubkey_modulus.slice(0, 32).toString('hex'));

  // Check if this is self-signed
  console.log('\n=== Self-signed check ===');
  console.log('Certificate subject:', cert.subject);
  console.log('Certificate issuer:', cert.issuer);
  console.log('Is self-signed:', cert.subject === cert.issuer ? 'YES' : 'NO');

  // Build certificate structure
  const certificateStruct = {
    dataType: dataType,
    signedAttributes: dsc_tbs_der_raw,
    keyOffset: keyOffset,
    expirationOffset: expirationOffset,
  };

  // Build ICAO member structure
  const icaoMemberStruct = {
    signature: sig,
    publicKey: csca_pubkey_modulus,
  };

  // Register the certificate on the blockchain
  await registerCertificate(certificateStruct, icaoMemberStruct, proof);

  console.log('Certificate registered successfully!');

  return {
    certificateStruct,
    icaoMemberStruct,
    proof,
  };
}
