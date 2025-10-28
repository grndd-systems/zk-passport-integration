import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { revokePassport } from '../blockchain/tx';
import { P_RSA_SHA256_2688, Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296 } from '../blockchain/eth';

interface Passport {
  dataType: string;
  zkType: string;
  signature: string;
  publicKey: string;
  passportHash: string;
}

export async function revokePassportIdentity() {
  console.log('Revoking passport identity...');

  // Load the generated passport data
  const passportFiles = fs.readdirSync(path.join(__dirname, '../../data/out_passport'));
  const latestPassportFile = passportFiles.sort().reverse()[0];
  const passportPath = path.join(__dirname, '../../data/out_passport', latestPassportFile);
  const passportData = JSON.parse(fs.readFileSync(passportPath, 'utf-8'));

  console.log('Using passport file:', latestPassportFile);

  // Extract circuit output values from the public-inputs file
  const publicInputsPath = path.join(__dirname, '../../data/proof/public-inputs');
  const publicInputsContent = fs.readFileSync(publicInputsPath, 'utf-8');
  const circuitOutputs = publicInputsContent
    .trim()
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => BigInt(line.trim()));

  console.log(
    'Circuit outputs extracted from public-inputs:',
    circuitOutputs.map((o) => ethers.toBeHex(o, 32)),
  );

  // The circuit public inputs/outputs are:
  // [0] = passportKey (OUTPUT - passport key)
  // [1] = passportHash (OUTPUT - hash of the passport data)
  // [2] = dgCommit (OUTPUT - commitment to DG1)
  // [3] = identityKey (OUTPUT - hashed identity key)
  // [4] = certificatesRoot (INPUT - passed to circuit for verification)

  const passportHash = circuitOutputs[1];
  const identityKey = circuitOutputs[3];

  // Extract modulus from DG15 for RSA operations
  const dg15Buffer = Buffer.from(passportData.dg15, 'base64');

  // Parse DG15 to extract the modulus
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

  const publicKey = crypto.createPublicKey({
    key: spki,
    format: 'der',
    type: 'spki',
  });

  const jwk = publicKey.export({ format: 'jwk' }) as crypto.JsonWebKey;
  const modulusBytes = Buffer.from(jwk.n!, 'base64');

  console.log('Using modulus as publicKey:', modulusBytes.length, 'bytes');

  const passport: Passport = {
    dataType: P_RSA_SHA256_2688, // RSA 2048-bit with SHA-256
    zkType: Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296, // Noir verifier type
    signature: '0x' + passportData.signature,
    publicKey: '0x' + modulusBytes.toString('hex'), // Send modulus only (256 bytes)
    passportHash: ethers.toBeHex(passportHash, 32),
  };

  console.log('\nTransaction parameters:');
  console.log('  identityKey:', ethers.toBeHex(identityKey, 32));
  console.log('  passport.dataType:', passport.dataType);
  console.log('  passport.zkType:', passport.zkType);
  console.log('  passport.signature:', passport.signature);
  console.log('  passport.publicKey:', passport.publicKey);
  console.log('  passport.passportHash:', passport.passportHash);

  // Use the tx.ts function to revoke the passport
  const tx = await revokePassport(identityKey, passport);

  console.log('Passport identity revoked successfully!');

  return {
    transactionHash: tx.hash,
  };
}
