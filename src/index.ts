import { setupICAORoot } from './workflows/setup';
import { registerCert as registerCert } from './workflows/register-certificate';
import { registerPassport } from './workflows/register-passport';
import {
  revokeSingleSession,
  revokeAllPassportSessions,
  revokeOtherPassportSessions,
} from './workflows/revoke-passport';
import { revokeUserKYC, revokeAllUserKYC, revokeSelfKYC } from './workflows/revoke-kyc';
import { generateBiometricPassportData } from './passport/biometric-passport-generator';
import { generateRegisterIdentityProof } from './workflows/generate-register-proof';
import { updateAASignature } from './passport/generate-aa-signature';
import { generateRandomPassportData } from './passport/random-passport-data';
import { executeQueryProofWorkflow, checkKYCStatus } from './workflows/execute-query-proof';
import { generateQueryProofFromContract } from './workflows/generate-query-proof-from-contract';
import { generateNoirQueryProofFromContract } from './workflows/generate-query-proof-noir';
import { executeNoirQueryProofWorkflow } from './workflows/execute-query-proof-noir';
import { checkPassportInfoFromProof } from './workflows/check-passport-info';
import { registerAndVerifyKYCWorkflow } from './workflows/register-and-verify-kyc';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

const command = process.argv[2] || 'help';

async function main() {
  if (command === 'setup') {
    await setupICAORoot();
  } else if (command === 'register-passport') {
    await registerPassport();
  } else if (command === 'register-certificate-rsapss') {
    await registerCert();
  } else if (command === 'generate-passport') {
    const randomData = generateRandomPassportData();
    console.log(`\n=== Generating passport for ${randomData.givenNames} ${randomData.surname} ===`);
    console.log(`  Passport Number: ${randomData.passportNumber}`);
    console.log(`  Date of Birth: ${randomData.dateOfBirth}`);
    console.log(`  Sex: ${randomData.sex}`);
    console.log(`  Nationality: ${randomData.nationality}`);
    console.log();

    const passportData = await generateBiometricPassportData({
      ...randomData,
      certFolder: 'rsapss',
    });

    const outDir = path.join(process.cwd(), 'data', 'out_passport');
    if (!fs.existsSync(outDir)) {
      fs.mkdirSync(outDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, '');
    const outputPath = path.join(outDir, `passport_${timestamp}.json`);
    fs.writeFileSync(outputPath, JSON.stringify(passportData, null, 2));

    console.log(`\n✅ Passport data generated and saved to: ${outputPath}`);
  } else if (command === 'generate-register-proof') {
    const passportDir = path.join(process.cwd(), 'data', 'out_passport');
    const passportFiles = fs.readdirSync(passportDir);
    const latestFile = passportFiles.sort().reverse()[0];
    const passportPath = path.join(passportDir, latestFile);

    // Generate BJJ secret key using BJJKeygen binary
    const dataDir = path.join(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    const skIdentityPath = path.join(dataDir, 'sk_identity');
    const bjjKeygenPath = path.join(process.cwd(), 'BJJKeygen');

    console.log('\n=== Generating BJJ secret key ===');
    console.log(`Running: ${bjjKeygenPath} ${skIdentityPath}`);

    try {
      const output = execSync(`"${bjjKeygenPath}" "${skIdentityPath}"`, {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      console.log('BJJKeygen output:', output.trim());
      console.log(`✅ Secret key saved to: ${skIdentityPath}\n`);
    } catch (error: any) {
      console.error('❌ Error running BJJKeygen:', error.message);
      process.exit(1);
    }

    await generateRegisterIdentityProof(passportPath);
    console.log('\n✅ Proof generation completed successfully!');
  } else if (command === 'update-aa-sig') {
    await updateAASignature();
  } else if (command === 'revoke-passport') {
    console.log('Mode: Revoke ALL sessions for passport\n');
    await revokeAllPassportSessions();
  } else if (command === 'revoke-other-sessions') {
    console.log('Mode: Revoke all sessions EXCEPT current one\n');
    await revokeOtherPassportSessions();
  } else if (command === 'revoke-session') {
    await revokeSingleSession();
  } else if (command === 'revoke-kyc') {
    // Get optional parameters
    const userAddress = process.argv[3];
    const passportHash = process.argv[4];

    if (!userAddress) {
      console.error('Error: userAddress is required');
      console.log('Usage: npm run revoke-kyc <userAddress> [passportHash]');
      console.log('  If passportHash is not provided, all KYC for the user will be revoked');
      process.exit(1);
    }

    if (passportHash) {
      console.log('Mode: Revoke specific passport KYC\n');
      await revokeUserKYC(userAddress, passportHash);
    } else {
      console.log('Mode: Revoke ALL KYC for user\n');
      await revokeAllUserKYC(userAddress);
    }
  } else if (command === 'revoke-self-kyc') {
    const passportHash = process.argv[3]; // Optional
    await revokeSelfKYC(passportHash);
  } else if (command === 'generate-query-proof') {
    // Get userAddress from command line argument
    const userAddress = process.argv[3];

    if (!userAddress) {
      console.error('Error: userAddress is required');
      console.log('Usage: npm run generate-query-proof <userAddress>');
      process.exit(1);
    }

    await generateQueryProofFromContract({
      userAddress,
    });
  } else if (command === 'generate-query-proof-noir') {
    // Get userAddress from command line argument
    const userAddress = process.argv[3];

    if (!userAddress) {
      console.error('Error: userAddress is required');
      console.log('Usage: npm run generate-query-proof-noir <userAddress>');
      process.exit(1);
    }

    await generateNoirQueryProofFromContract({
      userAddress,
    });
  } else if (command === 'execute-query-proof') {
    // Get optional userAddress from command line argument
    const userAddress = process.argv[3]; // Optional

    await executeQueryProofWorkflow({
      userAddress,
    });
  } else if (command === 'execute-query-proof-noir') {
    // Get optional userAddress from command line argument
    const userAddress = process.argv[3]; // Optional

    await executeNoirQueryProofWorkflow({
      userAddress,
    });
  } else if (command === 'register-and-verify-kyc') {
    // Get optional userAddress from command line argument
    const userAddress = process.argv[3]; // Optional

    await registerAndVerifyKYCWorkflow({
      userAddress,
    });
  } else if (command === 'check-kyc-status') {
    const address = process.argv[3]; // Optional
    await checkKYCStatus(address);
  } else if (command === 'check-passport-info') {
    await checkPassportInfoFromProof();
  } else {
    console.log('Usage: npm start [command]');
    console.log('\nSetup & Registration:');
    console.log('  setup                       - Initialize ICAO master tree root on blockchain');
    console.log(`  register-certificate-rsapss - Register RSA-PSS certificate with merkle proof`);
    console.log('  register-passport           - Register passport using Noir ZK proof');
    console.log('  generate-passport           - Generate biometric passport data');
    console.log('  generate-register-proof     - Generate ZK proof for passport registration');
    console.log('  update-aa-sig               - Update Active Authentication signature');
    console.log(
      '                                Use --random-challenge for random 8-byte challenge',
    );
    console.log('  check-passport-info         - Show passport info from registration proof');

    console.log('\nSession Management:');
    console.log('  revoke-passport             - Revoke ALL sessions for passport');
    console.log('  revoke-other-sessions       - Revoke all sessions EXCEPT current one');
    console.log('  revoke-session              - Revoke a single session');

    console.log('\nKYC Management:');
    console.log('  revoke-kyc <userAddress> [passportHash]');
    console.log(
      '                              - Revoke KYC for user. If passportHash not provided,',
    );
    console.log('                                revokes all KYC for the user');
    console.log('  revoke-self-kyc [passportHash]');
    console.log('                              - Revoke own KYC. If passportHash not provided,');
    console.log('                                revokes all your KYC');
    console.log('  check-kyc-status [address]  - Check KYC status (defaults to wallet address)');

    console.log('\nQuery Proofs:');
    console.log('  generate-query-proof <userAddress>');
    console.log('                              - Generate query proof (Circom/Groth16)');
    console.log('  generate-query-proof-noir <userAddress>');
    console.log('                              - Generate query proof (Noir/UltraPlonk)');
    console.log('  execute-query-proof [userAddress]');
    console.log('                              - Execute Circom query proof for KYC verification');
    console.log('  execute-query-proof-noir [userAddress]');
    console.log('                              - Execute Noir query proof for KYC verification');
    console.log('  register-and-verify-kyc [userAddress]');
    console.log(
      '                              - Register passport and verify KYC in one transaction',
    );

    process.exit(0);
  }
}

main()
  .then(() => {
    // Explicitly exit the process after successful completion
    // This is necessary because some operations (like snarkjs proof generation)
    // create worker threads that prevent Node.js from exiting naturally
    process.exit(0);
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
