import { setupICAORoot } from './workflows/setup';
import { registerCert as registerCert } from './workflows/register-certificate';
import { registerPassport } from './workflows/register-passport';
import { revokePassportIdentity } from './workflows/revoke-passport';
import { reissuePassport } from './workflows/reissue-identity';
import { generateBiometricPassportData } from './passport/biometric-passport-generator';
import { generateRegisterIdentityProof } from './workflows/generate-register-proof';
import { updateAASignature } from './passport/generate-aa-signature';
import { generateRandomPassportData } from './passport/random-passport-data';
import { executeQueryProofWorkflow, checkKYCStatus } from './workflows/execute-query-proof';
import { generateQueryProofFromContract } from './workflows/generate-query-proof-from-contract';
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
    await revokePassportIdentity();
  } else if (command === 'reissue-identity') {
    await reissuePassport();
  } else if (command === 'generate-query-proof') {
    // Get requestId and userAddress from command line arguments
    const requestId = process.argv[3];
    const userAddress = process.argv[4];

    if (!requestId || !userAddress) {
      console.error('Error: requestId and userAddress are required');
      console.log('Usage: npm run generate-query-proof <requestId> <userAddress>');
      process.exit(1);
    }

    await generateQueryProofFromContract({
      requestId,
      userAddress,
    });
  } else if (command === 'execute-query-proof') {
    // Get requestId from command line argument
    const requestId = process.argv[3];
    if (!requestId) {
      console.error('Error: requestId is required');
      console.log('Usage: npm run execute-query-proof <requestId> [userAddress]');
      process.exit(1);
    }

    const userAddress = process.argv[4]; // Optional

    await executeQueryProofWorkflow({
      requestId,
      userAddress,
    });
  } else if (command === 'check-kyc-status') {
    const address = process.argv[3]; // Optional
    await checkKYCStatus(address);
  } else {
    console.log('Usage: npm start [command]');
    console.log('\nCommands:');
    console.log('  setup                       - Initialize ICAO master tree root on blockchain');
    console.log(`  register-certificate-rsapss - Register RSA-PSS certificate with merkle proof. If you want to register more than one certificate, modify data/rsspss/masterlist.pem accordingly 
      and rerun setup with new ICAO root.`);
    console.log(
      '  register-passport           - Register passport using Noir ZK proof. Only for a specific circuit',
    );
    console.log(
      '  generate-passport           - Generate biometric passport data. Only for a specific circuit',
    );
    console.log('  generate-register-proof     - Generate ZK proof for passport registration');
    console.log(
      '  update-aa-sig - Update Active Authentication signature for last generated passport',
    );
    console.log(
      '                                       Use --random-challenge to generate signature with random 8-byte challenge',
    );
    console.log(
      '  revoke-passport             - Revoke passport identity using the latest passport data and proof',
    );
    console.log(
      '  reissue-passport            - Reissue identity with new identityKey (BJJ key pair) for same passport',
    );
    console.log(
      '  generate-query-proof <requestId> <userAddress> - Generate query proof using contract parameters',
    );
    console.log(
      '  execute-query-proof <requestId> [userAddress] - Execute query proof for KYC verification',
    );
    console.log(
      '  check-kyc-status [address]  - Check KYC status for an address (defaults to wallet address)',
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
