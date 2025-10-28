import { setupICAORoot } from './workflows/setup';
import { registerCert as registerCert } from './workflows/register-certificate';
import { registerPassport } from './workflows/register-passport';
import { generateBiometricPassportData } from './passport/biometric-passport-generator';
import { generateRegisterIdentityProof } from './workflows/generate-register-proof';
import { updateAASignature } from './passport/generate-aa-signature';
import { generateRandomPassportData } from './passport/random-passport-data';
import * as fs from 'fs';
import * as path from 'path';

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

    await generateRegisterIdentityProof(passportPath);
    console.log('\n✅ Proof generation completed successfully!');
  } else if (command === 'update-aa-sig') {
    await updateAASignature();
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
    console.log(
      '  generate-register-proof     - Generate ZK proof for passport registration',
    );
    console.log(
      '  update-aa-sig               - Update Active Authentication signature for last generated passport',
    );
    process.exit(0);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
