import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Generate verification key and Solidity contract using bb CLI directly
 * This works for circuits that cause "unreachable" errors in bb.js
 */
async function generateVerifierWithCLI(circuitPath: string, outputDir: string): Promise<void> {
  const circuitName = path.basename(circuitPath, '.json');

  console.log(`\n📝 Processing: ${circuitName}`);
  console.log(`   Circuit: ${circuitPath}`);

  // Check file size
  const stats = fs.statSync(circuitPath);
  const sizeMB = stats.size / (1024 * 1024);
  console.log(`   📊 Circuit size: ${sizeMB.toFixed(2)} MB`);

  // Create output directories
  const vkDir = path.join(outputDir, 'verification-keys', circuitName);
  const contractsDir = path.join(outputDir, 'verifier-contracts');

  if (!fs.existsSync(vkDir)) {
    fs.mkdirSync(vkDir, { recursive: true });
  }
  if (!fs.existsSync(contractsDir)) {
    fs.mkdirSync(contractsDir, { recursive: true });
  }

  // Paths
  const vkPath = path.join(vkDir, 'vk');
  const contractInVkDir = path.join(vkDir, `${circuitName}Verifier.sol`);
  const contractInContractsDir = path.join(contractsDir, `${circuitName}Verifier.sol`);

  // Path to trusted setup (bn254_g1.dat and bn254_g2.dat)
  const crsPath = path.join(__dirname, '../../../data/circuit');

  // Create temporary directory for bb CLI processing
  const tempDir = path.join(vkDir, 'temp');
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }

  try {
    // Step 1: Write bytecode to file (bb CLI needs it as a file)
    console.log('   📄 Extracting bytecode...');
    const circuitData = JSON.parse(fs.readFileSync(circuitPath, 'utf-8'));
    const bytecode = circuitData.bytecode;

    // Bytecode is base64 encoded in the JSON
    const bytecodeBuffer = Buffer.from(bytecode, 'base64');
    const bytecodePath = path.join(tempDir, 'bytecode');
    fs.writeFileSync(bytecodePath, bytecodeBuffer);
    console.log(`   ✓ Bytecode extracted (${bytecodeBuffer.length} bytes)`);

    // Step 2: Generate verification key using bb CLI with trusted setup
    console.log('   🔑 Generating verification key with bb CLI...');
    console.log(`   📁 Using trusted setup from: ${crsPath}`);

    execSync(`bb write_vk -b "${bytecodePath}" -o "${vkPath}" --crs-path "${crsPath}"`, {
      stdio: 'inherit',
      env: { ...process.env },
    });
    console.log(`   ✓ VK saved: ${vkPath}`);

    // Save VK metadata
    const vkBuffer = fs.readFileSync(vkPath);
    const vkJsonPath = path.join(vkDir, 'verification_key.json');
    fs.writeFileSync(
      vkJsonPath,
      JSON.stringify(
        {
          circuit: circuitName,
          vk: vkBuffer.toString('hex'),
          size: vkBuffer.length,
        },
        null,
        2,
      ),
    );

    // Step 3: Generate Solidity verifier contract
    console.log('   📄 Generating Solidity verifier contract...');
    execSync(`bb contract -k "${vkPath}" -o "${contractInVkDir}"`, {
      stdio: 'inherit',
    });
    console.log(`   ✓ Contract saved: ${contractInVkDir}`);

    // Copy to contracts directory
    fs.copyFileSync(contractInVkDir, contractInContractsDir);
    console.log(`   ✓ Contract copied to: ${contractInContractsDir}`);

    // Get contract size
    const contractStats = fs.statSync(contractInVkDir);
    console.log(`   📊 Contract size: ${(contractStats.size / 1024).toFixed(2)} KB`);

    // Cleanup temp directory
    fs.rmSync(tempDir, { recursive: true, force: true });

    console.log(`   ✅ Successfully processed ${circuitName}`);
  } catch (error: any) {
    console.error(`   ❌ Error:`, error.message || error);
    throw error;
  }
}

/**
 * Main execution
 */
async function main() {
  if (process.argv.length < 4) {
    console.error('Usage: node generate-verifier-cli.js <circuit-path> <output-dir>');
    process.exit(1);
  }

  const circuitPath = process.argv[2];
  const outputDir = process.argv[3];

  if (!fs.existsSync(circuitPath)) {
    console.error(`❌ Circuit not found: ${circuitPath}`);
    process.exit(1);
  }

  try {
    await generateVerifierWithCLI(circuitPath, outputDir);
    process.exit(0);
  } catch (error: any) {
    console.error(`\n❌ Error:`, error.message || error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

export { generateVerifierWithCLI };
