import { UltraPlonkBackend, BackendOptions } from '@aztec/bb.js';
import { CompiledCircuit } from '@noir-lang/noir_js';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

/**
 * Generate verification key and Solidity contract for a single circuit
 * This script runs as a separate process to avoid memory accumulation
 */
async function generateSingleVerifier(circuitPath: string, outputDir: string): Promise<void> {
  const circuitName = path.basename(circuitPath, '.json');

  console.log(`\n📝 Processing: ${circuitName}`);
  console.log(`   Circuit: ${circuitPath}`);

  // Check file size
  const stats = fs.statSync(circuitPath);
  const sizeMB = stats.size / (1024 * 1024);
  console.log(`   📊 Circuit size: ${sizeMB.toFixed(2)} MB`);

  // Read circuit
  const circuitData = JSON.parse(fs.readFileSync(circuitPath, 'utf-8'));
  const circuit = circuitData as unknown as CompiledCircuit;

  // Paths for trusted setup (bn254 curve parameters)
  const trustedSetupPath = path.join(__dirname, '../../../data/circuit/');

  // Create output directories
  const vkDir = path.join(outputDir, 'verification-keys', circuitName);
  const contractsDir = path.join(outputDir, 'verifier-contracts');

  if (!fs.existsSync(vkDir)) {
    fs.mkdirSync(vkDir, { recursive: true });
  }
  if (!fs.existsSync(contractsDir)) {
    fs.mkdirSync(contractsDir, { recursive: true });
  }

  // Initialize backend with trusted setup
  console.log('   ⚙️  Initializing backend with trusted setup...');
  const backendOptions: BackendOptions = { crsPath: trustedSetupPath };
  const backend = new UltraPlonkBackend(circuit.bytecode, backendOptions);

  // Generate verification key
  console.log('   🔑 Generating verification key...');
  const vk = await backend.getVerificationKey();

  // Save VK
  const vkPath = path.join(vkDir, 'vk');
  fs.writeFileSync(vkPath, vk);
  console.log(`   ✓ VK saved: ${vkPath}`);

  // Save VK in JSON format for easier inspection
  const vkJsonPath = path.join(vkDir, 'verification_key.json');
  fs.writeFileSync(
    vkJsonPath,
    JSON.stringify(
      {
        circuit: circuitName,
        vk: Buffer.from(vk).toString('hex'),
        size: vk.length,
      },
      null,
      2,
    ),
  );

  // Cleanup backend
  await backend.destroy();

  // Generate Solidity verifier contract using bb CLI
  console.log('   📄 Generating Solidity verifier contract...');
  const contractInVkDir = path.join(vkDir, `${circuitName}Verifier.sol`);
  const contractInContractsDir = path.join(contractsDir, `${circuitName}Verifier.sol`);

  // Execute bb contract command
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

  console.log(`   ✅ Successfully processed ${circuitName}`);
}

/**
 * Main execution
 */
async function main() {
  if (process.argv.length < 4) {
    console.error('Usage: node generate-single-verifier.js <circuit-path> <output-dir>');
    process.exit(1);
  }

  const circuitPath = process.argv[2];
  const outputDir = process.argv[3];

  if (!fs.existsSync(circuitPath)) {
    console.error(`❌ Circuit not found: ${circuitPath}`);
    process.exit(1);
  }

  try {
    await generateSingleVerifier(circuitPath, outputDir);
    process.exit(0);
  } catch (error: any) {
    console.error(`\n❌ Error:`, error.message || error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

export { generateSingleVerifier };
