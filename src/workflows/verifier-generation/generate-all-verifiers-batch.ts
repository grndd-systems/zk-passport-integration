import { execSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

interface CircuitResult {
  name: string;
  success: boolean;
  skipped?: boolean;
  error?: string;
  sizeMB: number;
  processingTime?: number;
  method?: 'bb.js' | 'bb-cli';
}

/**
 * Process a single circuit in a separate Node process
 * First tries bb.js, if it fails with "unreachable" tries bb CLI
 */
function processSingleCircuit(
  circuitPath: string,
  outputDir: string,
  circuitName: string,
): Promise<{ success: boolean; method?: 'bb.js' | 'bb-cli' }> {
  return new Promise((resolve) => {
    const bbJsScript = path.join(__dirname, 'generate-single-verifier.js');

    console.log(`\n🚀 Starting separate process for ${circuitName} (trying bb.js)...`);

    const startTime = Date.now();

    // Try with bb.js first
    const child = spawn(
      'node',
      ['--expose-gc', '--max-old-space-size=8192', bbJsScript, circuitPath, outputDir],
      {
        stdio: 'inherit',
        env: { ...process.env },
      },
    );

    child.on('exit', (code) => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      if (code === 0) {
        console.log(`   ✅ Process completed successfully with bb.js in ${elapsed}s`);
        resolve({ success: true, method: 'bb.js' });
      } else {
        console.error(`   ❌ bb.js failed with code ${code} after ${elapsed}s`);
        console.log(`   🔄 Retrying with bb CLI...`);

        // Retry with bb CLI
        const cliScript = path.join(__dirname, 'generate-verifier-cli.js');
        const cliStartTime = Date.now();

        const cliChild = spawn('node', [cliScript, circuitPath, outputDir], {
          stdio: 'inherit',
          env: { ...process.env },
        });

        cliChild.on('exit', (cliCode) => {
          const cliElapsed = ((Date.now() - cliStartTime) / 1000).toFixed(1);
          if (cliCode === 0) {
            console.log(`   ✅ Process completed successfully with bb CLI in ${cliElapsed}s`);
            resolve({ success: true, method: 'bb-cli' });
          } else {
            console.error(`   ❌ bb CLI also failed with code ${cliCode} after ${cliElapsed}s`);
            resolve({ success: false });
          }
        });

        cliChild.on('error', (error) => {
          console.error(`   ❌ bb CLI process error:`, error);
          resolve({ success: false });
        });
      }
    });

    child.on('error', (error) => {
      console.error(`   ❌ bb.js process error:`, error);
      resolve({ success: false });
    });
  });
}

/**
 * Generate verifiers for all circuits in directory
 * Processes each circuit in a separate process to avoid memory issues
 */
async function generateAllVerifiers(circuitDir: string, outputDir: string) {
  console.log('🚀 Starting batch verification key and contract generation\n');
  console.log(`📁 Circuit directory: ${circuitDir}`);
  console.log(`📁 Output directory: ${outputDir}`);
  console.log(`⚙️  Mode: Separate process per circuit (prevents OOM)\n`);

  // Create output directories
  const vkDir = path.join(outputDir, 'verification-keys');
  const contractsDir = path.join(outputDir, 'verifier-contracts');

  if (!fs.existsSync(vkDir)) {
    fs.mkdirSync(vkDir, { recursive: true });
  }
  if (!fs.existsSync(contractsDir)) {
    fs.mkdirSync(contractsDir, { recursive: true });
  }

  // Find all circuit JSON files
  const files = fs.readdirSync(circuitDir);
  const circuitFiles = files
    .filter((f) => f.endsWith('.json') && !f.includes('verification_key'))
    .sort();

  console.log(`📋 Found ${circuitFiles.length} circuit(s) to process\n`);
  console.log('='.repeat(80));

  const results: CircuitResult[] = [];
  let successCount = 0;
  let failCount = 0;
  let skippedCount = 0;

  const startTime = Date.now();

  // Process each circuit
  for (let i = 0; i < circuitFiles.length; i++) {
    const file = circuitFiles[i];
    const circuitPath = path.join(circuitDir, file);
    const circuitName = path.basename(file, '.json');

    // Get file size
    const stats = fs.statSync(circuitPath);
    const sizeMB = stats.size / (1024 * 1024);

    // Check if already processed
    const vkPath = path.join(vkDir, circuitName, 'vk');
    const contractPath = path.join(contractsDir, `${circuitName}Verifier.sol`);

    console.log(`\n${'='.repeat(80)}`);
    console.log(`[${i + 1}/${circuitFiles.length}] ${circuitName} (${sizeMB.toFixed(2)} MB)`);
    console.log('='.repeat(80));

    if (fs.existsSync(vkPath) && fs.existsSync(contractPath)) {
      console.log(`⏭️  Already processed, skipping...`);
      results.push({
        name: circuitName,
        success: true,
        skipped: true,
        sizeMB,
      });
      successCount++;
      skippedCount++;
      continue;
    }

    const circuitStartTime = Date.now();

    // Process in separate process
    const result = await processSingleCircuit(circuitPath, outputDir, circuitName);

    const processingTime = (Date.now() - circuitStartTime) / 1000;

    if (result.success) {
      successCount++;
    } else {
      failCount++;
    }

    results.push({
      name: circuitName,
      success: result.success,
      sizeMB,
      processingTime,
      method: result.method,
    });

    // Show progress
    const elapsed = ((Date.now() - startTime) / 1000 / 60).toFixed(1);
    console.log(
      `\n📊 Progress: ${i + 1}/${circuitFiles.length} | ✅ ${successCount} | ❌ ${failCount} | ⏭️  ${skippedCount} | Time: ${elapsed}m`,
    );
  }

  // Generate summary
  const totalTime = ((Date.now() - startTime) / 1000 / 60).toFixed(1);

  console.log('\n' + '='.repeat(80));
  console.log('📊 Final Summary\n');

  const alreadyDone = results.filter((r) => r.skipped);
  const processed = results.filter((r) => !r.skipped);
  const successful = processed.filter((r) => r.success);
  const failed = processed.filter((r) => !r.success);

  console.log(`Total circuits: ${results.length}`);
  console.log(`✅ Successfully generated: ${successful.length}`);
  console.log(`✓  Already existed: ${alreadyDone.length}`);
  console.log(`❌ Failed: ${failed.length}`);
  console.log(`\n⏱️  Total time: ${totalTime} minutes`);

  if (failed.length > 0) {
    console.log('\n❌ Failed circuits:');
    failed.forEach((f) =>
      console.log(`  - ${f.name} (${f.sizeMB.toFixed(2)}MB, ${f.processingTime?.toFixed(1)}s)`),
    );
  }

  // Save detailed summary
  const summaryPath = path.join(outputDir, 'generation-summary.json');
  fs.writeFileSync(
    summaryPath,
    JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        totalTime: `${totalTime}m`,
        total: results.length,
        successful: successCount,
        failed: failCount,
        skipped: skippedCount,
        circuits: results.map((r) => ({
          name: r.name,
          success: r.success,
          skipped: r.skipped || false,
          sizeMB: r.sizeMB,
          processingTime: r.processingTime ? `${r.processingTime.toFixed(1)}s` : undefined,
          method: r.method,
        })),
      },
      null,
      2,
    ),
  );

  console.log(`\n📄 Detailed summary saved to: ${summaryPath}`);
  console.log('='.repeat(80));

  return results;
}

/**
 * Main execution
 */
async function main() {
  const args = process.argv.slice(2);

  let circuitDir = path.join(__dirname, '../../../compiled_circuits');
  let outputDir = path.join(__dirname, '../../../generated_verifiers');

  // Parse command line arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--circuit-dir' && args[i + 1]) {
      circuitDir = path.resolve(args[i + 1]);
      i++;
    } else if (args[i] === '--output-dir' && args[i + 1]) {
      outputDir = path.resolve(args[i + 1]);
      i++;
    } else if (args[i] === '--help') {
      console.log(`
Usage: node generate-all-verifiers-batch.js [options]

Options:
  --circuit-dir <path>   Directory containing circuit JSON files (default: compiled_circuits)
  --output-dir <path>    Base output directory (default: generated_verifiers)
  --help                 Show this help message

Features:
  - Processes each circuit in a separate Node process
  - Prevents memory accumulation and OOM errors
  - Automatically skips already processed circuits
  - Works with circuits of any size
  - Shows detailed progress and timing

Example:
  npm run build
  npm run generate-all-verifiers
      `);
      process.exit(0);
    }
  }

  // Verify circuit directory exists
  if (!fs.existsSync(circuitDir)) {
    console.error(`❌ Circuit directory not found: ${circuitDir}`);
    process.exit(1);
  }

  // Run generation
  try {
    const results = await generateAllVerifiers(circuitDir, outputDir);
    const failed = results.filter((r) => !r.success && !r.skipped);

    if (failed.length === 0) {
      console.log('\n✅ All circuits processed successfully!\n');
      process.exit(0);
    } else {
      console.log(`\n⚠️  Completed with ${failed.length} failure(s)\n`);
      process.exit(1);
    }
  } catch (error: any) {
    console.error('\n❌ Fatal error:', error.message || error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

export { generateAllVerifiers, processSingleCircuit };
