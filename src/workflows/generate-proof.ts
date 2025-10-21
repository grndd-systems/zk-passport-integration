import { UltraPlonkBackend, BackendOptions } from '@aztec/bb.js';
import { Noir, CompiledCircuit } from '@noir-lang/noir_js';
import * as fs from 'fs';
import * as path from 'path';
import { preparePassportInputs, poseidon } from 'passport-zk-circuits-noir-js';
import { extractCertificateFromSOD } from '../utils/sod';
import { computeCertificateKey } from '../crypto/certificate-key';
import { getProofFromContract } from '../blockchain/contracts';
import { getCertificatesRoot } from '../blockchain/tx.js';
import circuitData from '../../data/circuit/registerIdentity_11_256_3_5_576_248_1_1808_5_296.json';
const circuit = circuitData as unknown as CompiledCircuit;

interface CircuitInputs {
  dg1: number[];
  dg15: number[];
  ec: number[];
  icao_root: string;
  inclusion_branches: string[];
  pk: string[];
  reduction_pk: string[];
  sa: number[];
  sig: string[];
  sk_identity: string;
}

async function generateProof(passportPath: string) {
  console.log('Starting proof generation...');

  // Paths (need to go up three levels from dist/src/workflows to project root)
  const trustedSetupPath = path.join(__dirname, '../../data/circuit/');

  // Load passport and extract certificate
  console.log('Loading passport from:', passportPath);
  const passportData = JSON.parse(fs.readFileSync(passportPath, 'utf-8'));
  const sodBuffer = Buffer.from(passportData.sod, 'base64');

  // Prepare passport inputs using preparePassportInputs function
  console.log('Preparing passport inputs...');
  const { inputs, compile_params, circuit_name } = preparePassportInputs(passportData);
  console.log('Circuit name:', circuit_name);

  console.log('Extracting certificate from passport SOD...');
  const certificate = extractCertificateFromSOD(sodBuffer);

  console.log('Computing certificate key from extracted certificate (using Poseidon hash)...');
  const certificateKey = await computeCertificateKey(certificate);
  const pk_hash = BigInt(certificateKey);

  // Get ICAO root from certificates SMT contract (this is the correct Poseidon root)
  console.log('Getting ICAO root from certificates SMT...');
  const icao_root = await getCertificatesRoot();
  console.log('ICAO root from contract:', icao_root);

  // Get Poseidon SMT siblings from contract for this certificate
  console.log('Getting Poseidon SMT proof from contract...');
  const contractProof = await getProofFromContract(certificateKey);

  // Use Poseidon SMT siblings directly (they are already in the correct format)
  const inclusionBranches = contractProof.siblings.map((sibling: string) =>
    BigInt(sibling).toString(),
  );

  console.log('Using', inclusionBranches.length, 'Poseidon SMT siblings from contract');

  const noirInputs = {
    dg1: inputs.dg1,
    dg15: inputs.dg15,
    ec: inputs.ec,
    sa: inputs.sa,
    pk: inputs.pk.map((v) => v.toString()),
    reduction_pk: inputs.reduction.map((v) => v.toString()),
    sig: inputs.sig.map((v) => v.toString()),
    sk_identity: inputs.sk_identity.toString(),
    icao_root: icao_root.toString(),
    inclusion_branches: inclusionBranches, // Fake 80 zeros
  };

  console.log('Initializing Noir...');
  const noir = new Noir(circuit);

  console.log('Generating witness...');
  const { witness } = await noir.execute(noirInputs as any);

  console.log('Initializing UltraPlonk backend...');
  const backendOptions: BackendOptions = { crsPath: trustedSetupPath };
  const backend = new UltraPlonkBackend(circuit.bytecode, backendOptions);

  console.log('Generating proof...');
  const vk = await backend.getVerificationKey();
  const proof = await backend.generateProof(witness);

  console.log('Proof generated successfully!');
  console.log('Proof length:', proof.proof.length, 'bytes');

  // Save to data/proof/ directory (used by register-passport)
  const proofDir = path.join(__dirname, '../../data/proof');
  if (!fs.existsSync(proofDir)) {
    fs.mkdirSync(proofDir, { recursive: true });
  }

  const vkPath = path.join(proofDir, 'vk');
  fs.writeFileSync(vkPath, vk);

  const proofPath = path.join(proofDir, 'proof');
  fs.writeFileSync(proofPath, proof.proof);
  console.log('Proof saved to:', proofPath);

  const publicInputsPath = path.join(proofDir, 'public-inputs');
  fs.writeFileSync(publicInputsPath, proof.publicInputs.join('\n'));
  console.log('Public inputs from Proof saved to:', publicInputsPath);

  console.log('Verifying proof...');
  const isValid = await backend.verifyProof(proof);
  console.log('Proof is valid:', isValid);

  // Destroy backend to clean up workers
  await backend.destroy();

  return proof;
}

if (require.main === module) {
  const passportDir = path.join(process.cwd(), 'data', 'out_passport');
  const passportFiles = fs.readdirSync(passportDir);
  const latestFile = passportFiles.sort().reverse()[0];
  const passportPath = path.join(passportDir, latestFile);

  if (!passportPath) {
    console.error('Error: Missing required argument');
    console.error('');
    console.error('Usage:');
    console.error('  node generate-proof.js --passport <path-to-passport.json>');
    console.error('');
    console.error('Description:');
    console.error('  Generates a ZK proof for passport identity registration.');
    console.error('  - Extracts the document signing certificate from passport SOD');
    console.error('  - Fetches the merkle proof from PoseidonSMT contract');
    console.error('  - Generates and verifies the ZK proof using UltraPlonk');
    console.error('');
    console.error('Example:');
    console.error('  node generate-proof.js --passport data/out_passport/passport_2025-10-16.json');
    process.exit(1);
  }

  generateProof(passportPath)
    .then(() => {
      console.log('\n✅ Proof generation completed successfully!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Error generating proof:', error.message || error);
      process.exit(1);
    });
}

export { generateProof };
