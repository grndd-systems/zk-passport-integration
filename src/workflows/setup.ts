import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { changeICAOMasterTreeRoot } from '../blockchain/tx';

// For CommonJS, use __dirname directly; for ESM, use import.meta.url
const currentDir: string =
  typeof __dirname !== 'undefined'
    ? __dirname
    : path.dirname(fileURLToPath(require.main?.filename || process.argv[1]));

export async function setupICAORoot(folderName: string = 'rsapss') {
  console.log(`Running ICAO root setup for folder: ${folderName}`);

  // Paths using the provided folder name
  const binaryPath = path.join(currentDir, '../../icao-root');
  const dataDir = path.join(currentDir, `../../data/${folderName}`);
  const masterlist = path.join(dataDir, 'masterlist.pem');
  const cert = path.join(dataDir, 'csca_cert.pem'); // CSCA certificate
  const merkle_output = path.join(dataDir, 'merkle_output.txt');

  // Execute the binary to generate merkle tree
  execSync(`${binaryPath} ${masterlist} ${cert} ${merkle_output}`, {
    stdio: 'inherit',
  });

  // Read the merkle output
  const raw = await fs.readFile(merkle_output, 'utf-8');
  const data = JSON.parse(raw);

  console.log('Merkle proofs:', data.proofs);
  console.log('ICAO Master Tree root:', data.root);

  // Update the ICAO root on the blockchain
  await changeICAOMasterTreeRoot(data.root);

  console.log('Setup completed successfully!');

  return {
    root: data.root,
    proofs: data.proofs,
  };
}
