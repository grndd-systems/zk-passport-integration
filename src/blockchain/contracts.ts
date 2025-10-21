/**
 * Smart contract interaction utilities
 */

import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';
import { CONFIG } from '../config';

export interface ContractProof {
  root: string;
  siblings: string[];
  existence: boolean;
  key: string;
  value: string;
  auxExistence: boolean;
  auxKey: string;
  auxValue: string;
}

/**
 * Get merkle proof from PoseidonSMT contract for a certificate key
 */
export async function getProofFromContract(
  certificateKey: string,
): Promise<{ root: string; siblings: string[] }> {
  if (!CONFIG.RPC_URL) {
    throw new Error('RPC_URL not configured in .env');
  }
  if (!CONFIG.CERTIFICATES_SMT_ADDRESS) {
    throw new Error('CERTIFICATES_SMT_ADDRESS not configured in .env');
  }

  console.log('Connecting to RPC:', CONFIG.RPC_URL);
  const provider = new ethers.JsonRpcProvider(CONFIG.RPC_URL);

  // Load PoseidonSMT ABI (need to go up two levels from dist/src to project root)
  const abiPath = path.join(__dirname, '../../data/abi/PoseidonSMT.json');
  const contractJson = JSON.parse(fs.readFileSync(abiPath, 'utf-8'));

  const contract = new ethers.Contract(CONFIG.CERTIFICATES_SMT_ADDRESS, contractJson.abi, provider);

  console.log('Fetching proof for certificate key:', certificateKey);

  const proof: ContractProof = await contract.getProof(certificateKey);

  console.log('Proof fetched from contract:');
  console.log('  Root:', proof.root);
  console.log('  Siblings count:', proof.siblings.length);
  console.log('  Existence:', proof.existence);

  // Check if the certificate exists in the merkle tree
  if (!proof.existence) {
    throw new Error(
      `Certificate not found in PoseidonSMT!\n` +
        `Certificate key: ${certificateKey}\n` +
        `This certificate has not been registered in the contract yet.`,
    );
  }

  return {
    root: proof.root,
    siblings: proof.siblings,
  };
}
