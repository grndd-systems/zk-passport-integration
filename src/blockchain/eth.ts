import { CONFIG } from '../config';
import { ethers } from 'ethers';
import fs from 'fs';

// Certificate data types
export const C_RSA_SHA2_2048 = ethers.keccak256(ethers.toUtf8Bytes('C_RSA_2048'));
export const C_RSAPSS_SHA2_2048 = ethers.keccak256(ethers.toUtf8Bytes('C_RSAPSS_SHA2_2048'));
// Passport data types
export const P_NO_AA = ethers.keccak256(ethers.toUtf8Bytes('P_NO_AA'));
export const P_RSA_SHA1_2688 = ethers.keccak256(ethers.toUtf8Bytes('P_RSA_SHA1_2688'));
export const P_RSA_SHA1_2688_3 = ethers.keccak256(ethers.toUtf8Bytes('P_RSA_SHA1_2688_3'));
export const P_ECDSA_SHA1_2704 = ethers.keccak256(ethers.toUtf8Bytes('P_ECDSA_SHA1_2704'));
export const P_RSA_SHA256_2688 = ethers.keccak256(ethers.toUtf8Bytes('P_RSA_SHA256_2688'));
export const P_RSA_SHA256_2688_3 = ethers.keccak256(ethers.toUtf8Bytes('P_RSA_SHA256_2688_3'));

// Verifier types (ZK proof types)
export const Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296 = ethers.keccak256(
  ethers.toUtf8Bytes('Z_NOIR_PASSPORT_11_256_3_5_576_248_1_1808_5_296'),
);
// Add your specific Noir circuit verifier here
// For the passport-zk-circuits-noir project, determine which verifier matches your circuit

export function getProviderAndWallet() {
  if (!CONFIG.RPC_URL) throw new Error('RPC_URL not set');
  if (!CONFIG.PRIVATE_KEY) throw new Error('PRIVATE_KEY not set');
  const provider = new ethers.JsonRpcProvider(CONFIG.RPC_URL);
  const wallet = new ethers.Wallet(CONFIG.PRIVATE_KEY, provider);
  return { provider, wallet };
}

export function loadAbi(path: string) {
  if (!path || !fs.existsSync(path)) {
    throw new Error('ABI path not found: ' + path);
  }
  return JSON.parse(fs.readFileSync(path).toString()).abi;
}

export function getStateKeeperContract(wallet: ethers.Wallet) {
  if (!CONFIG.STATEKEEPER_ABI_PATH) {
    throw new Error('STATEKEEPER_ABI_PATH not set');
  }
  const abi = loadAbi(CONFIG.STATEKEEPER_ABI_PATH);
  if (!CONFIG.STATEKEEPER_ADDRESS) {
    throw new Error('STATEKEEPER_ADDRESS not set');
  }
  return new ethers.Contract(CONFIG.STATEKEEPER_ADDRESS, abi, wallet);
}

export function getRegistration2Contract(wallet: ethers.Wallet) {
  if (!CONFIG.REGISTRATION2_ABI_PATH) {
    throw new Error('REGISTRATION2_ABI_PATH not set');
  }
  const abi = loadAbi(CONFIG.REGISTRATION2_ABI_PATH);
  if (!CONFIG.REGISTRATION2_ADDRESS) {
    throw new Error('REGISTRATION2_ADDRESS not set');
  }
  return new ethers.Contract(CONFIG.REGISTRATION2_ADDRESS, abi, wallet);
}
