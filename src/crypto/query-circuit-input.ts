import * as path from 'path';
import { ethers } from 'ethers';

// Re-export file loaders from utils
export {
  PassportData,
  RegistrationProofOutputs,
  loadRegistrationProofOutputs,
  loadPkPassportHash,
  loadPkIdentityHash,
  loadLatestPassportData,
  extractModulusFromDG15,
} from '../utils/file-loaders';

/**
 * Query Identity Circuit Input
 * All fields match exactly what the circuit expects
 */
export interface QueryCircuitInput extends Record<string, any> {
  // Private inputs
  dg1: string[]; // 744 bits in binary representation
  skIdentity: string;
  pkPassportHash: string;

  // Identity hash (replaces SMT proof)
  pkIdentityHash: string;

  // Event context
  eventID: string;
  eventData: string;

  // Selector for what to prove
  selector: string;

  // Public inputs
  timestamp: string;
  currentDate: string; // Format: 0x3Y3Y3M3M3D3D (hex ASCII codes)
  identityCounter: string;

  // Bounds
  timestampLowerbound: string;
  timestampUpperbound: string;
  identityCounterLowerbound: string;
  identityCounterUpperbound: string;
  birthDateLowerbound: string;
  birthDateUpperbound: string;
  expirationDateLowerbound: string;
  expirationDateUpperbound: string;

  // Citizenship mask
  citizenshipMask: string;
}

/**
 * Helper parameters for building QueryCircuitInput
 */
export interface QueryInputBuilder {
  // Required: passport data from registration
  dg1Bytes: number[]; // 93 bytes from preparePassportInputs
  skIdentity: bigint;
  pkPassportHash: bigint; // From registration proof public outputs

  // Identity hash (required)
  pkIdentityHash: bigint; // Public key identity hash

  // Event context
  eventID: string;
  eventData: string;

  // Current state
  timestamp: string;
  currentDate: string; // Format: 0x3Y3Y3M3M3D3D
  identityCounter: string;

  // Query parameters
  selector: number;
  citizenshipMask: string;

  // Bounds (explicit)
  timestampLowerbound?: string;
  timestampUpperbound?: string;
  identityCounterLowerbound?: string;
  identityCounterUpperbound?: string;
  birthDateLowerbound?: string;
  birthDateUpperbound?: string;
  expirationDateLowerbound?: string;
  expirationDateUpperbound?: string;
}

/**
 * Convert byte array to bit array (MSB first for each byte)
 */
function bytesToBits(bytes: number[]): string[] {
  const bits: string[] = [];
  for (const byte of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push(((byte >> i) & 1).toString());
    }
  }
  return bits;
}

/**
 * Build circuit input from parameters
 *
 * This function creates the input object for the QueryIdentity circuit.
 * All parameters are explicit - no hidden logic or file reading.
 *
 * Default values:
 * - All bounds default to 0 or ZERO_DATE (0x303030303030)
 *
 * @param params - Builder parameters with all required circuit inputs
 * @returns Complete circuit input ready for proof generation
 */
export function buildQueryCircuitInput(params: QueryInputBuilder): QueryCircuitInput {
  const {
    dg1Bytes,
    skIdentity,
    pkPassportHash,
    pkIdentityHash,
    eventID,
    eventData,
    timestamp,
    currentDate,
    identityCounter,
    selector,
    citizenshipMask,
    timestampLowerbound = '0',
    timestampUpperbound = '0',
    identityCounterLowerbound = '0',
    identityCounterUpperbound = '0',
    birthDateLowerbound = '0x303030303030',
    birthDateUpperbound = '0x303030303030',
    expirationDateLowerbound = '0x303030303030',
    expirationDateUpperbound = '0x303030303030',
  } = params;

  // Convert dg1 bytes to bits
  const dg1Bits = bytesToBits(dg1Bytes);

  // Convert hex strings to decimal strings for circuit inputs
  // Circom expects all field elements as decimal strings, not hex
  const convertToDecimal = (value: string): string => {
    if (value.startsWith('0x')) {
      return BigInt(value).toString();
    }
    return value;
  };

  return {
    // IMPORTANT: Order must match the reference implementation exactly
    dg1: dg1Bits,
    eventID: convertToDecimal(eventID),
    eventData: convertToDecimal(eventData),
    pkIdentityHash: pkIdentityHash.toString(),
    pkPassportHash: pkPassportHash.toString(),
    selector: selector.toString(),
    skIdentity: skIdentity.toString(),
    timestamp,
    currentDate: currentDate, // Keep as hex string (passport date format)
    identityCounter,
    timestampLowerbound: convertToDecimal(timestampLowerbound),
    timestampUpperbound: convertToDecimal(timestampUpperbound),
    identityCounterLowerbound: convertToDecimal(identityCounterLowerbound),
    identityCounterUpperbound: convertToDecimal(identityCounterUpperbound),
    birthDateLowerbound: birthDateLowerbound, // Keep as hex string (passport date format)
    birthDateUpperbound: birthDateUpperbound, // Keep as hex string (passport date format)
    expirationDateLowerbound: expirationDateLowerbound, // Keep as hex string (passport date format)
    expirationDateUpperbound: expirationDateUpperbound, // Keep as hex string (passport date format)
    citizenshipMask,
  };
}

/**
 * Helper to encode date in passport format YYMMDD (as hex ASCII codes)
 *
 * Passport dates are encoded as 6 ASCII characters in hex:
 * - Each digit is converted to its ASCII code (0x30-0x39 for '0'-'9')
 * - Example: "251011" becomes "0x323531303131"
 *   - '2' = 0x32, '5' = 0x35, '1' = 0x31, '0' = 0x30, '1' = 0x31, '1' = 0x31
 *
 * @param date - JavaScript Date object
 * @returns Hex string in format 0xYYMMDD (12 hex chars = 6 ASCII bytes)
 */
export function encodePassportDate(date: Date): string {
  const year = date.getFullYear().toString().slice(2); // Last 2 digits
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const day = date.getDate().toString().padStart(2, '0');
  const dateStr = year + month + day; // YYMMDD

  // Convert each character to hex ASCII code
  const hex = dateStr
    .split('')
    .map((c) => c.charCodeAt(0).toString(16))
    .join('');

  return `0x${hex}`;
}

/**
 * Helper to encode passport date as BigInt (for contract calls)
 *
 * Same as encodePassportDate but returns BigInt instead of hex string.
 * This is useful for contract calls that expect uint256.
 *
 * @param date - JavaScript Date object
 * @returns BigInt representation of the encoded date
 */
export function encodePassportDateAsBigInt(date: Date): bigint {
  return BigInt(encodePassportDate(date));
}

/**
 * Get current date from blockchain block timestamp
 * Returns the date encoded in passport format as BigInt
 *
 * @param provider - Ethers provider
 * @returns Encoded date as BigInt
 */
export async function getCurrentDateFromBlockchain(provider: any): Promise<bigint> {
  const block = await provider.getBlock('latest');

  if (!block) {
    throw new Error('Failed to get latest block');
  }

  const date = new Date(block.timestamp * 1000);
  return encodePassportDateAsBigInt(date);
}

/**
 * Helper to decode passport date from hex format back to Date object
 *
 * Reverses the encoding process:
 * - Parse hex pairs as ASCII character codes
 * - Convert to YYMMDD string
 * - Parse as Date (assumes 21st century, 20XX)
 *
 * @param hexDate - Hex string in format 0xYYMMDD (e.g., "0x323531303131")
 * @returns JavaScript Date object
 */
export function decodePassportDate(hexDate: string): Date {
  const dateStr = hexDate.replace('0x', '');
  let yymmdd = '';

  for (let i = 0; i < dateStr.length; i += 2) {
    const charCode = parseInt(dateStr.substr(i, 2), 16);
    yymmdd += String.fromCharCode(charCode);
  }

  const year = 2000 + parseInt(yymmdd.substring(0, 2));
  const month = parseInt(yymmdd.substring(2, 4)) - 1; // JS months are 0-indexed
  const day = parseInt(yymmdd.substring(4, 6));

  return new Date(year, month, day);
}

/**
 * Country codes in order as they appear in the circuit
 * This must match the COUNTRY_ARR in citizenshipCheck.circom
 */
export const COUNTRY_ORDER = [
  'ABW',
  'AFG',
  'AGO',
  'AIA',
  'ALB',
  'AND',
  'ANT',
  'ARE',
  'ARG',
  'ARM',
  'ASM',
  'ATA',
  'ATG',
  'AUS',
  'AUT',
  'AZE',
  'BDI',
  'BEL',
  'BEN',
  'BFA',
  'BGD',
  'BGR',
  'BHR',
  'BHS',
  'BIH',
  'BLM',
  'BLR',
  'BLZ',
  'BMU',
  'BOL',
  'BRA',
  'BRB',
  'BRN',
  'BTN',
  'BWA',
  'CAF',
  'CAN',
  'CCK',
  'CHE',
  'CHL',
  'CHN',
  'CIV',
  'CMR',
  'COD',
  'COG',
  'COK',
  'COL',
  'COM',
  'CPV',
  'CRI',
  'CUB',
  'CUW',
  'CXR',
  'CYM',
  'CYP',
  'CZE',
  'DEU',
  'DJI',
  'DMA',
  'DNK',
  'DOM',
  'DZA',
  'ECU',
  'EGY',
  'ERI',
  'ESH',
  'ESP',
  'EST',
  'ETH',
  'FIN',
  'FJI',
  'FLK',
  'FRA',
  'FRO',
  'FSM',
  'GAB',
  'GBR',
  'GEO',
  'GGY',
  'GHA',
  'GIB',
  'GIN',
  'GMB',
  'GNB',
  'GNQ',
  'GRC',
  'GRD',
  'GRL',
  'GTM',
  'GUM',
  'GUY',
  'HKG',
  'HND',
  'HRV',
  'HTI',
  'HUN',
  'IDN',
  'IMN',
  'IND',
  'IOT',
  'IRL',
  'IRN',
  'IRQ',
  'ISL',
  'ISR',
  'ITA',
  'JAM',
  'JEY',
  'JOR',
  'JPN',
  'KAZ',
  'KEN',
  'KGZ',
  'KHM',
  'KIR',
  'KNA',
  'KOR',
  'KWT',
  'LAO',
  'LBN',
  'LBR',
  'LBY',
  'LCA',
  'LIE',
  'LKA',
  'LSO',
  'LTU',
  'LUX',
  'LVA',
  'MAC',
  'MAF',
  'MAR',
  'MCO',
  'MDA',
  'MDG',
  'MDV',
  'MEX',
  'MHL',
  'MKD',
  'MLI',
  'MLT',
  'MMR',
  'MNE',
  'MNG',
  'MNP',
  'MOZ',
  'MRT',
  'MSR',
  'MUS',
  'MWI',
  'MYS',
  'MYT',
  'NAM',
  'NCL',
  'NER',
  'NGA',
  'NIC',
  'NIU',
  'NLD',
  'NOR',
  'NPL',
  'NRU',
  'NZL',
  'OMN',
  'PAK',
  'PAN',
  'PCN',
  'PER',
  'PHL',
  'PLW',
  'PNG',
  'POL',
  'PRI',
  'PRK',
  'PRT',
  'PRY',
  'PSE',
  'PYF',
  'QAT',
  'REU',
  'ROU',
  'RUS',
  'RWA',
  'SAU',
  'SDN',
  'SEN',
  'SGP',
  'SHN',
  'SJM',
  'SLB',
  'SLE',
  'SLV',
  'SMR',
  'SOM',
  'SPM',
  'SRB',
  'SSD',
  'STP',
  'SUR',
  'SVK',
  'SVN',
  'SWE',
  'SWZ',
  'SXM',
  'SYC',
  'SYR',
  'TCA',
  'TCD',
  'TGO',
  'THA',
  'TJK',
  'TKL',
  'TKM',
  'TLS',
  'TON',
  'TTO',
  'TUN',
  'TUR',
  'TUV',
  'TWN',
  'TZA',
  'UGA',
  'UKR',
  'URY',
  'USA',
  'UZB',
  'VAT',
  'VCT',
  'VEN',
  'VGB',
  'VIR',
  'VNM',
  'VUT',
  'WLF',
  'WSM',
  'XKX',
  'YEM',
  'ZAF',
  'ZMB',
  'ZWE',
];

/**
 * Calculate citizenship mask for blocked countries
 * The mask is a 240-bit number where each bit corresponds to a country
 * Bit = 1 means that country is BLOCKED
 */
export function calculateCitizenshipMask(blockedCountries: string[]): bigint {
  let mask = 0n;

  for (const country of blockedCountries) {
    const index = COUNTRY_ORDER.indexOf(country.toUpperCase());
    if (index === -1) {
      throw new Error(`Unknown country code: ${country}`);
    }

    // Set the bit at position (240 - 1 - index)
    // because of bit reversal in the circuit
    const bitPosition = 240 - 1 - index;
    mask |= 1n << BigInt(bitPosition);
  }

  return mask;
}

/**
 * Build selector value for QueryIdentity circuit
 *
 * The selector is an 18-bit value that controls which fields are revealed/checked in the proof.
 * Each bit corresponds to a specific check or reveal operation.
 *
 * Selector bits:
 * 0 - nullifier: Reveal nullifier in public signals (prevents double-use)
 * 1 - birth date: Reveal birth date
 * 2 - expiration date: Reveal expiration date
 * 3 - name: Reveal name
 * 4 - nationality: Reveal nationality
 * 5 - citizenship: Reveal citizenship
 * 6 - sex: Reveal sex
 * 7 - document number: Reveal document number
 * 8 - timestamp lowerbound: Check timestamp >= lowerbound
 * 9 - timestamp upperbound: Check timestamp <= upperbound
 * 10 - identity counter lowerbound: Check identityCounter >= lowerbound
 * 11 - identity counter upperbound: Check identityCounter <= upperbound
 * 12 - passport expiration lowerbound: Check expirationDate >= lowerbound
 * 13 - passport expiration upperbound: Check expirationDate <= upperbound
 * 14 - birth date lowerbound: Check birthDate >= lowerbound
 * 15 - birth date upperbound: Check birthDate <= upperbound (age verification)
 * 16 - verify citizenship mask as whitelist: Only allow countries in mask
 * 17 - verify citizenship mask as blacklist: Block countries in mask
 *
 * @param options - Object with boolean flags for each selector bit
 * @returns Selector value as number (0-262143, 18 bits)
 */
export function buildSelector(options: {
  enableNullifier?: boolean;
  enableBirthDate?: boolean;
  enableExpirationDate?: boolean;
  enableName?: boolean;
  enableNationality?: boolean;
  enableCitizenship?: boolean;
  enableSex?: boolean;
  enableDocumentNumber?: boolean;
  enableTimestampLowerbound?: boolean;
  enableTimestampUpperbound?: boolean;
  enableIdentityCounterLowerbound?: boolean;
  enableIdentityCounterUpperbound?: boolean;
  enableExpirationDateLowerbound?: boolean;
  enableExpirationDateUpperbound?: boolean;
  enableBirthDateLowerbound?: boolean;
  enableBirthDateUpperbound?: boolean;
  verifyCitizenshipWhitelist?: boolean;
  verifyCitizenshipBlacklist?: boolean;
}): number {
  let selector = 0;

  if (options.enableNullifier) selector |= 1 << 0;
  if (options.enableBirthDate) selector |= 1 << 1;
  if (options.enableExpirationDate) selector |= 1 << 2;
  if (options.enableName) selector |= 1 << 3;
  if (options.enableNationality) selector |= 1 << 4;
  if (options.enableCitizenship) selector |= 1 << 5;
  if (options.enableSex) selector |= 1 << 6;
  if (options.enableDocumentNumber) selector |= 1 << 7;
  if (options.enableTimestampLowerbound) selector |= 1 << 8;
  if (options.enableTimestampUpperbound) selector |= 1 << 9;
  if (options.enableIdentityCounterLowerbound) selector |= 1 << 10;
  if (options.enableIdentityCounterUpperbound) selector |= 1 << 11;
  if (options.enableExpirationDateLowerbound) selector |= 1 << 12;
  if (options.enableExpirationDateUpperbound) selector |= 1 << 13;
  if (options.enableBirthDateLowerbound) selector |= 1 << 14;
  if (options.enableBirthDateUpperbound) selector |= 1 << 15;
  if (options.verifyCitizenshipWhitelist) selector |= 1 << 16;
  if (options.verifyCitizenshipBlacklist) selector |= 1 << 17;

  return selector;
}
