/**
 * Random passport data generator with famous Romans from Republic and Empire
 */

export interface PassportPersonalData {
  surname: string;
  givenNames: string;
  passportNumber: string;
  nationality: string;
  dateOfBirth: string;
  sex: string;
  expiryDate: string;
  personalNumber: string;
  issuingCountry: string;
}

// Famous Romans from Republic and Empire
const ROMAN_NAMES = [
  { surname: 'CAESAR', givenNames: 'GAIUS JULIUS' },
  { surname: 'CICERO', givenNames: 'MARCUS TULLIUS' },
  { surname: 'AUGUSTUS', givenNames: 'GAIUS OCTAVIUS' },
  { surname: 'ANTONIUS', givenNames: 'MARCUS' },
  { surname: 'SCIPIO', givenNames: 'PUBLIUS CORNELIUS' },
  { surname: 'BRUTUS', givenNames: 'MARCUS JUNIUS' },
  { surname: 'POMPEIUS', givenNames: 'GNAEUS MAGNUS' },
  { surname: 'CATO', givenNames: 'MARCUS PORCIUS' },
  { surname: 'SULLA', givenNames: 'LUCIUS CORNELIUS' },
  { surname: 'GRACCHUS', givenNames: 'TIBERIUS SEMPRONIUS' },
  { surname: 'MARIUS', givenNames: 'GAIUS' },
  { surname: 'HADRIAN', givenNames: 'PUBLIUS AELIUS' },
  { surname: 'TRAJAN', givenNames: 'MARCUS ULPIUS' },
  { surname: 'AURELIUS', givenNames: 'MARCUS' },
  { surname: 'NERO', givenNames: 'LUCIUS DOMITIUS' },
  { surname: 'TIBERIUS', givenNames: 'CLAUDIUS' },
  { surname: 'CALIGULA', givenNames: 'GAIUS JULIUS' },
  { surname: 'VESPASIAN', givenNames: 'TITUS FLAVIUS' },
  { surname: 'SENECA', givenNames: 'LUCIUS ANNAEUS' },
  { surname: 'PLINY', givenNames: 'GAIUS SECUNDUS' },
];

/**
 * Generates random passport personal data with a famous Roman name
 */
export function generateRandomPassportData(): PassportPersonalData {
  const randomName = ROMAN_NAMES[Math.floor(Math.random() * ROMAN_NAMES.length)];

  // Random passport number: 2 letters + 7 digits
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const passportNumber =
    letters[Math.floor(Math.random() * letters.length)] +
    letters[Math.floor(Math.random() * letters.length)] +
    Math.floor(Math.random() * 10000000)
      .toString()
      .padStart(7, '0');

  // Random date of birth (between 1950 and 2005)
  const year = 50 + Math.floor(Math.random() * 56); // 50-105 (1950-2005)
  const month = 1 + Math.floor(Math.random() * 12);
  const day = 1 + Math.floor(Math.random() * 28); // Safe range for all months
  const dateOfBirth =
    year.toString().padStart(2, '0') +
    month.toString().padStart(2, '0') +
    day.toString().padStart(2, '0');

  // Random sex
  const sex = Math.random() > 0.5 ? 'M' : 'F';

  // Random personal number
  const personalNumber =
    'P' +
    Math.floor(Math.random() * 100000000)
      .toString()
      .padStart(8, '0');

  const issuingCountry = "ITA";
  return {
    ...randomName,
    passportNumber,
    nationality: 'ITA', // Italy nationality code
    dateOfBirth,
    sex,
    expiryDate: '351231', // Expires at end of 2035
    personalNumber,
    issuingCountry
  };
}
