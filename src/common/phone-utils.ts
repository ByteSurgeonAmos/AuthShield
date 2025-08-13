/**
 * Phone number utility functions with enhanced African country code support
 */

export interface PhoneNumberFormatResult {
  formatted: string;
  isValid: boolean;
  countryCode?: string;
  country?: string;
}

// African country codes mapping
const AFRICAN_COUNTRY_CODES = {
  '213': 'Algeria',
  '244': 'Angola',
  '229': 'Benin',
  '267': 'Botswana',
  '226': 'Burkina Faso',
  '257': 'Burundi',
  '237': 'Cameroon',
  '238': 'Cape Verde',
  '236': 'Central African Republic',
  '235': 'Chad',
  '269': 'Comoros',
  '242': 'Republic of the Congo',
  '243': 'Democratic Republic of the Congo',
  '225': "Côte d'Ivoire",
  '253': 'Djibouti',
  '20': 'Egypt',
  '240': 'Equatorial Guinea',
  '291': 'Eritrea',
  '251': 'Ethiopia',
  '241': 'Gabon',
  '220': 'Gambia',
  '233': 'Ghana',
  '224': 'Guinea',
  '245': 'Guinea-Bissau',
  '254': 'Kenya',
  '266': 'Lesotho',
  '231': 'Liberia',
  '218': 'Libya',
  '261': 'Madagascar',
  '265': 'Malawi',
  '223': 'Mali',
  '222': 'Mauritania',
  '230': 'Mauritius',
  '212': 'Morocco',
  '258': 'Mozambique',
  '264': 'Namibia',
  '227': 'Niger',
  '234': 'Nigeria',
  '250': 'Rwanda',
  '239': 'São Tomé and Príncipe',
  '221': 'Senegal',
  '248': 'Seychelles',
  '232': 'Sierra Leone',
  '252': 'Somalia',
  '27': 'South Africa',
  '211': 'South Sudan',
  '249': 'Sudan',
  '268': 'Swaziland',
  '255': 'Tanzania',
  '228': 'Togo',
  '216': 'Tunisia',
  '256': 'Uganda',
  '260': 'Zambia',
  '263': 'Zimbabwe',
};

// All country codes (including African and other major ones)
const ALL_COUNTRY_CODES = {
  ...AFRICAN_COUNTRY_CODES,
  '1': 'United States/Canada',
  '44': 'United Kingdom',
  '91': 'India',
  '86': 'China',
  '81': 'Japan',
  '49': 'Germany',
  '33': 'France',
  '39': 'Italy',
  '34': 'Spain',
  '7': 'Russia',
  '52': 'Mexico',
  '55': 'Brazil',
  '61': 'Australia',
  '31': 'Netherlands',
  '46': 'Sweden',
  '47': 'Norway',
  '45': 'Denmark',
  '41': 'Switzerland',
  '43': 'Austria',
  '32': 'Belgium',
  '351': 'Portugal',
  '30': 'Greece',
  '48': 'Poland',
  '90': 'Turkey',
  '82': 'South Korea',
  '65': 'Singapore',
  '60': 'Malaysia',
  '62': 'Indonesia',
  '66': 'Thailand',
  '84': 'Vietnam',
  '63': 'Philippines',
};

/**
 * Format a phone number using the provided country code or user's country code as fallback
 * Enhanced for African countries support
 * @param phoneNumber - The phone number to format
 * @param providedCountryCode - The country code provided in the request
 * @param userCountryCode - The user's saved country code from database
 * @param defaultCountryCode - The system default country code (default: '254')
 * @returns Formatted phone number result
 */
export function formatPhoneNumber(
  phoneNumber: string,
  providedCountryCode?: string,
  userCountryCode?: string,
  defaultCountryCode: string = '254',
): PhoneNumberFormatResult {
  if (!phoneNumber || typeof phoneNumber !== 'string') {
    return {
      formatted: '',
      isValid: false,
    };
  }

  // Clean the phone number (remove non-digits except +)
  let cleaned = phoneNumber.replace(/[^\d+]/g, '');

  // If it already starts with +, validate and return
  if (cleaned.startsWith('+')) {
    const extractedCode = extractCountryCode(cleaned);
    if (cleaned.length >= 10 && extractedCode) {
      return {
        formatted: cleaned,
        isValid: true,
        countryCode: extractedCode,
        country: ALL_COUNTRY_CODES[extractedCode] || 'Unknown',
      };
    }
    return {
      formatted: phoneNumber,
      isValid: false,
    };
  }

  // Remove leading zeros
  cleaned = cleaned.replace(/^0+/, '');

  // Check minimum length (African numbers are typically 9-10 digits after country code)
  if (cleaned.length < 8) {
    return {
      formatted: phoneNumber,
      isValid: false,
    };
  }

  // Determine which country code to use (priority order)
  const countryCodeToUse =
    providedCountryCode || userCountryCode || defaultCountryCode;

  // If the number already starts with the country code, don't add it again
  if (cleaned.startsWith(countryCodeToUse)) {
    const formatted = `+${cleaned}`;
    return {
      formatted,
      isValid: true,
      countryCode: countryCodeToUse,
      country: ALL_COUNTRY_CODES[countryCodeToUse] || 'Unknown',
    };
  }

  // Add the country code
  const formatted = `+${countryCodeToUse}${cleaned}`;

  return {
    formatted,
    isValid: formatted.length >= 12 && formatted.length <= 17, // International standard
    countryCode: countryCodeToUse,
    country: ALL_COUNTRY_CODES[countryCodeToUse] || 'Unknown',
  };
}

/**
 * Extract country code from a formatted phone number
 * Enhanced to support African and international country codes
 * @param phoneNumber - The formatted phone number (with + prefix)
 * @returns The country code or null if not found
 */
export function extractCountryCode(phoneNumber: string): string | null {
  if (!phoneNumber || !phoneNumber.startsWith('+')) {
    return null;
  }

  // Remove the + and get digits
  const digits = phoneNumber.substring(1);

  // Sort country codes by length (longest first) to match correctly
  const sortedCodes = Object.keys(ALL_COUNTRY_CODES).sort(
    (a, b) => b.length - a.length,
  );

  for (const code of sortedCodes) {
    if (digits.startsWith(code)) {
      return code;
    }
  }

  // Fallback: assume first 1-3 digits are country code
  if (digits.length >= 3) {
    return digits.substring(0, 3);
  } else if (digits.length >= 2) {
    return digits.substring(0, 2);
  } else if (digits.length >= 1) {
    return digits.substring(0, 1);
  }

  return null;
}

/**
 * Validate if a phone number is properly formatted
 * Enhanced validation for international numbers including African countries
 * @param phoneNumber - The phone number to validate
 * @returns Whether the phone number is valid
 */
export function isValidPhoneNumber(phoneNumber: string): boolean {
  if (!phoneNumber || typeof phoneNumber !== 'string') {
    return false;
  }

  // Should start with + and have proper length for international numbers
  const phoneRegex = /^\+[1-9]\d{8,15}$/;
  const isFormatValid = phoneRegex.test(phoneNumber);

  if (!isFormatValid) {
    return false;
  }

  // Additional validation: check if country code exists
  const countryCode = extractCountryCode(phoneNumber);
  return countryCode !== null && ALL_COUNTRY_CODES[countryCode] !== undefined;
}

/**
 * Get country information from phone number
 * @param phoneNumber - The phone number to analyze
 * @returns Country information or null
 */
export function getCountryFromPhoneNumber(
  phoneNumber: string,
): { code: string; name: string } | null {
  const countryCode = extractCountryCode(phoneNumber);
  if (countryCode && ALL_COUNTRY_CODES[countryCode]) {
    return {
      code: countryCode,
      name: ALL_COUNTRY_CODES[countryCode],
    };
  }
  return null;
}

/**
 * Check if a phone number belongs to an African country
 * @param phoneNumber - The phone number to check
 * @returns Whether the number is from an African country
 */
export function isAfricanPhoneNumber(phoneNumber: string): boolean {
  const countryCode = extractCountryCode(phoneNumber);
  return (
    countryCode !== null && AFRICAN_COUNTRY_CODES[countryCode] !== undefined
  );
}
