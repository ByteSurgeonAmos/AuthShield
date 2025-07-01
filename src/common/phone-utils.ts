/**
 * Phone number utility functions
 */

export interface PhoneNumberFormatResult {
  formatted: string;
  isValid: boolean;
  countryCode?: string;
}

/**
 * Format a phone number using the provided country code or user's country code as fallback
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
    if (cleaned.length >= 10) {
      return {
        formatted: cleaned,
        isValid: true,
        countryCode: cleaned.substring(
          1,
          cleaned.indexOf('0') > 0 ? cleaned.indexOf('0') : 4,
        ),
      };
    }
    return {
      formatted: phoneNumber,
      isValid: false,
    };
  }

  // Remove leading zeros
  cleaned = cleaned.replace(/^0+/, '');

  // Check minimum length
  if (cleaned.length < 7) {
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
    return {
      formatted: `+${cleaned}`,
      isValid: true,
      countryCode: countryCodeToUse,
    };
  }

  // Add the country code
  const formatted = `+${countryCodeToUse}${cleaned}`;

  return {
    formatted,
    isValid: true,
    countryCode: countryCodeToUse,
  };
}

/**
 * Extract country code from a formatted phone number
 * @param phoneNumber - The formatted phone number (with + prefix)
 * @returns The country code or null if not found
 */
export function extractCountryCode(phoneNumber: string): string | null {
  if (!phoneNumber || !phoneNumber.startsWith('+')) {
    return null;
  }

  // Remove the + and try to find where the country code ends
  const digits = phoneNumber.substring(1);

  // Most country codes are 1-3 digits
  // We'll try to identify common patterns
  const commonCountryCodes = [
    '1',
    '44',
    '91',
    '86',
    '81',
    '49',
    '33',
    '39',
    '34',
    '7',
    '52',
    '55',
    '254',
    '234',
    '27',
  ];

  for (const code of commonCountryCodes) {
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
 * @param phoneNumber - The phone number to validate
 * @returns Whether the phone number is valid
 */
export function isValidPhoneNumber(phoneNumber: string): boolean {
  if (!phoneNumber || typeof phoneNumber !== 'string') {
    return false;
  }

  // Should start with + and have at least 10 digits total
  const phoneRegex = /^\+[1-9]\d{8,14}$/;
  return phoneRegex.test(phoneNumber);
}
