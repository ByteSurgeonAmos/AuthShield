export function generateOtp(
  length: number = 6,
  options?: {
    digitsOnly?: boolean;
    includeSpecialChars?: boolean;
  },
): string {
  let characters = '0123456789';
  if (!options?.digitsOnly) {
    characters += 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  }

  if (options?.includeSpecialChars) {
    characters += '!@#$%^&*()_+[]{}<>?';
  }

  let otp = '';
  const charactersLength = characters.length;

  for (let i = 0; i < length; i++) {
    otp += characters.charAt(Math.floor(Math.random() * charactersLength));
  }

  return otp;
}
