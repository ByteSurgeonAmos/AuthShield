export function validateUsername(username: string): {
  isValid: boolean;
  error?: string;
} {
  if (!username) {
    return { isValid: false, error: 'Username is required' };
  }

  const minLength = 3;
  const maxLength = 30;

  if (username.length < minLength) {
    return {
      isValid: false,
      error: `Username must be at least ${minLength} characters long`,
    };
  }

  if (username.length > maxLength) {
    return {
      isValid: false,
      error: `Username must be no more than ${maxLength} characters long`,
    };
  }

  const usernameRegex = /^[a-zA-Z0-9_-]+$/;
  if (!usernameRegex.test(username)) {
    return {
      isValid: false,
      error:
        'Username can only contain letters, numbers, underscores, and hyphens',
    };
  }

  if (!/^[a-zA-Z0-9]/.test(username)) {
    return {
      isValid: false,
      error: 'Username must start with a letter or number',
    };
  }

  if (/[_-]$/.test(username)) {
    return {
      isValid: false,
      error: 'Username cannot end with underscore or hyphen',
    };
  }

  if (/[_-]{2,}/.test(username)) {
    return {
      isValid: false,
      error: 'Username cannot contain consecutive underscores or hyphens',
    };
  }

  const reservedWords = [
    'admin',
    'administrator',
    'root',
    'system',
    'api',
    'bot',
    'support',
    'help',
    'moderator',
    'staff',
    'official',
    'bitcoin',
    'crypto',
    'wallet',
    'trade',
    'trading',
    'exchange',
    'binance',
    'coinbase',
    'ethereum',
    'blockchain',
    'null',
    'undefined',
    'true',
    'false',
    'test',
    'demo',
    'xmobit',
  ];

  if (reservedWords.includes(username.toLowerCase())) {
    return { isValid: false, error: 'Username cannot be a reserved word' };
  }

  return { isValid: true };
}

export function isCryptoThemed(username: string): boolean {
  const cryptoKeywords = [
    'trader',
    'crypto',
    'bitcoin',
    'btc',
    'eth',
    'bull',
    'bear',
    'moon',
    'diamond',
    'gold',
    'silver',
    'whale',
    'shark',
    'wolf',
    'alpha',
    'beta',
    'hodl',
    'defi',
    'nft',
    'dao',
  ];

  const lowerUsername = username.toLowerCase();
  return cryptoKeywords.some((keyword) => lowerUsername.includes(keyword));
}

export function sanitizeUsername(username: string): string {
  if (!username) return '';

  let sanitized = username.replace(/[^a-zA-Z0-9_-]/g, '');

  sanitized = sanitized.replace(/^[_-]+/, '');

  sanitized = sanitized.replace(/[_-]+$/, '');

  sanitized = sanitized.replace(/[_-]{2,}/g, '_');

  if (sanitized.length > 30) {
    sanitized = sanitized.substring(0, 30);
  }

  return sanitized;
}
