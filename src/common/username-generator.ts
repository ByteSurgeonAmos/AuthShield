/**
 * Generates a random username for crypto trading platform
 * Format: [prefix][numbers][suffix]
 */
export function generateRandomUsername(): string {
  const cryptoPrefixes = [
    'Trader',
    'Crypto',
    'Bitcoin',
    'Bull',
    'Bear',
    'Moon',
    'Diamond',
    'Gold',
    'Silver',
    'Whale',
    'Shark',
    'Wolf',
    'Eagle',
    'Tiger',
    'Alpha',
    'Beta',
    'Gamma',
    'Delta',
    'Sigma',
    'Quantum',
    'Neural',
    'Pixel',
    'Cyber',
    'Digital',
    'Nexus',
    'Matrix',
    'Phoenix',
    'Titan',
  ];

  const suffixes = [
    'X',
    'Pro',
    'Elite',
    'Master',
    'Legend',
    'King',
    'Queen',
    'Lord',
    'Boss',
    'Chief',
    'Prime',
    'Max',
    'Ultra',
    'Super',
    'Mega',
    'Hyper',
    'Zen',
    'Ace',
    'Star',
    'Hero',
    'Nova',
    'Zero',
    'One',
    'Dev',
    'Tech',
  ];

  const prefix =
    cryptoPrefixes[Math.floor(Math.random() * cryptoPrefixes.length)];
  const numbers = Math.floor(Math.random() * 9999)
    .toString()
    .padStart(4, '0');
  const suffix = suffixes[Math.floor(Math.random() * suffixes.length)];

  // Randomly choose format
  const formats = [
    `${prefix}${numbers}`,
    `${prefix}${numbers}${suffix}`,
    `${prefix}${suffix}${numbers}`,
    `${numbers}${prefix}`,
  ];

  const selectedFormat = formats[Math.floor(Math.random() * formats.length)];
  return selectedFormat;
}

/**
 * Generates a random profile image URL using a seed
 * Using RoboHash.org for unique, deterministic avatar generation
 */
export function generateRandomProfileImage(seed?: string): string {
  const uniqueSeed = seed || Date.now().toString() + Math.random().toString(36);

  // RoboHash categories for different avatar styles
  const categories = [
    'set=set1', // Robots
    'set=set2', // Monsters
    'set=set3', // Robot heads
    'set=set4', // Cats
    'set=set5', // Humans
  ];

  const selectedCategory =
    categories[Math.floor(Math.random() * categories.length)];

  // Add some variation with background colors
  const bgColors = ['bg1', 'bg2', 'bg3', 'bg4', 'bg5'];
  const selectedBg = bgColors[Math.floor(Math.random() * bgColors.length)];

  return `https://robohash.org/${encodeURIComponent(uniqueSeed)}.png?${selectedCategory}&${selectedBg}&size=200x200`;
}

/**
 * Checks if username is unique in the database
 */
export async function ensureUniqueUsername(
  userRepository: any,
  baseUsername?: string,
): Promise<string> {
  let username = baseUsername || generateRandomUsername();
  let counter = 0;

  while (counter < 10) {
    // Prevent infinite loops
    const existingUser = await userRepository.findOne({
      where: { username },
    });

    if (!existingUser) {
      return username;
    }

    // If username exists, generate a new one or append counter
    if (baseUsername) {
      username = `${baseUsername}${counter + 1}`;
    } else {
      username = generateRandomUsername();
    }
    counter++;
  }

  // Fallback: use timestamp if all attempts fail
  return `User${Date.now()}`;
}
