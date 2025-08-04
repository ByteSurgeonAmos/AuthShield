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

  const formats = [
    `${prefix}${numbers}`,
    `${prefix}${numbers}${suffix}`,
    `${prefix}${suffix}${numbers}`,
    `${numbers}${prefix}`,
  ];

  const selectedFormat = formats[Math.floor(Math.random() * formats.length)];
  return selectedFormat;
}

export function generateRandomProfileImage(seed?: string): string {
  const uniqueSeed = seed || Date.now().toString() + Math.random().toString(36);

  const categories = [
    'set=set1',
    'set=set2',
    'set=set3',
    'set=set4',
    'set=set5',
  ];

  const selectedCategory =
    categories[Math.floor(Math.random() * categories.length)];

  const bgColors = ['bg1', 'bg2', 'bg3', 'bg4', 'bg5'];
  const selectedBg = bgColors[Math.floor(Math.random() * bgColors.length)];

  return `https://robohash.org/${encodeURIComponent(uniqueSeed)}.png?${selectedCategory}&${selectedBg}&size=200x200`;
}

export async function ensureUniqueUsername(
  userRepository: any,
  baseUsername?: string,
): Promise<string> {
  let username = baseUsername || generateRandomUsername();
  let counter = 0;

  while (counter < 10) {
    const existingUser = await userRepository.findOne({
      where: { username },
    });

    if (!existingUser) {
      return username;
    }

    if (baseUsername) {
      username = `${baseUsername}${counter + 1}`;
    } else {
      username = generateRandomUsername();
    }
    counter++;
  }

  return `User${Date.now()}`;
}
