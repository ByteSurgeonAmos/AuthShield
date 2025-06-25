import { createConnection } from 'pg';
import { config } from 'dotenv';
import * as fs from 'fs';
import * as path from 'path';

// Load environment variables
config();

async function resetDatabase() {
  const connectionString = process.env.DATABASE_URL;

  if (!connectionString) {
    console.error('❌ DATABASE_URL not found in environment variables');
    process.exit(1);
  }

  console.log('🔄 Connecting to database...');

  const client = createConnection({
    connectionString,
    ssl: process.env.SSL === 'true' ? { rejectUnauthorized: false } : false,
  });

  try {
    await client.connect();
    console.log('✅ Connected to database successfully');

    // Read and execute the reset script
    const resetScript = fs.readFileSync(
      path.join(__dirname, 'reset-tables.sql'),
      'utf8',
    );
    console.log('🔄 Executing reset script...');

    await client.query(resetScript);
    console.log('✅ Database tables reset successfully!');
    console.log('');
    console.log('🚀 You can now start your NestJS application:');
    console.log('   npm run start:dev');
  } catch (error) {
    console.error('❌ Error resetting database:', error.message);
    process.exit(1);
  } finally {
    await client.end();
  }
}

resetDatabase();
