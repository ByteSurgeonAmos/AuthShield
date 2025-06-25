import { Client } from 'pg';
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

  const client = new Client({
    connectionString,
    ssl: process.env.SSL === 'true' ? { rejectUnauthorized: false } : false,
  });

  try {
    await client.connect();
    console.log('✅ Connected to database successfully');

    // Execute reset queries
    console.log('🔄 Dropping existing tables...');

    const dropQueries = [
      'DROP TABLE IF EXISTS "Roles" CASCADE;',
      'DROP TABLE IF EXISTS "other_user_details" CASCADE;',
      'DROP TABLE IF EXISTS "security_questions" CASCADE;',
      'DROP TABLE IF EXISTS "security_audit_log" CASCADE;',
      'DROP TABLE IF EXISTS "auth_notifications" CASCADE;',
      'DROP TABLE IF EXISTS "user_account" CASCADE;',
      'DROP EXTENSION IF EXISTS "uuid-ossp" CASCADE;',
      'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";',
    ];

    for (const query of dropQueries) {
      console.log(`  Executing: ${query}`);
      await client.query(query);
    }

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
