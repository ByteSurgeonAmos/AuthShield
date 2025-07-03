const { Client } = require('pg');

const client = new Client({
  connectionString:
    'postgresql://datahub-admin:D4t4HubAdmin_7r9KzP2w@165.73.244.226:5432/datahub',
});

async function truncateAllTables() {
  await client.connect();

  // Get all table names in public schema
  const { rows } = await client.query(`
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public';
  `);

  const tableNames = rows
    .map((row) => `"public"."${row.tablename}"`)
    .join(', ');

  if (!tableNames) {
    console.log('⚠ No tables found.');
    return;
  }

  try {
    await client.query('BEGIN');
    await client.query('SET session_replication_role = replica;'); // disable FK constraints

    await client.query(`TRUNCATE ${tableNames} RESTART IDENTITY CASCADE;`);
    console.log('✅ All tables truncated successfully.');

    await client.query('SET session_replication_role = origin;'); // re-enable constraints
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Failed to truncate tables:', err.message);
  } finally {
    await client.end();
  }
}

truncateAllTables();
