const { Client } = require('pg');

const sourceClient = new Client({
  connectionString: '',
});

const targetClient = new Client({
  connectionString: '',
});

async function getTables(client) {
  const res = await client.query(`
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public';
  `);
  return res.rows.map((row) => row.tablename);
}

async function tableExists(client, table) {
  const res = await client.query(
    `
    SELECT EXISTS (
      SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = $1
    );
  `,
    [table],
  );
  return res.rows[0].exists;
}

// Basic PostgreSQL type mapping
function pgTypeToSQL(typeID) {
  const mapping = {
    16: 'BOOLEAN',
    20: 'BIGINT',
    21: 'SMALLINT',
    23: 'INTEGER',
    25: 'TEXT',
    1043: 'VARCHAR',
    1700: 'NUMERIC',
    701: 'DOUBLE PRECISION',
    1082: 'DATE',
    1114: 'TIMESTAMP',
  };
  return mapping[typeID] || 'TEXT';
}

async function copySchema(source, target, table) {
  try {
    const res = await source.query(`SELECT * FROM "${table}" LIMIT 0`);
    const columns = res.fields
      .map((f) => `"${f.name}" ${pgTypeToSQL(f.dataTypeID)}`)
      .join(',\n  ');
    const query = `CREATE TABLE "${table}" (\n  ${columns}\n);`;
    await target.query(query);
    console.log(`✔ Created schema for table: ${table}`);
  } catch (e) {
    console.error(`❌ Failed to create schema for ${table}:`, e.message);
  }
}

async function copyData(source, target, table) {
  let sourceRows;
  try {
    const res = await source.query(`SELECT * FROM "${table}"`);
    sourceRows = res.rows;
    if (sourceRows.length === 0) {
      console.log(`⚠ No data to copy in table: ${table}`);
      return;
    }
  } catch (e) {
    console.error(`❌ Failed to fetch data from table ${table}:`, e.message);
    return;
  }

  const sourceColumns = Object.keys(sourceRows[0]);

  // Get columns in target table
  let targetColumns;
  try {
    const colRes = await target.query(
      `
      SELECT column_name FROM information_schema.columns
      WHERE table_name = $1 AND table_schema = 'public';
    `,
      [table],
    );

    targetColumns = colRes.rows.map((row) => row.column_name);
  } catch (e) {
    console.error(`❌ Failed to fetch columns for ${table}:`, e.message);
    return;
  }

  // Only insert matching columns
  const commonColumns = sourceColumns.filter((col) =>
    targetColumns.includes(col),
  );
  if (commonColumns.length === 0) {
    console.log(`⚠ Skipping table ${table}, no matching columns.`);
    return;
  }

  for (const row of sourceRows) {
    const values = commonColumns.map((col) => row[col]);
    const placeholders = values.map((_, i) => `$${i + 1}`).join(', ');
    const query = `INSERT INTO "${table}" (${commonColumns.map((c) => `"${c}"`).join(', ')}) VALUES (${placeholders})`;

    try {
      await target.query(query, values);
    } catch (e) {
      console.error(`❌ Insert failed for table ${table}:`, e.message);
    }
  }

  console.log(`✔ Copied ${sourceRows.length} rows into: ${table}`);
}

(async () => {
  try {
    await sourceClient.connect();
    await targetClient.connect();

    const sourceTables = await getTables(sourceClient);

    for (const table of sourceTables) {
      try {
        const targetHasTable = await tableExists(targetClient, table);

        if (!targetHasTable) {
          await copySchema(sourceClient, targetClient, table);
        }

        await copyData(sourceClient, targetClient, table);
      } catch (err) {
        console.error(`❌ Skipping table ${table} due to error:`, err.message);
      }
    }

    console.log('\n✅ Migration completed successfully.');
  } catch (err) {
    console.error('❌ Migration failed:', err.message);
  } finally {
    await sourceClient.end();
    await targetClient.end();
  }
})();
