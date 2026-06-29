async function initDb() {
  // Keep trying until database is reachable
  while (true) {
    try {
      const client = await pool.connect();
      await client.query('SELECT 1');
      client.release();
      console.log('Connected to PostgreSQL.');
      break; // success, exit loop
    } catch (err) {
      console.log('Waiting for database...');
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  // Now create tables
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS _tables (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        columns TEXT NOT NULL,
        privacy TEXT DEFAULT '{}',
        sort_order INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS _webhooks (
        id SERIAL PRIMARY KEY,
        table_name TEXT NOT NULL,
        url TEXT NOT NULL,
        event TEXT NOT NULL CHECK(event IN ('insert','update','delete'))
      );
    `);

    const exists = await client.query("SELECT name FROM _tables WHERE name = 'items'");
    if (exists.rowCount === 0) {
      await client.query("INSERT INTO _tables (name, columns, privacy, sort_order) VALUES ('items', '[{\"name\":\"title\",\"type\":\"string\"}]', '{}', 0)");
      await client.query(`CREATE TABLE items (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        title TEXT NOT NULL
      )`);
    }
    console.log('Database tables ready.');
  } finally {
    client.release();
  }
}
