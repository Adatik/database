const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const axios = require('axios');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-random-string';
const SALT_ROUNDS = 10;

const ANON_KEY = process.env.ANON_KEY;
const ADMIN_KEY = process.env.ADMIN_KEY;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

async function initDb() {
  let attempts = 0;
  while (attempts < 20) {
    try {
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
        console.log('Database ready.');
        return;
      } finally {
        client.release();
      }
    } catch (err) {
      console.log(`Waiting for database... (${attempts + 1}/20)`);
      attempts++;
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
  throw new Error('Could not connect to database after 20 attempts');
}

function authMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    if (ADMIN_KEY && apiKey === ADMIN_KEY) {
      req.user = { id: 0, email: 'admin', admin: true };
      return next();
    }
    if (ANON_KEY && apiKey === ANON_KEY) {
      req.user = { id: -1, email: 'anon', admin: false };
      return next();
    }
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    req.user.admin = false;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

const opMap = {
  'eq': '=',
  'neq': '<>',
  'gt': '>',
  'lt': '<',
  'gte': '>=',
  'lte': '<=',
  'contains': 'LIKE',
  'not_contains': 'NOT LIKE'
};

function applyRule(rule, userId) {
  if (!rule) return '';
  let sql = rule.replace(/@user_id/g, '$1');
  const parts = sql.split(' ');
  if (parts.length >= 3 && opMap[parts[1]]) {
    parts[1] = opMap[parts[1]];
    if (parts[1] === 'LIKE' || parts[1] === 'NOT LIKE') {
      parts[2] = `'%${parts[2].replace(/'/g, '')}%'`;
    }
    sql = parts.join(' ');
  }
  return { sql, params: [userId] };
}

function mapType(type) {
  switch (type) {
    case 'int': case 'int8': case 'integer': return 'INTEGER';
    case 'float': case 'number': return 'REAL';
    case 'boolean': case 'bool': return 'BOOLEAN';
    case 'date': return 'DATE';
    case 'datetime': return 'TIMESTAMP';
    default: return 'TEXT';
  }
}

// Auth routes
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email, hash]
    );
    const user = result.rows[0];
    res.json({ user, token: jwt.sign(user, JWT_SECRET, { expiresIn: '7d' }) });
  } catch { res.status(400).json({ error: 'Email already exists' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(400).json({ error: 'Invalid credentials' });
  res.json({ user: { id: user.id, email: user.email }, token: jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' }) });
});

// Table management
app.get('/api/tables', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT name, columns, privacy, sort_order FROM _tables ORDER BY sort_order, id');
    res.json(result.rows.map(t => ({
      name: t.name,
      columns: JSON.parse(t.columns),
      privacy: JSON.parse(t.privacy || '{}'),
      sort_order: t.sort_order
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/tables', authMiddleware, async (req, res) => {
  const { name, columns } = req.body;
  if (!name || !Array.isArray(columns) || columns.length === 0)
    return res.status(400).json({ error: 'Name and at least one column required' });
  const safeName = name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
  if (!safeName) return res.status(400).json({ error: 'Invalid table name' });

  const colDefs = columns.map(c => {
    const colName = c.name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
    const type = mapType(c.type);
    return `"${colName}" ${type}`;
  }).join(', ');

  try {
    await pool.query(`CREATE TABLE "${safeName}" (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, ${colDefs})`);
    const maxOrder = await pool.query('SELECT COALESCE(MAX(sort_order), 0) as max FROM _tables');
    const nextOrder = maxOrder.rows[0].max + 1;
    await pool.query('INSERT INTO _tables (name, columns, privacy, sort_order) VALUES ($1, $2, $3, $4)',
      [safeName, JSON.stringify(columns), '{}', nextOrder]);
    res.status(201).json({ name: safeName, columns });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/tables/order', authMiddleware, async (req, res) => {
  const { order } = req.body;
  if (!Array.isArray(order)) return res.status(400).json({ error: 'Order array required' });
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (let i = 0; i < order.length; i++) {
        await client.query('UPDATE _tables SET sort_order = $1 WHERE name = $2', [i, order[i]]);
      }
      await client.query('COMMIT');
      res.json({ success: true });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally { client.release(); }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/tables/:name', authMiddleware, async (req, res) => {
  const name = req.params.name;
  try {
    const exists = await pool.query('SELECT name FROM _tables WHERE name = $1', [name]);
    if (exists.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    await pool.query(`DROP TABLE IF EXISTS "${name}"`);
    await pool.query('DELETE FROM _tables WHERE name = $1', [name]);
    await pool.query('DELETE FROM _webhooks WHERE table_name = $1', [name]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/tables/:name', authMiddleware, async (req, res) => {
  const oldName = req.params.name;
  const { newName } = req.body;
  if (!newName) return res.status(400).json({ error: 'New name required' });
  const safeNew = newName.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
  if (!safeNew) return res.status(400).json({ error: 'Invalid name' });
  try {
    const exists = await pool.query('SELECT name FROM _tables WHERE name = $1', [safeNew]);
    if (exists.rowCount > 0) return res.status(400).json({ error: 'Table name already exists' });

    await pool.query('UPDATE _tables SET name = $1 WHERE name = $2', [safeNew, oldName]);
    await pool.query(`ALTER TABLE "${oldName}" RENAME TO "${safeNew}"`);
    await pool.query('UPDATE _webhooks SET table_name = $1 WHERE table_name = $2', [safeNew, oldName]);
    res.json({ name: safeNew });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/tables/:name/privacy', authMiddleware, async (req, res) => {
  const { read, write, update, delete: del } = req.body;
  const privacy = JSON.stringify({ read: read || '', write: write || '', update: update || '', delete: del || '' });
  await pool.query('UPDATE _tables SET privacy = $1 WHERE name = $2', [privacy, req.params.name]);
  res.json({ success: true });
});

app.put('/api/tables/:name/schema', authMiddleware, async (req, res) => {
  const oldName = req.params.name;
  const { columns } = req.body;
  if (!Array.isArray(columns)) return res.status(400).json({ error: 'columns array required' });
  try {
    const table = await pool.query('SELECT * FROM _tables WHERE name = $1', [oldName]);
    if (table.rowCount === 0) return res.status(404).json({ error: 'Table not found' });

    const oldCols = JSON.parse(table.rows[0].columns);
    const newCols = columns.filter(c => !oldCols.find(oc => oc.name === c.name));
    for (const c of newCols) {
      const colName = c.name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
      const type = mapType(c.type);
      await pool.query(`ALTER TABLE "${oldName}" ADD COLUMN "${colName}" ${type}`).catch(() => {});
    }
    await pool.query('UPDATE _tables SET columns = $1 WHERE name = $2', [JSON.stringify(columns), oldName]);
    res.json({ name: oldName, columns });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Dynamic CRUD
app.get('/api/data/:table', authMiddleware, async (req, res) => {
  const table = req.params.table;
  try {
    const meta = await pool.query('SELECT columns, privacy FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const columns = JSON.parse(meta.rows[0].columns).map(c => c.name);
    const privacy = JSON.parse(meta.rows[0].privacy || '{}');

    let query = `SELECT id, user_id, ${columns.map(c => `"${c}"`).join(', ')} FROM "${table}"`;
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    // Apply privacy rules unless admin
    if (!req.user.admin && privacy.read) {
      const { sql, params: ruleParams } = applyRule(privacy.read, req.user.id);
      const replacedRule = sql.replace(/\$1/g, `$${paramIndex}`);
      paramIndex++;
      conditions.push(replacedRule);
      params.push(ruleParams[0]);
    }

    // Filters
    if (req.query.filter) {
      for (const [col, val] of Object.entries(req.query.filter)) {
        if (columns.includes(col)) {
          conditions.push(`"${col}" = $${paramIndex++}`);
          params.push(val);
        }
      }
    }

    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');

    // Sort
    if (req.query.sort && columns.includes(req.query.sort)) {
      query += ` ORDER BY "${req.query.sort}" ${req.query.order === 'desc' ? 'DESC' : 'ASC'}`;
    } else {
      query += ' ORDER BY id DESC';
    }

    // Pagination
    if (req.query.limit) {
      const limit = parseInt(req.query.limit) || 50;
      const offset = parseInt(req.query.offset) || 0;
      query += ` LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
      params.push(limit, offset);
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/data/:table', authMiddleware, async (req, res) => {
  const table = req.params.table;
  try {
    const meta = await pool.query('SELECT columns, privacy FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const columns = JSON.parse(meta.rows[0].columns);

    const fields = columns.filter(c => req.body[c.name] !== undefined);
    if (fields.length === 0) return res.status(400).json({ error: 'No valid fields' });

    const placeholders = fields.map((_, i) => `$${i + 3}`);
    const values = [req.user.id, ...fields.map(f => req.body[f.name])];
    const query = `INSERT INTO "${table}" (user_id, ${fields.map(f => `"${f.name}"`).join(', ')}) VALUES ($1, ${placeholders.join(', ')}) RETURNING *`;

    const result = await pool.query(query, values);
    const newRow = result.rows[0];
    broadcastChange('insert', null, newRow, table);
    triggerWebhooks('insert', null, newRow, table);
    res.status(201).json(newRow);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/data/:table/:id', authMiddleware, async (req, res) => {
  const table = req.params.table;
  const id = req.params.id;
  try {
    const meta = await pool.query('SELECT columns, privacy FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const columns = JSON.parse(meta.rows[0].columns);
    const privacy = JSON.parse(meta.rows[0].privacy || '{}');

    if (!req.user.admin && privacy.update) {
      const { sql, params } = applyRule(privacy.update, req.user.id);
      const check = await pool.query(`SELECT 1 FROM "${table}" WHERE id = $1 AND ${sql}`, [id, ...params]);
      if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden by update rule' });
    }

    const oldResult = await pool.query(`SELECT * FROM "${table}" WHERE id = $1`, [id]);
    if (oldResult.rowCount === 0) return res.status(404).json({ error: 'Row not found' });
    const oldRow = oldResult.rows[0];

    const fields = columns.filter(c => req.body[c.name] !== undefined);
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    const setClauses = fields.map((f, i) => `"${f.name}" = $${i + 2}`).join(', ');
    const values = [id, ...fields.map(f => req.body[f.name])];
    await pool.query(`UPDATE "${table}" SET ${setClauses} WHERE id = $1`, values);

    const newRow = await pool.query(`SELECT * FROM "${table}" WHERE id = $1`, [id]);
    broadcastChange('update', oldRow, newRow.rows[0], table);
    triggerWebhooks('update', oldRow, newRow.rows[0], table);
    res.json(newRow.rows[0]);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/data/:table/:id', authMiddleware, async (req, res) => {
  const table = req.params.table;
  const id = req.params.id;
  try {
    const meta = await pool.query('SELECT privacy FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const privacy = JSON.parse(meta.rows[0].privacy || '{}');

    const oldRow = await pool.query(`SELECT * FROM "${table}" WHERE id = $1`, [id]);
    if (oldRow.rowCount === 0) return res.status(404).json({ error: 'Row not found' });

    if (!req.user.admin && privacy.delete) {
      const { sql, params } = applyRule(privacy.delete, req.user.id);
      const check = await pool.query(`SELECT 1 FROM "${table}" WHERE id = $1 AND ${sql}`, [id, ...params]);
      if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden by delete rule' });
    }

    await pool.query(`DELETE FROM "${table}" WHERE id = $1`, [id]);
    broadcastChange('delete', oldRow.rows[0], null, table);
    triggerWebhooks('delete', oldRow.rows[0], null, table);
    res.json({ success: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Webhooks
app.get('/api/webhooks/:table', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, url, event FROM _webhooks WHERE table_name = $1', [req.params.table]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/webhooks/:table', authMiddleware, async (req, res) => {
  const { url, event } = req.body;
  try {
    await pool.query('INSERT INTO _webhooks (table_name, url, event) VALUES ($1, $2, $3)', [req.params.table, url, event]);
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/webhooks/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM _webhooks WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Health
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.send('OK');
  } catch { res.status(500).send('DB connection failed'); }
});

// WebSocket
const clients = new Map();
wss.on('connection', (ws) => {
  ws.on('message', (msg) => {
    try {
      const { type, token } = JSON.parse(msg);
      if (type === 'auth' && token) {
        const { id } = jwt.verify(token, JWT_SECRET);
        clients.set(ws, id);
        ws.send(JSON.stringify({ type: 'auth_ok' }));
      }
    } catch { ws.send(JSON.stringify({ type: 'error', message: 'Auth failed' })); }
  });
  ws.on('close', () => clients.delete(ws));
});

function broadcastChange(event, oldRecord, newRecord, table) {
  const msg = JSON.stringify({ type: 'item_change', event, old: oldRecord, new: newRecord, table });
  wss.clients.forEach(ws => ws.readyState === WebSocket.OPEN && ws.send(msg));
}

function triggerWebhooks(event, oldRecord, newRecord, table) {
  pool.query('SELECT url FROM _webhooks WHERE table_name = $1 AND event = $2', [table, event])
    .then(result => {
      result.rows.forEach(({ url }) => {
        axios.post(url, { event, old: oldRecord, new: newRecord, table }).catch(err => console.error('Webhook failed:', err.message));
      });
    })
    .catch(() => {});
}

// Start
initDb()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`Server running on http://0.0.0.0:${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
