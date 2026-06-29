const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const axios = require('axios');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Persistent log helper
const LOG_FILE = process.env.LOG_FILE || '/data/startup.log';
const logDir = path.dirname(LOG_FILE);
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

function startupLog(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + '\n');
}

startupLog('App starting...');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-random-string';
const SALT_ROUNDS = 10;

const ANON_KEY = process.env.ANON_KEY;
const ADMIN_KEY = process.env.ADMIN_KEY;

if (!process.env.DATABASE_URL) {
  startupLog('ERROR: DATABASE_URL not set.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ---------- Database init (infinite retry) ----------
async function initDb() {
  while (true) {
    try {
      startupLog('Trying to connect to PostgreSQL...');
      const client = await pool.connect();
      await client.query('SELECT 1');
      client.release();
      startupLog('Connected to PostgreSQL.');
      break;
    } catch (err) {
      startupLog('Waiting for database...');
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

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
    startupLog('Database tables ready.');
  } finally {
    client.release();
  }
}

// Auth middleware (supports API keys and JWT)
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

// Operator mapping
const opMap = {
  'eq': '=', 'neq': '<>', 'gt': '>', 'lt': '<', 'gte': '>=', 'lte': '<=',
  'contains': 'LIKE', 'not_contains': 'NOT LIKE'
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

// Table management (unchanged from previous – just included for completeness)
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

app.put('/api/tables/order', authMiddleware, async (req, res) => { /* unchanged */ });
app.delete('/api/tables/:name', authMiddleware, async (req, res) => { /* unchanged */ });
app.put('/api/tables/:name', authMiddleware, async (req, res) => { /* unchanged */ });
app.put('/api/tables/:name/privacy', authMiddleware, async (req, res) => { /* unchanged */ });
app.put('/api/tables/:name/schema', authMiddleware, async (req, res) => { /* unchanged */ });

// ---------- Dynamic CRUD (INSERT FIX) ----------
app.post('/api/data/:table', authMiddleware, async (req, res) => {
  const table = req.params.table;
  try {
    const meta = await pool.query('SELECT columns, privacy FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const columns = JSON.parse(meta.rows[0].columns);

    // Build list of fields actually provided
    const fields = columns.filter(c => req.body[c.name] !== undefined);
    if (fields.length === 0) return res.status(400).json({ error: 'No valid fields' });

    // Create placeholders $2, $3, ... and corresponding values
    const fieldNames = fields.map(f => f.name);
    const placeholders = fields.map((_, i) => `$${i + 2}`); // $2, $3, ...
    const values = fields.map(f => {
      // Convert boolean strings to actual booleans for PostgreSQL
      const colMeta = columns.find(c => c.name === f.name);
      if (colMeta && (colMeta.type === 'boolean' || colMeta.type === 'bool')) {
        return req.body[f.name] === 'true' || req.body[f.name] === true;
      }
      return req.body[f.name];
    });

    // user_id is always $1
    const query = `INSERT INTO "${table}" (user_id, ${fieldNames.map(n => `"${n}"`).join(', ')}) VALUES ($1, ${placeholders.join(', ')}) RETURNING *`;
    const result = await pool.query(query, [req.user.id, ...values]);
    const newRow = result.rows[0];
    broadcastChange('insert', null, newRow, table);
    triggerWebhooks('insert', null, newRow, table);
    res.status(201).json(newRow);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// (The rest of the CRUD routes are unchanged – GET, PUT, DELETE)
app.get('/api/data/:table', authMiddleware, async (req, res) => { /* unchanged */ });
app.put('/api/data/:table/:id', authMiddleware, async (req, res) => { /* unchanged */ });
app.delete('/api/data/:table/:id', authMiddleware, async (req, res) => { /* unchanged */ });

// Webhooks, Health, WebSocket (unchanged)
// ... (full code as before, but I've included only the changed insert for brevity – the complete file is below)
