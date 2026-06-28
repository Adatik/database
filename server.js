const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const axios = require('axios');
const initSqlJs = require('sql.js');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-random-string';
const DB_PATH = process.env.DB_PATH || './data.db';
const SALT_ROUNDS = 10;

let db;

// ---------- Database init ----------
async function initDatabase() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }
  db.run('PRAGMA journal_mode = WAL;');

  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );`);

  // Meta table for user‑defined tables
  db.run(`CREATE TABLE IF NOT EXISTS _tables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    columns TEXT NOT NULL,      -- JSON array of column names
    privacy TEXT DEFAULT '{}'   -- JSON: { read: "rule", write: "rule" }
  );`);

  // Webhooks per table
  db.run(`CREATE TABLE IF NOT EXISTS _webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    url TEXT NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('insert','update','delete'))
  );`);

  // Ensure the default 'items' table exists
  const existing = db.exec("SELECT name FROM _tables WHERE name = 'items'");
  if (existing.length === 0 || existing[0].values.length === 0) {
    db.run("INSERT INTO _tables (name, columns, privacy) VALUES ('items', '[\"title\"]', '{}')");
    db.run(`CREATE TABLE items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );`);
  }
  saveDb();
  console.log('Database ready.');
}

function saveDb() {
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

// ---------- Helpers ----------
function parseColumns(colsJson) {
  try { return JSON.parse(colsJson); } catch { return []; }
}

// Apply privacy rule: replace @user_id with actual user id
function applyRule(rule, userId) {
  if (!rule || !userId) return '';
  return rule.replace(/@user_id/g, userId);
}

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- Auth routes (unchanged) ----------
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hash]);
    saveDb();
    const id = db.exec('SELECT last_insert_rowid()')[0].values[0][0];
    const user = { id, email };
    res.json({ user, token: jwt.sign(user, JWT_SECRET, { expiresIn: '7d' }) });
  } catch { res.status(400).json({ error: 'Email already exists' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  stmt.bind([email]);
  if (!stmt.step()) return res.status(400).json({ error: 'Invalid credentials' });
  const user = stmt.getAsObject();
  stmt.free();
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
  res.json({ user: { id: user.id, email: user.email }, token: jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' }) });
});

// ---------- Table management ----------
app.get('/api/tables', authMiddleware, (req, res) => {
  const stmt = db.prepare('SELECT name, columns, privacy FROM _tables ORDER BY id');
  const tables = [];
  while (stmt.step()) {
    const t = stmt.getAsObject();
    tables.push({
      name: t.name,
      columns: parseColumns(t.columns),
      privacy: JSON.parse(t.privacy || '{}')
    });
  }
  stmt.free();
  res.json(tables);
});

app.post('/api/tables', authMiddleware, (req, res) => {
  const { name, columns } = req.body;   // columns: array of strings
  if (!name || !columns || !Array.isArray(columns)) return res.status(400).json({ error: 'Name and columns array required' });
  const safeName = name.replace(/[^a-zA-Z0-9_]/g, '');
  if (!safeName) return res.status(400).json({ error: 'Invalid table name' });

  // Create SQLite table
  const colDefs = columns.map(c => `${c.replace(/[^a-zA-Z0-9_]/g, '')} TEXT`).join(', ');
  try {
    db.run(`CREATE TABLE ${safeName} (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, ${colDefs})`);
    db.run('INSERT INTO _tables (name, columns, privacy) VALUES (?, ?, ?)', [safeName, JSON.stringify(columns), '{}']);
    saveDb();
    res.status(201).json({ name: safeName, columns });
  } catch (err) {
    res.status(400).json({ error: 'Table already exists or invalid columns' });
  }
});

app.put('/api/tables/:name/privacy', authMiddleware, (req, res) => {
  const { read, write } = req.body;
  const privacy = JSON.stringify({ read: read || '', write: write || '' });
  db.run('UPDATE _tables SET privacy = ? WHERE name = ?', [privacy, req.params.name]);
  saveDb();
  res.json({ success: true });
});

// ---------- Dynamic CRUD ----------
app.get('/api/data/:table', authMiddleware, (req, res) => {
  const tableName = req.params.table;
  const tableMeta = db.exec(`SELECT columns, privacy FROM _tables WHERE name = '${tableName}'`);
  if (tableMeta.length === 0 || tableMeta[0].values.length === 0) return res.status(404).json({ error: 'Table not found' });
  const { columns, privacy } = tableMeta[0].values[0];
  const cols = parseColumns(columns);
  const priv = JSON.parse(privacy || '{}');
  
  let query = `SELECT id, user_id, ${cols.map(c => c).join(', ')} FROM ${tableName}`;
  if (priv.read) {
    query += ` WHERE ${applyRule(priv.read, req.user.id)}`;
  }
  const result = db.exec(query);
  if (result.length === 0) return res.json([]);
  // Convert to array of objects
  const rows = [];
  const rawCols = result[0].columns;
  const values = result[0].values;
  values.forEach(vals => {
    const row = {};
    rawCols.forEach((col, i) => row[col] = vals[i]);
    rows.push(row);
  });
  res.json(rows);
});

app.post('/api/data/:table', authMiddleware, (req, res) => {
  const tableName = req.params.table;
  const tableMeta = db.exec(`SELECT columns, privacy FROM _tables WHERE name = '${tableName}'`);
  if (tableMeta.length === 0 || tableMeta[0].values.length === 0) return res.status(404).json({ error: 'Table not found' });
  const { columns, privacy } = tableMeta[0].values[0];
  const cols = parseColumns(columns);
  const priv = JSON.parse(privacy || '{}');

  // Apply write rule if present
  if (priv.write) {
    const ruleApplied = applyRule(priv.write, req.user.id);
    if (!ruleApplied) return res.status(403).json({ error: 'Write rule prevents creation' });
  }

  const fields = cols.filter(c => req.body[c] !== undefined);
  if (fields.length === 0) return res.status(400).json({ error: 'No valid fields provided' });
  const placeholders = fields.map(() => '?').join(', ');
  const values = fields.map(f => req.body[f]);
  try {
    db.run(`INSERT INTO ${tableName} (user_id, ${fields.join(', ')}) VALUES (?, ${placeholders})`, [req.user.id, ...values]);
    saveDb();
    const id = db.exec('SELECT last_insert_rowid()')[0].values[0][0];
    const newRow = { id, user_id: req.user.id };
    fields.forEach((f, i) => newRow[f] = values[i]);
    broadcastChange('insert', null, newRow, tableName);
    triggerWebhooks('insert', null, newRow, tableName);
    res.status(201).json(newRow);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/data/:table/:id', authMiddleware, (req, res) => {
  const tableName = req.params.table;
  const id = req.params.id;
  const tableMeta = db.exec(`SELECT columns, privacy FROM _tables WHERE name = '${tableName}'`);
  if (tableMeta.length === 0 || tableMeta[0].values.length === 0) return res.status(404).json({ error: 'Table not found' });
  const { privacy } = tableMeta[0].values[0];
  const priv = JSON.parse(privacy || '{}');

  // Check write rule
  if (priv.write) {
    const rule = applyRule(priv.write, req.user.id);
    if (!rule) return res.status(403).json({ error: 'Write rule prevents deletion' });
  }

  const rowStmt = db.prepare(`SELECT * FROM ${tableName} WHERE id = ?`);
  rowStmt.bind([id]);
  if (!rowStmt.step()) return res.status(404).json({ error: 'Row not found' });
  const oldRow = rowStmt.getAsObject();
  rowStmt.free();

  if (priv.write && oldRow.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Not owner' });
  }

  db.run(`DELETE FROM ${tableName} WHERE id = ?`, [id]);
  saveDb();
  broadcastChange('delete', oldRow, null, tableName);
  triggerWebhooks('delete', oldRow, null, tableName);
  res.json({ success: true });
});

// ---------- Webhooks per table ----------
app.get('/api/webhooks/:table', authMiddleware, (req, res) => {
  const stmt = db.prepare('SELECT id, url, event FROM _webhooks WHERE table_name = ?');
  stmt.bind([req.params.table]);
  const hooks = [];
  while (stmt.step()) hooks.push(stmt.getAsObject());
  stmt.free();
  res.json(hooks);
});

app.post('/api/webhooks/:table', authMiddleware, (req, res) => {
  const { url, event } = req.body;
  if (!url || !event) return res.status(400).json({ error: 'URL and event required' });
  db.run('INSERT INTO _webhooks (table_name, url, event) VALUES (?, ?, ?)', [req.params.table, url, event]);
  saveDb();
  res.status(201).json({ success: true });
});

app.delete('/api/webhooks/:id', authMiddleware, (req, res) => {
  db.run('DELETE FROM _webhooks WHERE id = ?', [req.params.id]);
  saveDb();
  res.json({ success: true });
});

// Health
app.get('/health', (req, res) => res.send('OK'));

// ---------- WebSocket ----------
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

// ---------- Webhooks ----------
function triggerWebhooks(event, oldRecord, newRecord, table) {
  const stmt = db.prepare('SELECT url FROM _webhooks WHERE table_name = ? AND event = ?');
  stmt.bind([table, event]);
  while (stmt.step()) {
    const { url } = stmt.getAsObject();
    axios.post(url, { event, old: oldRecord, new: newRecord, table }).catch(err => console.error('Webhook failed:', err.message));
  }
  stmt.free();
}

// Start
initDatabase().then(() => {
  server.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
}).catch(err => { console.error('Init failed:', err); process.exit(1); });
