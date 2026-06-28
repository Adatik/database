const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const axios = require('axios');
const Database = require('better-sqlite3');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-random-string';
const DB_PATH = process.env.DB_PATH || './data.db';
const SALT_ROUNDS = 10;

// Create directory for DB_PATH if needed
const dbDir = require('path').dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

// Database
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS _tables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    columns TEXT NOT NULL,
    privacy TEXT DEFAULT '{}'
  );
  CREATE TABLE IF NOT EXISTS _webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    url TEXT NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('insert','update','delete'))
  );
`);

// Ensure default 'items' table exists
const existing = db.prepare("SELECT name FROM _tables WHERE name = 'items'").get();
if (!existing) {
  db.prepare("INSERT INTO _tables (name, columns, privacy) VALUES (?, ?, ?)").run('items', '["title"]', '{}');
  db.exec(`CREATE TABLE items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );`);
}

// Middleware
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
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
}

// Auth routes
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    const info = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email, hash);
    const user = { id: info.lastInsertRowid, email };
    res.json({ user, token: jwt.sign(user, JWT_SECRET, { expiresIn: '7d' }) });
  } catch { res.status(400).json({ error: 'Email already exists' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(400).json({ error: 'Invalid credentials' });
  res.json({ user: { id: user.id, email: user.email }, token: jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' }) });
});

// Table management
app.get('/api/tables', authMiddleware, (req, res) => {
  const tables = db.prepare('SELECT name, columns, privacy FROM _tables ORDER BY id').all();
  res.json(tables.map(t => ({ name: t.name, columns: JSON.parse(t.columns), privacy: JSON.parse(t.privacy || '{}') })));
});

app.post('/api/tables', authMiddleware, (req, res) => {
  const { name, columns } = req.body;
  if (!name || !Array.isArray(columns)) return res.status(400).json({ error: 'Name and columns required' });
  const safeName = name.replace(/[^a-zA-Z0-9_]/g, '');
  const colDefs = columns.map(c => `${c.replace(/[^a-zA-Z0-9_]/g, '')} TEXT`).join(', ');
  try {
    db.prepare(`CREATE TABLE ${safeName} (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, ${colDefs})`).run();
    db.prepare('INSERT INTO _tables (name, columns, privacy) VALUES (?, ?, ?)').run(safeName, JSON.stringify(columns), '{}');
    res.status(201).json({ name: safeName, columns });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/tables/:name/privacy', authMiddleware, (req, res) => {
  const { read, write } = req.body;
  db.prepare('UPDATE _tables SET privacy = ? WHERE name = ?').run(JSON.stringify({ read: read || '', write: write || '' }), req.params.name);
  res.json({ success: true });
});

// Dynamic CRUD
app.get('/api/data/:table', authMiddleware, (req, res) => {
  const meta = db.prepare('SELECT columns, privacy FROM _tables WHERE name = ?').get(req.params.table);
  if (!meta) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.columns);
  const privacy = JSON.parse(meta.privacy || '{}');
  let query = `SELECT id, user_id, ${columns.join(', ')} FROM ${req.params.table}`;
  if (privacy.read) query += ` WHERE ${privacy.read.replace(/@user_id/g, req.user.id)}`;
  try {
    const rows = db.prepare(query).all();
    res.json(rows);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/data/:table', authMiddleware, (req, res) => {
  const meta = db.prepare('SELECT columns, privacy FROM _tables WHERE name = ?').get(req.params.table);
  if (!meta) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.columns);
  const fields = columns.filter(c => req.body[c] !== undefined);
  if (fields.length === 0) return res.status(400).json({ error: 'No valid fields' });
  const placeholders = fields.map(() => '?').join(', ');
  const values = fields.map(f => req.body[f]);
  try {
    const info = db.prepare(`INSERT INTO ${req.params.table} (user_id, ${fields.join(', ')}) VALUES (?, ${placeholders})`).run(req.user.id, ...values);
    const newRow = { id: info.lastInsertRowid, user_id: req.user.id };
    fields.forEach((f, i) => newRow[f] = values[i]);
    broadcastChange('insert', null, newRow, req.params.table);
    triggerWebhooks('insert', null, newRow, req.params.table);
    res.status(201).json(newRow);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/data/:table/:id', authMiddleware, (req, res) => {
  const meta = db.prepare('SELECT privacy FROM _tables WHERE name = ?').get(req.params.table);
  if (!meta) return res.status(404).json({ error: 'Table not found' });
  const row = db.prepare(`SELECT * FROM ${req.params.table} WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Row not found' });
  const privacy = JSON.parse(meta.privacy || '{}');
  if (privacy.write && row.user_id !== req.user.id) return res.status(403).json({ error: 'Not owner' });
  db.prepare(`DELETE FROM ${req.params.table} WHERE id = ?`).run(req.params.id);
  broadcastChange('delete', row, null, req.params.table);
  triggerWebhooks('delete', row, null, req.params.table);
  res.json({ success: true });
});

// Webhooks
app.get('/api/webhooks/:table', authMiddleware, (req, res) => {
  const hooks = db.prepare('SELECT id, url, event FROM _webhooks WHERE table_name = ?').all(req.params.table);
  res.json(hooks);
});
app.post('/api/webhooks/:table', authMiddleware, (req, res) => {
  const { url, event } = req.body;
  db.prepare('INSERT INTO _webhooks (table_name, url, event) VALUES (?, ?, ?)').run(req.params.table, url, event);
  res.status(201).json({ success: true });
});
app.delete('/api/webhooks/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM _webhooks WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Health
app.get('/health', (req, res) => res.send('OK'));

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
  const hooks = db.prepare('SELECT url FROM _webhooks WHERE table_name = ? AND event = ?').all(table, event);
  hooks.forEach(({ url }) => {
    axios.post(url, { event, old: oldRecord, new: newRecord, table }).catch(err => console.error('Webhook failed:', err.message));
  });
}

// Start
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
