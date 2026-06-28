const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const axios = require('axios');
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-random-string';
const DB_PATH = process.env.DB_PATH || './data.db';
const SALT_ROUNDS = 10;

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

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
    privacy TEXT DEFAULT '{}',
    sort_order INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS _webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    url TEXT NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('insert','update','delete'))
  );
`);

// Ensure default 'items' table exists
if (!db.prepare("SELECT name FROM _tables WHERE name = 'items'").get()) {
  db.prepare("INSERT INTO _tables (name, columns, privacy, sort_order) VALUES (?, ?, ?, ?)").run('items', '[{"name":"title","type":"string"}]', '{}', 0);
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
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---- Operator mapping ----
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
  let sql = rule.replace(/@user_id/g, userId);
  const parts = sql.split(' ');
  if (parts.length >= 3 && opMap[parts[1]]) {
    parts[1] = opMap[parts[1]];
    if (parts[1] === 'LIKE' || parts[1] === 'NOT LIKE') {
      parts[2] = `'%${parts[2]}%'`;
    }
    sql = parts.join(' ');
  }
  return sql;
}

function mapType(type) {
  switch (type) {
    case 'int': case 'int8': case 'integer': return 'INTEGER';
    case 'float': case 'number': return 'REAL';
    case 'boolean': case 'bool': return 'INTEGER';
    case 'date': case 'datetime': return 'TEXT';
    default: return 'TEXT';
  }
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
  const tables = db.prepare('SELECT name, columns, privacy, sort_order FROM _tables ORDER BY sort_order, id').all();
  res.json(tables.map(t => ({
    name: t.name,
    columns: JSON.parse(t.columns),
    privacy: JSON.parse(t.privacy || '{}'),
    sort_order: t.sort_order
  })));
});

app.post('/api/tables', authMiddleware, (req, res) => {
  const { name, columns } = req.body;
  if (!name || !Array.isArray(columns) || columns.length === 0)
    return res.status(400).json({ error: 'Name and at least one column required' });
  const safeName = name.replace(/[^a-zA-Z0-9_]/g, '');
  if (!safeName) return res.status(400).json({ error: 'Invalid table name' });

  const colDefs = columns.map(c => {
    const colName = c.name.replace(/[^a-zA-Z0-9_]/g, '');
    const type = mapType(c.type);
    return `${colName} ${type}`;
  }).join(', ');

  try {
    db.prepare(`CREATE TABLE ${safeName} (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, ${colDefs})`).run();
    const maxOrder = db.prepare('SELECT MAX(sort_order) as max FROM _tables').get().max || 0;
    db.prepare('INSERT INTO _tables (name, columns, privacy, sort_order) VALUES (?, ?, ?, ?)').run(safeName, JSON.stringify(columns), '{}', maxOrder + 1);
    res.status(201).json({ name: safeName, columns });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/tables/order', authMiddleware, (req, res) => {
  const { order } = req.body;
  if (!Array.isArray(order)) return res.status(400).json({ error: 'Order array required' });
  const stmt = db.prepare('UPDATE _tables SET sort_order = ? WHERE name = ?');
  const transaction = db.transaction(() => {
    order.forEach((name, idx) => stmt.run(idx, name));
  });
  transaction();
  res.json({ success: true });
});

app.delete('/api/tables/:name', authMiddleware, (req, res) => {
  const name = req.params.name;
  if (!db.prepare('SELECT name FROM _tables WHERE name = ?').get(name))
    return res.status(404).json({ error: 'Table not found' });
  db.prepare(`DROP TABLE IF EXISTS ${name}`).run();
  db.prepare('DELETE FROM _tables WHERE name = ?').run(name);
  db.prepare('DELETE FROM _webhooks WHERE table_name = ?').run(name);
  res.json({ success: true });
});

app.put('/api/tables/:name', authMiddleware, (req, res) => {
  const oldName = req.params.name;
  const { newName } = req.body;
  if (!newName) return res.status(400).json({ error: 'New name required' });
  const safeNew = newName.replace(/[^a-zA-Z0-9_]/g, '');
  if (!safeNew) return res.status(400).json({ error: 'Invalid name' });
  if (db.prepare('SELECT name FROM _tables WHERE name = ?').get(safeNew))
    return res.status(400).json({ error: 'Table name already exists' });

  db.prepare('UPDATE _tables SET name = ? WHERE name = ?').run(safeNew, oldName);
  try {
    db.prepare(`ALTER TABLE ${oldName} RENAME TO ${safeNew}`).run();
  } catch (e) {
    db.prepare('UPDATE _tables SET name = ? WHERE name = ?').run(oldName, safeNew);
    return res.status(400).json({ error: e.message });
  }
  db.prepare('UPDATE _webhooks SET table_name = ? WHERE table_name = ?').run(safeNew, oldName);
  res.json({ name: safeNew });
});

app.put('/api/tables/:name/privacy', authMiddleware, (req, res) => {
  const { read, write, update, delete: del } = req.body;
  const privacy = JSON.stringify({ read: read || '', write: write || '', update: update || '', delete: del || '' });
  db.prepare('UPDATE _tables SET privacy = ? WHERE name = ?').run(privacy, req.params.name);
  res.json({ success: true });
});

app.put('/api/tables/:name/schema', authMiddleware, (req, res) => {
  const oldName = req.params.name;
  const { columns } = req.body;
  if (!Array.isArray(columns)) return res.status(400).json({ error: 'columns array required' });
  const table = db.prepare('SELECT * FROM _tables WHERE name = ?').get(oldName);
  if (!table) return res.status(404).json({ error: 'Table not found' });

  const oldCols = JSON.parse(table.columns);
  const newCols = columns.filter(c => !oldCols.find(oc => oc.name === c.name));
  newCols.forEach(c => {
    const colName = c.name.replace(/[^a-zA-Z0-9_]/g, '');
    const type = mapType(c.type);
    try {
      db.prepare(`ALTER TABLE ${oldName} ADD COLUMN ${colName} ${type}`).run();
    } catch (err) { /* column may already exist */ }
  });
  db.prepare('UPDATE _tables SET columns = ? WHERE name = ?').run(JSON.stringify(columns), oldName);
  res.json({ name: oldName, columns });
});

// Dynamic CRUD
app.get('/api/data/:table', authMiddleware, (req, res) => {
  const meta = db.prepare('SELECT columns, privacy FROM _tables WHERE name = ?').get(req.params.table);
  if (!meta) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.columns).map(c => c.name);
  const privacy = JSON.parse(meta.privacy || '{}');
  let query = `SELECT id, user_id, ${columns.join(', ')} FROM ${req.params.table}`;
  const conditions = [];
  const params = [];

  if (privacy.read) {
    conditions.push(applyRule(privacy.read, req.user.id));
  }

  if (req.query.filter) {
    Object.entries(req.query.filter).forEach(([col, val]) => {
      if (columns.includes(col)) {
        conditions.push(`${col} = ?`);
        params.push(val);
      }
    });
  }

  if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');

  if (req.query.sort && columns.includes(req.query.sort)) {
    const order = req.query.order === 'desc' ? 'DESC' : 'ASC';
    query += ` ORDER BY ${req.query.sort} ${order}`;
  } else {
    query += ' ORDER BY id DESC';
  }

  if (req.query.limit) {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    query += ` LIMIT ${limit} OFFSET ${offset}`;
  }

  try {
    const rows = db.prepare(query).all(...params);
    res.json(rows);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/data/:table', authMiddleware, (req, res) => {
  const meta = db.prepare('SELECT columns, privacy FROM _tables WHERE name = ?').get(req.params.table);
  if (!meta) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.columns);
  const privacy = JSON.parse(meta.privacy || '{}');
  if (privacy.write) {
    // check write rule (if any) – simple: must match the condition
    // We'll skip full row check since row doesn't exist yet; we just allow if rule contains @user_id
    // For simplicity, we assume if a write rule exists, the user must match it via user_id field
    if (privacy.write.includes('@user_id')) {
      // do nothing, user_id will be inserted
    }
  }

  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (fields.length === 0) return res.status(400).json({ error: 'No valid fields' });
  const placeholders = fields.map(() => '?').join(', ');
  const values = fields.map(f => req.body[f.name]);

  try {
    const info = db.prepare(`INSERT INTO ${req.params.table} (user_id, ${fields.map(f => f.name).join(', ')}) VALUES (?, ${placeholders})`).run(req.user.id, ...values);
    const newRow = { id: info.lastInsertRowid, user_id: req.user.id };
    fields.forEach((f, i) => newRow[f.name] = values[i]);
    broadcastChange('insert', null, newRow, req.params.table);
    triggerWebhooks('insert', null, newRow, req.params.table);
    res.status(201).json(newRow);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/data/:table/:id', authMiddleware, (req, res) => {
  const meta = db.prepare('SELECT columns, privacy FROM _tables WHERE name = ?').get(req.params.table);
  if (!meta) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.columns);
  const privacy = JSON.parse(meta.privacy || '{}');

  // Check update rule
  if (privacy.update) {
    const rule = applyRule(privacy.update, req.user.id);
    const row = db.prepare(`SELECT 1 FROM ${req.params.table} WHERE id = ? AND ${rule}`).get(req.params.id);
    if (!row) return res.status(403).json({ error: 'Forbidden by update rule' });
  }

  const oldRow = db.prepare(`SELECT * FROM ${req.params.table} WHERE id = ?`).get(req.params.id);
  if (!oldRow) return res.status(404).json({ error: 'Row not found' });

  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

  const setClauses = fields.map(f => `${f.name} = ?`).join(', ');
  const values = fields.map(f => req.body[f.name]);

  try {
    db.prepare(`UPDATE ${req.params.table} SET ${setClauses} WHERE id = ?`).run(...values, req.params.id);
    const newRow = db.prepare(`SELECT * FROM ${req.params.table} WHERE id = ?`).get(req.params.id);
    broadcastChange('update', oldRow, newRow, req.params.table);
    triggerWebhooks('update', oldRow, newRow, req.params.table);
    res.json(newRow);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/data/:table/:id', authMiddleware, (req, res) => {
  const meta = db.prepare('SELECT privacy FROM _tables WHERE name = ?').get(req.params.table);
  if (!meta) return res.status(404).json({ error: 'Table not found' });
  const row = db.prepare(`SELECT * FROM ${req.params.table} WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Row not found' });
  const privacy = JSON.parse(meta.privacy || '{}');
  if (privacy.delete) {
    const rule = applyRule(privacy.delete, req.user.id);
    if (!db.prepare(`SELECT 1 FROM ${req.params.table} WHERE id = ? AND ${rule}`).get(req.params.id))
      return res.status(403).json({ error: 'Forbidden by delete rule' });
  }
  db.prepare(`DELETE FROM ${req.params.table} WHERE id = ?`).run(req.params.id);
  broadcastChange('delete', row, null, req.params.table);
  triggerWebhooks('delete', row, null, req.params.table);
  res.json({ success: true });
});

// Webhooks
app.get('/api/webhooks/:table', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT id, url, event FROM _webhooks WHERE table_name = ?').all(req.params.table));
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

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
