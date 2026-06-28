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

// ---------- Database setup ----------
async function initDatabase() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
    console.log(`Database loaded from ${DB_PATH}`);
  } else {
    db = new SQL.Database();
    console.log(`New database created at ${DB_PATH}`);
  }
  db.run('PRAGMA journal_mode = WAL;');

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT NOT NULL,
      event TEXT NOT NULL CHECK(event IN ('insert','update','delete'))
    );
  `);
  console.log('Tables created/verified.');
}

// Save database to disk
function saveDb() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
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

// ---------- Auth ----------
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hash]);
    saveDb();
    const result = db.exec('SELECT last_insert_rowid()')[0].values[0][0];
    const user = { id: result, email };
    res.json({ user, token: jwt.sign(user, JWT_SECRET, { expiresIn: '7d' }) });
  } catch (err) {
    res.status(400).json({ error: 'Email already exists' });
  }
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

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ user: { id: user.id, email: user.email }, token });
});

// ---------- Items ----------
app.get('/api/items', authMiddleware, (req, res) => {
  const stmt = db.prepare('SELECT id, title FROM items WHERE user_id = ? ORDER BY id DESC');
  stmt.bind([req.user.id]);
  const items = [];
  while (stmt.step()) items.push(stmt.getAsObject());
  stmt.free();
  res.json(items);
});

app.post('/api/items', authMiddleware, (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  db.run('INSERT INTO items (title, user_id) VALUES (?, ?)', [title, req.user.id]);
  saveDb();
  const result = db.exec('SELECT last_insert_rowid()')[0].values[0][0];
  const newItem = { id: result, title, user_id: req.user.id };
  broadcastChange('insert', null, newItem);
  triggerWebhooks('insert', null, newItem);
  res.status(201).json(newItem);
});

app.delete('/api/items/:id', authMiddleware, (req, res) => {
  const itemStmt = db.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?');
  itemStmt.bind([req.params.id, req.user.id]);
  if (!itemStmt.step()) return res.status(404).json({ error: 'Item not found' });
  const item = itemStmt.getAsObject();
  itemStmt.free();

  db.run('DELETE FROM items WHERE id = ?', [req.params.id]);
  saveDb();
  broadcastChange('delete', item, null);
  triggerWebhooks('delete', item, null);
  res.json({ success: true });
});

// Health check
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

function broadcastChange(event, oldRecord, newRecord) {
  const msg = JSON.stringify({ type: 'item_change', event, old: oldRecord, new: newRecord });
  wss.clients.forEach(ws => ws.readyState === WebSocket.OPEN && ws.send(msg));
}

// ---------- Webhooks ----------
function triggerWebhooks(event, oldRecord, newRecord) {
  const stmt = db.prepare('SELECT url FROM webhooks WHERE event = ?');
  stmt.bind([event]);
  while (stmt.step()) {
    const { url } = stmt.getAsObject();
    axios.post(url, { event, old: oldRecord, new: newRecord }).catch(err => console.error('Webhook failed:', err.message));
  }
  stmt.free();
}

// ---------- Start ----------
initDatabase().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}).catch(err => {
  console.error('Database init failed:', err);
  process.exit(1);
});
