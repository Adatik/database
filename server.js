const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-random-string';
const DB_PATH = process.env.DB_PATH || './data.db';   // <-- configurable via env
const SALT_ROUNDS = 10;

// ---------- Database (SQLite with WAL) ----------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('insert','update','delete'))
  );
`);

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // serves index.html from root

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized' });

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, email }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- Auth Routes ----------
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    const info = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email, hash);
    const user = { id: info.lastInsertRowid, email };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  } catch (err) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ user: { id: user.id, email: user.email }, token });
});

// ---------- Item Routes (scoped to user) ----------
app.get('/api/items', authMiddleware, (req, res) => {
  const items = db.prepare('SELECT id, title FROM items WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.json(items);
});

app.post('/api/items', authMiddleware, (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });

  const info = db.prepare('INSERT INTO items (title, user_id) VALUES (?, ?)').run(title, req.user.id);
  const newItem = { id: info.lastInsertRowid, title, user_id: req.user.id };

  broadcastChange('insert', null, newItem);
  triggerWebhooks('insert', null, newItem);

  res.status(201).json(newItem);
});

app.delete('/api/items/:id', authMiddleware, (req, res) => {
  const item = db.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!item) return res.status(404).json({ error: 'Item not found' });

  db.prepare('DELETE FROM items WHERE id = ?').run(req.params.id);

  broadcastChange('delete', item, null);
  triggerWebhooks('delete', item, null);

  res.json({ success: true });
});

// ---------- WebSocket (real‑time, sends old and new) ----------
const clients = new Map();

wss.on('connection', (ws) => {
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'auth' && data.token) {
        const payload = jwt.verify(data.token, JWT_SECRET);
        clients.set(ws, payload.id);
        ws.send(JSON.stringify({ type: 'auth_ok' }));
      }
    } catch (err) {
      ws.send(JSON.stringify({ type: 'error', message: 'Auth failed' }));
    }
  });

  ws.on('close', () => clients.delete(ws));
});

function broadcastChange(event, oldRecord, newRecord) {
  const message = JSON.stringify({
    type: 'item_change',
    event,
    old: oldRecord,
    new: newRecord
  });

  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// ---------- Webhooks (external HTTP calls) ----------
function triggerWebhooks(event, oldRecord, newRecord) {
  const hooks = db.prepare('SELECT url FROM webhooks WHERE event = ?').all(event);
  hooks.forEach(({ url }) => {
    axios.post(url, { event, old: oldRecord, new: newRecord })
      .catch(err => console.error(`Webhook ${url} failed:`, err.message));
  });
}

// ---------- Start ----------
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Database at ${DB_PATH}`);
});
