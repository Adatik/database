const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-random-string';
const DB_PATH = process.env.DB_PATH || './data.db';
const SALT_ROUNDS = 10;

// ---------- Database ----------
console.log(`Starting app with DB_PATH=${DB_PATH}`);

let Database;
try {
  Database = require('better-sqlite3');
  console.log('better-sqlite3 loaded');
} catch (e) {
  console.error('Failed to load better-sqlite3:', e);
  process.exit(1);
}

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
console.log('Database opened');

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
console.log('Tables ready');

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
    const { lastInsertRowid } = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email, hash);
    const user = { id: lastInsertRowid, email };
    res.json({ user, token: jwt.sign(user, JWT_SECRET, { expiresIn: '7d' }) });
  } catch (err) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(400).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ user: { id: user.id, email: user.email }, token });
});

// ---------- Items ----------
app.get('/api/items', authMiddleware, (req, res) => {
  const items = db.prepare('SELECT id, title FROM items WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.json(items);
});

app.post('/api/items', authMiddleware, (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const { lastInsertRowid } = db.prepare('INSERT INTO items (title, user_id) VALUES (?, ?)').run(title, req.user.id);
  const newItem = { id: lastInsertRowid, title, user_id: req.user.id };
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
  db.prepare('SELECT url FROM webhooks WHERE event = ?').all(event).forEach(({ url }) => {
    axios.post(url, { event, old: oldRecord, new: newRecord }).catch(err => console.error('Webhook failed:', err.message));
  });
}

// ---------- Start ----------
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
