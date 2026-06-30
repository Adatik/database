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

const ANON_KEY = process.env.ANON_KEY || 'anon-key-change-me';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin-key-change-me';

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
        url TEXT NOT NULL
      );
    `);

    // Migrations
    try { await client.query("ALTER TABLE _webhooks ADD COLUMN IF NOT EXISTS events TEXT NOT NULL DEFAULT '[]'"); } catch (e) {}
    try { await client.query("ALTER TABLE _webhooks ADD COLUMN IF NOT EXISTS headers TEXT NOT NULL DEFAULT '[]'"); } catch (e) {}
    try { await client.query("ALTER TABLE _webhooks ADD COLUMN IF NOT EXISTS name TEXT DEFAULT ''"); } catch (e) {}
    try { await client.query("ALTER TABLE _webhooks DROP COLUMN IF EXISTS event"); } catch (e) {}
    try { await client.query("ALTER TABLE _tables ADD COLUMN IF NOT EXISTS column_permissions TEXT DEFAULT '{}'"); } catch (e) {}

    const exists = await client.query("SELECT name FROM _tables WHERE name = 'items'");
    if (exists.rowCount === 0) {
      await client.query(`INSERT INTO _tables (name, columns, privacy, column_permissions, sort_order)
        VALUES ('items', '[{"name":"title","type":"string"}]', '{}', '{"read":["title"],"write":["title"],"update":["title"]}', 0)`);
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

// Auth middleware
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
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const tokenOrKey = authHeader.split(' ')[1];
    try {
      req.user = jwt.verify(tokenOrKey, JWT_SECRET);
      req.user.admin = true;
      return next();
    } catch (jwtErr) {
      if (tokenOrKey === ADMIN_KEY) {
        req.user = { id: 0, email: 'admin', admin: true };
        return next();
      }
      if (tokenOrKey === ANON_KEY) {
        req.user = { id: -1, email: 'anon', admin: false };
        return next();
      }
    }
  }

  return res.status(401).json({ error: 'Unauthorized' });
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
  // Check for multiple values (comma-separated) with eq operator
  if (rule.includes(' eq ')) {
    const parts = rule.split(' ');
    const col = parts[0];
    const op = parts[1];
    const valuePart = parts.slice(2).join(' ');
    if (valuePart.includes(',')) {
      const values = valuePart.split(',').map(v => v.trim()).filter(v => v);
      if (values.length === 0) return '';
      // Replace @user_id in each value
      const placeholders = values.map((v, i) => `$${i + 1}`);
      const replacedValues = values.map(v => v.replace(/@user_id/g, userId));
      return { sql: `"${col}" IN (${placeholders.join(',')})`, params: replacedValues };
    }
  }

  // Standard single value
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

// ==================== AUTH ROUTES ====================
app.post('/api/register', async (req, res) => { /* unchanged */ });
app.post('/api/login', async (req, res) => { /* unchanged */ });

// ==================== TABLE MANAGEMENT ====================
app.get('/api/tables', authMiddleware, async (req, res) => { /* unchanged */ });
app.post('/api/tables', authMiddleware, async (req, res) => { /* unchanged */ });
app.put('/api/tables/order', authMiddleware, async (req, res) => { /* unchanged */ });
app.delete('/api/tables/:name', authMiddleware, async (req, res) => { /* unchanged */ });
app.put('/api/tables/:name', authMiddleware, async (req, res) => { /* unchanged */ });
app.put('/api/tables/:name/privacy', authMiddleware, async (req, res) => { /* unchanged */ });
app.put('/api/tables/:name/schema', authMiddleware, async (req, res) => { /* unchanged */ });

// Dynamic CRUD (using applyRule for filters)
app.get('/api/data/:table', authMiddleware, async (req, res) => {
  const table = req.params.table;
  try {
    const meta = await pool.query('SELECT columns, privacy, column_permissions FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const columns = JSON.parse(meta.rows[0].columns);
    const privacy = JSON.parse(meta.rows[0].privacy || '{}');
    const colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
    const allowedCols = req.user.admin ? columns.map(c => c.name) : (colPerms.read || columns.map(c => c.name));
    const selectCols = ['id', 'user_id', ...allowedCols.filter(c => c !== 'id' && c !== 'user_id')];

    let query;
    const conditions = [];
    const allParams = [];
    let paramIndex = 1;

    // Count request
    if (req.query.count === 'true') {
      query = `SELECT COUNT(*) as total FROM "${table}"`;
    } else {
      query = `SELECT ${selectCols.map(c => `"${c}"`).join(', ')} FROM "${table}"`;
    }

    // Privacy rule (only for non-admin)
    if (!req.user.admin && privacy.read) {
      const result = applyRule(privacy.read, req.user.id);
      if (result && result !== '') {
        if (typeof result === 'string') {
          conditions.push(result);
        } else {
          const replacedRule = result.sql.replace(/\$1/g, `$${paramIndex}`);
          conditions.push(replacedRule);
          allParams.push(...result.params);
          paramIndex += result.params.length;
        }
      }
    }

    // Filters
    const filterResult = parseFilters(req, allowedCols, paramIndex);
    conditions.push(...filterResult.conditions);
    allParams.push(...filterResult.params);
    paramIndex = filterResult.nextIndex;

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    // Sorting (only for data query)
    if (req.query.count !== 'true') {
      if (req.query.sort && allowedCols.includes(req.query.sort)) {
        query += ` ORDER BY "${req.query.sort}" ${req.query.order === 'desc' ? 'DESC' : 'ASC'}`;
      } else {
        query += ' ORDER BY id DESC';
      }

      // Pagination
      if (req.query.limit) {
        const limit = Math.max(0, parseInt(req.query.limit, 10) || 50);
        const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
        query += ` LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
        allParams.push(limit, offset);
      }
    }

    const result = await pool.query(query, allParams);
    if (req.query.count === 'true') {
      res.json({ count: parseInt(result.rows[0].total) });
    } else {
      res.json(result.rows);
    }
  } catch (err) { res.status(400).json({ error: err.message }); }
});

function parseFilters(req, columns, startIndex) {
  const conditions = [];
  const params = [];
  let idx = startIndex;

  if (req.query.filter) {
    if (typeof req.query.filter === 'object' && !Array.isArray(req.query.filter)) {
      const keys = Object.keys(req.query.filter);
      if (keys.length > 0 && !isNaN(keys[0])) {
        keys.forEach(key => {
          const f = req.query.filter[key];
          if (f.column && f.value !== undefined && columns.includes(f.column)) {
            const op = f.operator || 'eq';
            const sqlOp = opMap[op] || '=';
            let condition;
            if (sqlOp === 'LIKE' || sqlOp === 'NOT LIKE') {
              condition = `"${f.column}" ${sqlOp} $${idx}`;
              params.push(`%${f.value}%`);
            } else {
              condition = `"${f.column}" ${sqlOp} $${idx}`;
              params.push(f.value);
            }
            conditions.push(condition);
            idx++;
          }
        });
        return { conditions, params, nextIndex: idx };
      }
    }
    // Fallback simple equality
    Object.entries(req.query.filter).forEach(([col, val]) => {
      if (columns.includes(col)) {
        conditions.push(`"${col}" = $${idx}`);
        params.push(val);
        idx++;
      }
    });
  }
  return { conditions, params, nextIndex: idx };
}

app.post('/api/data/:table', authMiddleware, async (req, res) => { /* unchanged */ });
app.put('/api/data/:table/:id', authMiddleware, async (req, res) => { /* unchanged */ });
app.delete('/api/data/:table/:id', authMiddleware, async (req, res) => { /* unchanged */ });
app.post('/api/data/:table/bulk/delete', authMiddleware, async (req, res) => { /* unchanged */ });
app.post('/api/data/:table/bulk/update', authMiddleware, async (req, res) => { /* unchanged */ });

// Webhooks
app.get('/api/webhooks/:table', authMiddleware, async (req, res) => { /* unchanged */ });
app.post('/api/webhooks/:table', authMiddleware, async (req, res) => { /* unchanged */ });
app.delete('/api/webhooks/:id', authMiddleware, async (req, res) => { /* unchanged */ });

// ==================== AUTH KEYS ENDPOINT ====================
app.get('/api/auth-keys', authMiddleware, async (req, res) => { /* unchanged */ });

// Health, WebSocket
app.get('/health', async (req, res) => { /* unchanged */ });

const clients = new Map();
wss.on('connection', (ws) => { /* unchanged */ });

function broadcastChange(event, oldRecord, newRecord, table) { /* unchanged */ }
function triggerWebhooks(event, oldRecord, newRecord, table) { /* unchanged */ }

initDb()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      startupLog(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    startupLog('FATAL: ' + err.message);
    process.exit(1);
  });
