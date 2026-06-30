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

// ---------- Database init ----------
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

    // Safe migrations
    try { await client.query("ALTER TABLE _webhooks ADD COLUMN IF NOT EXISTS events TEXT NOT NULL DEFAULT '[]'"); } catch (e) {}
    try { await client.query("ALTER TABLE _webhooks ADD COLUMN IF NOT EXISTS headers TEXT NOT NULL DEFAULT '[]'"); } catch (e) {}
    try { await client.query("ALTER TABLE _webhooks ADD COLUMN IF NOT EXISTS name TEXT DEFAULT ''"); } catch (e) {}
    try { await client.query("ALTER TABLE _webhooks DROP COLUMN IF EXISTS event"); } catch (e) {}
    try { await client.query("ALTER TABLE _tables ADD COLUMN IF NOT EXISTS column_permissions TEXT DEFAULT '{}'"); } catch (e) {}
    try { await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user'"); } catch (e) {}

    // Make the very first user an admin if not already
    await client.query("UPDATE users SET role = 'admin' WHERE id = 1 AND role = 'user'");

    // Ensure users table metadata exists and includes password column
    let userMeta = await client.query("SELECT columns FROM _tables WHERE name = 'users'");
    if (userMeta.rowCount === 0) {
      await client.query(`INSERT INTO _tables (name, columns, privacy, column_permissions, sort_order)
        VALUES ('users', '[{"name":"email","type":"string"},{"name":"password","type":"string"}]', '{}', '{}', 9999)`);
    } else {
      let cols = JSON.parse(userMeta.rows[0].columns);
      const hasPassword = cols.some(c => c.name === 'password');
      if (!hasPassword) {
        cols.push({ name: 'password', type: 'string' });
        await client.query("UPDATE _tables SET columns = $1 WHERE name = 'users'", [JSON.stringify(cols)]);
      }
    }

    // Create sample items table if not exists
    const itemsExists = await client.query("SELECT name FROM _tables WHERE name = 'items'");
    if (itemsExists.rowCount === 0) {
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

// Auth middleware – now properly separates admin from regular users
function authMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    if (ADMIN_KEY && apiKey === ADMIN_KEY) {
      req.user = { id: 0, email: 'admin', role: 'admin', admin: true };
      return next();
    }
    if (ANON_KEY && apiKey === ANON_KEY) {
      req.user = { id: -1, email: 'anon', role: 'user', admin: false };
      return next();
    }
  }

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const tokenOrKey = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(tokenOrKey, JWT_SECRET);
      req.user = decoded;
      req.user.admin = (req.user.role === 'admin');
      return next();
    } catch (jwtErr) {
      if (tokenOrKey === ADMIN_KEY) {
        req.user = { id: 0, email: 'admin', role: 'admin', admin: true };
        return next();
      }
      if (tokenOrKey === ANON_KEY) {
        req.user = { id: -1, email: 'anon', role: 'user', admin: false };
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

function applyRule(rule, userId, userEmail) {
  if (!rule || !rule.trim()) return null;
  let processed = rule.replace(/@user_id/g, userId.toString());
  processed = processed.replace(/@user_email/g, userEmail || '');

  // Handle IN clause for multiple values
  if (processed.includes(' eq ')) {
    const parts = processed.split(' ');
    const col = parts[0];
    const valuePart = parts.slice(2).join(' ');
    if (valuePart.includes(',')) {
      const values = valuePart.split(',').map(v => v.trim());
      const placeholders = values.map((_, i) => `$${i + 1}`);
      return { sql: `"${col}" IN (${placeholders.join(',')})`, params: values };
    }
  }

  let sql = processed;
  const parts = sql.split(' ');
  if (parts.length >= 3 && opMap[parts[1]]) {
    parts[1] = opMap[parts[1]];
    if (parts[1] === 'LIKE' || parts[1] === 'NOT LIKE') {
      parts[2] = `'%${parts[2].replace(/'/g, '')}%'`;
    }
    sql = parts.join(' ');
  }
  return { sql, params: [] };
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
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    // Determine role: first user becomes admin, others are regular users
    const userCount = await pool.query('SELECT COUNT(*) FROM users');
    const role = (parseInt(userCount.rows[0].count) === 0) ? 'admin' : 'user';
    const result = await pool.query(
      'INSERT INTO users (email, password, role) VALUES ($1, $2, $3) RETURNING id, email, role',
      [email, hash, role]
    );
    const user = result.rows[0];
    const tokenPayload = { id: user.id, email: user.email, role: user.role };
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user: { id: user.id, email: user.email, role: user.role }, token });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const result = await pool.query('SELECT id, email, password, role FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user) return res.status(400).json({ error: 'Invalid email or password' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid email or password' });
  const tokenPayload = { id: user.id, email: user.email, role: user.role };
  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });
  res.json({ user: { id: user.id, email: user.email, role: user.role }, token });
});

// ==================== TABLE MANAGEMENT ====================
app.get('/api/tables', authMiddleware, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  try {
    const result = await pool.query(
      "SELECT name, columns, privacy, column_permissions, sort_order FROM _tables ORDER BY sort_order, id"
    );
    res.json(result.rows.map(t => ({
      name: t.name,
      columns: JSON.parse(t.columns),
      privacy: JSON.parse(t.privacy || '{}'),
      column_permissions: JSON.parse(t.column_permissions || '{}'),
      sort_order: t.sort_order
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/tables', authMiddleware, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  const { name, columns } = req.body;
  if (!name || !Array.isArray(columns) || columns.length === 0)
    return res.status(400).json({ error: 'Name and at least one column required' });
  const safeName = name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
  if (!safeName) return res.status(400).json({ error: 'Invalid table name' });
  if (safeName === 'users') return res.status(400).json({ error: 'Table name reserved' });

  const colDefs = columns.map(c => {
    const colName = c.name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
    const type = mapType(c.type);
    let def = '';
    if (c.default !== undefined && c.default !== '') {
      if (type === 'BOOLEAN') def = ` DEFAULT ${c.default === 'true' ? 'TRUE' : 'FALSE'}`;
      else if (type === 'INTEGER' || type === 'REAL') def = ` DEFAULT ${c.default}`;
      else def = ` DEFAULT '${c.default.replace(/'/g, "''")}'`;
    }
    return `"${colName}" ${type}${def}`;
  }).join(', ');

  try {
    await pool.query(`CREATE TABLE "${safeName}" (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), ${colDefs})`);
    const maxOrder = await pool.query('SELECT COALESCE(MAX(sort_order), 0) as max FROM _tables');
    const nextOrder = maxOrder.rows[0].max + 1;
    const columnPerms = { read: columns.map(c => c.name), write: columns.map(c => c.name), update: columns.map(c => c.name) };
    await pool.query('INSERT INTO _tables (name, columns, privacy, column_permissions, sort_order) VALUES ($1, $2, $3, $4, $5)',
      [safeName, JSON.stringify(columns), '{}', JSON.stringify(columnPerms), nextOrder]);
    res.status(201).json({ name: safeName, columns });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/tables/order', authMiddleware, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  const { order } = req.body;
  if (!Array.isArray(order)) return res.status(400).json({ error: 'Order array required' });
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (let i = 0; i < order.length; i++) {
        await client.query('UPDATE _tables SET sort_order = $1 WHERE name = $2 AND name != \'users\'', [i, order[i]]);
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
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  const name = req.params.name;
  if (name === 'users') return res.status(400).json({ error: 'Cannot delete users table' });
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
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  const oldName = req.params.name;
  if (oldName === 'users') return res.status(400).json({ error: 'Cannot rename users table' });
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
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  const { read, write, update, delete: del, column_permissions } = req.body;
  const privacy = JSON.stringify({ read: read || '', write: write || '', update: update || '', delete: del || '' });
  const columnPerms = column_permissions ? JSON.stringify(column_permissions) : null;
  if (columnPerms) {
    await pool.query('UPDATE _tables SET privacy = $1, column_permissions = $2 WHERE name = $3', [privacy, columnPerms, req.params.name]);
  } else {
    await pool.query('UPDATE _tables SET privacy = $1 WHERE name = $2', [privacy, req.params.name]);
  }
  res.json({ success: true });
});

app.put('/api/tables/:name/schema', authMiddleware, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
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
      let def = '';
      if (c.default !== undefined && c.default !== '') {
        if (type === 'BOOLEAN') def = ` DEFAULT ${c.default === 'true' ? 'TRUE' : 'FALSE'}`;
        else if (type === 'INTEGER' || type === 'REAL') def = ` DEFAULT ${c.default}`;
        else def = ` DEFAULT '${c.default.replace(/'/g, "''")}'`;
      }
      await pool.query(`ALTER TABLE "${oldName}" ADD COLUMN "${colName}" ${type}${def}`).catch(() => {});
    }
    await pool.query('UPDATE _tables SET columns = $1 WHERE name = $2', [JSON.stringify(columns), oldName]);
    res.json({ name: oldName, columns });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// ==================== DYNAMIC CRUD ====================
app.get('/api/data/:table', authMiddleware, async (req, res) => {
  const table = req.params.table;
  try {
    const meta = await pool.query('SELECT columns, privacy, column_permissions FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const columns = JSON.parse(meta.rows[0].columns);
    const privacy = JSON.parse(meta.rows[0].privacy || '{}');
    const colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
    const allowedCols = req.user.admin ? columns.map(c => c.name) : (colPerms.read || columns.map(c => c.name));

    const isUsersTable = (table === 'users');
    const selectCols = ['id'];
    if (!isUsersTable) selectCols.push('user_id');
    selectCols.push(...allowedCols.filter(c => c !== 'id' && c !== 'user_id'));

    let query;
    const conditions = [];
    const allParams = [];
    let paramIndex = 1;

    if (req.query.count === 'true') {
      query = `SELECT COUNT(*) as total FROM "${table}"`;
    } else {
      query = `SELECT ${selectCols.map(c => `"${c}"`).join(', ')} FROM "${table}"`;
    }

    // Privacy only for non-admin
    if (!req.user.admin && privacy.read) {
      const ruleResult = applyRule(privacy.read, req.user.id, req.user.email);
      if (ruleResult) {
        conditions.push(ruleResult.sql);
        allParams.push(...ruleResult.params);
        paramIndex += ruleResult.params.length;
      }
    }

    // Global search
    if (req.query.search && req.query.search.trim()) {
      const term = `%${req.query.search.trim()}%`;
      const placeholder = `$${paramIndex}`;
      const searchClauses = selectCols.map(col => `"${col}"::text ILIKE ${placeholder}`);
      conditions.push(`(${searchClauses.join(' OR ')})`);
      allParams.push(term);
      paramIndex++;
    }

    // Filters
    const filterResult = parseFilters(req, allowedCols, paramIndex);
    conditions.push(...filterResult.conditions);
    allParams.push(...filterResult.params);
    paramIndex = filterResult.nextIndex;

    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');

    if (req.query.count !== 'true') {
      if (req.query.sort && selectCols.includes(req.query.sort)) {
        query += ` ORDER BY "${req.query.sort}" ${req.query.order === 'desc' ? 'DESC' : 'ASC'}`;
      } else {
        query += ' ORDER BY id DESC';
      }

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

app.post('/api/data/:table', authMiddleware, async (req, res) => {
  const table = req.params.table;
  try {
    const meta = await pool.query('SELECT columns, column_permissions FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const columns = JSON.parse(meta.rows[0].columns);
    const colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
    if (!req.user.admin) {
      const allowedWrite = colPerms.write || columns.map(c => c.name);
      const forbidden = Object.keys(req.body).filter(f => !allowedWrite.includes(f) && f !== 'user_id');
      if (forbidden.length > 0) return res.status(403).json({ error: `Write permission denied for: ${forbidden.join(', ')}` });
    }

    const isUsersTable = (table === 'users');
    if (isUsersTable && !req.user.admin) return res.status(403).json({ error: 'Admin access required for users table' });

    const fields = columns.filter(c => req.body[c.name] !== undefined);
    if (fields.length === 0) return res.status(400).json({ error: 'No valid fields' });

    if (isUsersTable) {
      // For users table, handle password hashing if provided
      const passwordField = fields.find(f => f.name === 'password');
      if (passwordField) {
        const hash = await bcrypt.hash(req.body.password, SALT_ROUNDS);
        req.body.password = hash;
      }
      const emailField = fields.find(f => f.name === 'email');
      if (!emailField) return res.status(400).json({ error: 'Email is required' });
      const result = await pool.query(
        `INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, role`,
        [req.body.email, req.body.password || '']
      );
      return res.status(201).json(result.rows[0]);
    }

    const fieldNames = fields.map(f => f.name);
    const placeholders = fields.map((_, i) => `$${i + 2}`);
    const values = fields.map(f => {
      const colMeta = columns.find(c => c.name === f.name);
      if (colMeta && (colMeta.type === 'boolean' || colMeta.type === 'bool')) {
        return req.body[f.name] === 'true' || req.body[f.name] === true;
      }
      return req.body[f.name];
    });

    const query = `INSERT INTO "${table}" (user_id, ${fieldNames.map(n => `"${n}"`).join(', ')}) VALUES ($1, ${placeholders.join(', ')}) RETURNING *`;
    const result = await pool.query(query, [req.user.id, ...values]);
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
    const meta = await pool.query('SELECT columns, privacy, column_permissions FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const columns = JSON.parse(meta.rows[0].columns);
    const privacy = JSON.parse(meta.rows[0].privacy || '{}');
    const colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');

    if (!req.user.admin) {
      if (privacy.update) {
        const ruleResult = applyRule(privacy.update, req.user.id, req.user.email);
        if (ruleResult) {
          const check = await pool.query(`SELECT 1 FROM "${table}" WHERE id = $1 AND ${ruleResult.sql}`, [id, ...ruleResult.params]);
          if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden by update rule' });
        }
      }
      const allowedUpdate = colPerms.update || columns.map(c => c.name);
      const forbidden = Object.keys(req.body).filter(f => !allowedUpdate.includes(f) && f !== 'id');
      if (forbidden.length > 0) return res.status(403).json({ error: `Update permission denied for: ${forbidden.join(', ')}` });
    }

    const oldResult = await pool.query(`SELECT * FROM "${table}" WHERE id = $1`, [id]);
    if (oldResult.rowCount === 0) return res.status(404).json({ error: 'Row not found' });
    const oldRow = oldResult.rows[0];

    // Special handling for users table: hash password if present
    if (table === 'users' && req.body.password) {
      const hash = await bcrypt.hash(req.body.password, SALT_ROUNDS);
      req.body.password = hash;
    }

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
  if (table === 'users' && !req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  try {
    const meta = await pool.query('SELECT privacy FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const privacy = JSON.parse(meta.rows[0].privacy || '{}');

    const oldRow = await pool.query(`SELECT * FROM "${table}" WHERE id = $1`, [id]);
    if (oldRow.rowCount === 0) return res.status(404).json({ error: 'Row not found' });

    if (!req.user.admin && privacy.delete) {
      const ruleResult = applyRule(privacy.delete, req.user.id, req.user.email);
      if (ruleResult) {
        const check = await pool.query(`SELECT 1 FROM "${table}" WHERE id = $1 AND ${ruleResult.sql}`, [id, ...ruleResult.params]);
        if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden by delete rule' });
      }
    }

    await pool.query(`DELETE FROM "${table}" WHERE id = $1`, [id]);
    broadcastChange('delete', oldRow.rows[0], null, table);
    triggerWebhooks('delete', oldRow.rows[0], null, table);
    res.json({ success: true });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Bulk endpoints
app.post('/api/data/:table/bulk/delete', authMiddleware, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  const table = req.params.table;
  const { ids } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids array required' });
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const id of ids) {
        await client.query(`DELETE FROM "${table}" WHERE id = $1`, [id]);
      }
      await client.query('COMMIT');
      broadcastChange('bulk_delete', null, null, table);
      triggerWebhooks('bulk_delete', null, null, table);
      res.json({ success: true });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally { client.release(); }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/data/:table/bulk/update', authMiddleware, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  const table = req.params.table;
  const { ids, field, value } = req.body;
  if (!Array.isArray(ids) || ids.length === 0 || !field) return res.status(400).json({ error: 'ids array, field, and value required' });
  try {
    const meta = await pool.query('SELECT column_permissions FROM _tables WHERE name = $1', [table]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
    if (!req.user.admin && colPerms.update && !colPerms.update.includes(field)) {
      return res.status(403).json({ error: 'Update not allowed for this column' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const id of ids) {
        await client.query(`UPDATE "${table}" SET "${field}" = $1 WHERE id = $2`, [value, id]);
      }
      await client.query('COMMIT');
      broadcastChange('bulk_update', null, null, table);
      triggerWebhooks('bulk_update', null, null, table);
      res.json({ success: true });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally { client.release(); }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Webhooks
app.get('/api/webhooks/:table', authMiddleware, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  try {
    const result = await pool.query('SELECT id, name, url, events, headers FROM _webhooks WHERE table_name = $1', [req.params.table]);
    res.json(result.rows.map(r => ({ ...r, events: JSON.parse(r.events || '[]'), headers: JSON.parse(r.headers || '[]') })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/webhooks/:table', authMiddleware, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  const { name, url, events, headers } = req.body;
  if (!url || !Array.isArray(events) || events.length === 0) return res.status(400).json({ error: 'URL and at least one event required' });
  try {
    await pool.query('INSERT INTO _webhooks (table_name, name, url, events, headers) VALUES ($1, $2, $3, $4, $5)',
      [req.params.table, name || '', url, JSON.stringify(events), JSON.stringify(headers || [])]);
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/webhooks/:id', authMiddleware, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: 'Admin access required' });
  try {
    await pool.query('DELETE FROM _webhooks WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==================== AUTH KEYS ENDPOINT ====================
app.get('/api/auth-keys', authMiddleware, async (req, res) => {
  if (req.user.admin) {
    res.json({ anonKey: ANON_KEY, adminKey: ADMIN_KEY });
  } else {
    res.json({ anonKey: ANON_KEY, adminKey: null });
  }
});

// Health, WebSocket
app.get('/health', async (req, res) => {
  try { await pool.query('SELECT 1'); res.send('OK'); } catch { res.status(500).send('DB connection failed'); }
});

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
  pool.query('SELECT url, events, headers FROM _webhooks WHERE table_name = $1', [table])
    .then(result => {
      result.rows.forEach(({ url, events, headers }) => {
        if (events.includes(event)) {
          const hdrs = JSON.parse(headers || '[]');
          const headersObj = {};
          hdrs.forEach(h => { if (h.key) headersObj[h.key] = h.value; });
          axios.post(url, { event, old: oldRecord, new: newRecord, table }, { headers: headersObj })
            .catch(err => console.error('Webhook failed:', err.message));
        }
      });
    })
    .catch(() => {});
}

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
