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
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || 'admin-jwt-secret-change-me';
const PROJECT_JWT_SECRET = process.env.PROJECT_JWT_SECRET || 'project-jwt-secret-change-me';
const SALT_ROUNDS = 10;

const ANON_KEY = process.env.ANON_KEY || 'anon-key-change-me';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin-key-change-me';
const ALLOW_PUBLIC_SIGNUP = process.env.ALLOW_PUBLIC_SIGNUP === 'true';
const PLATFORM_ADMIN_EMAIL = process.env.PLATFORM_ADMIN_EMAIL;
const PLATFORM_ADMIN_PASSWORD = process.env.PLATFORM_ADMIN_PASSWORD;

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
      CREATE TABLE IF NOT EXISTS platform_users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        platform_user_id INTEGER NOT NULL REFERENCES platform_users(id),
        name TEXT NOT NULL,
        auth_config TEXT DEFAULT '{"unique_fields":["email"]}'
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS project_users (
        id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        UNIQUE(project_id, email)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS _tables (
        id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        name TEXT NOT NULL,
        columns TEXT NOT NULL,
        privacy TEXT DEFAULT '{}',
        sort_order INTEGER DEFAULT 0,
        UNIQUE(project_id, name)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS _webhooks (
        id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        table_name TEXT NOT NULL,
        url TEXT NOT NULL
      );
    `);

    try { await client.query("ALTER TABLE _webhooks ADD COLUMN IF NOT EXISTS events TEXT NOT NULL DEFAULT '[]'"); } catch (e) {}
    try { await client.query("ALTER TABLE _webhooks ADD COLUMN IF NOT EXISTS headers TEXT NOT NULL DEFAULT '[]'"); } catch (e) {}
    try { await client.query("ALTER TABLE _webhooks ADD COLUMN IF NOT EXISTS name TEXT DEFAULT ''"); } catch (e) {}
    try { await client.query("ALTER TABLE _webhooks DROP COLUMN IF EXISTS event"); } catch (e) {}
    try { await client.query("ALTER TABLE _tables ADD COLUMN IF NOT EXISTS column_permissions TEXT DEFAULT '{}'"); } catch (e) {}
    try { await client.query("ALTER TABLE _tables ADD COLUMN IF NOT EXISTS project_id INTEGER"); } catch (e) {}

    if (!ALLOW_PUBLIC_SIGNUP && PLATFORM_ADMIN_EMAIL && PLATFORM_ADMIN_PASSWORD) {
      const adminCount = await client.query('SELECT COUNT(*) FROM platform_users');
      if (parseInt(adminCount.rows[0].count) === 0) {
        const hash = await bcrypt.hash(PLATFORM_ADMIN_PASSWORD, SALT_ROUNDS);
        await client.query('INSERT INTO platform_users (email, password) VALUES ($1, $2)', [PLATFORM_ADMIN_EMAIL, hash]);
        startupLog(`Platform admin created: ${PLATFORM_ADMIN_EMAIL}`);
      }
    }

    startupLog('Database tables ready.');
  } finally {
    client.release();
  }
}

// ============================================================
//  MIDDLEWARES
// ============================================================

function platformAuthMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, ADMIN_JWT_SECRET);
      req.platformUser = decoded; // { id, email, type: 'platform' }
      return next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid platform token' });
    }
  }
  return res.status(401).json({ error: 'Platform authentication required' });
}

function projectAuthMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, PROJECT_JWT_SECRET);
      req.projectUser = decoded; // { id, email, projectId, type: 'project_user' }
      return next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid project token' });
    }
  }
  return res.status(401).json({ error: 'Project authentication required' });
}

// ============================================================
//  PLATFORM USER ENDPOINTS
// ============================================================

app.get('/api/platform/config', (req, res) => {
  res.json({ allowSignup: ALLOW_PUBLIC_SIGNUP });
});

app.post('/api/platform/register', async (req, res) => {
  if (!ALLOW_PUBLIC_SIGNUP) return res.status(403).json({ error: 'Public sign-up is disabled' });
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    const result = await pool.query('INSERT INTO platform_users (email, password) VALUES ($1, $2) RETURNING id, email', [email, hash]);
    const user = result.rows[0];
    const projResult = await pool.query('INSERT INTO projects (platform_user_id, name) VALUES ($1, $2) RETURNING id, name', [user.id, 'Default Project']);
    const tokenPayload = { id: user.id, email: user.email, type: 'platform' };
    res.json({ user, token: jwt.sign(tokenPayload, ADMIN_JWT_SECRET, { expiresIn: '7d' }), project: projResult.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/platform/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const result = await pool.query('SELECT * FROM platform_users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user) return res.status(400).json({ error: 'Invalid email or password' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid email or password' });
  const tokenPayload = { id: user.id, email: user.email, type: 'platform' };
  res.json({ user: { id: user.id, email: user.email }, token: jwt.sign(tokenPayload, ADMIN_JWT_SECRET, { expiresIn: '7d' }) });
});

app.get('/api/platform/projects', platformAuthMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, auth_config FROM projects WHERE platform_user_id = $1 ORDER BY id', [req.platformUser.id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/platform/projects', platformAuthMiddleware, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Project name required' });
  try {
    const result = await pool.query('INSERT INTO projects (platform_user_id, name) VALUES ($1, $2) RETURNING *', [req.platformUser.id, name]);
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
//  PROJECT AUTH (application users within a project)
// ============================================================

app.post('/api/project/:projectId/auth/register', platformAuthMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const projCheck = await pool.query('SELECT * FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    const result = await pool.query('INSERT INTO project_users (project_id, email, password) VALUES ($1, $2, $3) RETURNING id, email', [projectId, email, hash]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already registered in this project' });
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/project/:projectId/auth/login', async (req, res) => {
  const { projectId } = req.params;
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const result = await pool.query('SELECT * FROM project_users WHERE project_id = $1 AND email = $2', [projectId, email]);
  const user = result.rows[0];
  if (!user) return res.status(400).json({ error: 'Invalid email or password' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid email or password' });
  const tokenPayload = { id: user.id, email: user.email, projectId: parseInt(projectId), type: 'project_user' };
  res.json({ user: { id: user.id, email: user.email }, token: jwt.sign(tokenPayload, PROJECT_JWT_SECRET, { expiresIn: '7d' }) });
});

// ============================================================
//  PROJECT TABLE MANAGEMENT
// ============================================================

app.get('/api/project/:projectId/tables', platformAuthMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  try {
    const result = await pool.query("SELECT name, columns, privacy, column_permissions, sort_order FROM _tables WHERE project_id = $1 ORDER BY sort_order, id", [projectId]);
    res.json(result.rows.map(t => ({
      name: t.name,
      columns: JSON.parse(t.columns),
      privacy: JSON.parse(t.privacy || '{}'),
      column_permissions: JSON.parse(t.column_permissions || '{}'),
      sort_order: t.sort_order
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/project/:projectId/tables', platformAuthMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const { name, columns } = req.body;
  if (!name || !Array.isArray(columns) || columns.length === 0) return res.status(400).json({ error: 'Name and at least one column required' });
  const safeName = name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
  if (!safeName) return res.status(400).json({ error: 'Invalid table name' });
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
  const tableFullName = `project_${projectId}_${safeName}`;
  try {
    await pool.query(`CREATE TABLE "${tableFullName}" (id SERIAL PRIMARY KEY, project_user_id INTEGER NOT NULL REFERENCES project_users(id), ${colDefs})`);
    const maxOrder = await pool.query('SELECT COALESCE(MAX(sort_order), 0) as max FROM _tables WHERE project_id = $1', [projectId]);
    const nextOrder = maxOrder.rows[0].max + 1;
    const columnPerms = { read: columns.map(c => c.name), write: columns.map(c => c.name), update: columns.map(c => c.name) };
    await pool.query('INSERT INTO _tables (project_id, name, columns, privacy, column_permissions, sort_order) VALUES ($1, $2, $3, $4, $5, $6)', [projectId, safeName, JSON.stringify(columns), '{}', JSON.stringify(columnPerms), nextOrder]);
    res.status(201).json({ name: safeName, columns });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/project/:projectId/tables/:name/schema', platformAuthMiddleware, async (req, res) => {
  const { projectId, name } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const { columns } = req.body;
  if (!Array.isArray(columns)) return res.status(400).json({ error: 'columns array required' });
  try {
    const meta = await pool.query('SELECT * FROM _tables WHERE project_id = $1 AND name = $2', [projectId, name]);
    if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
    const oldCols = JSON.parse(meta.rows[0].columns);
    const newCols = columns.filter(c => !oldCols.find(oc => oc.name === c.name));
    const tableFullName = `project_${projectId}_${name}`;
    for (const c of newCols) {
      const colName = c.name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
      const type = mapType(c.type);
      let def = '';
      if (c.default !== undefined && c.default !== '') {
        if (type === 'BOOLEAN') def = ` DEFAULT ${c.default === 'true' ? 'TRUE' : 'FALSE'}`;
        else if (type === 'INTEGER' || type === 'REAL') def = ` DEFAULT ${c.default}`;
        else def = ` DEFAULT '${c.default.replace(/'/g, "''")}'`;
      }
      await pool.query(`ALTER TABLE "${tableFullName}" ADD COLUMN "${colName}" ${type}${def}`).catch(() => {});
    }
    await pool.query('UPDATE _tables SET columns = $1 WHERE project_id = $2 AND name = $3', [JSON.stringify(columns), projectId, name]);
    res.json({ name, columns });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/project/:projectId/tables/:name/privacy', platformAuthMiddleware, async (req, res) => {
  const { projectId, name } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const { read, write, update, delete: del, column_permissions } = req.body;
  const privacy = JSON.stringify({ read: read || '', write: write || '', update: update || '', delete: del || '' });
  const columnPerms = column_permissions ? JSON.stringify(column_permissions) : null;
  if (columnPerms) {
    await pool.query('UPDATE _tables SET privacy = $1, column_permissions = $2 WHERE project_id = $3 AND name = $4', [privacy, columnPerms, projectId, name]);
  } else {
    await pool.query('UPDATE _tables SET privacy = $1 WHERE project_id = $2 AND name = $3', [privacy, projectId, name]);
  }
  res.json({ success: true });
});

app.delete('/api/project/:projectId/tables/:name', platformAuthMiddleware, async (req, res) => {
  const { projectId, name } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const tableFullName = `project_${projectId}_${name}`;
  try {
    await pool.query(`DROP TABLE IF EXISTS "${tableFullName}"`);
    await pool.query('DELETE FROM _tables WHERE project_id = $1 AND name = $2', [projectId, name]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
//  PROJECT DATA CRUD (admin)
// ============================================================

app.get('/api/project/:projectId/data/:table', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const meta = await pool.query('SELECT columns FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns);
  const tableFullName = `project_${projectId}_${table}`;
  const selectCols = ['id', 'project_user_id', ...columns.map(c => c.name)];

  let query = `SELECT ${selectCols.map(c => `"${c}"`).join(', ')} FROM "${tableFullName}"`;
  const conditions = [];
  const params = [];
  let paramIdx = 1;

  if (req.query.search && req.query.search.trim()) {
    const term = `%${req.query.search.trim()}%`;
    const placeholder = `$${paramIdx}`;
    const searchClauses = selectCols.map(col => `"${col}"::text ILIKE ${placeholder}`);
    conditions.push(`(${searchClauses.join(' OR ')})`);
    params.push(term);
    paramIdx++;
  }

  // filters
  if (req.query.filter) {
    if (typeof req.query.filter === 'object' && !Array.isArray(req.query.filter)) {
      const keys = Object.keys(req.query.filter);
      if (keys.length > 0 && !isNaN(keys[0])) {
        keys.forEach(key => {
          const f = req.query.filter[key];
          if (f.column && f.value !== undefined && columns.map(c => c.name).includes(f.column)) {
            const op = f.operator || 'eq';
            const sqlOp = opMap[op] || '=';
            if (sqlOp === 'LIKE' || sqlOp === 'NOT LIKE') {
              conditions.push(`"${f.column}" ${sqlOp} $${paramIdx}`);
              params.push(`%${f.value}%`);
            } else {
              conditions.push(`"${f.column}" ${sqlOp} $${paramIdx}`);
              params.push(f.value);
            }
            paramIdx++;
          }
        });
      }
    }
  }

  if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');

  if (req.query.sort && selectCols.includes(req.query.sort)) {
    query += ` ORDER BY "${req.query.sort}" ${req.query.order === 'desc' ? 'DESC' : 'ASC'}`;
  } else {
    query += ' ORDER BY id DESC';
  }

  if (req.query.limit) {
    const limit = Math.max(0, parseInt(req.query.limit, 10) || 50);
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    query += ` LIMIT $${paramIdx++} OFFSET $${paramIdx++}`;
    params.push(limit, offset);
  }

  try {
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/project/:projectId/data/:table', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const meta = await pool.query('SELECT columns FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns);
  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (fields.length === 0) return res.status(400).json({ error: 'No valid fields' });
  const fieldNames = fields.map(f => f.name);
  const placeholders = fields.map((_, i) => `$${i + 2}`);
  const values = fields.map(f => {
    const colMeta = columns.find(c => c.name === f.name);
    if (colMeta && (colMeta.type === 'boolean' || colMeta.type === 'bool')) {
      return req.body[f.name] === 'true' || req.body[f.name] === true;
    }
    return req.body[f.name];
  });
  const tableFullName = `project_${projectId}_${table}`;
  // Insert with a system project user? Actually we don't have one; we'll insert with NULL for now, or we need a system user for the project.
  // Let's create a system project user for admin inserts.
  let systemUserId = 0;
  const sysRes = await pool.query("SELECT id FROM project_users WHERE project_id = $1 AND email = 'system@internal'", [projectId]);
  if (sysRes.rowCount === 0) {
    const hash = await bcrypt.hash('unused', SALT_ROUNDS);
    const newSys = await pool.query("INSERT INTO project_users (project_id, email, password) VALUES ($1, 'system@internal', $2) RETURNING id", [projectId, hash]);
    systemUserId = newSys.rows[0].id;
  } else {
    systemUserId = sysRes.rows[0].id;
  }
  try {
    const result = await pool.query(`INSERT INTO "${tableFullName}" (project_user_id, ${fieldNames.map(n => `"${n}"`).join(', ')}) VALUES ($1, ${placeholders.join(', ')}) RETURNING *`, [systemUserId, ...values]);
    broadcastChange('insert', null, result.rows[0], table, projectId);
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/project/:projectId/data/:table/:id', platformAuthMiddleware, async (req, res) => {
  const { projectId, table, id } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const meta = await pool.query('SELECT columns FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns);
  const tableFullName = `project_${projectId}_${table}`;
  const oldResult = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]);
  if (oldResult.rowCount === 0) return res.status(404).json({ error: 'Row not found' });
  const oldRow = oldResult.rows[0];
  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
  const setClauses = fields.map((f, i) => `"${f.name}" = $${i + 2}`).join(', ');
  const values = [id, ...fields.map(f => req.body[f.name])];
  await pool.query(`UPDATE "${tableFullName}" SET ${setClauses} WHERE id = $1`, values);
  const newRow = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]);
  broadcastChange('update', oldRow, newRow.rows[0], table, projectId);
  res.json(newRow.rows[0]);
});

app.delete('/api/project/:projectId/data/:table/:id', platformAuthMiddleware, async (req, res) => {
  const { projectId, table, id } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const tableFullName = `project_${projectId}_${table}`;
  const oldRow = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]);
  if (oldRow.rowCount === 0) return res.status(404).json({ error: 'Row not found' });
  await pool.query(`DELETE FROM "${tableFullName}" WHERE id = $1`, [id]);
  broadcastChange('delete', oldRow.rows[0], null, table, projectId);
  res.json({ success: true });
});

// Bulk operations
app.post('/api/project/:projectId/data/:table/bulk/delete', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const { ids } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids array required' });
  const tableFullName = `project_${projectId}_${table}`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const id of ids) await client.query(`DELETE FROM "${tableFullName}" WHERE id = $1`, [id]);
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally { client.release(); }
});

app.post('/api/project/:projectId/data/:table/bulk/update', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const { ids, field, value } = req.body;
  if (!Array.isArray(ids) || ids.length === 0 || !field) return res.status(400).json({ error: 'ids array, field, and value required' });
  const tableFullName = `project_${projectId}_${table}`;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const id of ids) await client.query(`UPDATE "${tableFullName}" SET "${field}" = $1 WHERE id = $2`, [value, id]);
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally { client.release(); }
});

// ============================================================
//  WEBHOOKS (project-scoped)
// ============================================================

app.get('/api/project/:projectId/webhooks/:table', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  try {
    const result = await pool.query('SELECT id, name, url, events, headers FROM _webhooks WHERE project_id = $1 AND table_name = $2', [projectId, table]);
    res.json(result.rows.map(r => ({ ...r, events: JSON.parse(r.events || '[]'), headers: JSON.parse(r.headers || '[]') })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/project/:projectId/webhooks/:table', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  const { name, url, events, headers } = req.body;
  if (!url || !Array.isArray(events) || events.length === 0) return res.status(400).json({ error: 'URL and at least one event required' });
  try {
    await pool.query('INSERT INTO _webhooks (project_id, table_name, name, url, events, headers) VALUES ($1, $2, $3, $4, $5, $6)',
      [projectId, table, name || '', url, JSON.stringify(events), JSON.stringify(headers || [])]);
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/project/:projectId/webhooks/:id', platformAuthMiddleware, async (req, res) => {
  const { projectId, id } = req.params;
  const projCheck = await pool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, req.platformUser.id]);
  if (projCheck.rowCount === 0) return res.status(404).json({ error: 'Project not found or access denied' });
  try {
    await pool.query('DELETE FROM _webhooks WHERE id = $1 AND project_id = $2', [id, projectId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
//  USER-FACING DATA ENDPOINTS (project user)
// ============================================================

app.get('/api/user/project/data/:table', projectAuthMiddleware, async (req, res) => {
  const { table } = req.params;
  const projectId = req.projectUser.projectId;
  const meta = await pool.query('SELECT columns, privacy, column_permissions FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns);
  const privacy = JSON.parse(meta.rows[0].privacy || '{}');
  const colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
  const allowedCols = colPerms.read || columns.map(c => c.name);
  const selectCols = ['id', 'project_user_id', ...allowedCols.filter(c => c !== 'id' && c !== 'project_user_id')];
  const tableFullName = `project_${projectId}_${table}`;
  let query = `SELECT ${selectCols.map(c => `"${c}"`).join(', ')} FROM "${tableFullName}"`;
  const conditions = [];
  const params = [];
  let paramIdx = 1;
  conditions.push(`project_user_id = $${paramIdx}`);
  params.push(req.projectUser.id);
  paramIdx++;
  if (privacy.read) {
    const ruleResult = applyRule(privacy.read, req.projectUser.id, req.projectUser.email);
    if (ruleResult) {
      conditions.push(ruleResult.sql);
      params.push(...ruleResult.params);
      paramIdx += ruleResult.params.length;
    }
  }
  if (req.query.search && req.query.search.trim()) {
    const term = `%${req.query.search.trim()}%`;
    const placeholder = `$${paramIdx}`;
    const searchClauses = selectCols.map(col => `"${col}"::text ILIKE ${placeholder}`);
    conditions.push(`(${searchClauses.join(' OR ')})`);
    params.push(term);
    paramIdx++;
  }
  // filters ...
  if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
  if (req.query.sort && selectCols.includes(req.query.sort)) {
    query += ` ORDER BY "${req.query.sort}" ${req.query.order === 'desc' ? 'DESC' : 'ASC'}`;
  } else {
    query += ' ORDER BY id DESC';
  }
  if (req.query.limit) {
    const limit = Math.max(0, parseInt(req.query.limit, 10) || 50);
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    query += ` LIMIT $${paramIdx++} OFFSET $${paramIdx++}`;
    params.push(limit, offset);
  }
  try {
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/user/project/data/:table', projectAuthMiddleware, async (req, res) => {
  const { table } = req.params;
  const projectId = req.projectUser.projectId;
  const meta = await pool.query('SELECT columns, column_permissions FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns);
  const colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
  const allowedWrite = colPerms.write || columns.map(c => c.name);
  const forbidden = Object.keys(req.body).filter(f => !allowedWrite.includes(f));
  if (forbidden.length > 0) return res.status(403).json({ error: `Write permission denied for: ${forbidden.join(', ')}` });
  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (fields.length === 0) return res.status(400).json({ error: 'No valid fields' });
  const fieldNames = fields.map(f => f.name);
  const placeholders = fields.map((_, i) => `$${i + 2}`);
  const values = fields.map(f => {
    const colMeta = columns.find(c => c.name === f.name);
    if (colMeta && (colMeta.type === 'boolean' || colMeta.type === 'bool')) {
      return req.body[f.name] === 'true' || req.body[f.name] === true;
    }
    return req.body[f.name];
  });
  const tableFullName = `project_${projectId}_${table}`;
  try {
    const result = await pool.query(`INSERT INTO "${tableFullName}" (project_user_id, ${fieldNames.map(n => `"${n}"`).join(', ')}) VALUES ($1, ${placeholders.join(', ')}) RETURNING *`, [req.projectUser.id, ...values]);
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/user/project/data/:table/:id', projectAuthMiddleware, async (req, res) => {
  const { table, id } = req.params;
  const projectId = req.projectUser.projectId;
  const meta = await pool.query('SELECT columns, privacy, column_permissions FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns);
  const privacy = JSON.parse(meta.rows[0].privacy || '{}');
  const colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
  const tableFullName = `project_${projectId}_${table}`;
  const oldResult = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]);
  if (oldResult.rowCount === 0) return res.status(404).json({ error: 'Row not found' });
  const oldRow = oldResult.rows[0];
  if (oldRow.project_user_id !== req.projectUser.id) {
    if (privacy.update) {
      const ruleResult = applyRule(privacy.update, req.projectUser.id, req.projectUser.email);
      if (!ruleResult) return res.status(403).json({ error: 'Forbidden' });
      const check = await pool.query(`SELECT 1 FROM "${tableFullName}" WHERE id = $1 AND ${ruleResult.sql}`, [id, ...ruleResult.params]);
      if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden' });
    } else {
      return res.status(403).json({ error: 'You can only update your own rows' });
    }
  }
  const allowedUpdate = colPerms.update || columns.map(c => c.name);
  const forbidden = Object.keys(req.body).filter(f => !allowedUpdate.includes(f));
  if (forbidden.length > 0) return res.status(403).json({ error: `Update permission denied for: ${forbidden.join(', ')}` });
  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
  const setClauses = fields.map((f, i) => `"${f.name}" = $${i + 2}`).join(', ');
  const values = [id, ...fields.map(f => req.body[f.name])];
  await pool.query(`UPDATE "${tableFullName}" SET ${setClauses} WHERE id = $1`, values);
  const newRow = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]);
  res.json(newRow.rows[0]);
});

app.delete('/api/user/project/data/:table/:id', projectAuthMiddleware, async (req, res) => {
  const { table, id } = req.params;
  const projectId = req.projectUser.projectId;
  const meta = await pool.query('SELECT privacy FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const privacy = JSON.parse(meta.rows[0].privacy || '{}');
  const tableFullName = `project_${projectId}_${table}`;
  const oldRow = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]);
  if (oldRow.rowCount === 0) return res.status(404).json({ error: 'Row not found' });
  if (oldRow.rows[0].project_user_id !== req.projectUser.id) {
    if (privacy.delete) {
      const ruleResult = applyRule(privacy.delete, req.projectUser.id, req.projectUser.email);
      if (!ruleResult) return res.status(403).json({ error: 'Forbidden' });
      const check = await pool.query(`SELECT 1 FROM "${tableFullName}" WHERE id = $1 AND ${ruleResult.sql}`, [id, ...ruleResult.params]);
      if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden' });
    } else {
      return res.status(403).json({ error: 'You can only delete your own rows' });
    }
  }
  await pool.query(`DELETE FROM "${tableFullName}" WHERE id = $1`, [id]);
  res.json({ success: true });
});

// ============================================================
//  HELPERS
// ============================================================

const opMap = {
  'eq': '=', 'neq': '<>', 'gt': '>', 'lt': '<', 'gte': '>=', 'lte': '<=', 'contains': 'LIKE', 'not_contains': 'NOT LIKE'
};

function applyRule(rule, userId, userEmail) {
  if (!rule || !rule.trim()) return null;
  let processed = rule.replace(/@user_id/g, userId.toString()).replace(/@user_email/g, userEmail || '');
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

// WebSocket (basic broadcast)
const clients = new Map();
wss.on('connection', (ws) => {
  ws.on('message', (msg) => {
    try {
      const { type, token } = JSON.parse(msg);
      if (type === 'auth' && token) {
        const decoded = jwt.verify(token, ADMIN_JWT_SECRET);
        clients.set(ws, decoded.id);
        ws.send(JSON.stringify({ type: 'auth_ok' }));
      }
    } catch { ws.send(JSON.stringify({ type: 'error', message: 'Auth failed' })); }
  });
  ws.on('close', () => clients.delete(ws));
});

function broadcastChange(event, oldRecord, newRecord, table, projectId) {
  const msg = JSON.stringify({ type: 'item_change', event, old: oldRecord, new: newRecord, table, projectId });
  wss.clients.forEach(ws => ws.readyState === WebSocket.OPEN && ws.send(msg));
}

function triggerWebhooks(event, oldRecord, newRecord, table, projectId) {
  pool.query('SELECT url, events, headers FROM _webhooks WHERE project_id = $1 AND table_name = $2', [projectId, table])
    .then(result => {
      result.rows.forEach(({ url, events, headers }) => {
        if (events.includes(event)) {
          const hdrs = JSON.parse(headers || '[]');
          const headersObj = {};
          hdrs.forEach(h => { if (h.key) headersObj[h.key] = h.value; });
          axios.post(url, { event, old: oldRecord, new: newRecord, table, projectId }, { headers: headersObj })
            .catch(err => console.error('Webhook failed:', err.message));
        }
      });
    })
    .catch(() => {});
}

app.get('/health', async (req, res) => {
  try { await pool.query('SELECT 1'); res.send('OK'); } catch { res.status(500).send('DB connection failed'); }
});

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
