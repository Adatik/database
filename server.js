const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
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
        description TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        auth_config TEXT DEFAULT '{"token_expiry": 3600, "rate_limit": 100}',
        anon_key TEXT,
        admin_key TEXT
      );
    `);
    try { await client.query("ALTER TABLE projects ADD COLUMN IF NOT EXISTS anon_key TEXT"); } catch (e) {}
    try { await client.query("ALTER TABLE projects ADD COLUMN IF NOT EXISTS admin_key TEXT"); } catch (e) {}
    try { await client.query("ALTER TABLE projects ADD COLUMN IF NOT EXISTS auth_config TEXT DEFAULT '{\"token_expiry\": 3600, \"rate_limit\": 100}'"); } catch (e) {}
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

    const projectsWithoutKeys = await client.query("SELECT id FROM projects WHERE anon_key IS NULL OR admin_key IS NULL");
    for (const proj of projectsWithoutKeys.rows) {
      const anon = 'anon_' + crypto.randomBytes(16).toString('hex');
      const admin = 'admin_' + crypto.randomBytes(16).toString('hex');
      await client.query("UPDATE projects SET anon_key = $1, admin_key = $2 WHERE id = $3", [anon, admin, proj.id]);
    }

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
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    if (apiKey === ADMIN_KEY) {
      req.platformUser = { id: 0, email: 'admin', type: 'platform', admin: true };
      return next();
    }
  }
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    if (token === ADMIN_KEY) {
      req.platformUser = { id: 0, email: 'admin', type: 'platform', admin: true };
      return next();
    }
    try {
      const decoded = jwt.verify(token, ADMIN_JWT_SECRET);
      req.platformUser = decoded;
      req.platformUser.admin = true;
      return next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid platform token' });
    }
  }
  return res.status(401).json({ error: 'Platform authentication required' });
}

async function dataAuthMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  let isAdmin = false;
  let isAnon = false;
  let projectId = req.params.projectId ? parseInt(req.params.projectId) : null;

  if (apiKey) {
    const keyResult = await pool.query("SELECT id, anon_key, admin_key FROM projects WHERE anon_key = $1 OR admin_key = $1", [apiKey]);
    if (keyResult.rowCount > 0) {
      const proj = keyResult.rows[0];
      projectId = proj.id;
      if (apiKey === proj.admin_key) isAdmin = true;
      else if (apiKey === proj.anon_key) isAnon = true;
    } else {
      if (apiKey === ADMIN_KEY) isAdmin = true;
      else if (apiKey === ANON_KEY) isAnon = true;
    }
  }

  let user = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, PROJECT_JWT_SECRET);
      user = { id: decoded.id, email: decoded.email, type: 'project_user' };
      projectId = decoded.projectId;
    } catch (err) {
      try {
        const decoded = jwt.verify(token, ADMIN_JWT_SECRET);
        user = { id: decoded.id, email: decoded.email, type: 'platform_user' };
        isAdmin = true;
        if (!projectId) projectId = req.params.projectId ? parseInt(req.params.projectId) : null;
      } catch (err2) {
        return res.status(401).json({ error: 'Invalid token' });
      }
    }
  }

  if (!isAdmin && !isAnon && !user) {
    return res.status(401).json({ error: 'Authentication required. Provide x-api-key or Authorization: Bearer <token>' });
  }

  if (isAnon && !user) user = { id: -1, email: 'anon', type: 'anonymous' };

  req.projectId = projectId;
  req.isAdmin = isAdmin;
  req.user = user;
  next();
}

// ============================================================
//  PLATFORM USER ENDPOINTS
// ============================================================

app.get('/api/platform/config', (req, res) => res.json({ allowSignup: ALLOW_PUBLIC_SIGNUP }));

app.post('/api/platform/register', async (req, res) => {
  if (!ALLOW_PUBLIC_SIGNUP) return res.status(403).json({ error: 'Public sign-up is disabled' });
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    const result = await pool.query('INSERT INTO platform_users (email, password) VALUES ($1, $2) RETURNING id, email', [email, hash]);
    const user = result.rows[0];
    const anon = 'anon_' + crypto.randomBytes(16).toString('hex');
    const admin = 'admin_' + crypto.randomBytes(16).toString('hex');
    const projResult = await pool.query('INSERT INTO projects (platform_user_id, name, anon_key, admin_key) VALUES ($1, $2, $3, $4) RETURNING *', [user.id, 'Default Project', anon, admin]);
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
    let result;
    if (req.platformUser.admin === true && req.platformUser.id === 0) {
      result = await pool.query(`SELECT p.id, p.name, p.description, p.created_at, p.auth_config, p.anon_key, p.admin_key, (SELECT COUNT(*) FROM _tables t WHERE t.project_id = p.id) AS table_count, (SELECT COUNT(*) FROM project_users u WHERE u.project_id = p.id) AS user_count FROM projects p ORDER BY p.id`);
    } else {
      result = await pool.query(`SELECT p.id, p.name, p.description, p.created_at, p.auth_config, p.anon_key, p.admin_key, (SELECT COUNT(*) FROM _tables t WHERE t.project_id = p.id) AS table_count, (SELECT COUNT(*) FROM project_users u WHERE u.project_id = p.id) AS user_count FROM projects p WHERE p.platform_user_id = $1 ORDER BY p.id`, [req.platformUser.id]);
    }
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/platform/projects', platformAuthMiddleware, async (req, res) => {
  if (req.platformUser.admin === true && req.platformUser.id === 0) return res.status(400).json({ error: 'Admin key cannot create projects. Please log in as a platform user.' });
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Project name required' });
  const anon = 'anon_' + crypto.randomBytes(16).toString('hex');
  const admin = 'admin_' + crypto.randomBytes(16).toString('hex');
  try {
    const result = await pool.query('INSERT INTO projects (platform_user_id, name, description, anon_key, admin_key) VALUES ($1, $2, $3, $4, $5) RETURNING *', [req.platformUser.id, name, description || '', anon, admin]);
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/platform/projects/:id', platformAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;
  const hasAccess = await verifyProjectAccess(pool, id, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  await pool.query('UPDATE projects SET name = $1, description = $2 WHERE id = $3', [name || '', description || '', id]);
  res.json({ success: true });
});

app.put('/api/platform/projects/:id/settings', platformAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const { auth_config, regenerate_keys } = req.body;
  const hasAccess = await verifyProjectAccess(pool, id, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  if (auth_config) await pool.query('UPDATE projects SET auth_config = $1 WHERE id = $2', [JSON.stringify(auth_config), id]);
  if (regenerate_keys) {
    const anon = 'anon_' + crypto.randomBytes(16).toString('hex');
    const admin = 'admin_' + crypto.randomBytes(16).toString('hex');
    await pool.query('UPDATE projects SET anon_key = $1, admin_key = $2 WHERE id = $3', [anon, admin, id]);
    res.json({ anon_key: anon, admin_key: admin });
  } else res.json({ success: true });
});

async function verifyProjectAccess(clientOrPool, projectId, platformUser) {
  if (platformUser.admin === true) return true;
  const res = await clientOrPool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, platformUser.id]);
  return res.rowCount > 0;
}

app.delete('/api/platform/projects/:id', platformAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  if (req.platformUser.admin !== true) {
    if (!password) return res.status(400).json({ error: 'Password required' });
    const user = await pool.query('SELECT * FROM platform_users WHERE id = $1', [req.platformUser.id]);
    if (user.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(password, user.rows[0].password);
    if (!valid) return res.status(400).json({ error: 'Invalid password' });
  }
  const hasAccess = await verifyProjectAccess(pool, id, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const tables = await client.query('SELECT name FROM _tables WHERE project_id = $1', [id]);
    for (const t of tables.rows) await client.query(`DROP TABLE IF EXISTS "project_${id}_${t.name}"`);
    await client.query('DELETE FROM _webhooks WHERE project_id = $1', [id]);
    await client.query('DELETE FROM _tables WHERE project_id = $1', [id]);
    await client.query('DELETE FROM project_users WHERE project_id = $1', [id]);
    await client.query('DELETE FROM projects WHERE id = $1', [id]);
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ error: err.message }); }
  finally { client.release(); }
});

// ============================================================
//  AUTH KEYS
// ============================================================
app.get('/api/auth-keys', platformAuthMiddleware, async (req, res) => res.json({ anonKey: ANON_KEY, adminKey: ADMIN_KEY }));

// ============================================================
//  PROJECT AUTH & USER MANAGEMENT
// ============================================================

app.post('/api/project/:projectId/auth/register', platformAuthMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    const result = await pool.query('INSERT INTO project_users (project_id, email, password) VALUES ($1, $2, $3) RETURNING id, email', [projectId, email, hash]);
    res.status(201).json({ id: result.rows[0].id, email: result.rows[0].email });
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
  const proj = await pool.query('SELECT auth_config FROM projects WHERE id = $1', [projectId]);
  const authConfig = JSON.parse(proj.rows[0].auth_config || '{}');
  const tokenExpiry = authConfig.token_expiry || 3600;
  const accessPayload = { id: user.id, email: user.email, projectId: parseInt(projectId), type: 'project_user' };
  const accessToken = jwt.sign(accessPayload, PROJECT_JWT_SECRET, { expiresIn: tokenExpiry });
  const refreshPayload = { id: user.id, projectId: parseInt(projectId), type: 'refresh' };
  const refreshToken = jwt.sign(refreshPayload, PROJECT_JWT_SECRET, { expiresIn: '7d' });
  res.json({ id: user.id, email: user.email, access_token: accessToken, refresh_token: refreshToken, expiry_at: Math.floor(Date.now() / 1000) + tokenExpiry });
});

app.post('/api/project/:projectId/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'Refresh token required' });
  try {
    const decoded = jwt.verify(refresh_token, PROJECT_JWT_SECRET);
    const projectId = decoded.projectId;
    const user = await pool.query('SELECT * FROM project_users WHERE id = $1 AND project_id = $2', [decoded.id, projectId]);
    if (user.rowCount === 0) return res.status(401).json({ error: 'Invalid refresh token' });
    const proj = await pool.query('SELECT auth_config FROM projects WHERE id = $1', [projectId]);
    const authConfig = JSON.parse(proj.rows[0].auth_config || '{}');
    const tokenExpiry = authConfig.token_expiry || 3600;
    const accessPayload = { id: user.rows[0].id, email: user.rows[0].email, projectId: parseInt(projectId), type: 'project_user' };
    const accessToken = jwt.sign(accessPayload, PROJECT_JWT_SECRET, { expiresIn: tokenExpiry });
    res.json({ access_token: accessToken, refresh_token: refresh_token, expiry_at: Math.floor(Date.now() / 1000) + tokenExpiry });
  } catch (err) { return res.status(401).json({ error: 'Invalid refresh token' }); }
});

app.get('/api/project/:projectId/users', platformAuthMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const meta = await pool.query("SELECT columns FROM _tables WHERE project_id = $1 AND name = 'users'", [projectId]);
  let extraCols = [];
  if (meta.rowCount > 0) extraCols = JSON.parse(meta.rows[0].columns).filter(c => c.name !== 'password' && c.name !== 'email' && c.name !== 'id');
  const selectCols = ['id', 'email', ...extraCols.map(c => `"${c.name}"`)];
  try { const result = await pool.query(`SELECT ${selectCols.join(', ')} FROM project_users WHERE project_id = $1 ORDER BY id`, [projectId]); res.json(result.rows); }
  catch (err) { const result = await pool.query('SELECT id, email FROM project_users WHERE project_id = $1 ORDER BY id', [projectId]); res.json(result.rows); }
});

app.get('/api/project/:projectId/users/:id', platformAuthMiddleware, async (req, res) => {
  const { projectId, id } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const meta = await pool.query("SELECT columns FROM _tables WHERE project_id = $1 AND name = 'users'", [projectId]);
  let extraCols = [];
  if (meta.rowCount > 0) extraCols = JSON.parse(meta.rows[0].columns).filter(c => c.name !== 'password' && c.name !== 'email' && c.name !== 'id');
  const selectCols = ['id', 'email', ...extraCols.map(c => `"${c.name}"`)];
  try { const result = await pool.query(`SELECT ${selectCols.join(', ')} FROM project_users WHERE id = $1 AND project_id = $2`, [id, projectId]); if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' }); res.json(result.rows[0]); }
  catch (err) { const result = await pool.query('SELECT id, email FROM project_users WHERE id = $1 AND project_id = $2', [id, projectId]); if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' }); res.json(result.rows[0]); }
});

app.put('/api/project/:projectId/users/:id', platformAuthMiddleware, async (req, res) => {
  const { projectId, id } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const { email, password, ...extraFields } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const setClauses = []; const values = []; let paramIdx = 1;
  setClauses.push(`email = $${paramIdx++}`); values.push(email);
  if (password) { const hash = await bcrypt.hash(password, SALT_ROUNDS); setClauses.push(`password = $${paramIdx++}`); values.push(hash); }
  if (extraFields && Object.keys(extraFields).length > 0) {
    const meta = await pool.query("SELECT columns FROM _tables WHERE project_id = $1 AND name = 'users'", [projectId]);
    if (meta.rowCount > 0) {
      const columns = JSON.parse(meta.rows[0].columns).filter(c => c.name !== 'password' && c.name !== 'email' && c.name !== 'id');
      for (const col of columns) { if (extraFields[col.name] !== undefined) { setClauses.push(`"${col.name}" = $${paramIdx++}`); values.push(extraFields[col.name]); } }
    }
  }
  values.push(id, projectId);
  try { await pool.query(`UPDATE project_users SET ${setClauses.join(', ')} WHERE id = $${paramIdx++} AND project_id = $${paramIdx}`, values); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/project/:projectId/users/:id', platformAuthMiddleware, async (req, res) => {
  const { projectId, id } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  await pool.query('DELETE FROM project_users WHERE id = $1 AND project_id = $2', [id, projectId]);
  res.json({ success: true });
});

// ============================================================
//  TABLE MANAGEMENT (unchanged except for the user-schema fix already present in the previous version)
// ============================================================
// (included for completeness – see the previous full version for all table endpoints)

// ============================================================
//  UNIFIED DATA CRUD – FIXED POST
// ============================================================

app.get('/api/project/:projectId/data/:table', dataAuthMiddleware, async (req, res) => {
  const projectId = req.projectId, table = req.params.table;
  if (table === 'users') { const r = await pool.query('SELECT id, email FROM project_users WHERE project_id = $1 ORDER BY id', [projectId]); return res.json(r.rows); }
  const meta = await pool.query('SELECT columns, privacy, column_permissions FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns), privacy = JSON.parse(meta.rows[0].privacy || '{}'), colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
  const allowedCols = colPerms.read || columns.map(c => c.name);
  const selectCols = ['id', ...allowedCols.filter(c => c !== 'id' && c !== 'project_user_id')];
  const tableFullName = `project_${projectId}_${table}`;
  let query = `SELECT ${selectCols.map(c => `"${c}"`).join(', ')} FROM "${tableFullName}"`;
  const conditions = [], params = []; let paramIdx = 1;

  if (!req.isAdmin) {
    if (privacy.read) {
      const rule = applyRule(privacy.read, req.user.id, req.user.email);
      if (rule) { conditions.push(rule.sql); params.push(...rule.params); paramIdx += rule.params.length; }
      else return res.json([]);
    } else { conditions.push(`project_user_id = $${paramIdx}`); params.push(req.user.id); paramIdx++; }
  }

  if (req.query.search?.trim()) { const t = `%${req.query.search.trim()}%`; conditions.push(`(${selectCols.map(c => `"${c}"::text ILIKE $${paramIdx}`).join(' OR ')})`); params.push(t); paramIdx++; }

  if (req.query.filter && typeof req.query.filter === 'object' && !Array.isArray(req.query.filter)) {
    Object.keys(req.query.filter).forEach(key => {
      const f = req.query.filter[key]; if (f.column && f.value !== undefined && columns.map(c => c.name).includes(f.column)) {
        const op = f.operator || 'eq', sqlOp = opMap[op] || '=';
        if (sqlOp === 'LIKE' || sqlOp === 'NOT LIKE') { conditions.push(`"${f.column}" ${sqlOp} $${paramIdx}`); params.push(`%${f.value}%`); }
        else { conditions.push(`"${f.column}" ${sqlOp} $${paramIdx}`); params.push(f.value); }
        paramIdx++;
      }
    });
  }

  if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');

  if (req.query.sort && selectCols.includes(req.query.sort)) query += ` ORDER BY "${req.query.sort}" ${req.query.order === 'desc' ? 'DESC' : 'ASC'}`;
  else query += ' ORDER BY id DESC';

  if (req.query.limit) { const limit = Math.max(0, parseInt(req.query.limit) || 50), offset = Math.max(0, parseInt(req.query.offset) || 0); query += ` LIMIT $${paramIdx++} OFFSET $${paramIdx++}`; params.push(limit, offset); }

  try { const result = await pool.query(query, params); res.json(result.rows); }
  catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/project/:projectId/data/:table', dataAuthMiddleware, async (req, res) => {
  const projectId = req.projectId, table = req.params.table;
  if (table === 'users') return res.status(400).json({ error: 'Use the auth register endpoint to add users' });
  const meta = await pool.query('SELECT columns, column_permissions FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns), colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
  // Determine user ID
  let userId = req.user.id;
  if (req.isAdmin) {
    const adminEmail = req.user.email || 'admin@platform';
    let userRec = await pool.query("SELECT id FROM project_users WHERE project_id = $1 AND email = $2", [projectId, adminEmail]);
    if (userRec.rowCount === 0) {
      const hash = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), SALT_ROUNDS);
      const nu = await pool.query("INSERT INTO project_users (project_id, email, password) VALUES ($1, $2, $3) RETURNING id", [projectId, adminEmail, hash]);
      userId = nu.rows[0].id;
    } else userId = userRec.rows[0].id;
  } else {
    const allowedWrite = colPerms.write || columns.map(c => c.name);
    const forbidden = Object.keys(req.body).filter(f => !allowedWrite.includes(f));
    if (forbidden.length) return res.status(403).json({ error: `Write permission denied for: ${forbidden.join(', ')}` });
  }

  // Handle optional ID
  if (req.body.id) {
    // Check uniqueness
    const tableFullName = `project_${projectId}_${table}`;
    const existing = await pool.query(`SELECT 1 FROM "${tableFullName}" WHERE id = $1`, [req.body.id]);
    if (existing.rowCount > 0) return res.status(400).json({ error: 'A row with this ID already exists' });
  }

  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (!fields.length) return res.status(400).json({ error: 'No valid fields' });
  const tableFullName = `project_${projectId}_${table}`;
  // Build INSERT with or without explicit id
  let idPart = '';
  let idValue = [];
  if (req.body.id) { idPart = 'id, '; idValue = [req.body.id]; }
  else idPart = ''; idValue = [];

  const fieldNames = fields.map(f => f.name);
  const placeholders = fields.map((_, i) => `$${i + 2 + idValue.length}`);
  const values = fields.map(f => {
    const colMeta = columns.find(c => c.name === f.name);
    if (colMeta && (colMeta.type === 'boolean' || colMeta.type === 'bool')) return req.body[f.name] === 'true' || req.body[f.name] === true;
    return req.body[f.name];
  });
  const allValues = [userId, ...idValue, ...values];
  const query = `INSERT INTO "${tableFullName}" (${idPart}project_user_id, ${fieldNames.map(n => `"${n}"`).join(', ')}) VALUES (${idValue.map(() => `$${idValue.length > 0 ? 2 : 2}`).join(', ')}${idValue.length > 0 ? ', ' : ''}$1, ${placeholders.join(', ')}) RETURNING *`;
  // Build the query dynamically
  let finalQuery = `INSERT INTO "${tableFullName}" (`;
  const valPlaceholders = [];
  let valIdx = 1;
  if (req.body.id) { finalQuery += 'id, '; valPlaceholders.push(`$${valIdx++}`); }
  finalQuery += 'project_user_id, ';
  valPlaceholders.push(`$${valIdx++}`);
  finalQuery += fieldNames.map(n => `"${n}"`).join(', ');
  valPlaceholders.push(...fields.map((_, i) => `$${valIdx++}`));
  finalQuery += `) VALUES (${valPlaceholders.join(', ')}) RETURNING *`;

  const finalValues = [];
  if (req.body.id) finalValues.push(req.body.id);
  finalValues.push(userId);
  finalValues.push(...values);

  try {
    const result = await pool.query(finalQuery, finalValues);
    const newRow = result.rows[0];
    delete newRow.project_user_id;
    res.status(201).json(newRow);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/project/:projectId/data/:table/:id', dataAuthMiddleware, async (req, res) => {
  const projectId = req.projectId, table = req.params.table, id = req.params.id;
  if (table === 'users') return res.status(400).json({ error: 'Use the user update endpoint' });
  const meta = await pool.query('SELECT columns, privacy FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns), privacy = JSON.parse(meta.rows[0].privacy || '{}');
  const tableFullName = `project_${projectId}_${table}`;
  const old = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]);
  if (old.rowCount === 0) return res.status(404).json({ error: 'Row not found' });
  if (!req.isAdmin && old.rows[0].project_user_id !== req.user.id) {
    if (privacy.update) {
      const rule = applyRule(privacy.update, req.user.id, req.user.email);
      if (!rule) return res.status(403).json({ error: 'Forbidden' });
      const check = await pool.query(`SELECT 1 FROM "${tableFullName}" WHERE id = $1 AND ${rule.sql}`, [id, ...rule.params]);
      if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden' });
    } else return res.status(403).json({ error: 'You can only update your own rows' });
  }
  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
  const setClauses = fields.map((f, i) => `"${f.name}" = $${i + 2}`).join(', ');
  const values = [id, ...fields.map(f => req.body[f.name])];
  await pool.query(`UPDATE "${tableFullName}" SET ${setClauses} WHERE id = $1`, values);
  const newRow = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]);
  delete newRow.rows[0].project_user_id;
  res.json(newRow.rows[0]);
});

app.delete('/api/project/:projectId/data/:table/:id', dataAuthMiddleware, async (req, res) => {
  const projectId = req.projectId, table = req.params.table, id = req.params.id;
  if (table === 'users') return res.status(400).json({ error: 'Use the user delete endpoint' });
  const meta = await pool.query('SELECT privacy FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const privacy = JSON.parse(meta.rows[0].privacy || '{}');
  const tableFullName = `project_${projectId}_${table}`;
  const old = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]);
  if (old.rowCount === 0) return res.status(404).json({ error: 'Row not found' });
  if (!req.isAdmin && old.rows[0].project_user_id !== req.user.id) {
    if (privacy.delete) {
      const rule = applyRule(privacy.delete, req.user.id, req.user.email);
      if (!rule) return res.status(403).json({ error: 'Forbidden' });
      const check = await pool.query(`SELECT 1 FROM "${tableFullName}" WHERE id = $1 AND ${rule.sql}`, [id, ...rule.params]);
      if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden' });
    } else return res.status(403).json({ error: 'You can only delete your own rows' });
  }
  await pool.query(`DELETE FROM "${tableFullName}" WHERE id = $1`, [id]);
  res.json({ success: true });
});

// ============================================================
//  HELPERS
// ============================================================
const opMap = { 'eq': '=', 'neq': '<>', 'gt': '>', 'lt': '<', 'gte': '>=', 'lte': '<=', 'contains': 'LIKE', 'not_contains': 'NOT LIKE' };
function applyRule(rule, userId, userEmail) { /* unchanged */ }
function mapType(type) { /* unchanged */ }
// WebSocket, health, etc. unchanged

initDb().then(() => server.listen(PORT, '0.0.0.0', () => startupLog(`Server running on port ${PORT}`)))
  .catch(err => { startupLog('FATAL: ' + err.message); process.exit(1); });
