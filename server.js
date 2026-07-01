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
  if (apiKey) { if (apiKey === ADMIN_KEY) { req.platformUser = { id: 0, email: 'admin', type: 'platform', admin: true }; return next(); } }
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    if (token === ADMIN_KEY) { req.platformUser = { id: 0, email: 'admin', type: 'platform', admin: true }; return next(); }
    try { const decoded = jwt.verify(token, ADMIN_JWT_SECRET); req.platformUser = decoded; req.platformUser.admin = true; return next(); }
    catch (err) { return res.status(401).json({ error: 'Invalid platform token' }); }
  }
  return res.status(401).json({ error: 'Platform authentication required' });
}

async function dataAuthMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  let isAdmin = false; let isAnon = false;
  let projectId = req.params.projectId ? parseInt(req.params.projectId) : null;
  if (apiKey) {
    const keyResult = await pool.query("SELECT id, anon_key, admin_key FROM projects WHERE anon_key = $1 OR admin_key = $1", [apiKey]);
    if (keyResult.rowCount > 0) { const proj = keyResult.rows[0]; projectId = proj.id; if (apiKey === proj.admin_key) isAdmin = true; else if (apiKey === proj.anon_key) isAnon = true; }
    else { if (apiKey === ADMIN_KEY) isAdmin = true; else if (apiKey === ANON_KEY) isAnon = true; }
  }
  let user = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try { const decoded = jwt.verify(token, PROJECT_JWT_SECRET); user = { id: decoded.id, email: decoded.email, type: 'project_user' }; projectId = decoded.projectId; }
    catch (err) {
      try { const decoded = jwt.verify(token, ADMIN_JWT_SECRET); user = { id: decoded.id, email: decoded.email, type: 'platform_user' }; isAdmin = true; if (!projectId) projectId = req.params.projectId ? parseInt(req.params.projectId) : null; }
      catch (err2) { return res.status(401).json({ error: 'Invalid token' }); }
    }
  }
  if (!isAdmin && !isAnon && !user) return res.status(401).json({ error: 'Authentication required. Provide x-api-key or Authorization: Bearer <token>' });
  if (isAnon && !user) user = { id: -1, email: 'anon', type: 'anonymous' };
  req.projectId = projectId; req.isAdmin = isAdmin; req.user = user;
  next();
}

async function verifyProjectAccess(clientOrPool, projectId, platformUser) {
  if (platformUser.admin === true) return true;
  const res = await clientOrPool.query('SELECT id FROM projects WHERE id = $1 AND platform_user_id = $2', [projectId, platformUser.id]);
  return res.rowCount > 0;
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
    const accessToken = jwt.sign(tokenPayload, ADMIN_JWT_SECRET, { expiresIn: '7d' });
    res.json({ id: user.id, email: user.email, access_token: accessToken, token_type: 'Bearer', expires_in: 604800, expires_at: Math.floor(Date.now() / 1000) + 604800, project: projResult.rows[0] });
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
  const accessToken = jwt.sign(tokenPayload, ADMIN_JWT_SECRET, { expiresIn: '7d' });
  res.json({ id: user.id, email: user.email, access_token: accessToken, token_type: 'Bearer', expires_in: 604800, expires_at: Math.floor(Date.now() / 1000) + 604800 });
});

app.get('/api/platform/projects', platformAuthMiddleware, async (req, res) => {
  try {
    let result;
    if (req.platformUser.admin === true && req.platformUser.id === 0) {
      result = await pool.query(`SELECT p.id, p.name, p.description, p.created_at, p.auth_config, p.anon_key, p.admin_key, (SELECT COUNT(*) FROM _tables t WHERE t.project_id = p.id) AS table_count, (SELECT COUNT(*) FROM project_users u WHERE u.project_id = p.id AND u.email != 'system@internal') AS user_count FROM projects p ORDER BY p.id`);
    } else {
      result = await pool.query(`SELECT p.id, p.name, p.description, p.created_at, p.auth_config, p.anon_key, p.admin_key, (SELECT COUNT(*) FROM _tables t WHERE t.project_id = p.id) AS table_count, (SELECT COUNT(*) FROM project_users u WHERE u.project_id = p.id AND u.email != 'system@internal') AS user_count FROM projects p WHERE p.platform_user_id = $1 ORDER BY p.id`, [req.platformUser.id]);
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
  const { id } = req.params; const { name, description } = req.body;
  const hasAccess = await verifyProjectAccess(pool, id, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  await pool.query('UPDATE projects SET name = $1, description = $2 WHERE id = $3', [name || '', description || '', id]);
  res.json({ success: true });
});

app.put('/api/platform/projects/:id/settings', platformAuthMiddleware, async (req, res) => {
  const { id } = req.params; const { auth_config, regenerate_keys } = req.body;
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

app.delete('/api/platform/projects/:id', platformAuthMiddleware, async (req, res) => {
  const { id } = req.params; const { password } = req.body;
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
    const user = result.rows[0];
    const proj = await pool.query('SELECT auth_config FROM projects WHERE id = $1', [projectId]);
    const authConfig = JSON.parse(proj.rows[0].auth_config || '{}');
    const tokenExpiry = authConfig.token_expiry || 3600;
    const accessPayload = { id: user.id, email: user.email, projectId: parseInt(projectId), type: 'project_user' };
    const accessToken = jwt.sign(accessPayload, PROJECT_JWT_SECRET, { expiresIn: tokenExpiry });
    const refreshPayload = { id: user.id, projectId: parseInt(projectId), type: 'refresh' };
    const refreshToken = jwt.sign(refreshPayload, PROJECT_JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ id: user.id, email: user.email, access_token: accessToken, refresh_token: refreshToken, token_type: 'Bearer', expires_in: tokenExpiry, expires_at: Math.floor(Date.now() / 1000) + tokenExpiry });
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
  res.json({ id: user.id, email: user.email, access_token: accessToken, refresh_token: refreshToken, token_type: 'Bearer', expires_in: tokenExpiry, expires_at: Math.floor(Date.now() / 1000) + tokenExpiry });
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
    res.json({ access_token: accessToken, refresh_token: refresh_token, token_type: 'Bearer', expires_in: tokenExpiry, expires_at: Math.floor(Date.now() / 1000) + tokenExpiry });
  } catch (err) { return res.status(401).json({ error: 'Invalid refresh token' }); }
});

// Users list – exclude system@internal
app.get('/api/project/:projectId/users', platformAuthMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const meta = await pool.query("SELECT columns FROM _tables WHERE project_id = $1 AND name = 'users'", [projectId]);
  let extraCols = [];
  if (meta.rowCount > 0) extraCols = JSON.parse(meta.rows[0].columns).filter(c => c.name !== 'password' && c.name !== 'email' && c.name !== 'id');
  const selectCols = ['id', 'email', ...extraCols.map(c => `"${c.name}"`)];
  try {
    const result = await pool.query(`SELECT ${selectCols.join(', ')} FROM project_users WHERE project_id = $1 AND email != 'system@internal' ORDER BY id`, [projectId]);
    res.json(result.rows);
  } catch (err) {
    const result = await pool.query("SELECT id, email FROM project_users WHERE project_id = $1 AND email != 'system@internal' ORDER BY id", [projectId]);
    res.json(result.rows);
  }
});

app.get('/api/project/:projectId/users/:id', platformAuthMiddleware, async (req, res) => {
  const { projectId, id } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const meta = await pool.query("SELECT columns FROM _tables WHERE project_id = $1 AND name = 'users'", [projectId]);
  let extraCols = [];
  if (meta.rowCount > 0) extraCols = JSON.parse(meta.rows[0].columns).filter(c => c.name !== 'password' && c.name !== 'email' && c.name !== 'id');
  const selectCols = ['id', 'email', ...extraCols.map(c => `"${c.name}"`)];
  try {
    const result = await pool.query(`SELECT ${selectCols.join(', ')} FROM project_users WHERE id = $1 AND project_id = $2 AND email != 'system@internal'`, [id, projectId]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    const result = await pool.query("SELECT id, email FROM project_users WHERE id = $1 AND project_id = $2 AND email != 'system@internal'", [id, projectId]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  }
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
//  TABLE MANAGEMENT
// ============================================================

app.get('/api/project/:projectId/tables', platformAuthMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const result = await pool.query("SELECT name, columns, privacy, column_permissions, sort_order FROM _tables WHERE project_id = $1 ORDER BY sort_order, id", [projectId]);
  res.json(result.rows.map(t => ({ name: t.name, columns: JSON.parse(t.columns), privacy: JSON.parse(t.privacy || '{}'), column_permissions: JSON.parse(t.column_permissions || '{}'), sort_order: t.sort_order })));
});

app.post('/api/project/:projectId/tables', platformAuthMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const { name, columns } = req.body;
  if (!name || !Array.isArray(columns) || columns.length === 0) return res.status(400).json({ error: 'Name and at least one column required' });
  const safeName = name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
  if (!safeName) return res.status(400).json({ error: 'Invalid table name' });
  if (safeName === 'users') {
    const newCols = columns.filter(c => c.name !== 'email' && c.name !== 'password' && c.name !== 'id');
    const table = await pool.query('SELECT * FROM _tables WHERE project_id = $1 AND name = $2', [projectId, 'users']);
    if (table.rowCount === 0) await pool.query('INSERT INTO _tables (project_id, name, columns, privacy, sort_order) VALUES ($1, $2, $3, $4, 0)', [projectId, 'users', JSON.stringify(columns), '{}']);
    else await pool.query('UPDATE _tables SET columns = $1 WHERE project_id = $2 AND name = $3', [JSON.stringify(columns), projectId, 'users']);
    for (const c of newCols) {
      const colName = c.name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
      const type = mapType(c.type);
      let def = '';
      if (c.default !== undefined && c.default !== '') { if (type === 'BOOLEAN') def = ` DEFAULT ${c.default === 'true' ? 'TRUE' : 'FALSE'}`; else if (type === 'INTEGER' || type === 'REAL') def = ` DEFAULT ${c.default}`; else def = ` DEFAULT '${c.default.replace(/'/g, "''")}'`; }
      await pool.query(`ALTER TABLE project_users ADD COLUMN IF NOT EXISTS "${colName}" ${type}${def}`).catch(() => {});
    }
    return res.status(201).json({ name: 'users', columns });
  }
  const colDefs = columns.map(c => { const colName = c.name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase(); const type = mapType(c.type); let def = ''; if (c.default !== undefined && c.default !== '') { if (type === 'BOOLEAN') def = ` DEFAULT ${c.default === 'true' ? 'TRUE' : 'FALSE'}`; else if (type === 'INTEGER' || type === 'REAL') def = ` DEFAULT ${c.default}`; else def = ` DEFAULT '${c.default.replace(/'/g, "''")}'`; } return `"${colName}" ${type}${def}`; }).join(', ');
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
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const { columns } = req.body;
  if (!Array.isArray(columns)) return res.status(400).json({ error: 'columns array required' });
  if (name === 'users') {
    const table = await pool.query('SELECT * FROM _tables WHERE project_id = $1 AND name = $2', [projectId, 'users']);
    const oldCols = table.rowCount > 0 ? JSON.parse(table.rows[0].columns) : [];
    const newCols = columns.filter(c => !oldCols.find(oc => oc.name === c.name));
    for (const c of newCols) {
      if (c.name === 'email' || c.name === 'password' || c.name === 'id') continue;
      const colName = c.name.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
      const type = mapType(c.type);
      let def = '';
      if (c.default !== undefined && c.default !== '') { if (type === 'BOOLEAN') def = ` DEFAULT ${c.default === 'true' ? 'TRUE' : 'FALSE'}`; else if (type === 'INTEGER' || type === 'REAL') def = ` DEFAULT ${c.default}`; else def = ` DEFAULT '${c.default.replace(/'/g, "''")}'`; }
      await pool.query(`ALTER TABLE project_users ADD COLUMN IF NOT EXISTS "${colName}" ${type}${def}`).catch(() => {});
    }
    await pool.query('UPDATE _tables SET columns = $1 WHERE project_id = $2 AND name = $3', [JSON.stringify(columns), projectId, 'users']);
    return res.json({ name: 'users', columns });
  }
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
      if (c.default !== undefined && c.default !== '') { if (type === 'BOOLEAN') def = ` DEFAULT ${c.default === 'true' ? 'TRUE' : 'FALSE'}`; else if (type === 'INTEGER' || type === 'REAL') def = ` DEFAULT ${c.default}`; else def = ` DEFAULT '${c.default.replace(/'/g, "''")}'`; }
      await pool.query(`ALTER TABLE "${tableFullName}" ADD COLUMN "${colName}" ${type}${def}`).catch(() => {});
    }
    await pool.query('UPDATE _tables SET columns = $1 WHERE project_id = $2 AND name = $3', [JSON.stringify(columns), projectId, name]);
    res.json({ name, columns });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/project/:projectId/tables/:name/privacy', platformAuthMiddleware, async (req, res) => {
  const { projectId, name } = req.params;
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const { read, write, update, delete: del, column_permissions } = req.body;
  const privacy = JSON.stringify({ read: read || '', write: write || '', update: update || '', delete: del || '' });
  const columnPerms = column_permissions ? JSON.stringify(column_permissions) : null;
  if (columnPerms) await pool.query('UPDATE _tables SET privacy = $1, column_permissions = $2 WHERE project_id = $3 AND name = $4', [privacy, columnPerms, projectId, name]);
  else await pool.query('UPDATE _tables SET privacy = $1 WHERE project_id = $2 AND name = $3', [privacy, projectId, name]);
  res.json({ success: true });
});

app.delete('/api/project/:projectId/tables/:name', platformAuthMiddleware, async (req, res) => {
  const { projectId, name } = req.params;
  if (name === 'users') return res.status(400).json({ error: 'Cannot delete users table' });
  const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser);
  if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const tableFullName = `project_${projectId}_${name}`;
  try { await pool.query(`DROP TABLE IF EXISTS "${tableFullName}"`); await pool.query('DELETE FROM _tables WHERE project_id = $1 AND name = $2', [projectId, name]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
//  UNIFIED DATA CRUD
// ============================================================

app.get('/api/project/:projectId/data/:table', dataAuthMiddleware, async (req, res) => {
  const projectId = req.projectId, table = req.params.table;
  if (table === 'users') { const r = await pool.query("SELECT id, email FROM project_users WHERE project_id = $1 AND email != 'system@internal' ORDER BY id", [projectId]); return res.json(r.rows); }
  const meta = await pool.query('SELECT columns, privacy, column_permissions FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns), privacy = JSON.parse(meta.rows[0].privacy || '{}'), colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
  const allowedCols = colPerms.read || columns.map(c => c.name);
  const selectCols = ['id', ...allowedCols.filter(c => c !== 'id' && c !== 'project_user_id')];
  const tableFullName = `project_${projectId}_${table}`;
  let query = `SELECT ${selectCols.map(c => `"${c}"`).join(', ')} FROM "${tableFullName}"`;
  const conditions = [], params = []; let paramIdx = 1;
  if (!req.isAdmin) { if (privacy.read) { const rule = applyRule(privacy.read, req.user.id, req.user.email); if (rule) { conditions.push(rule.sql); params.push(...rule.params); paramIdx += rule.params.length; } else return res.json([]); } else { conditions.push(`project_user_id = $${paramIdx}`); params.push(req.user.id); paramIdx++; } }
  if (req.query.search?.trim()) { const t = `%${req.query.search.trim()}%`; conditions.push(`(${selectCols.map(c => `"${c}"::text ILIKE $${paramIdx}`).join(' OR ')})`); params.push(t); paramIdx++; }
  if (req.query.filter && typeof req.query.filter === 'object' && !Array.isArray(req.query.filter)) { Object.keys(req.query.filter).forEach(key => { const f = req.query.filter[key]; if (f.column && f.value !== undefined && columns.map(c => c.name).includes(f.column)) { const op = f.operator || 'eq', sqlOp = opMap[op] || '='; if (sqlOp === 'LIKE' || sqlOp === 'NOT LIKE') { conditions.push(`"${f.column}" ${sqlOp} $${paramIdx}`); params.push(`%${f.value}%`); } else { conditions.push(`"${f.column}" ${sqlOp} $${paramIdx}`); params.push(f.value); } paramIdx++; } }); }
  if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
  if (req.query.sort && selectCols.includes(req.query.sort)) query += ` ORDER BY "${req.query.sort}" ${req.query.order === 'desc' ? 'DESC' : 'ASC'}`; else query += ' ORDER BY id DESC';
  if (req.query.limit) { const limit = Math.max(0, parseInt(req.query.limit) || 50), offset = Math.max(0, parseInt(req.query.offset) || 0); query += ` LIMIT $${paramIdx++} OFFSET $${paramIdx++}`; params.push(limit, offset); }
  try { const result = await pool.query(query, params); res.json(result.rows); } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/project/:projectId/data/:table', dataAuthMiddleware, async (req, res) => {
  const projectId = req.projectId, table = req.params.table;
  if (table === 'users') return res.status(400).json({ error: 'Use the auth register endpoint to add users' });
  const meta = await pool.query('SELECT columns, column_permissions FROM _tables WHERE project_id = $1 AND name = $2', [projectId, table]);
  if (meta.rowCount === 0) return res.status(404).json({ error: 'Table not found' });
  const columns = JSON.parse(meta.rows[0].columns), colPerms = JSON.parse(meta.rows[0].column_permissions || '{}');
  let userId = req.user.id;
  if (req.isAdmin) { const adminEmail = req.user.email || 'admin@platform'; let userRec = await pool.query("SELECT id FROM project_users WHERE project_id = $1 AND email = $2", [projectId, adminEmail]); if (userRec.rowCount === 0) { const hash = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), SALT_ROUNDS); const nu = await pool.query("INSERT INTO project_users (project_id, email, password) VALUES ($1, $2, $3) RETURNING id", [projectId, adminEmail, hash]); userId = nu.rows[0].id; } else userId = userRec.rows[0].id; }
  else { const allowedWrite = colPerms.write || columns.map(c => c.name); const forbidden = Object.keys(req.body).filter(f => !allowedWrite.includes(f)); if (forbidden.length) return res.status(403).json({ error: `Write permission denied for: ${forbidden.join(', ')}` }); }
  if (req.body.id) { const tableFullName = `project_${projectId}_${table}`; const existing = await pool.query(`SELECT 1 FROM "${tableFullName}" WHERE id = $1`, [req.body.id]); if (existing.rowCount > 0) return res.status(400).json({ error: 'A row with this ID already exists' }); }
  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (!fields.length) return res.status(400).json({ error: 'No valid fields' });
  const tableFullName = `project_${projectId}_${table}`;
  let finalQuery = `INSERT INTO "${tableFullName}" (`; const valPlaceholders = []; let valIdx = 1;
  if (req.body.id) { finalQuery += 'id, '; valPlaceholders.push(`$${valIdx++}`); }
  finalQuery += 'project_user_id, '; valPlaceholders.push(`$${valIdx++}`);
  finalQuery += fields.map(f => `"${f.name}"`).join(', '); valPlaceholders.push(...fields.map(() => `$${valIdx++}`));
  finalQuery += `) VALUES (${valPlaceholders.join(', ')}) RETURNING *`;
  const finalValues = []; if (req.body.id) finalValues.push(req.body.id); finalValues.push(userId);
  finalValues.push(...fields.map(f => { const colMeta = columns.find(c => c.name === f.name); if (colMeta && (colMeta.type === 'boolean' || colMeta.type === 'bool')) return req.body[f.name] === 'true' || req.body[f.name] === true; return req.body[f.name]; }));
  try { const result = await pool.query(finalQuery, finalValues); const newRow = result.rows[0]; delete newRow.project_user_id; res.status(201).json(newRow); } catch (err) { res.status(400).json({ error: err.message }); }
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
  if (!req.isAdmin && old.rows[0].project_user_id !== req.user.id) { if (privacy.update) { const rule = applyRule(privacy.update, req.user.id, req.user.email); if (!rule) return res.status(403).json({ error: 'Forbidden' }); const check = await pool.query(`SELECT 1 FROM "${tableFullName}" WHERE id = $1 AND ${rule.sql}`, [id, ...rule.params]); if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden' }); } else return res.status(403).json({ error: 'You can only update your own rows' }); }
  const fields = columns.filter(c => req.body[c.name] !== undefined);
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
  const setClauses = fields.map((f, i) => `"${f.name}" = $${i + 2}`).join(', '); const values = [id, ...fields.map(f => req.body[f.name])];
  await pool.query(`UPDATE "${tableFullName}" SET ${setClauses} WHERE id = $1`, values);
  const newRow = await pool.query(`SELECT * FROM "${tableFullName}" WHERE id = $1`, [id]); delete newRow.rows[0].project_user_id; res.json(newRow.rows[0]);
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
  if (!req.isAdmin && old.rows[0].project_user_id !== req.user.id) { if (privacy.delete) { const rule = applyRule(privacy.delete, req.user.id, req.user.email); if (!rule) return res.status(403).json({ error: 'Forbidden' }); const check = await pool.query(`SELECT 1 FROM "${tableFullName}" WHERE id = $1 AND ${rule.sql}`, [id, ...rule.params]); if (check.rowCount === 0) return res.status(403).json({ error: 'Forbidden' }); } else return res.status(403).json({ error: 'You can only delete your own rows' }); }
  await pool.query(`DELETE FROM "${tableFullName}" WHERE id = $1`, [id]); res.json({ success: true });
});

// Bulk endpoints
app.post('/api/project/:projectId/data/:table/bulk/delete', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params; const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser); if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const { ids } = req.body; if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids array required' });
  const tableFullName = `project_${projectId}_${table}`; const client = await pool.connect();
  try { await client.query('BEGIN'); for (const id of ids) await client.query(`DELETE FROM "${tableFullName}" WHERE id = $1`, [id]); await client.query('COMMIT'); res.json({ success: true }); }
  catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
});

app.post('/api/project/:projectId/data/:table/bulk/update', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params; const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser); if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const { ids, field, value } = req.body; if (!Array.isArray(ids) || ids.length === 0 || !field) return res.status(400).json({ error: 'ids array, field, and value required' });
  const tableFullName = `project_${projectId}_${table}`; const client = await pool.connect();
  try { await client.query('BEGIN'); for (const id of ids) await client.query(`UPDATE "${tableFullName}" SET "${field}" = $1 WHERE id = $2`, [value, id]); await client.query('COMMIT'); res.json({ success: true }); }
  catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
});

// Webhooks
app.get('/api/project/:projectId/webhooks/:table', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params; const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser); if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const result = await pool.query('SELECT id, name, url, events, headers FROM _webhooks WHERE project_id = $1 AND table_name = $2', [projectId, table]);
  res.json(result.rows.map(r => ({ ...r, events: JSON.parse(r.events || '[]'), headers: JSON.parse(r.headers || '[]') })));
});

app.post('/api/project/:projectId/webhooks/:table', platformAuthMiddleware, async (req, res) => {
  const { projectId, table } = req.params; const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser); if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  const { name, url, events, headers } = req.body; if (!url || !Array.isArray(events) || events.length === 0) return res.status(400).json({ error: 'URL and at least one event required' });
  await pool.query('INSERT INTO _webhooks (project_id, table_name, name, url, events, headers) VALUES ($1, $2, $3, $4, $5, $6)', [projectId, table, name || '', url, JSON.stringify(events), JSON.stringify(headers || [])]);
  res.status(201).json({ success: true });
});

app.delete('/api/project/:projectId/webhooks/:id', platformAuthMiddleware, async (req, res) => {
  const { projectId, id } = req.params; const hasAccess = await verifyProjectAccess(pool, projectId, req.platformUser); if (!hasAccess) return res.status(404).json({ error: 'Project not found or access denied' });
  await pool.query('DELETE FROM _webhooks WHERE id = $1 AND project_id = $2', [id, projectId]); res.json({ success: true });
});

// ============================================================
//  HELPERS
// ============================================================
const opMap = { 'eq': '=', 'neq': '<>', 'gt': '>', 'lt': '<', 'gte': '>=', 'lte': '<=', 'contains': 'LIKE', 'not_contains': 'NOT LIKE' };

function applyRule(rule, userId, userEmail) {
  if (!rule || !rule.trim()) return null;
  let processed = rule.replace(/@user_id/g, userId.toString()).replace(/@user_email/g, userEmail || '');
  if (processed.includes(' eq ')) { const parts = processed.split(' '); const col = parts[0]; const valuePart = parts.slice(2).join(' '); if (valuePart.includes(',')) { const values = valuePart.split(',').map(v => v.trim()); const placeholders = values.map((_, i) => `$${i + 1}`); return { sql: `"${col}" IN (${placeholders.join(',')})`, params: values }; } }
  let sql = processed; const parts = sql.split(' '); if (parts.length >= 3 && opMap[parts[1]]) { parts[1] = opMap[parts[1]]; if (parts[1] === 'LIKE' || parts[1] === 'NOT LIKE') parts[2] = `'%${parts[2].replace(/'/g, '')}%'`; sql = parts.join(' '); }
  return { sql, params: [] };
}

function mapType(type) {
  switch (type) { case 'int': case 'int8': case 'integer': return 'INTEGER'; case 'float': case 'number': return 'REAL'; case 'boolean': case 'bool': return 'BOOLEAN'; case 'date': return 'DATE'; case 'datetime': return 'TIMESTAMP'; default: return 'TEXT'; }
}

// WebSocket
const clients = new Map();
wss.on('connection', (ws) => {
  ws.on('message', (msg) => { try { const { type, token } = JSON.parse(msg); if (type === 'auth' && token) { const decoded = jwt.verify(token, ADMIN_JWT_SECRET); clients.set(ws, decoded.id); ws.send(JSON.stringify({ type: 'auth_ok' })); } } catch { ws.send(JSON.stringify({ type: 'error', message: 'Auth failed' })); } });
  ws.on('close', () => clients.delete(ws));
});

function broadcastChange(event, oldRecord, newRecord, table, projectId) { const msg = JSON.stringify({ type: 'item_change', event, old: oldRecord, new: newRecord, table, projectId }); wss.clients.forEach(ws => ws.readyState === WebSocket.OPEN && ws.send(msg)); }

function triggerWebhooks(event, oldRecord, newRecord, table, projectId) { pool.query('SELECT url, events, headers FROM _webhooks WHERE project_id = $1 AND table_name = $2', [projectId, table]).then(result => { result.rows.forEach(({ url, events, headers }) => { if (events.includes(event)) { const hdrs = JSON.parse(headers || '[]'); const headersObj = {}; hdrs.forEach(h => { if (h.key) headersObj[h.key] = h.value; }); axios.post(url, { event, old: oldRecord, new: newRecord, table, projectId }, { headers: headersObj }).catch(err => console.error('Webhook failed:', err.message)); } }); }).catch(() => {}); }

app.get('/health', async (req, res) => { try { await pool.query('SELECT 1'); res.send('OK'); } catch { res.status(500).send('DB connection failed'); } });

initDb().then(() => { server.listen(PORT, '0.0.0.0', () => { startupLog(`Server running on port ${PORT}`); }); }).catch(err => { startupLog('FATAL: ' + err.message); process.exit(1); });
