// backend-service/app.js
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import * as mysql from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import Prometheus from 'prom-client';

dotenv.config();

const app = express();

// Prometheus setup
const register = new Prometheus.Registry();
Prometheus.collectDefaultMetrics({ register });

// Custom metrics
const httpCounter = new Prometheus.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'code'],
});
const httpHistogram = new Prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'code'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2],
});
const dbCounter = new Prometheus.Counter({
  name: 'db_query_total',
  help: 'Total number of database queries',
  labelNames: ['operation'],
});
const dbHistogram = new Prometheus.Histogram({
  name: 'db_query_duration_seconds',
  help: 'Database query duration in seconds',
  labelNames: ['operation'],
  buckets: [0.001, 0.01, 0.1, 1],
});

// Register custom metrics
register.registerMetric(httpCounter);
register.registerMetric(httpHistogram);
register.registerMetric(dbCounter);
register.registerMetric(dbHistogram);

// Security & parsing
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      fontSrc: ["'self'"],
      imgSrc: ["'self'"],
    }
  }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DB,
  waitForConnections: true,
  connectionLimit: 10,
});

// Initialize DB with retries
async function initDatabase() {
  let retries = 5;
  while (retries) {
    try {
      const connection = await pool.getConnection();
      console.log('✅ Successfully connected to database');
      connection.release();
      break;
    } catch (err) {
      console.error(`❌ Database connection failed (${retries} retries):`, err.message);
      retries--;
      if (retries === 0) process.exit(1);
      await new Promise(res => setTimeout(res, 5000));
    }
  }
}

// Middleware to collect HTTP metrics
app.use((req, res, next) => {
  const route = req.route?.path || req.path;
  const endTimer = httpHistogram.startTimer({ method: req.method, route });
  res.on('finish', () => {
    httpCounter.inc({ method: req.method, route, code: res.statusCode });
    endTimer({ code: res.statusCode });
  });
  next();
});

// DB helper with metrics
async function execWithMetrics(sql, params) {
  const operation = sql.trim().split(' ')[0];
  const endDb = dbHistogram.startTimer({ operation });
  const result = await pool.query(sql, params);
  endDb();
  dbCounter.inc({ operation });
  return result;
}

// JWT helpers
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
}
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/, '');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Unauthorized' });
  }
}

// Utility: ensure no existing pending/reviewed objection
async function canSubmit(farmerId) {
  const [rows] = await execWithMetrics(
    `SELECT 1 FROM objection WHERE farmer_id=? AND status IN('pending','reviewed')`,
    [farmerId]
  );
  return rows.length === 0;
}

// Routes
// 1) Farmer Registration
app.post('/farmer/register', async (req, res) => {
  const { first_name, last_name, phone, national_id, password } = req.body;
  try {
    await execWithMetrics(
      `INSERT INTO farmer (first_name,last_name,phone,national_id,password) VALUES (?,?,?,?,?)`,
      [first_name, last_name, phone, national_id, password]
    );
    res.json({ message: 'Registered' });
  } catch (e) {
    console.error(e);
    res.status(400).json({ message: 'Registration error' });
  }
});

// 2) Farmer Login
app.post('/farmer/login', async (req, res) => {
  const { national_id, password } = req.body;
  const [[farmer]] = await execWithMetrics(
    'SELECT * FROM farmer WHERE national_id=?',
    [national_id]
  );
  if (!farmer || password !== farmer.password) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = signToken({ id: farmer.id, role: 'farmer' });
  res.json({ token, farmer: { id: farmer.id, first_name: farmer.first_name, last_name: farmer.last_name } });
});

// 3) Forgot Password -> send code
app.post('/farmer/forgot-password', async (req, res) => {
  const { national_id, phone } = req.body;
  const [[farmer]] = await execWithMetrics(
    'SELECT * FROM farmer WHERE national_id=? AND phone=?',
    [national_id, phone]
  );
  if (!farmer) return res.status(404).json({ message: 'Not found' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const token = crypto.randomBytes(32).toString('hex');
  await execWithMetrics('DELETE FROM password_reset WHERE farmer_id=?', [farmer.id]);
  await execWithMetrics(
    `INSERT INTO password_reset (farmer_id,national_id,reset_token,verification_code,expires_at)
     VALUES (?,?,?,?,DATE_ADD(NOW(), INTERVAL 2 HOUR))`,
    [farmer.id, national_id, token, code]
  );
  console.log(`Code for ${national_id}: ${code}`);
  res.json({ reset_token: token });
});

// 4) Verify Code
app.post('/farmer/verify-code', async (req, res) => {
  const { national_id, verification_code } = req.body;
  const [[row]] = await execWithMetrics(
    `SELECT * FROM password_reset WHERE national_id=? AND verification_code=? AND expires_at>NOW()`,
    [national_id, verification_code]
  );
  if (!row) return res.status(400).json({ message: 'Invalid or expired code' });
  res.json({ reset_token: row.reset_token });
});

// 5) Reset Password
app.post('/farmer/reset-password', async (req, res) => {
  const { national_id, reset_token, password } = req.body;
  const [[row]] = await execWithMetrics(
    `SELECT * FROM password_reset WHERE national_id=? AND reset_token=? AND expires_at>NOW()`,
    [national_id, reset_token]
  );
  if (!row) return res.status(400).json({ message: 'Invalid or expired token' });

  await execWithMetrics('UPDATE farmer SET password=? WHERE id=?', [password, row.farmer_id]);
  await execWithMetrics('DELETE FROM password_reset WHERE farmer_id=?', [row.farmer_id]);
  res.json({ message: 'Password reset' });
});

// 6) List Objections (farmer)
app.get('/objection', requireAuth, async (req, res) => {
  const [rows] = await execWithMetrics(
    'SELECT * FROM objection WHERE farmer_id=? ORDER BY created_at DESC',
    [req.user.id]
  );
  res.json(rows);
});

// 7) Can Submit New?
app.get('/objection/can-submit', requireAuth, async (req, res) => {
  res.json({ canSubmit: await canSubmit(req.user.id) });
});

// 8) Submit New Objection
app.post('/objection', requireAuth, async (req, res) => {
  if (!(await canSubmit(req.user.id))) {
    return res.status(403).json({ message: 'Already have pending/reviewed' });
  }
  const code = `OBJ-${Math.floor(1000 + Math.random() * 9000)}`;
  await execWithMetrics(
    `INSERT INTO objection (farmer_id,code,transaction_number,status) VALUES (?,?,?,'pending')`,
    [req.user.id, code, req.body.transaction_number]
  );
  res.json({ message: 'Submitted' });
});

// 9) Admin Login
app.post('/objection/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ message: 'Bad creds' });
  }
  const token = signToken({ role: 'admin' });
  res.json({ token });
});

// Admin: List pending/reviewed objections
app.get('/admin/objections', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const offset = (page - 1) * limit;
  const search = (req.query.search || '').trim(); // Trim the search parameter

  let sql = 'SELECT * FROM objection WHERE status IN("pending","reviewed")';
  const params = [];
  if (search) {
    sql += ' AND (code LIKE ? OR transaction_number LIKE ?)'; // Add transaction_number to search
    params.push(`%${search}%`, `%${search}%`);
  }
  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  try {
    const rows = await execWithMetrics(sql, params);
    let countSql = 'SELECT COUNT(*) AS total FROM objection WHERE status IN("pending","reviewed")';
    const countParams = [];
    if (search) {
      countSql += ' AND (code LIKE ? OR transaction_number LIKE ?)'; // Also update here
      countParams.push(`%${search}%`, `%${search}%`);
    }
    const countResult = await execWithMetrics(countSql, countParams);
    const total = countResult[0][0].total;
    res.json({ rows: rows[0], page, totalPages: Math.ceil(total / limit), searchTerm: search });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Admin: Resolve objection (generic)
app.post('/admin/resolve-objection', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { objection_id } = req.body;
  await execWithMetrics('UPDATE objection SET status="resolved" WHERE id=?', [objection_id]);
  res.json({ message: 'Objection resolved' });
});

// Admin: Resolve by URL param
app.post('/admin/objection/:id/resolve', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  await execWithMetrics('UPDATE objection SET status="resolved" WHERE id=?', [req.params.id]);
  res.json({ message: 'Objection resolved' });
});

// Admin: Review objection
app.post('/admin/objection/:id/review', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  await execWithMetrics('UPDATE objection SET status="reviewed" WHERE id=?', [req.params.id]);
  res.json({ message: 'Objection reviewed' });
});

// Admin: List resolved objections (archive)
app.get('/admin/archive', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const offset = (page - 1) * limit;
  const search = (req.query.search || '').trim(); // Trim the search parameter

  let sql = `SELECT o.*, f.first_name, f.last_name FROM objection o JOIN farmer f ON o.farmer_id=f.id WHERE o.status="resolved"`;
  const params = [];
  if (search) {
    sql += ' AND (o.code LIKE ? OR f.first_name LIKE ? OR f.last_name LIKE ? OR o.transaction_number LIKE ?)'; // Add transaction_number
    params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
  }
  sql += ' ORDER BY o.updated_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  try {
    const rows = await execWithMetrics(sql, params);
    const countResult = await execWithMetrics('SELECT COUNT(*) AS total FROM objection WHERE status="resolved"');
    const total = countResult[0][0].total;
    res.json({ rows: rows[0], page, totalPages: Math.ceil(total / limit), searchTerm: search });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Health checks
app.get('/health', async (req, res) => {
  try {
    if (process.env.NODE_ENV === 'test') return res.status(200).send('OK');
    const mysqlModule = await import('mysql2/promise');
    const conn = await mysqlModule.createConnection(process.env.DB_URL);
    await conn.query('SELECT 1');
    await conn.end();
    res.status(200).send('OK');
  } catch (err) {
    console.error('Health check failed:', err.message);
    res.status(500).send('DB query failed');
  }
});
app.get('/livez', (req, res) => res.status(200).send('Objection backend is up'));
app.get('/health-pod', async (req, res) => {
  try {
    await pool.execute('SELECT 1');
    res.status(200).send('OK');
  } catch (err) {
    console.error('Health pod check failed:', err.message);
    res.status(500).send('DB connection failed');
  }
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    console.error('Error generating metrics:', err);
    res.status(500).end();
  }
});

// Start server
initDatabase().then(() => {
  app.listen(process.env.PORT || 3001, () => {
    console.log(`🚀 App started on port ${process.env.PORT || 3001}`);
  });
});

export default app;
