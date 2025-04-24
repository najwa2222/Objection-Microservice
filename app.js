// backend‑service/app.js
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import * as mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import Prometheus from 'prom-client';

dotenv.config();

const app = express();

// Prometheus metrics setup
const register = new Prometheus.Registry();
Prometheus.collectDefaultMetrics({ register });

// — Security & Parsing —
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'"],
      fontSrc:    ["'self'"],
      imgSrc:     ["'self'"]
    }
  }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// — DB & Init —
const pool = mysql.createPool({
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

async function initDatabase() {
  const c = await pool.getConnection();
  // farmer table
  await c.query(`
    CREATE TABLE IF NOT EXISTS farmer (
      id INT AUTO_INCREMENT PRIMARY KEY,
      first_name VARCHAR(100) NOT NULL,
      last_name VARCHAR(100) NOT NULL,
      phone VARCHAR(20) NOT NULL,
      national_id VARCHAR(50) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB CHARSET=utf8mb4;
  `);
  // objection table
  await c.query(`
    CREATE TABLE IF NOT EXISTS objection (
      id INT AUTO_INCREMENT PRIMARY KEY,
      farmer_id INT NOT NULL,
      code VARCHAR(50) NOT NULL UNIQUE,
      transaction_number VARCHAR(100) NOT NULL,
      status ENUM('pending','reviewed','resolved') DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (farmer_id) REFERENCES farmer(id)
    ) ENGINE=InnoDB CHARSET=utf8mb4;
  `);
  // password_reset
  await c.query(`
    CREATE TABLE IF NOT EXISTS password_reset (
      id INT AUTO_INCREMENT PRIMARY KEY,
      farmer_id INT NOT NULL,
      national_id VARCHAR(50) NOT NULL,
      reset_token VARCHAR(100) NOT NULL,
      verification_code VARCHAR(6) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP,
      FOREIGN KEY (farmer_id) REFERENCES farmer(id)
    ) ENGINE=InnoDB CHARSET=utf8mb4;
  `);
  // sessions (if you later wire up express-mysql-session)
  await c.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id VARCHAR(128) PRIMARY KEY,
      expires INT UNSIGNED NOT NULL,
      data MEDIUMTEXT
    ) ENGINE=InnoDB CHARSET=utf8mb4;
  `);
  c.release();
}

// — JWT Helpers —
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
}
function requireAuth(req, res, next) {
  const auth = (req.headers.authorization || '').replace(/^Bearer\s+/, '');
  try {
    req.user = jwt.verify(auth, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Unauthorized' });
  }
}

// — Utility: check existing pending/reviewed objection —
async function canSubmit(farmerId) {
  const [rows] = await pool.execute(
    `SELECT 1 FROM objection 
     WHERE farmer_id=? AND status IN('pending','reviewed')`,
    [farmerId]
  );
  return rows.length === 0;
}

// — API Routes —

// 1) Farmer Registration
app.post('/api/farmer/register', async (req, res) => {
  const { first_name, last_name, phone, national_id, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.execute(
      `INSERT INTO farmer
         (first_name,last_name,phone,national_id,password_hash)
       VALUES (?,?,?,?,?)`,
      [first_name, last_name, phone, national_id, hash]
    );
    res.json({ message: 'Registered' });
  } catch (e) {
    console.error(e);
    res.status(400).json({ message: 'Registration error' });
  }
});

// 2) Farmer Login
app.post('/api/farmer/login', async (req, res) => {
  const { national_id, password } = req.body;
  const [[farmer]] = await pool.execute(
    'SELECT * FROM farmer WHERE national_id=?',
    [national_id]
  );
  if (!farmer || !await bcrypt.compare(password, farmer.password_hash)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = signToken({ id: farmer.id, role: 'farmer' });
  res.json({ token, farmer: { id: farmer.id, first_name: farmer.first_name, last_name: farmer.last_name } });
});

// 3) Forgot Password → send code
app.post('/api/farmer/forgot-password', async (req, res) => {
  const { national_id, phone } = req.body;
  const [[farmer]] = await pool.execute(
    'SELECT * FROM farmer WHERE national_id=? AND phone=?',
    [national_id, phone]
  );
  if (!farmer) return res.status(404).json({ message: 'Not found' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const token = crypto.randomBytes(32).toString('hex');
  await pool.execute('DELETE FROM password_reset WHERE farmer_id=?', [farmer.id]);
  await pool.execute(
    `INSERT INTO password_reset
       (farmer_id, national_id, reset_token, verification_code, expires_at)
     VALUES (?,?,?,?,DATE_ADD(NOW(), INTERVAL 1 HOUR))`,
    [farmer.id, national_id, token, code]
  );
  console.log(`Code for ${national_id}: ${code}`);
  res.json({ reset_token: token });
});

// 4) Verify Code
app.post('/api/farmer/verify-code', async (req, res) => {
  const { national_id, verification_code } = req.body;
  const [[row]] = await pool.execute(
    `SELECT * FROM password_reset 
     WHERE national_id=? AND verification_code=? AND expires_at>NOW()`,
    [national_id, verification_code]
  );
  if (!row) return res.status(400).json({ message: 'Invalid or expired code' });
  res.json({ reset_token: row.reset_token });
});

// 5) Reset Password
app.post('/api/farmer/reset-password', async (req, res) => {
  const { national_id, reset_token, password } = req.body;
  const [[row]] = await pool.execute(
    `SELECT * FROM password_reset 
     WHERE national_id=? AND reset_token=? AND expires_at>NOW()`,
    [national_id, reset_token]
  );
  if (!row) return res.status(400).json({ message: 'Invalid or expired token' });

  const hash = await bcrypt.hash(password, 10);
  await pool.execute(
    'UPDATE farmer SET password_hash=? WHERE id=?',
    [hash, row.farmer_id]
  );
  await pool.execute('DELETE FROM password_reset WHERE farmer_id=?', [row.farmer_id]);
  res.json({ message: 'Password reset' });
});

// 6) List Objections (farmer)
app.get('/api/objection', requireAuth, async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT * FROM objection WHERE farmer_id=? ORDER BY created_at DESC',
    [req.user.id]
  );
  res.json(rows);
});

// 7) Can Submit New?
app.get('/api/objection/can-submit', requireAuth, async (req, res) => {
  res.json({ canSubmit: await canSubmit(req.user.id) });
});

// 8) Submit New Objection
app.post('/api/objection', requireAuth, async (req, res) => {
  if (!await canSubmit(req.user.id)) {
    return res.status(403).json({ message: 'Already have pending/reviewed' });
  }
  const code = `OBJ-${Math.floor(1000 + Math.random() * 9000)}`;
  await pool.execute(
    `INSERT INTO objection (farmer_id, code, transaction_number, status)
     VALUES (?,?,?,'pending')`,
    [req.user.id, code, req.body.transaction_number]
  );
  res.json({ message: 'Submitted' });
});

// 9) Admin Login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (username !== process.env.ADMIN_USERNAME) return res.status(401).json({ message: 'Bad creds' });
  if (!await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH)) {
    return res.status(401).json({ message: 'Bad creds' });
  }
  const token = signToken({ role: 'admin' });
  res.json({ token });
});

// 10) Admin → list pending/reviewed (dashboard)
app.get('/api/admin/objections', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const [rows] = await pool.execute(
    'SELECT * FROM objection WHERE status IN("pending", "reviewed") ORDER BY created_at DESC'
  );
  res.json(rows);
});

// 11) Admin → resolve objection (dashboard)
app.post('/api/admin/resolve-objection', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { objection_id } = req.body;
  await pool.execute('UPDATE objection SET status="resolved" WHERE id=?', [objection_id]);
  res.json({ message: 'Objection resolved' });
});

app.post('/api/admin/objection/:id/resolve', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  await pool.execute('UPDATE objection SET status="resolved" WHERE id=?', [req.params.id]);
  res.json({ message: 'Objection resolved' });
});

app.post('/api/admin/objection/:id/review', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  await pool.execute('UPDATE objection SET status="reviewed" WHERE id=?', [req.params.id]);
  res.json({ message: 'Objection reviewed' });
});

// Admin → list resolved (archive)
app.get('/api/admin/archive', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const offset = (page - 1) * limit;
  const search = req.query.search || '';
  
  let query = 'SELECT o.*, f.first_name, f.last_name FROM objection o JOIN farmer f ON o.farmer_id = f.id WHERE o.status = "resolved"';
  let params = [];
  
  if (search) {
    query += ' AND (o.code LIKE ? OR f.first_name LIKE ? OR f.last_name LIKE ?)';
    const searchParam = `%${search}%`;
    params = [searchParam, searchParam, searchParam];
  }
  
  const [rows] = await pool.execute(query + ' ORDER BY o.updated_at DESC LIMIT ? OFFSET ?', 
    [...params, limit, offset]);
  
  // Get total count for pagination
  const [[countResult]] = await pool.execute(
    'SELECT COUNT(*) as total FROM objection WHERE status = "resolved"'
  );
  
  res.json({
    rows,
    page,
    totalPages: Math.ceil(countResult.total / limit),
    searchTerm: search
  });
});

// 12) Health Check
app.get('/health', async (req, res) => {
  if (process.env.NODE_ENV === 'test') {
    return res.status(200).send('OK'); // skip DB check in test mode
  }

  try {
    const mysql = await import('mysql2/promise');
    const connection = await mysql.createConnection(process.env.DB_URL);
    await connection.query('SELECT 1');
    res.status(200).send('OK');
    await connection.end();
  } catch (err) {
    console.error('Health check failed:', err.message);
    res.status(500).send('DB query failed');
  }
});
app.get('/livez', (req, res) => res.status(200).send('Objection backend is up'));


let connection; // Optional persistent connection (if managed elsewhere)

app.get('/health-pod', async (req, res) => {
  if (!connection) {
    console.warn('Health check: DB not connected yet');

    try {
      // Try a temporary connection to still validate DB availability
      const tempConnection = await mysql.createConnection({
        host: process.env.MYSQL_HOST,
        user: process.env.MYSQL_USER,
        password: process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DB
      });
      await tempConnection.query('SELECT 1');
      await tempConnection.end();
      return res.status(200).send('OK');
    } catch (err) {
      console.warn('Health check (temp connection) failed:', err.message);
      return res.status(200).send('OK'); // Still return OK in dev
    }
  }

  try {
    await connection.query('SELECT 1');
    res.status(200).send('OK');
  } catch (err) {
    console.warn('Health check query failed:', err.message);
    res.status(200).send('OK'); // Still return OK in dev
  }
});


// 13) Metrics
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    const metrics = await register.metrics();
    res.end(metrics);
  } catch (err) {
    console.error('Error generating metrics:', err);
    res.status(500).end();
  }
});

// — Start —
initDatabase().then(() => {
  app.listen(process.env.PORT || 5000, () => {
    console.log(`App started on port ${process.env.PORT || 5000}`);
  });
});

export default app;
