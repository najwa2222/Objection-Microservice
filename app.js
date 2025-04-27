// backend‑service/app.js
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import * as mysql from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import Prometheus from 'prom-client';

dotenv.config();

const app = express();

// Prometheus metrics setup
const register = new Prometheus.Registry();
Prometheus.collectDefaultMetrics({ register });

const httpCounter = new Prometheus.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method','route','code'],
});
const httpHistogram = new Prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method','route','code'],
  buckets: [0.01,0.05,0.1,0.5,1,2],
});

// DB metrics
const dbCounter = new Prometheus.Counter({
  name: 'db_query_total',
  help: 'Total number of database queries',
  labelNames: ['operation'],
});
const dbHistogram = new Prometheus.Histogram({
  name: 'db_query_duration_seconds',
  help: 'Duration of DB queries in seconds',
  labelNames: ['operation'],
  buckets: [0.001,0.01,0.1,1],
});

// Middleware to collect HTTP metrics
app.use((req,res,next) => {
  const route = req.route?.path || req.path;
  const end = httpHistogram.startTimer({ method: req.method, route });
  res.on('finish', () => {
    httpCounter.inc({ method: req.method, route, code: res.statusCode });
    end({ code: res.statusCode });
  });
  next();
});

// Helper for DB queries
async function execWithMetrics(sql, params) {
  const op = sql.trim().split(' ')[0];
  const endDb = dbHistogram.startTimer({ operation: op });
  const result = await pool.execute(sql, params);
  endDb();
  dbCounter.inc({ operation: op });
  return result;
}

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
  host:     process.env.MYSQL_HOST,
  user:     process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DB,
  waitForConnections: true,
  connectionLimit: 10
});

async function initDatabase() {
  let retries = 5;
  let connection;
  
  while (retries) {
    try {
      connection = await pool.getConnection();
      console.log('Successfully connected to database');
      break;
    } catch (err) {
      console.error(`Failed to connect to database (${retries} retries left): ${err.message}`);
      retries--;
      if (retries === 0) {
        console.error('All database connection attempts failed');
        process.exit(1); // Optional: exit on complete failure
      }
      // Wait 5 seconds before retrying
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }

  if (connection) connection.release();
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
app.post('/farmer/register', async (req, res) => {
  const { first_name, last_name, phone, national_id, password } = req.body;
  try {
await pool.execute(
  `INSERT INTO farmer
     (first_name,last_name,phone,national_id,password)
   VALUES (?,?,?,?,?)`,
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
  console.log('▶️ [API] /farmer/login payload:', req.body);
  const { national_id, password } = req.body;
  const [[farmer]] = await pool.execute(
    'SELECT * FROM farmer WHERE national_id=?',
    [national_id]
  );
if (!farmer || password !== farmer.password) {
  return res.status(401).json({ message: 'Invalid credentials' });
}
  const token = signToken({ id: farmer.id, role: 'farmer' });
  res.json({ token, farmer: { id: farmer.id, first_name: farmer.first_name, last_name: farmer.last_name } });
});

// 3) Forgot Password → send code
app.post('/farmer/forgot-password', async (req, res) => {
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
     VALUES (?,?,?,?,DATE_ADD(NOW(), INTERVAL 2 HOUR))`,
    [farmer.id, national_id, token, code]
  );
  console.log(`Code for ${national_id}: ${code}`);
  res.json({ reset_token: token });
});

// 4) Verify Code
app.post('/farmer/verify-code', async (req, res) => {
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
app.post('/farmer/reset-password', async (req, res) => {
  const { national_id, reset_token, password } = req.body;
  const [[row]] = await pool.execute(
    `SELECT * FROM password_reset 
     WHERE national_id=? AND reset_token=? AND expires_at>NOW()`,
    [national_id, reset_token]
  );
  if (!row) return res.status(400).json({ message: 'Invalid or expired token' });

  
  await pool.execute(
    'UPDATE farmer SET password=? WHERE id=?',
    [password, row.farmer_id]
  );
  await pool.execute('DELETE FROM password_reset WHERE farmer_id=?', [row.farmer_id]);
  res.json({ message: 'Password reset' });
});

// 6) List Objections (farmer)
app.get('/objection', requireAuth, async (req, res) => {
  const [rows] = await pool.execute(
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
app.post('/admin/login', async (req, res) => {
  console.log('▶️ [API] /admin/login payload:', req.body);
  const { username, password } = req.body;
  if (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ message: 'Bad creds' });
  }
  const token = signToken({ role: 'admin' });
  res.json({ token });
});

// Admin → list pending/reviewed (dashboard) with pagination
app.get('/admin/objections', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') 
    return res.status(403).json({ message: 'Forbidden' });

  const page   = parseInt(req.query.page)  || 1;
  const limit  = 10;
  const offset = (page - 1) * limit;
  const search = req.query.search || '';

  // Build SQL & params
  let sql    = 'SELECT * FROM objection WHERE status IN("pending","reviewed")';
  const params = [];

  if (search) {
    sql += ' AND code LIKE ?';
    params.push(`%${search}%`);
  }

  // Inline pagination rather than binding it
  sql += ' ORDER BY created_at DESC';
  sql += ` LIMIT ${limit} OFFSET ${offset}`;

  try {
    // Only bind the search term (if any)
    const [rows] = await pool.execute(sql, params);

    // Count total for pagination (no LIMIT/OFFSET here)
    let countSql    = 'SELECT COUNT(*) AS total FROM objection WHERE status IN("pending","reviewed")';
    const countParams = [];
    if (search) {
      countSql += ' AND code LIKE ?';
      countParams.push(`%${search}%`);
    }
    const [[{ total }]] = await pool.execute(countSql, countParams);

    res.json({
      rows,
      page,
      totalPages: Math.ceil(total / limit),
      searchTerm: search
    });
  } catch (err) {
    console.error('❌ [API] GET /admin/objections error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// 11) Admin → resolve objection (dashboard)
app.post('/admin/resolve-objection', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const { objection_id } = req.body;
  await pool.execute('UPDATE objection SET status="resolved" WHERE id=?', [objection_id]);
  res.json({ message: 'Objection resolved' });
});

app.post('/admin/objection/:id/resolve', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  await pool.execute('UPDATE objection SET status="resolved" WHERE id=?', [req.params.id]);
  res.json({ message: 'Objection resolved' });
});

app.post('/admin/objection/:id/review', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  await pool.execute('UPDATE objection SET status="reviewed" WHERE id=?', [req.params.id]);
  res.json({ message: 'Objection reviewed' });
});

// Admin → list resolved (archive)
app.get('/admin/archive', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') 
    return res.status(403).json({ message: 'Forbidden' });

  const page   = parseInt(req.query.page)  || 1;
  const limit  = 10;
  const offset = (page - 1) * limit;
  const search = req.query.search || '';

  let sql    = `
    SELECT o.*, f.first_name, f.last_name
      FROM objection o
      JOIN farmer f ON o.farmer_id = f.id
     WHERE o.status = "resolved"
  `;
  const params = [];

  if (search) {
    sql += ' AND (o.code LIKE ? OR f.first_name LIKE ? OR f.last_name LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  sql += ' ORDER BY o.updated_at DESC';
  sql += ` LIMIT ${limit} OFFSET ${offset}`;

  try {
    const [rows] = await pool.execute(sql, params);

    const [[{ total }]] = await pool.execute(
      'SELECT COUNT(*) AS total FROM objection WHERE status = "resolved"'
    );

    res.json({
      rows,
      page,
      totalPages: Math.ceil(total / limit),
      searchTerm: search
    });
  } catch (err) {
    console.error('❌ [API] GET /admin/archive error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
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
  try {
    // Use the existing pool instead of creating a new connection
    let [rows] = await pool.query('SELECT 1');
    console.log('Health check passed: DB connected');
    res.status(200).send('OK');
  } catch (err) {
    console.error('Health check failed:', err.message);
    // In production, you should return 500 to indicate failure
    res.status(500).send('DB connection failed');
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
  app.listen(process.env.PORT || 3001, () => {
    console.log(`App started on port ${process.env.PORT || 3001}`);
  });
});

export default app;
