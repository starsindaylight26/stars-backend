// ============================================
// STARS — Node.js/Express Backend
// ============================================
const express    = require('express');
const mysql      = require('mysql2/promise');
const multer     = require('multer');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');
const fs         = require('fs');
const nodemailer = require('nodemailer');
const crypto     = require('crypto');

const app  = express();
const PORT = 8081;
const JWT_SECRET = 'stars_secret_key_2025';

// ---- EMAIL CONFIG ----
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'starsindaylight26@gmail.com',
    pass: 'fhqvsywsxoupimmr'
  }
});

// ---- MIDDLEWARE ----
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ---- UPLOADS FOLDER ----
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

// ---- MULTER (file upload) ----
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, './uploads'),
  filename:    (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.pdf'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

// ---- DATABASE ----
const db = mysql.createPool({
  host:              process.env.DB_HOST,
  port:              parseInt(process.env.DB_PORT),
  database:          process.env.DB_NAME,
  user:              process.env.DB_USER,
  password:          process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit:   10,
  ssl:               { rejectUnauthorized: false }
});

// ---- AUTH MIDDLEWARE ----
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ success: false, message: 'No token.' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid token.' });
  }
}

// ---- SEND VERIFICATION EMAIL ----
async function sendVerificationEmail(email, fullName, token) {
  const verifyUrl = 'http://localhost/verify.html?token=' + token;
  await transporter.sendMail({
    from:    '"STARS — Gordon College" <starsindaylight26@gmail.com>',
    to:      email,
    subject: 'STARS — Verify Your Account',
    html: '<div style="font-family:sans-serif;max-width:520px;margin:auto;background:#06082c;color:#fff;border-radius:12px;padding:32px;"><h2 style="color:#ee781c;">STARS</h2><p>Hi <strong>' + fullName + '</strong>,</p><p>Please verify your STARS account by clicking the button below.</p><p>This link expires in <strong>24 hours</strong>.</p><a href="' + verifyUrl + '" style="display:inline-block;margin:20px 0;padding:12px 28px;background:#ee781c;color:#fff;border-radius:8px;text-decoration:none;font-weight:bold;">Verify My Account</a><p style="color:#aaa;font-size:12px;">If you did not request this, ignore this email.</p><p style="color:#aaa;font-size:12px;">CCS, Gordon College</p></div>'
  });
}

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.json({ success: false, message: 'Email and password required.' });

  try {
    const [rows] = await db.query(
      'SELECT * FROM students WHERE email = ? AND is_active = 1',
      [email]
    );
    if (!rows.length)
      return res.json({ success: false, message: 'Invalid email or password.' });

    const student = rows[0];
    const match   = await bcrypt.compare(password, student.password);
    if (!match)
      return res.json({ success: false, message: 'Invalid email or password.' });

    // CHECK EMAIL VERIFICATION every 30 days
    const now          = new Date();
    const lastVerified = student.last_verified_at ? new Date(student.last_verified_at) : null;
    const daysSince    = lastVerified ? (now - lastVerified) / (1000 * 60 * 60 * 24) : 999;

    if (!lastVerified || daysSince >= 30) {
      const verifyToken   = crypto.randomBytes(32).toString('hex');
      const verifyExpires = new Date(now.getTime() + 24 * 60 * 60 * 1000);

      await db.query(
        'UPDATE students SET verify_token = ?, verify_expires = ? WHERE student_id = ?',
        [verifyToken, verifyExpires, student.student_id]
      );

      try {
        await sendVerificationEmail(student.email, student.full_name, verifyToken);
      } catch (mailErr) {
        console.error('Email error:', mailErr.message);
      }

      return res.json({
        success: false,
        requiresVerification: true,
        message: 'Please verify your email. A verification link has been sent to ' + student.email + '.'
      });
    }

    const token = jwt.sign({ student_id: student.student_id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      success:   true,
      token,
      fullName:  student.full_name,
      studentId: student.student_id,
      email:     student.email,
      program:   student.program,
      block:     student.block,
      yearLevel: student.year_level
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/auth/verify?token=xxx
app.get('/api/auth/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.json({ success: false, message: 'No token provided.' });

  try {
    const [rows] = await db.query(
      'SELECT * FROM students WHERE verify_token = ? AND verify_expires > NOW()',
      [token]
    );
    if (!rows.length)
      return res.json({ success: false, message: 'Invalid or expired verification link.' });

    await db.query(
      'UPDATE students SET verify_token = NULL, verify_expires = NULL, last_verified_at = NOW() WHERE student_id = ?',
      [rows[0].student_id]
    );

    res.json({ success: true, message: 'Email verified! You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', async (req, res) => {
  const { studentId, currentPassword, newPassword } = req.body;
  try {
    const [rows] = await db.query('SELECT * FROM students WHERE student_id = ?', [studentId]);
    if (!rows.length) return res.json({ success: false, message: 'Student not found.' });
    const match = await bcrypt.compare(currentPassword, rows[0].password);
    if (!match) return res.json({ success: false, message: 'Current password is incorrect.' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE students SET password = ? WHERE student_id = ?', [hashed, studentId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/students/register
app.post('/api/students/register', async (req, res) => {
  const { fullName, studentId, email, program, block, yearLevel, password } = req.body;
  if (!fullName || !studentId || !email || !password)
    return res.json({ success: false, message: 'All fields are required.' });
  try {
    const [existing] = await db.query(
      'SELECT id FROM students WHERE student_id = ? OR email = ?',
      [studentId, email]
    );
    if (existing.length)
      return res.json({ success: false, message: 'Student ID or email already registered.' });
    const hashed = await bcrypt.hash(password, 10);
    await db.query(
      'INSERT INTO students (student_id, full_name, email, program, block, year_level, password, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)',
      [studentId, fullName, email, program, block, yearLevel, hashed]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/points/:studentId
app.get('/api/points/:studentId', authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT achiever_points, engage_points, punctual_points, scholar_points, points FROM students WHERE student_id = ?',
      [req.params.studentId]
    );
    if (!rows.length) return res.json({ success: false, message: 'Student not found.' });
    const s = rows[0];
    const achiever = s.achiever_points || 0;
    const engage   = s.engage_points   || 0;
    const punctual = s.punctual_points || 0;
    const scholar  = s.scholar_points  || 0;
    res.json({
      success: true,
      total: achiever + engage + punctual + scholar,
      categories: [
        { name: 'Achievers Mark', points: achiever },
        { name: 'Engage Badge',   points: engage   },
        { name: 'Punctual Pass',  points: punctual },
        { name: 'Scholar Track',  points: scholar  }
      ]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/submissions/student/:studentId
app.get('/api/submissions/student/:studentId', authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM submissions WHERE student_id = ? ORDER BY submitted_at DESC',
      [req.params.studentId]
    );
    res.json({ success: true, submissions: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/submissions/verify-pin
app.get('/api/submissions/verify-pin', authMiddleware, async (req, res) => {
  const { pin } = req.query;
  if (!pin) return res.json({ valid: false, message: 'PIN is required.' });
  try {
    const [rows] = await db.query(
      'SELECT * FROM lost_found_certificates WHERE pin_code = ?',
      [pin.toUpperCase()]
    );
    if (!rows.length) return res.json({ valid: false, message: 'PIN not found.' });
    if (rows[0].is_used) return res.json({ valid: false, message: 'This PIN has already been used.' });
    res.json({ valid: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ valid: false, message: 'Server error.' });
  }
});

// POST /api/submissions
app.post('/api/submissions', authMiddleware, upload.single('proof'), async (req, res) => {
  const { studentId, title, category_id, description, pin_code } = req.body;
  const proofPath = req.file ? req.file.filename : null;
  if (!studentId || !title || !category_id)
    return res.json({ success: false, message: 'Missing required fields.' });
  try {
    const [cats] = await db.query('SELECT category_name FROM categories WHERE id = ?', [category_id]);
    const categoryName = cats.length ? cats[0].category_name : '';
    if (category_id === '3' && pin_code) {
      await db.query(
        'UPDATE lost_found_certificates SET is_used = 1, used_at = NOW() WHERE pin_code = ?',
        [pin_code.toUpperCase()]
      );
    }
    await db.query(
      "INSERT INTO submissions (student_id, category_id, title, description, points_requested, proof_path, status, category_name) VALUES (?, ?, ?, ?, 0, ?, 'pending', ?)",
      [studentId, category_id, title, description || '', proofPath, categoryName]
    );
    res.json({ success: true, message: 'Submission received!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/rewards
app.get('/api/rewards', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT reward_id, name AS reward_name, description, points_required, stock FROM rewards WHERE is_active = 1'
    );
    res.json({ success: true, rewards: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/rewards/redeem
app.post('/api/rewards/redeem', authMiddleware, async (req, res) => {
  const { rewardId, studentId } = req.body;
  try {
    const [rewards] = await db.query('SELECT * FROM rewards WHERE reward_id = ? AND is_active = 1', [rewardId]);
    if (!rewards.length) return res.json({ success: false, message: 'Reward not found.' });
    const reward = rewards[0];
    if (reward.stock <= 0) return res.json({ success: false, message: 'Out of stock.' });
    const [students] = await db.query('SELECT points FROM students WHERE student_id = ?', [studentId]);
    if (!students.length) return res.json({ success: false, message: 'Student not found.' });
    const currentPoints = students[0].points || 0;
    if (currentPoints < reward.points_required) return res.json({ success: false, message: 'Not enough points.' });
    await db.query('UPDATE students SET points = points - ? WHERE student_id = ?', [reward.points_required, studentId]);
    await db.query('UPDATE rewards SET stock = stock - 1 WHERE reward_id = ?', [rewardId]);
    await db.query("INSERT INTO redemptions (student_id, reward_id, points_spent, reward_name, status) VALUES (?, ?, ?, ?, 'pending')", [studentId, rewardId, reward.points_required, reward.name]);
    res.json({ success: true, message: 'Redeemed successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/rewards/history/:studentId
app.get('/api/rewards/history/:studentId', authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM redemptions WHERE student_id = ? ORDER BY redeemed_at DESC',
      [req.params.studentId]
    );
    res.json({ success: true, history: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/ranking
app.get('/api/ranking', authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT student_id, full_name, program, block, year_level, COALESCE(achiever_points,0) + COALESCE(engage_points,0) + COALESCE(punctual_points,0) + COALESCE(scholar_points,0) AS total_points FROM students WHERE is_active = 1 ORDER BY total_points DESC LIMIT 100'
    );
    res.json({ success: true, ranking: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.listen(PORT, () => {
  console.log('STARS Backend running at http://localhost:' + PORT);
  console.log('API Base: http://localhost:' + PORT + '/api');
});
