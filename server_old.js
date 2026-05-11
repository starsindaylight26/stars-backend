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

const app  = express();
const PORT = 8081;
const JWT_SECRET = 'stars_secret_key_2025';

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
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.pdf'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

// ---- DATABASE ----
const db = mysql.createPool({
  host:     'localhost',
  port:     3306,
  user:     'root',
  password: '',
  database: 'stars_db_new',
  waitForConnections: true,
  connectionLimit: 10
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

// ============================================
// AUTH ROUTES
// ============================================

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

// POST /api/auth/change-password
app.post('/api/auth/change-password', async (req, res) => {
  const { studentId, currentPassword, newPassword } = req.body;
  try {
    const [rows] = await db.query('SELECT * FROM students WHERE student_id = ?', [studentId]);
    if (!rows.length) return res.json({ success: false, message: 'Student not found.' });

    const match = await bcrypt.compare(currentPassword, rows[0].password);
    if (!match)  return res.json({ success: false, message: 'Current password is incorrect.' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE students SET password = ? WHERE student_id = ?', [hashed, studentId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ============================================
// STUDENT ROUTES
// ============================================

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
      `INSERT INTO students (student_id, full_name, email, program, block, year_level, password, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
      [studentId, fullName, email, program, block, yearLevel, hashed]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ============================================
// POINTS ROUTES
// ============================================

// GET /api/points/:studentId
app.get('/api/points/:studentId', authMiddleware, async (req, res) => {
  const { studentId } = req.params;
  try {
    const [rows] = await db.query(
      'SELECT achiever_points, engage_points, punctual_points, scholar_points, points FROM students WHERE student_id = ?',
      [studentId]
    );
    if (!rows.length) return res.json({ success: false, message: 'Student not found.' });

    const s = rows[0];
    const achiever  = s.achiever_points  || 0;
    const engage    = s.engage_points    || 0;
    const punctual  = s.punctual_points  || 0;
    const scholar   = s.scholar_points   || 0;
    const total     = achiever + engage + punctual + scholar;

    res.json({
      success: true,
      total,
      categories: [
        { name: 'Achievers Mark',  points: achiever },
        { name: 'Engage Badge',    points: engage   },
        { name: 'Punctual Pass',   points: punctual },
        { name: 'Scholar Track',   points: scholar  }
      ]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ============================================
// SUBMISSIONS ROUTES
// ============================================

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
    if (!rows.length)
      return res.json({ valid: false, message: 'PIN not found.' });
    if (rows[0].is_used)
      return res.json({ valid: false, message: 'This PIN has already been used.' });

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
    // Get category name
    const [cats] = await db.query('SELECT category_name FROM categories WHERE id = ?', [category_id]);
    const categoryName = cats.length ? cats[0].category_name : '';

    // If Lost & Found — mark PIN as used
    if (category_id === '3' && pin_code) {
      await db.query(
        'UPDATE lost_found_certificates SET is_used = 1, used_at = NOW() WHERE pin_code = ?',
        [pin_code.toUpperCase()]
      );
    }

    await db.query(
      `INSERT INTO submissions (student_id, category_id, title, description, points_requested, proof_path, status, category_name)
       VALUES (?, ?, ?, ?, 0, ?, 'pending', ?)`,
      [studentId, category_id, title, description || '', proofPath, categoryName]
    );

    res.json({ success: true, message: 'Submission received!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ============================================
// REWARDS ROUTES
// ============================================

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
    // Get reward
    const [rewards] = await db.query(
      'SELECT * FROM rewards WHERE reward_id = ? AND is_active = 1',
      [rewardId]
    );
    if (!rewards.length)
      return res.json({ success: false, message: 'Reward not found.' });

    const reward = rewards[0];
    if (reward.stock <= 0)
      return res.json({ success: false, message: 'Out of stock.' });

    // Get student points
    const [students] = await db.query(
      'SELECT points FROM students WHERE student_id = ?',
      [studentId]
    );
    if (!students.length)
      return res.json({ success: false, message: 'Student not found.' });

    const currentPoints = students[0].points || 0;
    if (currentPoints < reward.points_required)
      return res.json({ success: false, message: 'Not enough points.' });

    // Deduct points & decrement stock
    await db.query(
      'UPDATE students SET points = points - ? WHERE student_id = ?',
      [reward.points_required, studentId]
    );
    await db.query(
      'UPDATE rewards SET stock = stock - 1 WHERE reward_id = ?',
      [rewardId]
    );

    // Record redemption
    await db.query(
      `INSERT INTO redemptions (student_id, reward_id, points_spent, reward_name, status)
       VALUES (?, ?, ?, ?, 'pending')`,
      [studentId, rewardId, reward.points_required, reward.name]
    );

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

// ============================================
// RANKING ROUTE
// ============================================

// GET /api/ranking
app.get('/api/ranking', authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT student_id, full_name, program, block, year_level,
              COALESCE(achiever_points,0) + COALESCE(engage_points,0) +
              COALESCE(punctual_points,0) + COALESCE(scholar_points,0) AS total_points
       FROM students
       WHERE is_active = 1
       ORDER BY total_points DESC
       LIMIT 100`
    );
    res.json({ success: true, ranking: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`✅ STARS Backend running at http://localhost:${PORT}`);
  console.log(`   API Base: http://localhost:${PORT}/api`);
});
