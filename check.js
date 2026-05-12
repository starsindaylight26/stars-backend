const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

// Read .env manually
const envFile = fs.readFileSync('.env', 'utf8');
envFile.split('\n').forEach(line => {
  const [key, ...val] = line.split('=');
  if (key && val) process.env[key.trim()] = val.join('=').trim();
});

async function check() {
  const db = mysql.createPool({
    host:     process.env.DB_HOST,
    port:     parseInt(process.env.DB_PORT),
    database: process.env.DB_NAME,
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl:      { rejectUnauthorized: false }
  });
  console.log('=== proof_path values in DB ===');
  const [rows] = await db.query('SELECT id, title, proof_path FROM submissions LIMIT 10');
  rows.forEach(r => console.log('ID:', r.id, '| Title:', r.title, '| proof_path:', r.proof_path));

  console.log('\n=== files in uploads/ folder ===');
  const uploadsDir = path.join(__dirname, 'uploads');
  fs.readdirSync(uploadsDir).forEach(f => console.log(f));

  process.exit();
}
check().catch(err => { console.error(err); process.exit(1); });
