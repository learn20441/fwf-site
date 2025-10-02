import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_me_secret';
const ORG_PREFIX = process.env.ORG_PREFIX || 'FWF';

// Static site root one level up from backend/
const siteRoot = path.resolve(__dirname, '..');

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(siteRoot));

// --- DB setup ---
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'fwf.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id TEXT UNIQUE,
  name TEXT,
  mobile TEXT UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT,
  role TEXT CHECK(role IN ('member','admin')) NOT NULL DEFAULT 'member',
  membership_active INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS wallets (
  user_id INTEGER UNIQUE,
  balance_inr REAL DEFAULT 0,
  lifetime_earned_inr REAL DEFAULT 0,
  lifetime_applied_inr REAL DEFAULT 0,
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS member_projects (
  user_id INTEGER UNIQUE,
  project_id INTEGER,
  project_name TEXT,
  project_cost REAL,
  target60_inr REAL,
  cash_credited_inr REAL DEFAULT 0,
  wallet_applied_inr REAL DEFAULT 0,
  eligible_flag INTEGER DEFAULT 0,
  eligible_on TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

function nextMemberId(){
  const row = db.prepare(`SELECT member_id FROM users WHERE role='member' ORDER BY id DESC LIMIT 1`).get();
  let n = 0;
  if(row && row.member_id){
    const m = row.member_id.match(/(\d{6})$/);
    if(m) n = parseInt(m[1],10);
  }
  const next = (n+1).toString().padStart(6,'0');
  return `${ORG_PREFIX}-${next}`;
}
function randPass(len=10){
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#$%';
  let p='';
  for(let i=0;i<len;i++) p += chars[Math.floor(Math.random()*chars.length)];
  return p;
}
function signToken(payload){
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

// Seed admin if not exists
const findAdmin = db.prepare(`SELECT * FROM users WHERE role='admin' LIMIT 1`).get();
if(!findAdmin){
  const hash = bcrypt.hashSync(process.env.ADMIN_PASS || 'Admin@12345', 10);
  const memberId = `${ORG_PREFIX}-ADMIN-001`;
  db.prepare(`INSERT INTO users(member_id,name,email,password_hash,role,membership_active) VALUES(?,?,?,?,?,1)`)
    .run(memberId, 'FWF Admin', process.env.ADMIN_USER || 'admin@fwf', hash, 'admin');
  console.log(`Admin created -> user: ${process.env.ADMIN_USER || 'admin@fwf'} | pass: ${process.env.ADMIN_PASS || 'Admin@12345'}`);
}

// --- Auth middleware ---
function auth(requiredRole){
  return (req,res,next)=>{
    try{
      const token = req.cookies.token;
      if(!token) return res.status(401).json({error:'Unauthorized'});
      const data = jwt.verify(token, JWT_SECRET);
      req.user = data;
      if(requiredRole && data.role !== requiredRole) return res.status(403).json({error:'Forbidden'});
      next();
    }catch(e){
      return res.status(401).json({error:'Unauthorized'});
    }
  }
}

// --- Routes ---
// simulate join payment (replace with gateway webhook later)
app.post('/api/pay/simulate-join', (req,res)=>{
  const { name, mobile, email } = req.body;
  if(!name || !mobile) return res.status(400).json({error:'name & mobile required'});
  const exists = db.prepare(`SELECT id FROM users WHERE mobile=? OR email=?`).get(mobile, email||null);
  if(exists) return res.status(400).json({error:'mobile/email already registered'});

  const memberId = nextMemberId();
  const plain = randPass();
  const hash = bcrypt.hashSync(plain, 10);

  const info = db.prepare(`INSERT INTO users(member_id,name,mobile,email,password_hash,role,membership_active) VALUES(?,?,?,?,?,'member',1)`)
               .run(memberId, name, mobile, email||null, hash);
  db.prepare(`INSERT OR IGNORE INTO wallets(user_id) VALUES(?)`).run(info.lastInsertRowid);

  res.json({ ok:true, memberId, password: plain });
});

app.post('/api/auth/login', (req,res)=>{
  const { memberId, password } = req.body;
  const u = db.prepare(`SELECT * FROM users WHERE member_id=?`).get(memberId);
  if(!u) return res.status(400).json({error:'Invalid credentials'});
  if(!bcrypt.compareSync(password, u.password_hash)) return res.status(400).json({error:'Invalid credentials'});
  const token = signToken({ uid: u.id, role: u.role, memberId: u.member_id, name: u.name });
  res.cookie('token', token, { httpOnly:true, sameSite:'lax' });
  res.json({ ok:true, role: u.role });
});

app.post('/api/admin/login', (req,res)=>{
  const { username, password } = req.body;
  const u = db.prepare(`SELECT * FROM users WHERE email=? AND role='admin'`).get(username);
  if(!u) return res.status(400).json({error:'Invalid credentials'});
  if(!bcrypt.compareSync(password, u.password_hash)) return res.status(400).json({error:'Invalid credentials'});
  const token = signToken({ uid: u.id, role: u.role, memberId: u.member_id, name: u.name });
  res.cookie('token', token, { httpOnly:true, sameSite:'lax' });
  res.json({ ok:true });
});

app.post('/api/auth/logout', (req,res)=>{
  res.clearCookie('token');
  res.json({ ok:true });
});

app.get('/api/member/me', auth('member'), (req,res)=>{
  const u = db.prepare(`SELECT id, member_id, name, mobile, email, created_at FROM users WHERE id=?`).get(req.user.uid);
  const w = db.prepare(`SELECT balance_inr, lifetime_earned_inr, lifetime_applied_inr FROM wallets WHERE user_id=?`).get(req.user.uid) || {balance_inr:0,lifetime_earned_inr:0,lifetime_applied_inr:0};
  const p = db.prepare(`SELECT project_name, project_cost, target60_inr, cash_credited_inr, wallet_applied_inr, eligible_flag FROM member_projects WHERE user_id=?`).get(req.user.uid) || null;
  res.json({ user:u, wallet:w, project:p });
});

app.post('/api/member/apply-wallet', auth('member'), (req,res)=>{
  const { amount } = req.body;
  const w = db.prepare(`SELECT balance_inr FROM wallets WHERE user_id=?`).get(req.user.uid);
  if(!w || w.balance_inr <= 0) return res.status(400).json({error:'No wallet balance'});
  const amt = Math.min(parseFloat(amount||0), w.balance_inr);
  if(amt <= 0) return res.status(400).json({error:'Invalid amount'});
  db.prepare(`UPDATE wallets SET balance_inr = balance_inr - ?, lifetime_applied_inr = lifetime_applied_inr + ?, updated_at = datetime('now') WHERE user_id=?`).run(amt, amt, req.user.uid);
  db.prepare(`INSERT INTO member_projects(user_id, project_name, project_cost, target60_inr) 
              SELECT ?, 'Not Selected', NULL, 0 WHERE NOT EXISTS(SELECT 1 FROM member_projects WHERE user_id=?)`).run(req.user.uid, req.user.uid);
  db.prepare(`UPDATE member_projects SET wallet_applied_inr = wallet_applied_inr + ? WHERE user_id=?`).run(amt, req.user.uid);
  res.json({ ok:true });
});

app.get('/api/admin/overview', auth('admin'), (req,res)=>{
  const totals = {
    members: db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='member'`).get().c,
    active_members: db.prepare(`SELECT COUNT(*) as c FROM users WHERE role='member' AND membership_active=1`).get().c
  };
  const latest = db.prepare(`SELECT member_id,name,mobile,created_at FROM users WHERE role='member' ORDER BY id DESC LIMIT 10`).all();
  res.json({ totals, latest });
});

app.listen(PORT, ()=>{
  console.log(`FWF backend running on http://localhost:${PORT}`);
  console.log(`Site served from: ${siteRoot}`);
});
