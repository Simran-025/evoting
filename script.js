'use strict';
/**
 * e-VBS Portal — Election Commission of India
 * 
 * FILE STRUCTURE (everything flat, one folder):
 *   VOTING/
 *   ├── server.js    ← this file
 *   ├── schema.js
 *   ├── helpers.js
 *   ├── index.html   ← the website
 *   └── package.json
 *
 * HOW TO RUN:
 *   Open terminal inside VOTING folder, then:
 *   node --experimental-sqlite server.js
 *
 *   Open browser: http://localhost:3000
 */

const http   = require('node:http');
const fs     = require('node:fs');
const path   = require('node:path');
const crypto = require('node:crypto');

const PORT = parseInt(process.env.PORT || 3000);
const DIR  = __dirname; // serve files from same folder as server.js

// ── Load modules ──────────────────────────────────────────────
let db, H;
try {
  db = require('./schema.js').db;
  H  = require('./helpers.js');
  console.log('[OK] Database and helpers loaded.');
} catch (e) {
  console.error('\n❌  ERROR loading modules:', e.message);
  console.error('\n    Make sure you are running from inside the VOTING folder:');
  console.error('      cd VOTING');
  console.error('      node --experimental-sqlite server.js\n');
  process.exit(1);
}

// ═══════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => { raw += c; if (raw.length > 2e6) reject(new Error('Body too large')); });
    req.on('end',  () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

function send(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}
function ok(res, data)        { send(res, 200, { success: true,  ...data }); }
function fail(res, code, msg) { send(res, code, { success: false, error: msg }); }

function getToken(req) {
  const auth = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (auth) return auth;
  const m = (req.headers['cookie'] || '').match(/evbs_token=([^;]+)/);
  return m ? m[1] : null;
}

function requireAuth(req, res) {
  const t = getToken(req);
  if (!t) { fail(res, 401, 'Not logged in. Please log in first.'); return null; }
  const p = H.verifyToken(t);
  if (!p) { fail(res, 401, 'Session expired. Please log in again.'); return null; }
  const v = db.prepare('SELECT * FROM voters WHERE id = ?').get(p.id);
  if (!v) { fail(res, 401, 'Account not found.'); return null; }
  return v;
}

function clientIP(req) {
  return req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
}

function auditLog(vid, action, ip, detail = '') {
  try { db.prepare('INSERT INTO audit_log (voter_id,action,ip,detail) VALUES (?,?,?,?)').run(vid || 'anon', action, ip, detail); } catch (_) {}
}

// ═══════════════════════════════════════════════════════
// API ROUTES
// ═══════════════════════════════════════════════════════
const ROUTES = {};

/* ── REGISTER ──────────────────────────────── */
ROUTES['POST /api/auth/register'] = async (req, res) => {
  const b = await parseBody(req);
  const { aadhaar, epic, name, dob, gender, phone, email, state, constituency, password } = b;

  if (!aadhaar || !epic || !name || !dob || !phone || !state || !constituency || !password)
    return fail(res, 400, 'Please fill in all required fields.');

  const clean = aadhaar.replace(/[\s\-]/g, '');
  if (!/^\d{12}$/.test(clean))
    return fail(res, 400, 'Aadhaar number must be exactly 12 digits.');

  const epicC = epic.toUpperCase().trim();
  if (!/^[A-Z]{3}\d{7}$/.test(epicC))
    return fail(res, 400, 'EPIC number must be 3 letters + 7 digits. Example: ABC1234567');

  if (!/^\d{10}$/.test(phone.replace(/\s/g, '')))
    return fail(res, 400, 'Mobile number must be exactly 10 digits.');

  if (password.length < 8)
    return fail(res, 400, 'Password must be at least 8 characters long.');

  const aadhaarHash = H.hashAadhaar(clean);
  const existing = db.prepare('SELECT id, epic FROM voters WHERE aadhaar_hash = ? OR epic = ?').get(aadhaarHash, epicC);

  if (existing) {
    return fail(res, 409, existing.epic === epicC
      ? 'This EPIC number is already registered. Please log in instead.'
      : 'This Aadhaar number is already registered with another account.');
  }

  const id = H.uuid();
  db.prepare(`
    INSERT INTO voters (id, name, dob, gender, aadhaar_hash, epic, phone, email, state, constituency, password_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name.trim(), dob, gender || 'Other', aadhaarHash, epicC,
         phone.trim(), email?.trim() || '', state, constituency, H.hashPassword(password));

  auditLog(id, 'REGISTER', clientIP(req), `${state} · ${constituency}`);

  ok(res, { message: 'Registration successful! You can now log in with your EPIC number and password.' });
};

/* ── LOGIN ─────────────────────────────────── */
ROUTES['POST /api/auth/login'] = async (req, res) => {
  const { epic, password } = await parseBody(req);
  if (!epic || !password)
    return fail(res, 400, 'Please enter your EPIC number and password.');

  const voter = db.prepare('SELECT * FROM voters WHERE epic = ?').get(epic.toUpperCase().trim());
  if (!voter || !H.verifyPassword(password, voter.password_hash))
    return fail(res, 401, 'Incorrect EPIC number or password. Please try again.');

  const token = H.makeToken(voter.id);
  db.prepare('INSERT OR REPLACE INTO sessions (token, voter_id, expires_at, ip) VALUES (?, ?, ?, ?)')
    .run(token, voter.id, new Date(Date.now() + 86400000).toISOString(), clientIP(req));

  auditLog(voter.id, 'LOGIN', clientIP(req));

  res.setHeader('Set-Cookie', `evbs_token=${token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict`);
  ok(res, {
    token,
    voter: {
      id:           voter.id,
      name:         voter.name,
      epic:         voter.epic,
      state:        voter.state,
      constituency: voter.constituency,
      has_voted:    voter.has_voted === 1
    }
  });
};

/* ── LOGOUT ────────────────────────────────── */
ROUTES['POST /api/auth/logout'] = async (req, res) => {
  const token = getToken(req);
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.setHeader('Set-Cookie', 'evbs_token=; HttpOnly; Path=/; Max-Age=0');
  ok(res, { message: 'Logged out successfully.' });
};

/* ── GET CURRENT USER ──────────────────────── */
ROUTES['GET /api/auth/me'] = async (req, res) => {
  const voter = requireAuth(req, res); if (!voter) return;
  ok(res, {
    id:           voter.id,
    name:         voter.name,
    dob:          voter.dob,
    gender:       voter.gender,
    epic:         voter.epic,
    phone:        voter.phone,
    email:        voter.email,
    state:        voter.state,
    constituency: voter.constituency,
    has_voted:    voter.has_voted === 1,
    voted_at:     voter.voted_at,
    created_at:   voter.created_at
  });
};

/* ── SEND OTP ──────────────────────────────── */
ROUTES['POST /api/otp/send'] = async (req, res) => {
  const voter = requireAuth(req, res); if (!voter) return;

  const otp     = H.generateOTP();
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  db.prepare('INSERT OR REPLACE INTO otp_store (phone, otp, attempts, expires_at) VALUES (?, ?, 0, ?)')
    .run(voter.phone, otp, expires);

  auditLog(voter.id, 'OTP_SENT', clientIP(req));

  // Print OTP to terminal (since we can't send real SMS)
  console.log('\n' + '─'.repeat(50));
  console.log('  📱  OTP GENERATED (Development Mode)');
  console.log('─'.repeat(50));
  console.log(`  Voter : ${voter.name}`);
  console.log(`  EPIC  : ${voter.epic}`);
  console.log(`  OTP   : [ ${otp} ]  ← enter this in the browser`);
  console.log(`  Valid : 10 minutes`);
  console.log('─'.repeat(50) + '\n');

  ok(res, {
    message: `OTP sent to mobile ending ···${voter.phone.slice(-3)}`,
    _dev_otp: otp  // shown in browser for easy testing (remove in production)
  });
};

/* ── VERIFY OTP ────────────────────────────── */
ROUTES['POST /api/otp/verify'] = async (req, res) => {
  const voter = requireAuth(req, res); if (!voter) return;
  const { otp } = await parseBody(req);

  const record = db.prepare('SELECT * FROM otp_store WHERE phone = ?').get(voter.phone);
  if (!record)
    return fail(res, 400, 'No OTP was requested. Please click "Send OTP" first.');
  if (new Date(record.expires_at) < new Date())
    return fail(res, 400, 'This OTP has expired. Please request a new one.');
  if (record.attempts >= 3) {
    db.prepare('DELETE FROM otp_store WHERE phone = ?').run(voter.phone);
    return fail(res, 429, 'Too many wrong attempts. Please request a new OTP.');
  }
  if (record.otp !== String(otp)) {
    db.prepare('UPDATE otp_store SET attempts = attempts + 1 WHERE phone = ?').run(voter.phone);
    return fail(res, 400, `Incorrect OTP. ${2 - record.attempts} attempt(s) remaining.`);
  }

  ok(res, { message: 'OTP verified successfully.' });
};

/* ── GET CANDIDATES ────────────────────────── */
ROUTES['GET /api/election/candidates'] = async (req, res) => {
  const voter = requireAuth(req, res); if (!voter) return;
  const candidates = db.prepare(`
    SELECT id, serial_no, name, party, party_hi, symbol, age, education
    FROM candidates WHERE constituency = ? ORDER BY serial_no
  `).all(voter.constituency);
  ok(res, { candidates, constituency: voter.constituency });
};

/* ── CAST VOTE ─────────────────────────────── */
ROUTES['POST /api/vote/cast'] = async (req, res) => {
  const voter = requireAuth(req, res); if (!voter) return;

  if (voter.has_voted)
    return fail(res, 409, 'You have already voted in this election. Each voter may only vote once.');

  const { candidate_id, otp } = await parseBody(req);
  if (!candidate_id || !otp)
    return fail(res, 400, 'Please select a candidate and enter the OTP.');

  // Check OTP
  const otpRecord = db.prepare('SELECT * FROM otp_store WHERE phone = ?').get(voter.phone);
  if (!otpRecord)
    return fail(res, 400, 'No active OTP found. Please request a new OTP.');
  if (new Date(otpRecord.expires_at) < new Date())
    return fail(res, 400, 'OTP has expired. Please request a new one.');
  if (otpRecord.otp !== String(otp))
    return fail(res, 400, 'Incorrect OTP. Please try again.');

  // Validate candidate belongs to voter's constituency
  const candidate = db.prepare('SELECT * FROM candidates WHERE id = ? AND constituency = ?')
    .get(candidate_id, voter.constituency);
  if (!candidate)
    return fail(res, 400, 'Invalid candidate selection for your constituency.');

  // Generate cryptographic proof artifacts
  const sessionKey = crypto.randomBytes(32).toString('hex');
  const nullifier  = H.generateNullifier(voter.aadhaar_hash, sessionKey);
  const ipfsCID    = H.generateCID({ constituency: voter.constituency, state: voter.state, ts: new Date().toISOString() });
  const txHash     = H.generateTxHash();
  const latest     = db.prepare('SELECT * FROM blocks ORDER BY block_number DESC LIMIT 1').get();
  const newBlockNum = latest.block_number + 1;
  const blockHash   = H.generateBlockHash(newBlockNum, latest.block_hash, nullifier, ipfsCID, Date.now());

  // Atomic transaction — all or nothing
  db.transaction(() => {
    db.prepare(`UPDATE voters SET has_voted = 1, nullifier = ?, voted_at = datetime('now') WHERE id = ?`)
      .run(nullifier, voter.id);
    db.prepare('UPDATE candidates SET vote_count = vote_count + 1 WHERE id = ?')
      .run(candidate_id);
    db.prepare(`
      INSERT INTO blocks (block_number, prev_hash, block_hash, tx_hash, nullifier, ipfs_cid, candidate_id, voter_id, gas_used)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(newBlockNum, latest.block_hash, blockHash, txHash, nullifier, ipfsCID, candidate_id, voter.id, 21000);
    db.prepare('DELETE FROM otp_store WHERE phone = ?').run(voter.phone);
    auditLog(voter.id, 'VOTE_CAST', clientIP(req), `Block #${newBlockNum}`);
  })();

  console.log(`\n✅  VOTE RECORDED — ${voter.name} voted for ${candidate.name} (Block #${newBlockNum})\n`);

  ok(res, {
    receipt: {
      tx_hash:      txHash,
      block_number: newBlockNum,
      block_hash:   '0x' + blockHash,
      nullifier:    nullifier,
      ipfs_cid:     ipfsCID,
      candidate:    { name: candidate.name, party: candidate.party, symbol: candidate.symbol },
      constituency: voter.constituency,
      timestamp:    new Date().toISOString()
    }
  });
};

/* ── RESULTS ───────────────────────────────── */
ROUTES['GET /api/election/results'] = async (req, res) => {
  const constituencies = db.prepare('SELECT DISTINCT constituency FROM candidates ORDER BY constituency').all().map(r => r.constituency);
  const by_constituency = {};
  constituencies.forEach(c => {
    const cands = db.prepare('SELECT id, serial_no, name, party, party_hi, symbol, vote_count FROM candidates WHERE constituency = ? ORDER BY vote_count DESC').all(c);
    by_constituency[c] = { candidates: cands, total: cands.reduce((s, x) => s + x.vote_count, 0) };
  });
  const overall = db.prepare('SELECT name, party, party_hi, symbol, SUM(vote_count) AS total FROM candidates WHERE serial_no <= 4 GROUP BY serial_no, name ORDER BY total DESC').all();
  const grand_total = db.prepare('SELECT SUM(vote_count) AS t FROM candidates WHERE serial_no <= 4').get().t || 0;
  ok(res, { by_constituency, overall, grand_total });
};

/* ── STATS ─────────────────────────────────── */
ROUTES['GET /api/election/stats'] = async (req, res) => {
  ok(res, {
    total_votes:  db.prepare('SELECT SUM(vote_count) AS t FROM candidates WHERE serial_no <= 4').get().t || 0,
    total_blocks: db.prepare('SELECT COUNT(*) AS c FROM blocks').get().c,
    total_voters: db.prepare('SELECT COUNT(*) AS c FROM voters').get().c,
    voted_count:  db.prepare('SELECT COUNT(*) AS c FROM voters WHERE has_voted = 1').get().c,
    nodes: 247,
    avg_block_time: '2.3s'
  });
};

/* ── BLOCKCHAIN BLOCKS ─────────────────────── */
ROUTES['GET /api/blockchain/blocks'] = async (req, res) => {
  ok(res, { blocks: db.prepare('SELECT * FROM blocks ORDER BY block_number DESC LIMIT 20').all() });
};

/* ── VOTE RECEIPT ──────────────────────────── */
ROUTES['GET /api/voter/receipt'] = async (req, res) => {
  const voter = requireAuth(req, res); if (!voter) return;
  if (!voter.has_voted) return ok(res, { has_voted: false });
  const block = db.prepare('SELECT * FROM blocks WHERE nullifier = ?').get(voter.nullifier);
  ok(res, { has_voted: true, nullifier: voter.nullifier, voted_at: voter.voted_at, block: block || null });
};

/* ── AUDIT LOG ─────────────────────────────── */
ROUTES['GET /api/admin/audit'] = async (req, res) => {
  const voter = requireAuth(req, res); if (!voter) return;
  ok(res, { logs: db.prepare('SELECT action, ip, detail, created_at FROM audit_log WHERE voter_id = ? ORDER BY created_at DESC LIMIT 30').all(voter.id) });
};

/* ── HEALTH CHECK ──────────────────────────── */
ROUTES['GET /api/health'] = async (req, res) => {
  ok(res, { status: 'ok', time: new Date().toISOString(), node: process.version });
};

// ═══════════════════════════════════════════════════════
// STATIC FILE SERVER
// (serves index.html and any other files from same folder)
// ═══════════════════════════════════════════════════════
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.svg':  'image/svg+xml'
};

function serveFile(req, res) {
  const urlPath = req.url.split('?')[0];

  // Root URL → serve index.html
  const fileName = urlPath === '/' ? 'index.html' : urlPath.replace(/^\//, '');
  const filePath = path.join(DIR, fileName);

  // Security: don't serve files outside this folder
  if (!filePath.startsWith(DIR + path.sep) && filePath !== path.join(DIR, 'index.html')) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  // Don't serve server-side files directly
  const blocked = ['server.js', 'schema.js', 'helpers.js', 'evbs.db', 'evbs.db-shm', 'evbs.db-wal'];
  if (blocked.includes(fileName)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Fallback: serve index.html (SPA routing)
      fs.readFile(path.join(DIR, 'index.html'), (e2, d2) => {
        if (e2) { res.writeHead(404); res.end('index.html not found in ' + DIR); return; }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(d2);
      });
      return;
    }
    const ext  = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}

// ═══════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  // Allow cross-origin requests (needed during local development)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url     = req.url.split('?')[0];
  const key     = `${req.method} ${url}`;
  const handler = ROUTES[key];

  if (handler) {
    try {
      await handler(req, res);
    } catch (err) {
      console.error('[ERROR]', err.message);
      if (!res.headersSent) fail(res, 500, 'Something went wrong on the server. Please try again.');
    }
  } else if (url.startsWith('/api/')) {
    fail(res, 404, `API route not found: ${key}`);
  } else {
    serveFile(req, res);
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n❌  Port ${PORT} is already in use.`);
    console.error(`    Stop the other process, or set a different port:`);
    console.error(`    PORT=8080 node --experimental-sqlite server.js\n`);
  } else {
    console.error('❌  Server error:', err.message);
  }
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('\n' + '═'.repeat(52));
  console.log('  e-VBS — Election Commission of India');
  console.log('═'.repeat(52));
  console.log('');
  console.log('  ✅  Server is RUNNING');
  console.log('');
  console.log('  Open this in your browser:');
  console.log('');
  console.log(`  →  http://localhost:${PORT}`);
  console.log('');
  console.log('  OTP codes will appear here when requested.');
  console.log('  Press Ctrl+C to stop the server.');
  console.log('');
  console.log('═'.repeat(52) + '\n');
});

process.on('SIGINT',             () => { console.log('\n👋  Server stopped.'); process.exit(0); });
process.on('SIGTERM',            () => process.exit(0));
process.on('uncaughtException',  e  => console.error('[ERROR]', e.message));
process.on('unhandledRejection', e  => console.error('[ERROR]', e));