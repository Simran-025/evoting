'use strict';

// ─────────────────────────────────────────────────────────────────
//  e-VBS Portal — Backend Server
//  Election Commission of India
//
//  HOW TO RUN (from inside the evbs_full folder):
//    node --experimental-sqlite server.js
//    node --experimental-sqlite server.js --port=8080
// ─────────────────────────────────────────────────────────────────

const http   = require('node:http');
const fs     = require('node:fs');
const path   = require('node:path');
const crypto = require('node:crypto');

// Parse --port= argument
const portFlag = process.argv.find(a => a.startsWith('--port'));
const PORT = parseInt(
  portFlag ? (portFlag.includes('=') ? portFlag.split('=')[1] : process.argv[process.argv.indexOf(portFlag)+1])
           : (process.env.PORT || 3000)
);

// Load DB and helpers
let db, H;
try {
  db = require('./db/schema.js').db;
  H  = require('./helpers.js');
} catch (e) {
  console.error('\n❌  STARTUP ERROR:', e.message);
  console.error('    Make sure you run from inside the evbs_full folder:\n');
  console.error('    cd evbs_full');
  console.error('    node --experimental-sqlite server.js\n');
  process.exit(1);
}

const PUBLIC = path.join(__dirname, 'public');

// ════════════════════════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════════════════════════
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => { raw += c; if (raw.length > 2e6) reject(new Error('Too large')); });
    req.on('end',  () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve({}); } });
    req.on('error', reject);
  });
}
function send(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(data));
}
function ok(res, data)        { send(res, 200, { success: true, ...data }); }
function fail(res, code, msg) { send(res, code, { success: false, error: msg }); }
function getToken(req) {
  const h = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (h) return h;
  const m = (req.headers['cookie'] || '').match(/evbs_token=([^;]+)/);
  return m ? m[1] : null;
}
function auth(req, res) {
  const t = getToken(req);
  if (!t) { fail(res, 401, 'Not authenticated.'); return null; }
  const p = H.verifyToken(t);
  if (!p) { fail(res, 401, 'Session expired. Please log in again.'); return null; }
  const v = db.prepare('SELECT * FROM voters WHERE id=?').get(p.id);
  if (!v) { fail(res, 401, 'Account not found.'); return null; }
  return v;
}
function ip(req) { return req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown'; }
function log(vid, action, reqIp, detail='') {
  try { db.prepare('INSERT INTO audit_log (voter_id,action,ip,detail) VALUES (?,?,?,?)').run(vid||'anon', action, reqIp, detail); } catch(_){}
}

// ════════════════════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════════════════════
const R = {};

// REGISTER
R['POST /api/auth/register'] = async (req, res) => {
  const b = await parseBody(req);
  const { aadhaar, epic, name, dob, gender, phone, email, state, constituency, password } = b;
  if (!aadhaar||!epic||!name||!dob||!phone||!state||!constituency||!password)
    return fail(res, 400, 'All required fields must be filled in.');
  const clean = aadhaar.replace(/[\s\-]/g,'');
  if (!/^\d{12}$/.test(clean)) return fail(res, 400, 'Aadhaar must be 12 digits.');
  const epicC = epic.toUpperCase().trim();
  if (!/^[A-Z]{3}\d{7}$/.test(epicC)) return fail(res, 400, 'EPIC must be 3 letters + 7 digits (e.g. ABC1234567).');
  if (password.length < 8) return fail(res, 400, 'Password must be at least 8 characters.');
  const ah = H.hashAadhaar(clean);
  const ex = db.prepare('SELECT id,epic FROM voters WHERE aadhaar_hash=? OR epic=?').get(ah, epicC);
  if (ex) return fail(res, 409, ex.epic===epicC ? 'EPIC already registered. Please log in.' : 'Aadhaar already registered.');
  const id = H.uuid();
  db.prepare('INSERT INTO voters (id,name,dob,gender,aadhaar_hash,epic,phone,email,state,constituency,password_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .run(id, name.trim(), dob, gender||'Other', ah, epicC, phone.trim(), email?.trim()||'', state, constituency, H.hashPassword(password));
  log(id, 'REGISTER', ip(req), `${state} · ${constituency}`);
  ok(res, { message: 'Registration successful! You can now log in.' });
};

// LOGIN
R['POST /api/auth/login'] = async (req, res) => {
  const { epic, password } = await parseBody(req);
  if (!epic||!password) return fail(res, 400, 'EPIC and password are required.');
  const v = db.prepare('SELECT * FROM voters WHERE epic=?').get(epic.toUpperCase().trim());
  if (!v || !H.verifyPassword(password, v.password_hash))
    return fail(res, 401, 'Invalid EPIC or password.');
  const token = H.makeToken(v.id);
  db.prepare('INSERT OR REPLACE INTO sessions (token,voter_id,expires_at,ip) VALUES (?,?,?,?)')
    .run(token, v.id, new Date(Date.now()+86400000).toISOString(), ip(req));
  log(v.id, 'LOGIN', ip(req));
  res.setHeader('Set-Cookie', `evbs_token=${token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict`);
  ok(res, { token, voter: { id:v.id, name:v.name, epic:v.epic, state:v.state, constituency:v.constituency, has_voted:v.has_voted===1 } });
};

// LOGOUT
R['POST /api/auth/logout'] = async (req, res) => {
  const t = getToken(req);
  if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(t);
  res.setHeader('Set-Cookie', 'evbs_token=; HttpOnly; Path=/; Max-Age=0');
  ok(res, { message: 'Logged out.' });
};

// ME
R['GET /api/auth/me'] = async (req, res) => {
  const v = auth(req, res); if (!v) return;
  ok(res, { id:v.id, name:v.name, dob:v.dob, gender:v.gender, epic:v.epic, phone:v.phone, email:v.email, state:v.state, constituency:v.constituency, has_voted:v.has_voted===1, voted_at:v.voted_at, created_at:v.created_at });
};

// SEND OTP
R['POST /api/otp/send'] = async (req, res) => {
  const v = auth(req, res); if (!v) return;
  const otp = H.generateOTP();
  db.prepare('INSERT OR REPLACE INTO otp_store (phone,otp,attempts,expires_at) VALUES (?,?,0,?)')
    .run(v.phone, otp, new Date(Date.now()+600000).toISOString());
  log(v.id, 'OTP_SENT', ip(req));
  console.log(`\n┌─ OTP ─────────────────────────────┐`);
  console.log(`│  Voter: ${v.name} (${v.epic})`);
  console.log(`│  OTP  : ${otp}  (valid 10 min)`);
  console.log(`└───────────────────────────────────┘\n`);
  ok(res, { message: `OTP sent to ···${v.phone.slice(-3)}`, _dev_otp: otp });
};

// VERIFY OTP
R['POST /api/otp/verify'] = async (req, res) => {
  const v = auth(req, res); if (!v) return;
  const { otp } = await parseBody(req);
  const r = db.prepare('SELECT * FROM otp_store WHERE phone=?').get(v.phone);
  if (!r) return fail(res, 400, 'No OTP found. Request one first.');
  if (new Date(r.expires_at)<new Date()) return fail(res, 400, 'OTP expired. Request a new one.');
  if (r.attempts>=3) { db.prepare('DELETE FROM otp_store WHERE phone=?').run(v.phone); return fail(res, 429, 'Too many attempts. Request new OTP.'); }
  if (r.otp!==String(otp)) { db.prepare('UPDATE otp_store SET attempts=attempts+1 WHERE phone=?').run(v.phone); return fail(res, 400, `Wrong OTP. ${2-r.attempts} attempt(s) left.`); }
  ok(res, { message: 'OTP verified.' });
};

// CANDIDATES
R['GET /api/election/candidates'] = async (req, res) => {
  const v = auth(req, res); if (!v) return;
  const c = db.prepare('SELECT id,serial_no,name,party,party_hi,symbol,age,education FROM candidates WHERE constituency=? ORDER BY serial_no').all(v.constituency);
  ok(res, { candidates: c, constituency: v.constituency });
};

// CAST VOTE
R['POST /api/vote/cast'] = async (req, res) => {
  const v = auth(req, res); if (!v) return;
  if (v.has_voted) return fail(res, 409, 'You have already voted in this election.');
  const { candidate_id, otp } = await parseBody(req);
  if (!candidate_id||!otp) return fail(res, 400, 'Candidate and OTP are required.');
  const otpR = db.prepare('SELECT * FROM otp_store WHERE phone=?').get(v.phone);
  if (!otpR)                               return fail(res, 400, 'No active OTP. Request a new one.');
  if (new Date(otpR.expires_at)<new Date()) return fail(res, 400, 'OTP expired. Request a new one.');
  if (otpR.otp!==String(otp))              return fail(res, 400, 'Wrong OTP.');
  const cand = db.prepare('SELECT * FROM candidates WHERE id=? AND constituency=?').get(candidate_id, v.constituency);
  if (!cand) return fail(res, 400, 'Invalid candidate for your constituency.');
  const key       = crypto.randomBytes(32).toString('hex');
  const nullifier = H.generateNullifier(v.aadhaar_hash, key);
  const cid       = H.generateCID({ constituency:v.constituency, state:v.state, ts:new Date().toISOString() });
  const txHash    = H.generateTxHash();
  const latest    = db.prepare('SELECT * FROM blocks ORDER BY block_number DESC LIMIT 1').get();
  const newNum    = latest.block_number + 1;
  const bHash     = H.generateBlockHash(newNum, latest.block_hash, nullifier, cid, Date.now());
  db.transaction(() => {
    db.prepare(`UPDATE voters SET has_voted=1,nullifier=?,voted_at=datetime('now') WHERE id=?`).run(nullifier, v.id);
    db.prepare('UPDATE candidates SET vote_count=vote_count+1 WHERE id=?').run(candidate_id);
    db.prepare('INSERT INTO blocks (block_number,prev_hash,block_hash,tx_hash,nullifier,ipfs_cid,candidate_id,voter_id,gas_used) VALUES (?,?,?,?,?,?,?,?,?)').run(newNum,latest.block_hash,bHash,txHash,nullifier,cid,candidate_id,v.id,21000);
    db.prepare('DELETE FROM otp_store WHERE phone=?').run(v.phone);
    db.prepare('INSERT INTO audit_log (voter_id,action,ip,detail) VALUES (?,?,?,?)').run(v.id,'VOTE_CAST',ip(req),`Block:#${newNum}`);
  })();
  ok(res, { receipt: { tx_hash:txHash, block_number:newNum, block_hash:'0x'+bHash, nullifier, ipfs_cid:cid, candidate:{name:cand.name,party:cand.party,symbol:cand.symbol}, constituency:v.constituency, timestamp:new Date().toISOString() } });
};

// RESULTS
R['GET /api/election/results'] = async (req, res) => {
  const cons = db.prepare('SELECT DISTINCT constituency FROM candidates ORDER BY constituency').all().map(r=>r.constituency);
  const by_constituency = {};
  cons.forEach(c => {
    const cs = db.prepare('SELECT id,serial_no,name,party,party_hi,symbol,vote_count FROM candidates WHERE constituency=? ORDER BY vote_count DESC').all(c);
    by_constituency[c] = { candidates:cs, total:cs.reduce((s,x)=>s+x.vote_count,0) };
  });
  const overall     = db.prepare('SELECT name,party,party_hi,symbol,SUM(vote_count) AS total FROM candidates WHERE serial_no<=4 GROUP BY serial_no,name ORDER BY total DESC').all();
  const grand_total = db.prepare('SELECT SUM(vote_count) AS t FROM candidates WHERE serial_no<=4').get().t || 0;
  ok(res, { by_constituency, overall, grand_total });
};

// STATS
R['GET /api/election/stats'] = async (req, res) => {
  ok(res, {
    total_votes:  db.prepare('SELECT SUM(vote_count) AS t FROM candidates WHERE serial_no<=4').get().t || 0,
    total_blocks: db.prepare('SELECT COUNT(*) AS c FROM blocks').get().c,
    total_voters: db.prepare('SELECT COUNT(*) AS c FROM voters').get().c,
    voted_count:  db.prepare('SELECT COUNT(*) AS c FROM voters WHERE has_voted=1').get().c,
    nodes: 247, avg_block_time: '2.3s'
  });
};

// BLOCKS
R['GET /api/blockchain/blocks'] = async (req, res) => {
  ok(res, { blocks: db.prepare('SELECT * FROM blocks ORDER BY block_number DESC LIMIT 20').all() });
};

// RECEIPT
R['GET /api/voter/receipt'] = async (req, res) => {
  const v = auth(req, res); if (!v) return;
  if (!v.has_voted) return ok(res, { has_voted:false });
  ok(res, { has_voted:true, nullifier:v.nullifier, voted_at:v.voted_at, block: db.prepare('SELECT * FROM blocks WHERE nullifier=?').get(v.nullifier)||null });
};

// AUDIT
R['GET /api/admin/audit'] = async (req, res) => {
  const v = auth(req, res); if (!v) return;
  ok(res, { logs: db.prepare('SELECT action,ip,detail,created_at FROM audit_log WHERE voter_id=? ORDER BY created_at DESC LIMIT 30').all(v.id) });
};

// HEALTH CHECK
R['GET /api/health'] = async (req, res) => {
  ok(res, { status:'ok', node: process.version, time: new Date().toISOString() });
};

// ════════════════════════════════════════════════════════════════
//  STATIC FILE SERVER
// ════════════════════════════════════════════════════════════════
const MIME = {
  '.html':'text/html; charset=utf-8', '.js':'application/javascript',
  '.css':'text/css', '.json':'application/json',
  '.png':'image/png', '.ico':'image/x-icon', '.svg':'image/svg+xml'
};
function serveFile(req, res) {
  const urlPath = req.url.split('?')[0];
  const fp = path.join(PUBLIC, urlPath === '/' ? 'index.html' : urlPath);
  if (!fp.startsWith(PUBLIC)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(fp, (e, data) => {
    if (e) {
      fs.readFile(path.join(PUBLIC,'index.html'), (e2, d2) => {
        if (e2) { res.writeHead(404); res.end('Not Found'); return; }
        res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'}); res.end(d2);
      });
      return;
    }
    res.writeHead(200,{'Content-Type':MIME[path.extname(fp).toLowerCase()]||'application/octet-stream'});
    res.end(data);
  });
}

// ════════════════════════════════════════════════════════════════
//  START SERVER
// ════════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method==='OPTIONS') { res.writeHead(204); res.end(); return; }

  const url     = req.url.split('?')[0];
  const key     = `${req.method} ${url}`;
  const handler = R[key];

  if (handler) {
    try { await handler(req, res); }
    catch(e) {
      console.error('[ERROR]', e.message);
      if (!res.headersSent) fail(res, 500, 'Server error. Please try again.');
    }
  } else if (url.startsWith('/api/')) {
    fail(res, 404, `Not found: ${key}`);
  } else {
    serveFile(req, res);
  }
});

server.on('error', (e) => {
  if (e.code==='EADDRINUSE') {
    console.error(`\n❌  Port ${PORT} is already in use!`);
    console.error(`    Try: node --experimental-sqlite server.js --port=8080\n`);
  } else {
    console.error('❌  Server error:', e.message);
  }
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n${'═'.repeat(56)}`);
  console.log(`  e-VBS Portal — Election Commission of India`);
  console.log(`${'─'.repeat(56)}`);
  console.log(`  ✅  Server is running!`);
  console.log(``);
  console.log(`  Open in your browser:`);
  console.log(`  👉  http://localhost:${PORT}`);
  console.log(`  👉  http://127.0.0.1:${PORT}`);
  console.log(``);
  console.log(`  OTP codes appear here (dev mode)`);
  console.log(`  Press Ctrl+C to stop`);
  console.log(`${'═'.repeat(56)}\n`);
});

process.on('SIGINT',  () => { console.log('\n👋  Stopped.'); server.close(); process.exit(0); });
process.on('SIGTERM', () => { server.close(); process.exit(0); });
process.on('uncaughtException', e => console.error('[UNCAUGHT]', e.message));
process.on('unhandledRejection', e => console.error('[UNHANDLED]', e));