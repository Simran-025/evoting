'use strict';
const crypto = require('node:crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'evbs-eci-2025-xK9mP3nQzW7r';
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

// ── PASSWORD ──
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64, SCRYPT_PARAMS).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  try {
    const h = crypto.scryptSync(pw, salt, 64, SCRYPT_PARAMS).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex'));
  } catch { return false; }
}

// ── JWT-LIKE TOKEN ──
function makeToken(voterId) {
  const payload = { id: voterId, iat: Date.now(), exp: Date.now() + 24 * 3600 * 1000 };
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', JWT_SECRET).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}
function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const [b64, sig] = token.split('.');
  if (!b64 || !sig) return null;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(b64).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  } catch { return null; }
  const payload = JSON.parse(Buffer.from(b64, 'base64url').toString());
  if (payload.exp < Date.now()) return null;
  return payload;
}

// ── AADHAAR HASH ──
const AADHAAR_SALT = 'eci-uid-pepper-2025-do-not-change';
function hashAadhaar(aadhaar) {
  return crypto.createHmac('sha3-256', AADHAAR_SALT).update(aadhaar.replace(/\s/g, '')).digest('hex');
}

// ── NULLIFIER (Poseidon-simulated with HMAC) ──
function generateNullifier(aadhaarHash, sessionKey) {
  return '0x' + crypto.createHmac('sha256', sessionKey).update(aadhaarHash + ':nullifier').digest('hex');
}

// ── IPFS CID (simulated) ──
function generateCID(data) {
  const h = crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
  const b = Buffer.from(h, 'hex').toString('base64url').slice(0, 38);
  return 'Qm' + b.replace(/-/g,'a').replace(/_/g,'b');
}

// ── BLOCK HASH ──
function generateBlockHash(num, prevHash, nullifier, cid, ts) {
  return crypto.createHash('sha256').update(`${num}|${prevHash}|${nullifier}|${cid}|${ts}`).digest('hex');
}

// ── TX HASH ──
function generateTxHash() {
  return '0x' + crypto.randomBytes(32).toString('hex');
}

// ── OTP ──
function generateOTP() {
  return String(crypto.randomInt(100000, 999999));
}

// ── UUID ──
function uuid() {
  return crypto.randomUUID();
}

module.exports = {
  hashPassword, verifyPassword, makeToken, verifyToken,
  hashAadhaar, generateNullifier, generateCID,
  generateBlockHash, generateTxHash, generateOTP, uuid
};