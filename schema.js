'use strict';

// ─────────────────────────────────────────────────
//  schema.js  —  Database setup
//  Place this in the SAME folder as server.js
// ─────────────────────────────────────────────────

const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// DB file created in the same folder as this script
const DB_FILE = path.join(__dirname, 'evbs.db');
const db = new DatabaseSync(DB_FILE);

function init() {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS voters (
      id            TEXT PRIMARY KEY,
      name          TEXT NOT NULL,
      dob           TEXT NOT NULL,
      gender        TEXT DEFAULT 'Other',
      aadhaar_hash  TEXT UNIQUE NOT NULL,
      epic          TEXT UNIQUE NOT NULL,
      phone         TEXT NOT NULL,
      email         TEXT DEFAULT '',
      state         TEXT NOT NULL,
      constituency  TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      has_voted     INTEGER DEFAULT 0,
      nullifier     TEXT UNIQUE,
      voted_at      TEXT,
      created_at    TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS candidates (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      serial_no     INTEGER NOT NULL,
      name          TEXT NOT NULL,
      party         TEXT NOT NULL,
      party_hi      TEXT NOT NULL,
      symbol        TEXT NOT NULL,
      constituency  TEXT NOT NULL,
      vote_count    INTEGER DEFAULT 0,
      age           INTEGER DEFAULT 45,
      education     TEXT DEFAULT 'Graduate'
    );

    CREATE TABLE IF NOT EXISTS blocks (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      block_number  INTEGER UNIQUE NOT NULL,
      prev_hash     TEXT NOT NULL,
      block_hash    TEXT NOT NULL,
      tx_hash       TEXT,
      nullifier     TEXT,
      ipfs_cid      TEXT,
      candidate_id  INTEGER,
      voter_id      TEXT,
      gas_used      INTEGER DEFAULT 21000,
      mined_at      TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token       TEXT PRIMARY KEY,
      voter_id    TEXT NOT NULL,
      expires_at  TEXT NOT NULL,
      ip          TEXT,
      created_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS otp_store (
      phone       TEXT PRIMARY KEY,
      otp         TEXT NOT NULL,
      attempts    INTEGER DEFAULT 0,
      expires_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      voter_id    TEXT,
      action      TEXT NOT NULL,
      ip          TEXT,
      detail      TEXT,
      created_at  TEXT DEFAULT (datetime('now'))
    );
  `);

  // ── Seed candidates if empty ──
  const candCount = db.prepare('SELECT COUNT(*) AS c FROM candidates').get().c;
  if (candCount === 0) {
    const ins = db.prepare(`
      INSERT INTO candidates (serial_no,name,party,party_hi,symbol,constituency,vote_count,age,education)
      VALUES (?,?,?,?,?,?,?,?,?)
    `);
    const template = [
      [1,'Rajendra Kumar Sharma','National Alliance Party','राष्ट्रीय गठबंधन दल','🪷',320000+Math.floor(Math.random()*200000),52,'Post-Graduate'],
      [2,'Priya Mehta','Progressive Democratic Front','प्रगतिशील लोकतांत्रिक मोर्चा','✋',260000+Math.floor(Math.random()*150000),47,'PhD'],
      [3,'Arjun Singh Rawat',"People's Development Party",'जन विकास पार्टी','⚙️',180000+Math.floor(Math.random()*100000),55,'Graduate'],
      [4,'Sunita Devi Yadav','Kisan Mazdoor Ekta Party','किसान मजदूर एकता पार्टी','🌾',90000+Math.floor(Math.random()*60000),41,'12th Pass'],
      [5,'NOTA','None of the Above','उपरोक्त में से कोई नहीं','❌',3000+Math.floor(Math.random()*4000),0,'—'],
    ];
    const constituencies = [
      'Lucknow (18-UP)', 'Mumbai North (06-MH)', 'New Delhi (01-DL)',
      'Patna Sahib (03-BR)', 'Chennai Central (07-TN)',
      'Bangalore South (08-KA)', 'Jaipur (01-RJ)', 'Kolkata North (01-WB)'
    ];
    constituencies.forEach(con => {
      template.forEach(([sno, name, party, partyHi, sym, votes, age, edu]) => {
        ins.run(sno, name, party, partyHi, sym, con, votes, age, edu);
      });
    });
    console.log('[DB] ✅ Candidates seeded (40 candidates, 8 constituencies)');
  }

  // ── Seed genesis block if empty ──
  const blockCount = db.prepare('SELECT COUNT(*) AS c FROM blocks').get().c;
  if (blockCount === 0) {
    const genesisHash = crypto.createHash('sha256').update('genesis-eci-evbs-2025').digest('hex');
    db.prepare(`INSERT INTO blocks (block_number,prev_hash,block_hash,mined_at) VALUES (0,'0000000000000000',?,datetime('now','-3 hours'))`).run(genesisHash);
    let prev = genesisHash;
    for (let i = 1; i <= 6; i++) {
      const h = crypto.createHash('sha256').update(prev + i + 'seed').digest('hex');
      const tx = '0x' + crypto.randomBytes(16).toString('hex');
      db.prepare(`INSERT INTO blocks (block_number,prev_hash,block_hash,tx_hash,gas_used,mined_at) VALUES (?,?,?,?,?,datetime('now','-${180 - i*25} minutes'))`).run(2847284 + i, prev, h, tx, 21000 + Math.floor(Math.random() * 5000));
      prev = h;
    }
    console.log('[DB] ✅ Genesis + sample blocks seeded');
  }

  console.log('[DB] ✅ Database ready →', DB_FILE);
  return db;
}

module.exports = { db: init() };