// A minimal file-based "database" so this project runs anywhere with zero
// setup (no Postgres/Mongo install required). It stores everything in
// data.json next to this file.
//
// This is fine for development and small-scale use, but it is NOT safe for
// concurrent writes at real scale (each write reads and rewrites the whole
// file). When you're ready for production, swap this module for a real
// database — Postgres via Supabase or Neon is the easiest upgrade path,
// since the shape of `readDB()`/`writeDB()` below maps directly onto a
// `users` table.

const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data.json');

function readDB() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: [] }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

module.exports = { readDB, writeDB };
