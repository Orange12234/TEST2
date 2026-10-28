'use strict';
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite'); // built into Node 22.13+, nothing to compile

const db = new DatabaseSync(process.env.DB_PATH || path.join(__dirname, 'chess.db'));
db.exec('PRAGMA journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  username_lc TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL,
  rating INTEGER NOT NULL DEFAULT 1200,
  games INTEGER NOT NULL DEFAULT 0,
  wins INTEGER NOT NULL DEFAULT 0,
  losses INTEGER NOT NULL DEFAULT 0,
  draws INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS games (
  id TEXT PRIMARY KEY,
  white_name TEXT NOT NULL,
  black_name TEXT NOT NULL,
  white_id INTEGER,
  black_id INTEGER,
  result TEXT NOT NULL,
  reason TEXT NOT NULL,
  moves TEXT NOT NULL,
  tc TEXT NOT NULL,
  rated INTEGER NOT NULL,
  white_delta INTEGER,
  black_delta INTEGER,
  ended_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS games_white ON games(white_id);
CREATE INDEX IF NOT EXISTS games_black ON games(black_id);
`);

// Upgrade databases created before titles and bios existed.
{
  const cols = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
  if (!cols.includes('title')) db.exec("ALTER TABLE users ADD COLUMN title TEXT NOT NULL DEFAULT ''");
  if (!cols.includes('bio')) db.exec("ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''");
  if (!cols.includes('role')) db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT ''");
  if (!cols.includes('ban_until')) db.exec('ALTER TABLE users ADD COLUMN ban_until INTEGER NOT NULL DEFAULT 0');
  if (!cols.includes('ban_reason')) db.exec("ALTER TABLE users ADD COLUMN ban_reason TEXT NOT NULL DEFAULT ''");
  if (!cols.includes('banned_by')) db.exec("ALTER TABLE users ADD COLUMN banned_by TEXT NOT NULL DEFAULT ''");
}

db.exec(`
CREATE TABLE IF NOT EXISTS mod_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
`);

const SESSION_TTL_MS = 30 * 24 * 3600 * 1000;

const q = {
  insertUser: db.prepare('INSERT INTO users (username, username_lc, pass_hash, created_at) VALUES (?, ?, ?, ?)'),
  byName: db.prepare('SELECT * FROM users WHERE username_lc = ?'),
  byId: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertSession: db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)'),
  session: db.prepare('SELECT user_id, created_at FROM sessions WHERE token = ?'),
  delSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  stats: db.prepare(`UPDATE users SET rating = ?, games = games + 1,
    wins = wins + ?, losses = losses + ?, draws = draws + ? WHERE id = ?`),
  insertGame: db.prepare(`INSERT OR REPLACE INTO games
    (id, white_name, black_name, white_id, black_id, result, reason, moves, tc, rated, white_delta, black_delta, ended_at)
    VALUES (@id, @white_name, @black_name, @white_id, @black_id, @result, @reason, @moves, @tc, @rated, @white_delta, @black_delta, @ended_at)`),
  setTitle: db.prepare('UPDATE users SET title = ? WHERE id = ?'),
  setBio: db.prepare('UPDATE users SET bio = ? WHERE id = ?'),
  setRole: db.prepare('UPDATE users SET role = ? WHERE id = ?'),
  ban: db.prepare('UPDATE users SET ban_until = ?, ban_reason = ?, banned_by = ? WHERE id = ?'),
  unban: db.prepare("UPDATE users SET ban_until = 0, ban_reason = '', banned_by = '' WHERE id = ?"),
  delUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
  log: db.prepare('INSERT INTO mod_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)'),
  modLog: db.prepare('SELECT at, actor, action, target, detail FROM mod_log ORDER BY id DESC LIMIT ?'),
  bans: db.prepare('SELECT username, title, ban_until, ban_reason, banned_by FROM users WHERE ban_until > ? ORDER BY ban_until DESC'),
  staff: db.prepare("SELECT username, role FROM users WHERE role != '' ORDER BY role DESC, username"),
  leaderboard: db.prepare('SELECT username, title, rating, games, wins, losses, draws FROM users WHERE games > 0 AND ban_until <= ? ORDER BY rating DESC LIMIT 20'),
  searchUsers: db.prepare(`SELECT username, title, rating FROM users WHERE username_lc LIKE ? ESCAPE '\\'
    ORDER BY (username_lc LIKE ? ESCAPE '\\') DESC, username_lc LIMIT 8`),
  userGames: db.prepare(`SELECT id, white_name, black_name, white_id, black_id, result, reason, tc, rated,
    white_delta, black_delta, ended_at FROM games WHERE white_id = ? OR black_id = ? ORDER BY ended_at DESC LIMIT 20`),
};

function getUserByName(name) { return q.byName.get(String(name).toLowerCase()) || null; }
function getUserById(id) { return q.byId.get(id) || null; }

function createUser(username, passHash) {
  const info = q.insertUser.run(username, username.toLowerCase(), passHash, Date.now());
  return getUserById(Number(info.lastInsertRowid));
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  q.insertSession.run(token, userId, Date.now());
  return token;
}

function userForToken(token) {
  if (typeof token !== 'string' || token.length !== 64) return null;
  const s = q.session.get(token);
  if (!s) return null;
  if (Date.now() - s.created_at > SESSION_TTL_MS) { q.delSession.run(token); return null; }
  return getUserById(s.user_id);
}

function deleteSession(token) { q.delSession.run(token); }

// outcome: 'win' | 'loss' | 'draw'
function recordResult(userId, newRating, outcome) {
  q.stats.run(newRating, outcome === 'win' ? 1 : 0, outcome === 'loss' ? 1 : 0, outcome === 'draw' ? 1 : 0, userId);
}

function saveGame(g) { q.insertGame.run(g); }
function leaderboard() { return q.leaderboard.all(Date.now()); }
function setTitle(userId, title) { q.setTitle.run(title, userId); }
function setBio(userId, bio) { q.setBio.run(bio, userId); }
function setRole(userId, role) { q.setRole.run(role, userId); }
function banUser(userId, until, reason, by) { q.ban.run(until, reason, by, userId); }
function unbanUser(userId) { q.unban.run(userId); }
function deleteSessionsForUser(userId) { q.delUserSessions.run(userId); }
function logAction(a) { q.log.run(Date.now(), a.actor_name, a.action, a.target_name, a.detail || ''); }
function modLog(limit = 30) { return q.modLog.all(limit); }
function listBans() { return q.bans.all(Date.now()); }
function listStaff() { return q.staff.all(); }
function userGames(id) { return q.userGames.all(id, id); }
// Players whose name contains `term`, names that start with it first. `term` must be letters, digits or underscores.
function searchUsers(term) {
  const e = String(term).toLowerCase().replace(/_/g, '\\_');
  return q.searchUsers.all('%' + e + '%', e + '%');
}

module.exports = {
  getUserByName, getUserById, createUser, createSession, userForToken,
  deleteSession, recordResult, saveGame, leaderboard, userGames, setTitle, setBio, searchUsers,
  setRole, banUser, unbanUser, deleteSessionsForUser, logAction, modLog, listBans, listStaff,
};
