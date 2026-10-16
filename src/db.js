/**
 * Pure-JS persistence for GenKey
 * Supports both passwordless and classic 2FA (password + passkey) modes
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, '..', 'genkey-data.json');

let data = {
  users: {},
  credentials: {},
  sessions: {}
};

function load() {
  try {
    if (fs.existsSync(DB_PATH)) {
      data = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (e) {
    console.warn('Could not load DB, starting fresh');
  }
}

function save() {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('Failed to save DB', e.message);
  }
}

load();

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

const db = {
  getUserByUsername(username) {
    return Object.values(data.users).find(u => u.username === username) || null;
  },
  getUserById(id) {
    return data.users[id] || null;
  },
  createUser(user) {
    data.users[user.id] = user;
    save();
    return user;
  },
  setPassword(userId, password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    if (data.users[userId]) {
      data.users[userId].passwordHash = hash;
      data.users[userId].passwordSalt = salt;
      data.users[userId].hasPassword = true;
      save();
    }
  },
  verifyPassword(userId, password) {
    const user = data.users[userId];
    if (!user || !user.passwordHash || !user.passwordSalt) return false;
    const hash = hashPassword(password, user.passwordSalt);
    return hash === user.passwordHash;
  },
  getCredentialsForUser(userId) {
    return Object.values(data.credentials).filter(c => c.user_id === userId);
  },
  getCredentialById(credId) {
    return Object.values(data.credentials).find(c => c.credential_id === credId) || null;
  },
  createCredential(cred) {
    data.credentials[cred.id] = cred;
    save();
    return cred;
  },
  updateCredentialCounter(id, counter) {
    if (data.credentials[id]) {
      data.credentials[id].counter = counter;
      save();
    }
  },
  createSession(sess) {
    data.sessions[sess.id] = sess;
    save();
    return sess;
  },
  getSession(id) {
    return data.sessions[id] || null;
  },
  updateSession(id, updates) {
    if (data.sessions[id]) {
      Object.assign(data.sessions[id], updates);
      save();
    }
  },
  deleteSession(id) {
    delete data.sessions[id];
    save();
  }
};

module.exports = db;
