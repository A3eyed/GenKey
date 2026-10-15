const express = require('express');
const session = require('express-session');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const db = require('./db');
const { computeRisk } = require('./risk');

const app = express();
const PORT = process.env.PORT || 3000;

// In production set these properly
const rpName = 'GenKey';
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || `http://localhost:${PORT}`;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'genkey-dev-secret-change-me-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24h
  }
}));

// Helpers
function getUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function getCredentialsForUser(userId) {
  return db.prepare('SELECT * FROM credentials WHERE user_id = ?').all(userId);
}

function getCredentialById(credId) {
  return db.prepare('SELECT * FROM credentials WHERE credential_id = ?').get(credId);
}

// ========== Registration ==========
app.post('/api/register/options', async (req, res) => {
  try {
    const { username, displayName } = req.body;
    if (!username) return res.status(400).json({ error: 'username required' });

    let user = getUserByUsername(username);
    if (!user) {
      const id = uuidv4();
      db.prepare('INSERT INTO users (id, username, display_name, created_at) VALUES (?, ?, ?, ?)')
        .run(id, username, displayName || username, Date.now());
      user = getUserById(id);
    }

    const existingCreds = getCredentialsForUser(user.id);
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(user.id),
      userName: user.username,
      userDisplayName: user.display_name || user.username,
      attestationType: 'none',
      excludeCredentials: existingCreds.map(c => ({
        id: Buffer.from(c.credential_id, 'base64url'),
        transports: c.transports ? JSON.parse(c.transports) : undefined
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: 'platform'
      }
    });

    req.session.currentChallenge = options.challenge;
    req.session.pendingUserId = user.id;

    res.json(options);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/register/verify', async (req, res) => {
  try {
    const { response } = req.body;
    const expectedChallenge = req.session.currentChallenge;
    const userId = req.session.pendingUserId;

    if (!expectedChallenge || !userId) {
      return res.status(400).json({ error: 'No pending registration' });
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Verification failed' });
    }

    const { credential } = verification.registrationInfo;
    const credId = Buffer.from(credential.id).toString('base64url');

    db.prepare(`
      INSERT INTO credentials (id, user_id, credential_id, public_key, counter, transports, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      uuidv4(),
      userId,
      credId,
      Buffer.from(credential.publicKey).toString('base64'),
      credential.counter,
      JSON.stringify(response.response.transports || []),
      Date.now()
    );

    // Create session
    const sessionId = uuidv4();
    db.prepare(`
      INSERT INTO sessions (id, user_id, risk_score, last_ip, last_device_fp, last_check, created_at)
      VALUES (?, ?, 0, ?, ?, ?, ?)
    `).run(sessionId, userId, req.ip, null, Date.now(), Date.now());

    req.session.userId = userId;
    req.session.sessionId = sessionId;
    req.session.currentChallenge = undefined;
    req.session.pendingUserId = undefined;

    const user = getUserById(userId);
    res.json({ verified: true, user: { id: user.id, username: user.username, displayName: user.display_name } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ========== Login ==========
app.post('/api/login/options', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'username required' });

    const user = getUserByUsername(username);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const creds = getCredentialsForUser(user.id);
    if (creds.length === 0) return res.status(400).json({ error: 'No credentials registered' });

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: creds.map(c => ({
        id: Buffer.from(c.credential_id, 'base64url'),
        transports: c.transports ? JSON.parse(c.transports) : undefined
      })),
      userVerification: 'preferred'
    });

    req.session.currentChallenge = options.challenge;
    req.session.pendingUserId = user.id;

    res.json(options);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login/verify', async (req, res) => {
  try {
    const { response, deviceFp } = req.body;
    const expectedChallenge = req.session.currentChallenge;
    const userId = req.session.pendingUserId;

    if (!expectedChallenge || !userId) {
      return res.status(400).json({ error: 'No pending login' });
    }

    const credId = Buffer.from(response.id, 'base64url').toString('base64url');
    const dbCred = getCredentialById(credId);
    if (!dbCred || dbCred.user_id !== userId) {
      return res.status(400).json({ error: 'Credential not found' });
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: Buffer.from(dbCred.credential_id, 'base64url'),
        publicKey: Buffer.from(dbCred.public_key, 'base64'),
        counter: dbCred.counter,
        transports: dbCred.transports ? JSON.parse(dbCred.transports) : undefined
      }
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Verification failed' });
    }

    // Update counter
    db.prepare('UPDATE credentials SET counter = ? WHERE id = ?')
      .run(verification.authenticationInfo.newCounter, dbCred.id);

    // Create / update session
    const sessionId = uuidv4();
    const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    db.prepare(`
      INSERT INTO sessions (id, user_id, risk_score, last_ip, last_device_fp, last_check, created_at)
      VALUES (?, ?, 0, ?, ?, ?, ?)
    `).run(sessionId, userId, ip, deviceFp || null, Date.now(), Date.now());

    req.session.userId = userId;
    req.session.sessionId = sessionId;
    req.session.currentChallenge = undefined;
    req.session.pendingUserId = undefined;

    const user = getUserById(userId);
    res.json({
      verified: true,
      user: { id: user.id, username: user.username, displayName: user.display_name },
      risk: { score: 0, level: 'low' }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ========== Session & Continuous Risk ==========
app.get('/api/session', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ authenticated: false });
  }
  const user = getUserById(req.session.userId);
  const sess = db.prepare('SELECT * FROM sessions WHERE id = ?').get(req.session.sessionId);

  res.json({
    authenticated: true,
    user: user ? { id: user.id, username: user.username, displayName: user.display_name } : null,
    risk: sess ? { score: sess.risk_score, lastCheck: sess.last_check } : null
  });
});

app.post('/api/risk/check', (req, res) => {
  if (!req.session.userId || !req.session.sessionId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const sess = db.prepare('SELECT * FROM sessions WHERE id = ?').get(req.session.sessionId);
  if (!sess) return res.status(401).json({ error: 'Session not found' });

  const signals = {
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown',
    deviceFp: req.body.deviceFp,
    behaviorScore: req.body.behaviorScore // 0-1 from client
  };

  const previous = {
    last_ip: sess.last_ip,
    last_device_fp: sess.last_device_fp,
    last_check: sess.last_check
  };

  const result = computeRisk(signals, previous);

  // Persist
  db.prepare(`
    UPDATE sessions SET risk_score = ?, last_ip = ?, last_device_fp = ?, last_check = ?
    WHERE id = ?
  `).run(result.score, signals.ip, signals.deviceFp || sess.last_device_fp, Date.now(), sess.id);

  res.json(result);
});

// ========== Step-up ==========
app.post('/api/stepup/options', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const user = getUserById(req.session.userId);
    const creds = getCredentialsForUser(user.id);

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: creds.map(c => ({
        id: Buffer.from(c.credential_id, 'base64url'),
        transports: c.transports ? JSON.parse(c.transports) : undefined
      })),
      userVerification: 'required'
    });

    req.session.currentChallenge = options.challenge;
    res.json(options);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/stepup/verify', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const { response } = req.body;
    const expectedChallenge = req.session.currentChallenge;
    if (!expectedChallenge) return res.status(400).json({ error: 'No pending step-up' });

    const credId = Buffer.from(response.id, 'base64url').toString('base64url');
    const dbCred = getCredentialById(credId);
    if (!dbCred || dbCred.user_id !== req.session.userId) {
      return res.status(400).json({ error: 'Invalid credential' });
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: Buffer.from(dbCred.credential_id, 'base64url'),
        publicKey: Buffer.from(dbCred.public_key, 'base64'),
        counter: dbCred.counter,
        transports: dbCred.transports ? JSON.parse(dbCred.transports) : undefined
      }
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Step-up failed' });
    }

    // Reset risk after successful step-up
    db.prepare('UPDATE sessions SET risk_score = 0, last_check = ? WHERE id = ?')
      .run(Date.now(), req.session.sessionId);

    req.session.currentChallenge = undefined;
    res.json({ verified: true, risk: { score: 0, level: 'low' } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  if (req.session.sessionId) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(req.session.sessionId);
  }
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.listen(PORT, () => {
  console.log(`GenKey running at ${origin}`);
  console.log(`RP ID: ${rpID}`);
});
