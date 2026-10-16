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
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

// ========== Registration (passwordless + classic 2FA) ==========
app.post('/api/register/options', async (req, res) => {
  try {
    const { username, displayName, mode } = req.body;
    if (!username) return res.status(400).json({ error: 'username required' });

    let user = db.getUserByUsername(username);
    if (!user) {
      user = db.createUser({
        id: uuidv4(),
        username,
        display_name: displayName || username,
        hasPassword: false,
        created_at: Date.now()
      });
    }

    const existingCreds = db.getCredentialsForUser(user.id);

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
        authenticatorAttachment: undefined
      },
      extensions: { credProps: true }
    });

    req.session.currentChallenge = options.challenge;
    req.session.pendingUserId = user.id;
    req.session.regMode = mode || 'passwordless';

    res.json(options);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/register/verify', async (req, res) => {
  try {
    const { response, password } = req.body;
    const expectedChallenge = req.session.currentChallenge;
    const userId = req.session.pendingUserId;
    const mode = req.session.regMode || 'passwordless';

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

    db.createCredential({
      id: uuidv4(),
      user_id: userId,
      credential_id: credId,
      public_key: Buffer.from(credential.publicKey).toString('base64'),
      counter: credential.counter,
      transports: JSON.stringify(response.response.transports || []),
      created_at: Date.now()
    });

    if (mode === 'classic' && password) {
      db.setPassword(userId, password);
    }

    const sessionId = uuidv4();
    db.createSession({
      id: sessionId,
      user_id: userId,
      risk_score: 0,
      last_ip: req.ip,
      last_device_fp: null,
      last_check: Date.now(),
      created_at: Date.now()
    });

    req.session.userId = userId;
    req.session.sessionId = sessionId;
    req.session.currentChallenge = undefined;
    req.session.pendingUserId = undefined;
    req.session.regMode = undefined;

    const user = db.getUserById(userId);
    res.json({
      verified: true,
      mode: user.hasPassword ? 'classic' : 'passwordless',
      user: { id: user.id, username: user.username, displayName: user.display_name, hasPassword: !!user.hasPassword }
    });
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

    const user = db.getUserByUsername(username);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const creds = db.getCredentialsForUser(user.id);
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

    res.json({
      ...options,
      requiresPassword: !!user.hasPassword
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login/verify', async (req, res) => {
  try {
    const { response, deviceFp, password } = req.body;
    const expectedChallenge = req.session.currentChallenge;
    const userId = req.session.pendingUserId;

    if (!expectedChallenge || !userId) {
      return res.status(400).json({ error: 'No pending login' });
    }

    const user = db.getUserById(userId);

    if (user.hasPassword) {
      if (!password || !db.verifyPassword(userId, password)) {
        return res.status(401).json({ error: 'Invalid password' });
      }
    }

    const credId = Buffer.from(response.id, 'base64url').toString('base64url');
    const dbCred = db.getCredentialById(credId);
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

    db.updateCredentialCounter(dbCred.id, verification.authenticationInfo.newCounter);

    const sessionId = uuidv4();
    const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    db.createSession({
      id: sessionId,
      user_id: userId,
      risk_score: 0,
      last_ip: ip,
      last_device_fp: deviceFp || null,
      last_check: Date.now(),
      created_at: Date.now()
    });

    req.session.userId = userId;
    req.session.sessionId = sessionId;
    req.session.currentChallenge = undefined;
    req.session.pendingUserId = undefined;

    res.json({
      verified: true,
      mode: user.hasPassword ? 'classic' : 'passwordless',
      user: { id: user.id, username: user.username, displayName: user.display_name, hasPassword: !!user.hasPassword },
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
  const user = db.getUserById(req.session.userId);
  const sess = db.getSession(req.session.sessionId);

  res.json({
    authenticated: true,
    mode: user && user.hasPassword ? 'classic' : 'passwordless',
    user: user ? { id: user.id, username: user.username, displayName: user.display_name, hasPassword: !!user.hasPassword } : null,
    risk: sess ? { score: sess.risk_score, lastCheck: sess.last_check } : null
  });
});

app.post('/api/risk/check', (req, res) => {
  if (!req.session.userId || !req.session.sessionId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const sess = db.getSession(req.session.sessionId);
  if (!sess) return res.status(401).json({ error: 'Session not found' });

  const signals = {
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown',
    deviceFp: req.body.deviceFp,
    behaviorScore: req.body.behaviorScore
  };

  const previous = {
    last_ip: sess.last_ip,
    last_device_fp: sess.last_device_fp,
    last_check: sess.last_check
  };

  const result = computeRisk(signals, previous);

  db.updateSession(sess.id, {
    risk_score: result.score,
    last_ip: signals.ip,
    last_device_fp: signals.deviceFp || sess.last_device_fp,
    last_check: Date.now()
  });

  res.json(result);
});

// ========== Step-up ==========
app.post('/api/stepup/options', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const user = db.getUserById(req.session.userId);
    const creds = db.getCredentialsForUser(user.id);

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
    const dbCred = db.getCredentialById(credId);
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

    db.updateSession(req.session.sessionId, {
      risk_score: 0,
      last_check: Date.now()
    });

    req.session.currentChallenge = undefined;
    res.json({ verified: true, risk: { score: 0, level: 'low' } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  if (req.session.sessionId) {
    db.deleteSession(req.session.sessionId);
  }
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`GenKey running at ${origin}`);
  console.log(`RP ID: ${rpID}`);
  console.log('Supports: Passwordless multi-factor + Classic 2FA (password + passkey)');
  console.log('Cross-device: platform + roaming authenticators');
});
