const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const authPanel = document.getElementById('auth-panel');
const dashboard = document.getElementById('dashboard');
const usernameInput = document.getElementById('username');
const authStatus = document.getElementById('auth-status');
const displayName = document.getElementById('display-name');
const scoreValue = document.getElementById('score-value');
const scoreCircle = document.getElementById('score-circle');
const riskLevel = document.getElementById('risk-level');
const riskReasons = document.getElementById('risk-reasons');
const stepupPanel = document.getElementById('stepup-panel');

let currentUser = null;
let monitoringInterval = null;

// Simple device fingerprint
function getDeviceFp() {
  const data = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    new Date().getTimezoneOffset(),
    navigator.hardwareConcurrency || 0
  ].join('|');
  // Basic hash
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    hash = ((hash << 5) - hash) + data.charCodeAt(i);
    hash |= 0;
  }
  return 'fp_' + Math.abs(hash).toString(16);
}

// Simulated behavioral score (0 = normal, 1 = highly anomalous)
// In a real system this would come from typing dynamics, mouse entropy, motion sensors, etc.
function getBehaviorScore() {
  // Mostly normal, occasionally inject anomaly for demo purposes
  return Math.random() < 0.08 ? 0.7 + Math.random() * 0.3 : Math.random() * 0.15;
}

function setStatus(msg, type = '') {
  authStatus.textContent = msg;
  authStatus.className = 'status ' + type;
}

function showDashboard(user) {
  currentUser = user;
  authPanel.classList.add('hidden');
  dashboard.classList.remove('hidden');
  displayName.textContent = user.displayName || user.username;
  startMonitoring();
}

function showAuth() {
  currentUser = null;
  dashboard.classList.add('hidden');
  authPanel.classList.remove('hidden');
  stepupPanel.classList.add('hidden');
  if (monitoringInterval) clearInterval(monitoringInterval);
}

function updateRiskUI(result) {
  scoreValue.textContent = Math.round(result.score);
  riskLevel.textContent = result.level.toUpperCase();
  riskLevel.className = 'risk-level ' + result.level;

  // Update circle gradient
  const pct = Math.min(100, result.score);
  let color = '#2ecc71';
  if (result.level === 'medium') color = '#f39c12';
  if (result.level === 'high') color = '#e74c3c';
  scoreCircle.style.background = `conic-gradient(${color} ${pct}%, #1a2338 ${pct}%)`;

  riskReasons.innerHTML = '';
  (result.reasons || []).forEach(r => {
    const li = document.createElement('li');
    li.textContent = r;
    riskReasons.appendChild(li);
  });

  if (result.requireStepUp) {
    stepupPanel.classList.remove('hidden');
  } else {
    stepupPanel.classList.add('hidden');
  }
}

async function checkRisk() {
  try {
    const res = await fetch('/api/risk/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        deviceFp: getDeviceFp(),
        behaviorScore: getBehaviorScore()
      })
    });
    if (!res.ok) return;
    const result = await res.json();
    updateRiskUI(result);
  } catch (e) {
    console.error('Risk check failed', e);
  }
}

function startMonitoring() {
  checkRisk();
  monitoringInterval = setInterval(checkRisk, 12000); // every 12s
}

// Registration
document.getElementById('btn-register').addEventListener('click', async () => {
  const username = usernameInput.value.trim();
  if (!username) return setStatus('Enter a username', 'error');

  setStatus('Creating passkey…');
  try {
    const optRes = await fetch('/api/register/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, displayName: username })
    });
    const options = await optRes.json();
    if (!optRes.ok) throw new Error(options.error || 'Options failed');

    const attResp = await startRegistration({ optionsJSON: options });

    const verRes = await fetch('/api/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ response: attResp })
    });
    const verification = await verRes.json();
    if (!verRes.ok) throw new Error(verification.error || 'Verification failed');

    setStatus('Registered successfully!', 'success');
    showDashboard(verification.user);
  } catch (err) {
    console.error(err);
    setStatus(err.message || 'Registration failed', 'error');
  }
});

// Login
document.getElementById('btn-login').addEventListener('click', async () => {
  const username = usernameInput.value.trim();
  if (!username) return setStatus('Enter a username', 'error');

  setStatus('Authenticating…');
  try {
    const optRes = await fetch('/api/login/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username })
    });
    const options = await optRes.json();
    if (!optRes.ok) throw new Error(options.error || 'Options failed');

    const authResp = await startAuthentication({ optionsJSON: options });

    const verRes = await fetch('/api/login/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ response: authResp, deviceFp: getDeviceFp() })
    });
    const verification = await verRes.json();
    if (!verRes.ok) throw new Error(verification.error || 'Verification failed');

    setStatus('Signed in!', 'success');
    showDashboard(verification.user);
    if (verification.risk) updateRiskUI(verification.risk);
  } catch (err) {
    console.error(err);
    setStatus(err.message || 'Login failed', 'error');
  }
});

// Step-up
document.getElementById('btn-stepup').addEventListener('click', async () => {
  try {
    const optRes = await fetch('/api/stepup/options', {
      method: 'POST',
      credentials: 'include'
    });
    const options = await optRes.json();
    if (!optRes.ok) throw new Error(options.error);

    const authResp = await startAuthentication({ optionsJSON: options });

    const verRes = await fetch('/api/stepup/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ response: authResp })
    });
    const verification = await verRes.json();
    if (!verRes.ok) throw new Error(verification.error);

    updateRiskUI(verification.risk);
    stepupPanel.classList.add('hidden');
  } catch (err) {
    console.error(err);
    alert('Step-up failed: ' + (err.message || err));
  }
});

document.getElementById('btn-check-risk').addEventListener('click', checkRisk);

document.getElementById('btn-logout').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST', credentials: 'include' });
  showAuth();
  setStatus('');
});

// Check existing session on load
(async () => {
  try {
    const res = await fetch('/api/session', { credentials: 'include' });
    const data = await res.json();
    if (data.authenticated && data.user) {
      showDashboard(data.user);
      if (data.risk) updateRiskUI({ score: data.risk.score, level: data.risk.score >= 60 ? 'high' : data.risk.score >= 30 ? 'medium' : 'low', reasons: [] });
    }
  } catch (e) {}
})();
