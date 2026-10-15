/**
 * GenKey Risk Engine
 * Continuous scoring based on multiple signals.
 * Score 0-100. Higher = more risk.
 * Thresholds: <30 low, 30-60 medium, >60 high → step-up
 */

function computeRisk(signals, previous = {}) {
  let score = 0;
  const reasons = [];

  // IP change
  if (previous.last_ip && signals.ip && previous.last_ip !== signals.ip) {
    score += 25;
    reasons.push('IP address changed');
  }

  // Device fingerprint mismatch
  if (previous.last_device_fp && signals.deviceFp && previous.last_device_fp !== signals.deviceFp) {
    score += 35;
    reasons.push('Device fingerprint mismatch');
  }

  // Unusual time gap (session idle too long or too short for action)
  const now = Date.now();
  if (previous.last_check) {
    const deltaMin = (now - previous.last_check) / 60000;
    if (deltaMin > 30) {
      score += 20;
      reasons.push('Long idle period');
    }
  }

  // Simulated behavioral anomalies (in real system: typing, mouse, motion)
  if (signals.behaviorScore !== undefined) {
    // behaviorScore expected 0-1 where 1 is highly anomalous
    const behaviorPenalty = Math.round(signals.behaviorScore * 40);
    score += behaviorPenalty;
    if (behaviorPenalty > 15) reasons.push('Behavioral anomaly detected');
  }

  // New device / first seen
  if (!previous.last_device_fp && signals.deviceFp) {
    score += 15;
    reasons.push('New device');
  }

  // Time of day anomaly (very basic)
  const hour = new Date().getHours();
  if (hour >= 2 && hour <= 5) {
    score += 10;
    reasons.push('Unusual hour');
  }

  // Cap
  score = Math.min(100, Math.max(0, score));

  let level = 'low';
  if (score >= 60) level = 'high';
  else if (score >= 30) level = 'medium';

  return {
    score,
    level,
    reasons,
    requireStepUp: score >= 60
  };
}

module.exports = { computeRisk };
