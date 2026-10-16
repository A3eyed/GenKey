# GenKey

**Next-generation authentication that works as both classic 2-Step / 2FA and modern passwordless multi-factor — across every device.**

GenKey supports two modes so you can choose the right balance of security and convenience:

### Mode 1 – Passwordless (Recommended)
- Just a passkey (Face ID / fingerprint / PIN / security key)
- Counts as multi-factor under NIST guidelines
- Phishing-resistant, lowest friction
- Works on phone, tablet, laptop, desktop

### Mode 2 – Classic 2FA / 2-Step
- Password + Passkey (or password + authenticator app later)
- Traditional two different factors
- Familiar flow for users and enterprises that still require a password

Both modes include **continuous risk monitoring** after login (device, IP, behavior, timing). High risk automatically triggers a step-up challenge.

## Cross-device support
- Platform authenticators (iPhone Face ID, Android biometrics, Windows Hello, macOS Touch ID)
- Roaming authenticators (YubiKey, Titan, etc.)
- Hybrid transport so you can approve a login on one device from another
- Works in modern mobile and desktop browsers

## Quick Start

```bash
npm install
npm start
```

Open http://localhost:3000 (or your deployed public URL)

1. Choose **Register** → create a passkey (this is already multi-factor)
2. Or register with a password + passkey for classic 2FA mode
3. Sign in from any device that has the passkey or can use hybrid flow

## Why GenKey
- Works as pure passwordless **or** classic password + second factor
- Phishing-resistant by design
- Continuous assurance instead of one-time checks
- Runs on phones, tablets, and computers
- Ready for real-world use and further extension (TOTP fallback, hardware keys, enterprise policies)

## License
MIT
