# GenKey

**Next-generation continuous, adaptive, phishing-resistant authentication.**

GenKey moves beyond traditional 2FA (SMS, TOTP, push) to a system built on:

- **Passkeys / WebAuthn** – phishing-resistant cryptographic credentials
- **Continuous risk scoring** – behavioral + contextual signals evaluated throughout the session
- **Adaptive step-up** – extra verification only when risk is elevated
- **Low friction** – often invisible on trusted devices and normal behavior

## Features

- Passwordless registration and login with platform authenticators (Face ID, Touch ID, Windows Hello, etc.)
- Device-bound credentials with origin binding
- Continuous session monitoring endpoint
- Simple risk engine (device fingerprint, IP change, time-based anomalies, simulated behavioral signals)
- Automatic step-up challenge when risk exceeds threshold
- SQLite persistence for users and credentials
- Clean modern UI

## Quick Start

```bash
npm install
npm start
```

Open http://localhost:3000

> **Note**: WebAuthn requires a secure context. For local development use `localhost`. In production you need HTTPS and a proper `rpID`.

## Architecture

```
Client (browser)
  ├── Passkey registration / authentication (WebAuthn)
  ├── Continuous signal collection (device, timing, simple behavioral)
  └── Risk check calls

Server
  ├── @simplewebauthn for cryptographic verification
  ├── Risk engine (score = device + IP + time + behavior)
  ├── Session store with continuous re-evaluation
  └── Step-up challenge generation when score is high
```

## API Overview

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/register/options` | POST | Generate registration options |
| `/api/register/verify` | POST | Verify registration response |
| `/api/login/options` | POST | Generate authentication options |
| `/api/login/verify` | POST | Verify authentication response |
| `/api/session` | GET | Current session + risk status |
| `/api/risk/check` | POST | Continuous risk evaluation |
| `/api/stepup/options` | POST | Generate step-up challenge |
| `/api/stepup/verify` | POST | Verify step-up |

## Why GenKey over classic 2FA

- Phishing-resistant by design (origin-bound keys)
- Continuous assurance instead of point-in-time
- Dramatically lower user friction
- Resistant to SIM swap, MFA fatigue, and real-time proxy attacks
- Ready for AI-agent and high-assurance scenarios

## License

MIT
