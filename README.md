# IoT Backend Security Suite

[![Security Test Suite](https://github.com/Suraj-Tirumali/iot-backend-security-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/Suraj-Tirumali/iot-backend-security-suite/actions/workflows/ci.yml)

An OWASP ISVS-aligned security test suite for IoT backend APIs. Built with FastAPI, PostgreSQL, and pytest.

**Scope:** This project tests IoT *backend APIs* — not firmware or hardware. IoT devices communicate with backend APIs, and this suite validates whether those APIs meet OWASP IoT Security Verification Standard (ISVS) controls. All testing is implemented at the software and API layer.

---

## What This Project Does

- Runs a FastAPI application that simulates an IoT device management backend
- Exposes both **secure** and **intentionally vulnerable** endpoints as test targets
- Tests OWASP ISVS controls across three sections using pytest
- Generates structured JSON test reports as artifacts
- Runs automatically on every push via GitHub Actions

---

## OWASP ISVS Coverage

| Section | Controls Tested |
|---|---|
| 2.1 — Authentication & Authorization | JWT algorithm enforcement, token expiry, brute force protection, user enumeration prevention, BOLA detection, password policy |
| 4 — Software Platform Security | Security headers, input validation, SQL injection resistance, error disclosure |
| 6 — Communications Security | TLS 1.2+ enforcement, certificate validation, HTTP→HTTPS redirect |

---

## Project Structure
```
iot-backend-security-suite/
├── app/                        # FastAPI target application
│   ├── core/                   # Config, database, security, dependencies
│   ├── models/                 # SQLAlchemy User and Device models
│   ├── routers/                # Auth, devices, password reset endpoints
│   │   └── vulnerable/         # Intentionally misconfigured test targets
│   ├── schemas/                # Pydantic request/response models
│   ├── services/               # Auth, email, token business logic
│   └── main.py                 # App entry point with security middleware
├── framework/                  # Reusable security testing primitives
│   ├── analyzers/              # JWT, cookie, and TLS analyzers
│   ├── runners/                # Brute force and rate limit probers
│   └── reporting/              # JSON and HTML report generators
├── tests/
│   ├── isvs/                   # OWASP ISVS security tests
│   │   ├── section_2_1/        # Authentication and authorization
│   │   ├── section_4/          # Platform security
│   │   └── section_6/          # Communications security
│   └── unit/                   # Unit tests for framework modules
├── reports/                    # Test output artifacts
├── .github/workflows/ci.yml    # GitHub Actions CI
├── docker-compose.yml          # Full stack: app + postgres + mailhog
└── pyproject.toml              # Dependencies and tool config
```

---

## Quick Start

**Requirements:** Docker Desktop with WSL2 backend (Windows) or Docker Engine (Linux/Mac)
```bash
# Clone the repo
git clone https://github.com/Suraj-Tirumali/iot-backend-security-suite.git
cd iot-backend-security-suite

# Copy and configure environment
cp .env.example .env
# Edit .env — set SECRET_KEY and Mailtrap credentials

# Start the full stack
make up
# or: docker compose up --build -d

# Run database migrations
make migrate
# or: alembic upgrade head
```

App is now running at `http://localhost:8000`
API docs at `http://localhost:8000/docs`
Mailhog (email catcher) at `http://localhost:8025`

---

## Running Tests
```bash
# Activate virtual environment
source .venv/bin/activate

# Unit tests — no server required
make test-unit

# ISVS integration tests — requires running server and database
make test-isvs

# All tests
make test-all
```

---

## Email — Password Reset Flow

Password reset emails are sent via [Mailtrap](https://mailtrap.io) in development. Mailtrap catches all outgoing emails — no real email is ever delivered.

To configure:
1. Create a free Mailtrap account
2. Copy your SMTP credentials into `.env`
3. Trigger a reset: `POST /auth/password-reset/request`
4. View the email in your Mailtrap inbox

**Production:** Replace Mailtrap credentials in `.env` with any real SMTP provider (SendGrid, AWS SES, Postmark). No code changes required.

---

## Vulnerable Endpoints

The `vulnerable/` router exposes intentionally misconfigured endpoints as test targets. Every vulnerability is documented with the ISVS control it violates.

| Endpoint | Vulnerability | ISVS Control Violated |
|---|---|---|
| `POST /vulnerable/login-no-lockout` | No brute force protection, user enumeration | 2.1.2, 2.1.5 |
| `POST /vulnerable/login-weak-jwt` | Token never expires (year 2099) | 2.1.3 |
| `GET /vulnerable/user-info/{id}` | BOLA — no auth, exposes hashed password | 2.1.1 |
| `GET /vulnerable/ping` | No rate limiting | 4.1 |
| `POST /vulnerable/echo` | No input size validation | 4.2 |
| `GET /vulnerable/debug-info` | Exposes internal stack details | 4.3 |

**These endpoints exist only to be tested against. Never use these patterns in production.**

---

## CI/CD

GitHub Actions runs on every push:

- **Unit Tests** — Framework module tests, no server needed (~25s)
- **ISVS Integration Tests** — Full stack with PostgreSQL service (~60s)

Test artifacts (JUnit XML) are uploaded on every run.

---

## Environment Variables

See `.env.example` — every variable is documented inline.

Key variables:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | JWT signing key — generate with `openssl rand -hex 32` |
| `DATABASE_URL` | PostgreSQL connection string — use `@db:5432` in Docker, `@localhost:5432` locally |
| `MAIL_USERNAME` / `MAIL_PASSWORD` | Mailtrap SMTP credentials |
| `RATE_LIMIT_MAX_ATTEMPTS` | Login attempts before lockout |

---

## Tech Stack

| Layer | Technology |
|---|---|
| API Framework | FastAPI 0.115 |
| Database | PostgreSQL 16 + SQLAlchemy 2.0 (async) |
| Migrations | Alembic |
| Auth | JWT (python-jose) + bcrypt |
| Email | fastapi-mail + Mailtrap |
| Testing | pytest + pytest-asyncio + httpx |
| HTTP Client | httpx (async) |
| Containers | Docker + docker-compose |
| CI | GitHub Actions |