# CodeAlpha_SecureCodingReview — Secure Code Review Report

CodeAlpha Cyber Security Internship, **Task 3**. Target: a small Flask (Python) web app with users, login, file download and utilities.

| File | Purpose |
|---|---|
| `vulnerable_app.py` | The audited application (intentionally insecure, 9 findings tagged `F1`–`F9`) |
| `secure_app.py` | Remediated version (every fix tagged with the same ID) |
| `README.md` | This report |

## 1. Scope & methodology
1. **Entry-point mapping** – every route that takes user input: `/register`, `/login`, `/hello`, `/ping`, `/download`, `/profile/<id>`, `/load`.
2. **Static analysis** – `bandit vulnerable_app.py` (Python SAST tool).
3. **Manual review** – line-by-line check against the OWASP Top 10 (2021), because scanners miss logic and context bugs.
4. **Remediation + verification** – fixed code re-scanned with Bandit and attacked with the same payloads.

## 2. Summary of findings
| ID | Vulnerability | Line | Severity | CWE | OWASP 2021 | Found by |
|---|---|---|---|---|---|---|
| F1 | Hardcoded secret key | 10 | High | CWE-798 | A02 Cryptographic Failures | Bandit B105 |
| F2 | Weak unsalted MD5 password hashing | 17, 25 | High | CWE-327 | A02 Cryptographic Failures | Bandit B324 |
| F3 | SQL injection (string-built queries) | 18, 26, 47 | Critical | CWE-89 | A03 Injection | Bandit B608 |
| F4 | Reflected cross-site scripting (XSS) | 32 | Medium | CWE-79 | A03 Injection | **Manual only** |
| F5 | OS command injection (`shell=True`) | 37 | Critical | CWE-78 | A03 Injection | Bandit B602 |
| F6 | Path traversal in file download | 42 | High | CWE-22 | A01 Broken Access Control | **Manual only** |
| F7 | Missing authentication / authorization (IDOR) | 46–47 | High | CWE-306, CWE-639 | A01 Broken Access Control | **Manual only** |
| F8 | Insecure deserialization (`pickle.loads`) | 52 | Critical | CWE-502 | A08 Integrity Failures | Bandit B301 |
| F9 | Debug mode on + bound to all interfaces | 56 | High | CWE-489, CWE-605 | A05 Security Misconfiguration | Bandit B201, B104 |

Totals: **3 Critical, 5 High, 1 Medium**.

## 3. Detailed findings & remediation
**F1 – Hardcoded secret key.** `SECRET_KEY = "super-secret-123"` is in source control, so anyone with the code can forge session cookies.
*Fix:* `os.environ["APP_SECRET_KEY"]`; keep secrets in env vars / a secrets manager and rotate them.

**F2 – MD5 password hashing.** MD5 is fast and unsalted: identical passwords give identical hashes and a leaked DB is cracked in minutes with rainbow tables/GPUs.
*Fix:* `generate_password_hash()` / `check_password_hash()` (salted scrypt/PBKDF2); alternatives: bcrypt, Argon2. Enforce a minimum password length.

**F3 – SQL injection.** User input is concatenated into SQL. Login bypass: name = `' OR '1'='1' --`.
*Fix:* parameterized queries `db.execute("... WHERE name = ?", (name,))`. Note: line 47 is not exploitable because Flask's `<int:uid>` converter only accepts integers, but it is still a bad pattern and was fixed.

**F4 – Reflected XSS.** `/hello?name=<script>alert(1)</script>` runs in the victim's browser (session theft, defacement).
*Fix:* escape output (`markupsafe.escape`) or use Jinja2 templates (auto-escaping); add a Content-Security-Policy header.

**F5 – Command injection.** `/ping?host=127.0.0.1;id` runs arbitrary commands on the server.
*Fix:* no shell, pass a list `["ping","-c","1",host]`, allow-list the host with a regex, add a timeout, require login.

**F6 – Path traversal.** `/download?file=../vulnerable_app.py` reads any file the process can access.
*Fix:* `send_from_directory(FILES_DIR, name)` which rejects paths outside the directory.

**F7 – Missing authorization (IDOR).** Anyone can read `/profile/1`, `/profile/2`, … without logging in.
*Fix:* store the user id in a signed session at login and check `session["uid"] == uid` on every request; deny by default.

**F8 – Insecure deserialization.** `pickle.loads()` on request data allows remote code execution.
*Fix:* never unpickle untrusted data; use JSON and validate the structure.

**F9 – Debug mode / bind all interfaces.** The Werkzeug debugger allows code execution; `0.0.0.0` exposes the app to the whole network.
*Fix:* `debug=False`, bind to `127.0.0.1` behind a reverse proxy (nginx) and a production server (gunicorn) with HTTPS.

## 4. Tool results
**Bandit on `vulnerable_app.py`: 12 issues** (4 High, 5 Medium, 3 Low).
Bandit **did not detect F4 (XSS), F6 (path traversal) and F7 (missing authorization)**: 3 of 9 real vulnerabilities. This is why static analysis must be combined with manual review.

**Bandit on `secure_app.py`: 0 High, 0 Medium, 3 Low** (B404, B603, B607 — all about `subprocess`). Reviewed and accepted: no shell is used, arguments are a list, and the host is allow-listed by regex. Hardening option: use the absolute path of `ping`.

**Verification of fixes (same attack payloads):**
| Test | Vulnerable app | Secure app |
|---|---|---|
| Login with `' OR '1'='1' --` | logs in | 401 denied |
| `/hello?name=<script>…` | script returned as HTML | returned as `&lt;script&gt;…` (inert) |
| `/profile/2` as user 1 | data returned | 403 |
| `/download?file=../secret.txt` | file content leaked | 404 |
| `/ping?host=127.0.0.1;echo INJECTED` | injected command runs | 400 |
| `/load` with non-JSON/pickle data | code executed | 400 |

## 5. Secure coding best practices checklist
- Validate all input with allow-lists; encode all output for its context (HTML, SQL, shell).
- Use parameterized queries / an ORM; never build SQL, shell commands or file paths from raw input.
- Hash passwords with Argon2/bcrypt/scrypt; never store plaintext; never roll your own crypto.
- Keep secrets out of code; use environment variables or a vault; rotate them.
- Enforce authentication **and** authorization on every endpoint (deny by default, least privilege).
- Never deserialize untrusted data with pickle/YAML-unsafe loaders; prefer JSON.
- Disable debug in production; set secure cookie flags; use HTTPS and security headers (CSP, HSTS, X-Content-Type-Options).
- Keep dependencies updated (`pip-audit`), run SAST (Bandit/Semgrep) in CI, and review code manually.

**Not implemented in this demo (recommended next):** CSRF tokens (Flask-WTF), rate limiting / account lockout on `/login` (Flask-Limiter), security logging, HTTPS.

## 6. How to reproduce
```bash
pip install flask bandit
bandit vulnerable_app.py                              # static analysis
export APP_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
mkdir -p files && echo hello > files/a.txt
python3 secure_app.py                                 # run the fixed app
```
Run `vulnerable_app.py` only on your own machine (localhost) for demonstration.
