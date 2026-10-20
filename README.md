# Part 2 — SecureBank: Web Security Project (Vulnerable vs Safe)

A full-stack **online-banking** web app built to demonstrate how XSS, CSRF and
SQL Injection actually work, and how to fix them. The **same codebase** runs in
two modes selected by the `MODE` environment variable:

- `MODE=vulnerable` — every attack below works end-to-end.
- `MODE=safe` — identical features, hardened with real defenses.

Each vulnerability lives behind an explicit `if (SAFE) { ...fix... } else
{ ...bug... }` in [`src/server.js`](src/server.js), so at the viva you can point
at the exact line that is the fix.

**Tech stack:** Node.js + Express + MySQL (`mysql2`), server-rendered HTML.

---

## Use case

SecureBank is an online-banking portal: users log in, see their balance and
transactions, search their transaction history, leave support notes, and
**transfer funds**. That gives natural, realistic sinks for every required
vulnerability:

| Feature | Vulnerability demonstrated |
|---|---|
| Login form | SQL Injection (authentication bypass) |
| Transaction search | Reflected XSS + SQL Injection (error-based & UNION) |
| Support notes on dashboard | Stored XSS |
| "Statement note" (`#hash`) | DOM-based XSS |
| Transfer funds | CSRF |

---

## How to run

**Requirements:** Docker Desktop. Nothing else — MySQL and Node run in
containers, and the schema + seed data load automatically on first start.

```powershell
cd part2-webapp

# VULNERABLE version (default) — attacks work
docker compose up --build

# SAFE version — attacks are blocked
$env:MODE="safe"; docker compose up --build        # PowerShell
# MODE=safe docker compose up --build              # bash/Git Bash
```

Then open <http://localhost:3000>. A red/green banner at the top shows which
version is live.

**Demo accounts** (also the data the SQLi dump reveals):

| username | password | role |
|---|---|---|
| admin  | Sup3rSecret!2026 | administrator (first row) |
| ali    | ali-banking-pw   | customer |
| ayesha | ayesha-pw-2026   | customer |
| fatima | fatima!secure    | customer |

---

## The vulnerabilities and their fixes

### 1. SQL Injection

**Level 1 — Easy (login bypass).** The vulnerable login builds the query by
string concatenation:
```js
"SELECT ... WHERE username = '" + username + "' AND password = '" + password + "'"
```
Logging in with username `admin' -- ` (or `' OR '1'='1' -- `) comments out the
password check and logs you in as admin.
**Fix:** `pool.execute("... WHERE username=? AND password=?", [username, password])`
— the input is bound as data, never parsed as SQL — plus username format
validation.

**Level 2 — Intermediate (error-based).** The vulnerable search page leaks the
raw MySQL error. Injecting `extractvalue()`/`updatexml()` forces the database to
put secret data *inside an error message*, which the page prints back.
**Fix:** parameterised query + generic error message (no DB internals leaked).

**Level 3 — Advanced (UNION chain).** On the search page: determine the column
count (`ORDER BY`), then `UNION SELECT` against `information_schema` to list
tables and columns, then dump `username, password` from `users`.
**Fix:** same parameterised query — a UNION injected as a search term is now
treated as literal text to search for.

### 2. Cross-Site Scripting (XSS)

- **Reflected** — the search page echoes the raw `q` parameter into the HTML.
  **Fix:** HTML-encode on output (`escapeHtml`).
- **Stored** — a support note is saved to the DB and rendered to every viewer of
  the dashboard as raw HTML. **Fix:** HTML-encode the body on output.
- **DOM-based** — [`public/dom.js`](public/dom.js) writes `location.hash` into
  `innerHTML` entirely client-side (the server never sees it).
  **Fix:** use `textContent` instead of `innerHTML`.

The single fix behind all three: **context-correct output encoding** — treat
untrusted data as text, not markup.

### 3. CSRF (transfer funds)

The vulnerable `/transfer` performs the money transfer with no proof the request
came from our own page. [`public/attacker/csrf.html`](public/attacker/csrf.html)
is a fake "free iPhone" page that auto-submits a transfer; if the victim is
logged in, their money moves. (Per the brief, the attack page is hosted on the
same origin.)
**Fix:** a per-session CSRF token that the attacker cannot read (same-origin
policy) is required on the POST, plus a `SameSite=Strict` session cookie as an
independent second layer.

---

## Project structure
```
part2-webapp/
├─ docker-compose.yml      app + MySQL
├─ Dockerfile              Node app image
├─ src/
│  ├─ server.js            all routes; every vuln behind if(SAFE){...}else{...}
│  ├─ db.js                MySQL pool (query vs execute)
│  └─ views.js             layout + escapeHtml (the XSS fix)
├─ public/
│  ├─ style.css
│  ├─ dom.js               DOM-XSS sink (innerHTML vs textContent)
│  └─ attacker/csrf.html   same-origin CSRF attack page
└─ db/
   ├─ schema.sql
   └─ seed-data.sql        populated demo data
```

See [`PAYLOADS.md`](PAYLOADS.md) for every working payload and where to screenshot it.

> Note on password storage: this lab stores passwords in plaintext so the
> advanced SQLi stage can dump real credentials. A production "safe" build would
> additionally hash them with a password-specific algorithm (e.g. bcrypt); that
> is separate from the injection fix, which is parameterised queries.
