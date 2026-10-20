// SecureBank - a deliberately vulnerable online-banking demo.
//
// ONE codebase, TWO behaviours chosen by the MODE environment variable:
//   MODE=vulnerable  -> every attack below works end to end
//   MODE=safe        -> the same features, hardened with real defenses
//
// Every vulnerability lives behind an `if (SAFE) { ...fix... } else { ...bug... }`
// so the examiner can see the exact line that changes between the two versions.
//
// Defenses demonstrated in SAFE mode:
//   - SQL injection  -> parameterised queries (execute with ? placeholders) + input validation
//   - XSS            -> output encoding (escapeHtml) + textContent instead of innerHTML
//   - CSRF           -> per-session token checked on state change + SameSite=Strict cookie

const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const path = require("path");
const pool = require("./db");
const { escapeHtml, layout, MODE } = require("./views");

const SAFE = MODE === "safe";
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "..", "public")));

app.use(
  session({
    name: "sbsession",
    secret: "securebank-demo-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      // SAFE mode pins the cookie to its own site so a cross-site POST from an
      // attacker page cannot ride along on it. VULNERABLE mode uses the loose
      // default, so the forged request is authenticated automatically.
      sameSite: SAFE ? "strict" : "lax",
    },
  })
);

// Give every session a CSRF token the first time we see it.
app.use((req, res, next) => {
  if (!req.session.csrf) {
    req.session.csrf = crypto.randomBytes(16).toString("hex");
  }
  next();
});

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

// ---------------------------------------------------------------------------
// Home
// ---------------------------------------------------------------------------
app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/dashboard" : "/login");
});

// ---------------------------------------------------------------------------
// LOGIN  -- SQL Injection, level 1 (EASY): authentication bypass
// ---------------------------------------------------------------------------
app.get("/login", (req, res) => {
  const err = req.query.err ? `<p class="error">${escapeHtml(req.query.err)}</p>` : "";
  res.send(
    layout(
      "Login",
      `<section class="card">
         <h1>Sign in</h1>
         ${err}
         <form method="POST" action="/login">
           <label>Username <input name="username" autofocus></label>
           <label>Password <input name="password" type="password"></label>
           <button type="submit">Sign in</button>
         </form>
         <p class="hint">Demo users are listed in the project README.</p>
       </section>`
    )
  );
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    let rows;
    if (SAFE) {
      // FIX: the username/password are bound as data, never parsed as SQL.
      // Also validate the username shape before it ever reaches the database.
      if (!/^[A-Za-z0-9_]{1,32}$/.test(username || "")) {
        return res.redirect("/login?err=" + encodeURIComponent("Invalid username format"));
      }
      [rows] = await pool.execute(
        "SELECT id, username, full_name, balance FROM users WHERE username = ? AND password = ?",
        [username, password]
      );
    } else {
      // BUG: user input is concatenated straight into the query string, so
      //   username:  ' OR '1'='1' --
      // turns the WHERE clause into something always true and logs us in as
      // the first user (an administrator) without knowing any password.
      const sql =
        "SELECT id, username, full_name, balance FROM users " +
        "WHERE username = '" + username + "' AND password = '" + password + "'";
      console.log("[login SQL] " + sql);
      [rows] = await pool.query(sql);
    }

    if (rows.length === 0) {
      return res.redirect("/login?err=" + encodeURIComponent("Invalid credentials"));
    }
    req.session.user = { id: rows[0].id, username: rows[0].username };
    res.redirect("/dashboard");
  } catch (e) {
    // VULNERABLE mode leaks the raw DB error, which is what makes error-based
    // SQL injection (level 2) possible. SAFE mode hides it.
    if (SAFE) return res.redirect("/login?err=" + encodeURIComponent("Login failed"));
    res.status(500).send(layout("Error", `<pre class="error">${escapeHtml(e.message)}</pre>`));
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// ---------------------------------------------------------------------------
// DASHBOARD  -- Stored XSS sink (support messages rendered back to the user)
// ---------------------------------------------------------------------------
app.get("/dashboard", requireLogin, async (req, res) => {
  const [[acct]] = await pool.query(
    "SELECT full_name, balance FROM users WHERE id = " + Number(req.session.user.id)
  );
  const [messages] = await pool.query(
    "SELECT body, created_at FROM messages WHERE user_id = " +
      Number(req.session.user.id) +
      " ORDER BY id DESC"
  );

  const msgHtml = messages
    .map((m) => {
      // Stored XSS: the message body was saved earlier. VULNERABLE mode drops
      // it into the page as raw HTML, so a saved <script>/<img onerror> payload
      // runs in the browser of anyone who views the dashboard. SAFE mode encodes
      // it on output so it is shown as text.
      const body = SAFE ? escapeHtml(m.body) : m.body;
      return `<li>${body} <time>${escapeHtml(String(m.created_at))}</time></li>`;
    })
    .join("");

  res.send(
    layout(
      "Dashboard",
      `<section class="card">
         <h1>Welcome, ${escapeHtml(acct.full_name)}</h1>
         <p class="balance">Available balance: <b>$${escapeHtml(String(acct.balance))}</b></p>
       </section>
       <section class="card">
         <h2>Support / note to self</h2>
         <form method="POST" action="/message">
           <input type="hidden" name="csrf" value="${req.session.csrf}">
           <textarea name="body" placeholder="Leave a note..."></textarea>
           <button type="submit">Save note</button>
         </form>
         <ul class="messages">${msgHtml || "<li>No notes yet.</li>"}</ul>
       </section>`,
      req.session.user
    )
  );
});

app.post("/message", requireLogin, async (req, res) => {
  // Saving a note is a state change, so SAFE mode also protects it with the
  // CSRF token. The XSS itself is about how the body is rendered (see above).
  if (SAFE && req.body.csrf !== req.session.csrf) {
    return res.status(403).send("CSRF token mismatch");
  }
  await pool.execute("INSERT INTO messages (user_id, body) VALUES (?, ?)", [
    req.session.user.id,
    req.body.body || "",
  ]);
  res.redirect("/dashboard");
});

// ---------------------------------------------------------------------------
// TRANSACTION SEARCH  -- Reflected XSS  +  SQL Injection levels 2 & 3
// ---------------------------------------------------------------------------
app.get("/search", requireLogin, async (req, res) => {
  const q = req.query.q;
  let resultHtml = "";
  let error = "";

  if (q !== undefined) {
    try {
      let rows;
      if (SAFE) {
        // FIX: parameterised LIKE, so the search term is pure data.
        [rows] = await pool.execute(
          "SELECT description, amount, created_at FROM transactions " +
            "WHERE user_id = ? AND description LIKE CONCAT('%', ?, '%') ORDER BY id DESC",
          [req.session.user.id, q]
        );
      } else {
        // BUG: the search term is concatenated in. This single visible query
        // supports error-based injection (level 2, via the leaked error) and
        // UNION-based injection (level 3) because results are printed back.
        const sql =
          "SELECT description, amount, created_at FROM transactions " +
          "WHERE user_id = " + Number(req.session.user.id) +
          " AND description LIKE '%" + q + "%' ORDER BY id DESC";
        console.log("[search SQL] " + sql);
        [rows] = await pool.query(sql);
      }
      resultHtml =
        "<table class='tx'><tr><th>Description</th><th>Amount</th><th>Date</th></tr>" +
        rows
          .map(
            (r) =>
              `<tr><td>${escapeHtml(String(r.description))}</td>` +
              `<td>${escapeHtml(String(r.amount))}</td>` +
              `<td>${escapeHtml(String(r.created_at))}</td></tr>`
          )
          .join("") +
        "</table>";
    } catch (e) {
      // Leaking this message is the realistic misconfiguration that enables
      // error-based SQL injection in VULNERABLE mode.
      error = SAFE
        ? "<p class='error'>Search failed.</p>"
        : `<pre class="error">${escapeHtml(e.message)}</pre>`;
    }
  }

  // Reflected XSS: the raw search term is echoed back into the page.
  // VULNERABLE mode prints it as HTML; SAFE mode encodes it.
  const echo =
    q === undefined
      ? ""
      : `<p class="echo">Results for: ${SAFE ? escapeHtml(q) : q}</p>`;

  res.send(
    layout(
      "Transactions",
      `<section class="card">
         <h1>Search transactions</h1>
         <form method="GET" action="/search">
           <input name="q" value="${escapeHtml(q || "")}" placeholder="e.g. grocery">
           <button type="submit">Search</button>
         </form>
         ${echo}
         ${error}
         ${resultHtml}
       </section>`,
      req.session.user
    )
  );
});

// ---------------------------------------------------------------------------
// TRANSFER FUNDS  -- CSRF target (a genuine state-changing action)
// ---------------------------------------------------------------------------
app.get("/transfer", requireLogin, (req, res) => {
  const done = req.query.done
    ? `<p class="ok">Transfer complete.</p>`
    : "";
  res.send(
    layout(
      "Transfer",
      `<section class="card">
         <h1>Transfer funds</h1>
         ${done}
         <form method="POST" action="/transfer">
           ${/* SAFE mode embeds the anti-CSRF token; VULNERABLE mode has none */""}
           ${SAFE ? `<input type="hidden" name="csrf" value="${req.session.csrf}">` : ""}
           <label>Payee account # <input name="to_account" value="99999999"></label>
           <label>Amount <input name="amount" value="100"></label>
           <button type="submit">Send money</button>
         </form>
       </section>`,
      req.session.user
    )
  );
});

app.post("/transfer", requireLogin, async (req, res) => {
  // The core of the CSRF demo. VULNERABLE mode performs the transfer with no
  // proof the request came from our own form, so an attacker page that just
  // submits to /transfer while the victim is logged in moves their money.
  if (SAFE) {
    // FIX: require the unguessable per-session token. An attacker's page cannot
    // read it (same-origin policy), so a forged POST is rejected here. The
    // SameSite=Strict cookie is a second, independent layer of defense.
    if (req.body.csrf !== req.session.csrf) {
      return res.status(403).send(layout("Blocked", `<p class="error">CSRF token missing or invalid. Transfer blocked.</p>`, req.session.user));
    }
  }
  const amount = Number(req.body.amount) || 0;
  await pool.execute("UPDATE users SET balance = balance - ? WHERE id = ?", [
    amount,
    req.session.user.id,
  ]);
  await pool.execute(
    "INSERT INTO transactions (user_id, description, amount) VALUES (?, ?, ?)",
    [req.session.user.id, "Transfer to account " + (req.body.to_account || "?"), -amount]
  );
  res.redirect("/transfer?done=1");
});

// ---------------------------------------------------------------------------
// STATEMENT VIEWER  -- DOM-based XSS (vulnerability is purely client-side)
// ---------------------------------------------------------------------------
app.get("/dom", requireLogin, (req, res) => {
  // The page ships a flag telling the client script which sink to use. The
  // server never sees or processes the payload: it lives entirely in the URL
  // fragment (location.hash), which browsers do not send to the server.
  res.send(
    layout(
      "Statement viewer",
      `<section class="card">
         <h1>Quick statement note</h1>
         <p>Add <code>#your text</code> to the URL to label this statement.</p>
         <div id="label">(no label)</div>
         <script>window.__SAFE__ = ${SAFE ? "true" : "false"};</script>
         <script src="/dom.js"></script>
       </section>`,
      req.session.user
    )
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`SecureBank running in ${MODE.toUpperCase()} mode on http://localhost:${PORT}`)
);
