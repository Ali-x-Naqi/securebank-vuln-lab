// Tiny view layer: a layout wrapper plus the output-encoding helper that the
// SAFE mode relies on to stop XSS. Keeping escapeHtml() here, visible and
// named, makes it easy to point at during the viva: "this one function,
// applied on output, is the whole Stored/Reflected XSS fix."

// Output encoding: turn characters that are significant in HTML into their
// harmless entity form so the browser renders them as text, not markup.
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const MODE = process.env.MODE === "safe" ? "safe" : "vulnerable";

function layout(title, bodyHtml, user) {
  const badge =
    MODE === "safe"
      ? '<span class="badge safe">SAFE VERSION</span>'
      : '<span class="badge vuln">VULNERABLE VERSION</span>';
  const nav = user
    ? `<nav>
         <a href="/dashboard">Dashboard</a>
         <a href="/search">Transactions</a>
         <a href="/transfer">Transfer</a>
         <a href="/dom">Statement viewer</a>
         <span class="who">Signed in as <b>${escapeHtml(user.username)}</b></span>
         <a href="/logout">Log out</a>
       </nav>`
    : "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} - SecureBank</title>
  <link rel="stylesheet" href="/style.css" />
</head>
<body>
  <header>
    <div class="brand">SecureBank <small>Online Banking</small></div>
    ${badge}
  </header>
  ${nav}
  <main>${bodyHtml}</main>
  <footer>SecureBank demo application &mdash; Information Security Assignment 2</footer>
</body>
</html>`;
}

module.exports = { escapeHtml, layout, MODE };
