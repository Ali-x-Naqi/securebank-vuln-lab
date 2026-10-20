// DOM-based XSS demonstration (client-side only).
//
// location.hash is the part of the URL after '#'. Browsers never send it to
// the server, so this vulnerability is invisible server-side: it is caused
// entirely by how the client-side JavaScript handles the value.
(function () {
  var label = document.getElementById("label");
  var raw = decodeURIComponent(location.hash.slice(1));
  if (!raw) return;

  if (window.__SAFE__) {
    // FIX: assign to textContent. The browser treats the value as plain text,
    // so markup in the fragment is displayed, not executed.
    label.textContent = raw;
  } else {
    // BUG: assigning untrusted input to innerHTML parses it as HTML. A payload
    // such as   #<img src=x onerror=alert('DOM-XSS')>   runs script.
    label.innerHTML = raw;
  }
})();
