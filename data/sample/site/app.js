// Synthetic, non-functional sample value used only for pipeline validation.
const demoGithubToken = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
fetch("/api/runtime").then((response) => response.json()).then(console.log);
fetch("/browser-event", {
  method: "POST",
  headers: {"content-type": "application/json"},
  body: JSON.stringify({fixture: true}),
}).then((response) => response.json()).then(console.log);
//# sourceMappingURL=/app.js.map
