// Entrypoint for Vercel's server runtime: serves the exact handler that lives
// in api/index.js (locally verified) as a plain HTTP server on $PORT.
const http = require("http");
const handler = require("./api/index.js");

const port = process.env.PORT || 3000;
const server = http.createServer((req, res) => {
  Promise.resolve(handler(req, res)).catch((e) => {
    try {
      console.log(JSON.stringify({ kind: "shim_error", err: String(e).slice(0, 300) }));
      if (!res.headersSent) {
        const raw = Buffer.from(JSON.stringify({ decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: null }));
        res.writeHead(200, { "content-type": "application/json", "content-length": raw.length });
        res.end(raw);
      }
    } catch (_) {}
  });
});
server.listen(port, () => {
  console.log(`gatekeeper server listening on :${port}`);
});
