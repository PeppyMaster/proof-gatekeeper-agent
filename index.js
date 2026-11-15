"use strict";
// Root entrypoint for Vercel: export the Gatekeeper handler as a plain
// function (no listen() — the legacy-server bridge stalls non-GET requests).
module.exports = require("./api/index.js");
