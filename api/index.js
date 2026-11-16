// Proof Gatekeeper agent for zkVerify Agent Games (Season 01) — Vercel serverless build.
// Deterministic decisions over the task fields + Groth16 proof of the decision
// using the tournament's official gatekeeper circuit (snarkjs fullProve).
// Fail closed: any uncertainty -> REJECT (or a proof-less REJECT on prover errors).
// State (seen proof_tx set + per-task cache) is in-memory per instance: best
// effort on serverless, acceptable because reuse detection is a scoring input,
// not an eligibility gate.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const SECRET = (process.env.AGENT_SECRET || "").trim();

// ---------- circuit artifacts: local copy if present, else download + verify ----------
const CIRCUITS = {
  "gatekeeper.wasm": {
    url: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
    sha256: "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f",
  },
  "gatekeeper_final.zkey": {
    url: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
    sha256: "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d",
  },
};
function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}
let circuitsPromise = null;
function ensureCircuits() {
  if (circuitsPromise) return circuitsPromise;
  circuitsPromise = (async () => {
    const dir = "/tmp/agentgames-circuits";
    fs.mkdirSync(dir, { recursive: true });
    const out = {};
    for (const [name, meta] of Object.entries(CIRCUITS)) {
      const candidates = [
        path.join(__dirname, "..", "circuits", name),
        path.join(__dirname, "circuits", name),
        path.join(process.cwd(), "circuits", name),
        path.join(dir, name),
      ];
      let file = null;
      for (const c of candidates) {
        try {
          if (fs.existsSync(c) && sha256(fs.readFileSync(c)) === meta.sha256) { file = c; break; }
        } catch (_) {}
      }
      if (!file) {
        const res = await fetch(meta.url);
        if (!res.ok) throw new Error(`circuit download failed: ${name} HTTP ${res.status}`);
        const buf = Buffer.from(await res.arrayBuffer());
        if (sha256(buf) !== meta.sha256) throw new Error(`circuit sha256 mismatch: ${name}`);
        file = path.join(dir, name);
        fs.writeFileSync(file, buf);
      }
      out[name] = file;
    }
    return { wasm: out["gatekeeper.wasm"], zkey: out["gatekeeper_final.zkey"] };
  })();
  circuitsPromise.catch(() => { circuitsPromise = null; });
  return circuitsPromise;
}

// ---------- in-memory state ----------
const seenProofTx = new Set();
const taskCache = {};
function log(obj) {
  try { console.log(JSON.stringify({ t: new Date().toISOString(), ...obj })); } catch (_) {}
}

// ---------- helpers ----------
function hmacHex(secret, data) {
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}
function timingSafeEq(a, b) {
  const ba = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
function toField(x) {
  if (x === null || x === undefined) return null;
  const s = String(x).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s).toString(10);
  if (/^[0-9]+$/.test(s)) return BigInt(s).toString(10);
  return null;
}
function parseTaskId(task_id) {
  // "gk_24_9d1" -> 24 (first integer group). Pure numeric ids pass through.
  if (task_id === null || task_id === undefined) return "0";
  const s = String(task_id);
  if (/^[0-9]+$/.test(s)) return s;
  const m = s.match(/[0-9]+/);
  return m ? m[0] : "0";
}
function randomSalt() {
  return BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString(10);
}

// ---------- decision logic (identical to the standalone server) ----------
function decide(inp) {
  const proofTx = (inp.proof_tx || "").toLowerCase();
  if (proofTx && seenProofTx.has(proofTx)) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", reused: true };
  }
  const regVk = toField(inp.registered_vk);
  const proofVk = toField(inp.proof_vk);
  if (regVk === null || proofVk === null || regVk !== proofVk) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", reused: false };
  }
  const minimum = toField(inp.minimum);
  const balance = toField(inp.public_balance);
  if (minimum === null || balance === null || BigInt(balance) < BigInt(minimum)) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", reused: false };
  }
  const expiry = toField(inp.expiry_block);
  const current = toField(inp.current_block);
  if (expiry === null || current === null || BigInt(current) >= BigInt(expiry)) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", reused: false };
  }
  const recipient = toField(inp.recipient);
  const condRecipient = toField(inp.condition_recipient);
  if (recipient === null || condRecipient === null || recipient !== condRecipient) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", reused: false };
  }
  const amount = toField(inp.amount);
  const maxTransfer = toField(inp.max_transfer);
  if (amount === null || maxTransfer === null || BigInt(amount) > BigInt(maxTransfer)) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", reused: false };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", reused: false };
}

function circuitInput(inp, taskIdNum, decisionNum, salt) {
  return {
    taskId: taskIdNum,
    minimum: toField(inp.minimum),
    publicBalance: toField(inp.public_balance),
    expiryBlock: toField(inp.expiry_block),
    currentBlock: toField(inp.current_block),
    recipient: toField(inp.recipient),
    conditionRecipient: toField(inp.condition_recipient),
    amount: toField(inp.amount),
    maxTransfer: toField(inp.max_transfer),
    registeredVkHash: toField(inp.registered_vk),
    proofVkHash: toField(inp.proof_vk),
    salt,
    decision: decisionNum,
  };
}

// Serialize proving within the instance: witness generation is CPU-heavy.
let proveChain = Promise.resolve();
function prove(input) {
  const run = async () => {
    const { wasm, zkey } = await ensureCircuits();
    return snarkjs.groth16.fullProve(input, wasm, zkey);
  };
  const p = proveChain.then(run, run);
  proveChain = p.catch(() => {});
  return p;
}

async function handleTask(body) {
  const inp = body.input || (body.payload && body.payload.input) || body.payload || body;
  const taskIdRaw = body.task_id || body.taskId || inp.task_id || null;

  if (taskIdRaw && taskCache[taskIdRaw]) {
    log({ kind: "cache_hit", task_id: taskIdRaw });
    return taskCache[taskIdRaw];
  }

  const verdict = decide(inp);
  const response = {
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof_tx: inp.proof_tx || null,
  };

  if (!verdict.reused) {
    const taskIdNum = parseTaskId(taskIdRaw);
    const salt = randomSalt();
    const wantDecision = verdict.decision === "APPROVE" ? "1" : "0";
    try {
      const { proof, publicSignals } = await prove(circuitInput(inp, taskIdNum, wantDecision, salt));
      response.proof = proof;
      response.public_signals = publicSignals;
    } catch (e1) {
      // The circuit is the referee for field-based verdicts: if it refuses our
      // decision, prove the opposite one and adopt it (never for PROOF_REUSED,
      // which is excluded from proofs by the scoring rules).
      try {
        const flipped = wantDecision === "1" ? "0" : "1";
        const { proof, publicSignals } = await prove(circuitInput(inp, taskIdNum, flipped, salt));
        response.proof = proof;
        response.public_signals = publicSignals;
        response.decision = flipped === "1" ? "APPROVE" : "REJECT";
        response.reason_code = flipped === "1" ? "VALID_CONDITION" : verdict.reason_code;
        log({ kind: "decision_flipped_by_circuit", task_id: taskIdRaw, from: verdict.decision, to: response.decision, err: String(e1).slice(0, 200) });
      } catch (e2) {
        log({ kind: "prove_failed", task_id: taskIdRaw, err: String(e2).slice(0, 200) });
      }
    }
  }

  if (inp.proof_tx) {
    seenProofTx.add(String(inp.proof_tx).toLowerCase());
  }
  if (taskIdRaw) taskCache[taskIdRaw] = response;
  log({ kind: "task", task_id: taskIdRaw, mode: body.mode || null, decision: response.decision, reason_code: response.reason_code, proof: !!response.proof });
  return response;
}

// ---------- raw body reading (multi-shape: Vercel's server runtime does not
// deliver a plain Node stream in the way `for await` expects — it stalls) ----
async function readRawBody(req) {
  if (req.rawBody) return Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.from(req.rawBody);
  if (req.body !== undefined && req.body !== null && typeof req.on !== "function") {
    if (Buffer.isBuffer(req.body)) return req.body;
    if (typeof req.body === "string") return Buffer.from(req.body);
    return Buffer.from(JSON.stringify(req.body));
  }
  if (typeof req.text === "function" && typeof req.on !== "function") {
    return Buffer.from(await req.text());
  }
  const chunks = [];
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(); } };
    req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on("end", finish);
    req.on("error", (e) => { if (!done) { done = true; reject(e); } });
    if (req.readableEnded) finish();
    setTimeout(finish, 10000); // never hang past the platform's patience
  });
  if (chunks.length === 0 && req.body !== undefined && req.body !== null) {
    if (Buffer.isBuffer(req.body)) return req.body;
    if (typeof req.body === "string") return Buffer.from(req.body);
    if (typeof req.body === "object") return Buffer.from(JSON.stringify(req.body));
  }
  return Buffer.concat(chunks);
}

// ---------- handler ----------
async function handler(req, res) {
  const send = (code, obj) => {
    const raw = Buffer.from(JSON.stringify(obj));
    const headers = { "content-type": "application/json", "content-length": raw.length };
    if (SECRET) headers["x-agent-games-signature"] = hmacHex(SECRET, raw);
    res.writeHead(code, headers);
    res.end(raw);
  };

  if (req.method === "GET" || req.method === "HEAD") {
    return send(200, { status: "ok", agent: "proof-gatekeeper", version: "1.0" });
  }
  if (req.method !== "POST") return send(405, { error: "method_not_allowed" });

  const raw = await readRawBody(req);

  if (SECRET) {
    const sig = req.headers["x-agent-games-signature"] || req.headers["x-signature"] || "";
    if (!timingSafeEq(sig, hmacHex(SECRET, raw))) {
      log({ kind: "bad_signature" });
      return send(401, { error: "invalid_signature" });
    }
  }
  let body;
  try {
    body = JSON.parse(raw.toString("utf8"));
  } catch (_) {
    return send(400, { error: "invalid_json" });
  }
  const inp = body && (body.input || (body.payload && body.payload.input));
  if (!inp || typeof inp !== "object" || !("proof_tx" in inp || "registered_vk" in inp)) {
    // Preflight / unknown envelope: signed protocol-v1 JSON (platform requirement).
    log({ kind: "preflight_or_unknown", type: body && body.type, mode: body && body.mode });
    return send(200, { ok: true, protocolVersion: "v1" });
  }
  try {
    const response = await handleTask(body);
    return send(200, response);
  } catch (e) {
    log({ kind: "handler_error", err: String(e).slice(0, 300) });
    // Fail closed.
    return send(200, { decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: inp.proof_tx || null });
  }
}

module.exports = handler;
module.exports.config = { api: { bodyParser: false } };
