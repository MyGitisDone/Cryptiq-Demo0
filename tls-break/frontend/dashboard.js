const $ = (id) => document.getElementById(id);
let packets = 0, seenCreds = new Set();
let manualPause = false, hoverPause = false;
let queue = [];              // buffered {cls, tag, body, kind} while paused
let currentFilter = "all";

function isPaused() { return manualPause || hoverPause; }

function updatePauseUI() {
  $("feed").classList.toggle("paused", isPaused());
  $("pause").textContent = manualPause ? "▶ Resume" : "⏸ Pause";
  $("pause").classList.toggle("on", manualPause);
}

async function boot() {
  const st = await fetch("/api/status").then((r) => r.json());
  $("iface").textContent = st.iface;
  $("open-bad").href = st.banks.bad;
  $("open-good").href = st.banks.good;
  $("status").textContent = st.tshark
    ? `● live · tshark on ${st.iface}` : "● live · polling capture (tshark not detected)";
  $("status").classList.add("live");
  const w = await fetch("/api/wallet").then((r) => r.json()).catch(() => ({ balance: 0 }));
  $("wallet-balance").textContent = "$" + (w.balance || 0).toLocaleString();
  connect();
}

function connect() {
  const es = new EventSource("/api/feed");
  es.onmessage = (m) => { try { handle(JSON.parse(m.data)); } catch {} };
  es.onerror = () => { $("status").textContent = "● reconnecting…"; };
}

// --- rendering ---
function feedLine(kind, cls, tag, body) {
  if (isPaused()) { queue.push({ kind, cls, tag, body }); return; }
  renderLine(kind, cls, tag, body);
}
function renderLine(kind, cls, tag, body) {
  const empty = $("empty"); if (empty) empty.remove();
  const el = document.createElement("div");
  el.className = `line ${cls}`;
  el.dataset.kind = kind;
  if (currentFilter !== "all" && !matchesFilter(kind, currentFilter)) el.classList.add("hidden-by-filter");
  el.innerHTML = `<span class="tag">${tag}</span><span class="body">${body}</span>`;
  const feed = $("feed"); feed.prepend(el);
  while (feed.children.length > 300) feed.lastChild.remove();
}
function matchesFilter(kind, filter) {
  if (filter === "all") return true;
  if (filter === "wire") return kind === "wire" || kind === "cracked" || kind === "safe";
  if (filter === "cracked") return kind === "cracked";
  return true;
}

function handle(ev) {
  switch (ev.event) {
    case "listening":
      feedLine("sys", "packet", "sys", `listening on ${ev.iface} · tshark=${ev.tshark}`); break;
    case "packet":
      packets++; $("counter").textContent = `${packets} packets`;
      feedLine("packet", "packet", "TCP", `:${ev.src_port} → :${ev.dst_port}  ${ev.length}B  ${ev.proto}`); break;
    case "wire":
      feedLine("wire", `wire ${ev.bank}`, ev.bank === "bad" ? "BANK✗" : "BANK✓",
        `${ev.bank} · ${ev.mode} · wrapped=${ev.wrapped_key} · enc=${ev.payload_preview} (${ev.bits}-bit key)`); break;
    case "cracked": onCracked(ev); break;
    case "safe":
      feedLine("safe", "safe", "SAFE", `Good Secure Bank login · real ML-KEM-768 key exchange — no shared secret to recover from the wire. Credentials unrecoverable.`); break;
  }
}

// ---- Shor terminal --------------------------------------------------------
// Animates a step-by-step break walkthrough when a crack event fires.
// Each entry is [delay_ms, css_class, text].
function buildScript(ev) {
  const hex40 = (ev.payload_hex || "").slice(0, 40) + "…";
  const plaintext = `username=${ev.username}&password=${ev.password}`;
  return [
    [0,    "c-dim",    "# intercepted packet — POST /api/auth body:"],
    [300,  "c-amber",  `wrapped_key = "${ev.wrapped_key}"`],
    [600,  "c-coral",  `payload_hex = "${hex40}"`],
    [1000, "c-dim",    ""],
    [1200, "c-dim",    `# RSA public key from certificate: N=${ev.rsa_N}, e=${ev.rsa_e}`],
    [1700, "c-dim",    "# N is small — running Shor's algorithm on the quantum simulator…"],
    [2200, "c-violet", ">> initialising QPE circuit…"],
    [2800, "c-violet", `>> superposition of ${Math.max(8, Math.round(Math.log2(ev.rsa_N||15)*4))} qubits`],
    [3600, "c-violet", ">> measuring phase register…"],
    [4400, "c-violet", ">> applying continued-fractions expansion…"],
    [5000, "c-amber",  `>> period r found → gcd(a^(r/2)±1, N) → factors: ${ev.factors?.[0]} × ${ev.factors?.[1]}`],
    [5600, "c-dim",    ""],
    [5800, "c-dim",    "# private exponent recovered from factors:"],
    [6200, "c-amber",  `d = pow(e, -1, (p-1)*(q-1))`],
    [6600, "c-amber",  `session_key = pow(wrapped_key, d, N)  →  ${ev.wrapped_key ? Number(ev.wrapped_key) : "?"}`],
    [7200, "c-dim",    ""],
    [7400, "c-dim",    "# decrypting payload with recovered session key…"],
    [7900, "c-green",  `plaintext = "${plaintext}"`],
    [8400, "c-dim",    ""],
    [8600, "c-white",  `✔  credentials recovered: ${ev.username} / ${ev.password}`],
  ];
}

let shorRunning = false;
async function runShorTerminal(ev) {
  if (shorRunning) return;
  shorRunning = true;
  const section = $("shor-section");
  const pre = $("st-pre");
  section.hidden = false;
  section.scrollIntoView({ behavior: "smooth", block: "nearest" });
  pre.innerHTML = "";

  const cursor = document.createElement("span");
  cursor.className = "cursor";
  pre.appendChild(cursor);

  const script = buildScript(ev);
  const t0 = Date.now();
  for (const [absDelay, cls, text] of script) {
    const wait = absDelay - (Date.now() - t0);
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    if (text === "") {
      pre.insertBefore(document.createTextNode("\n"), cursor);
    } else {
      const span = document.createElement("span");
      span.className = cls;
      span.textContent = text + "\n";
      pre.insertBefore(span, cursor);
    }
    pre.scrollTop = pre.scrollHeight;
  }
  cursor.remove();
  shorRunning = false;
}

function onCracked(ev) {
  feedLine("cracked", "cracked", "CRACK", `factored N = ${ev.factors[0]}×${ev.factors[1]} → decrypted ${ev.mode} → ${ev.username} / ${ev.password}`);
  const id = ev.username + ":" + ev.password;
  if (seenCreds.has(id)) return;
  seenCreds.add(id);
  toast(`🔓 Credentials intercepted: ${ev.username} / ${ev.password}`);
  runShorTerminal(ev);   // ← animate the break in the terminal panel

  const empty = $("loot").querySelector(".empty"); if (empty) empty.remove();
  const card = document.createElement("div");
  card.className = "loot-card";

  // Truncate payload_hex for display (show first 40 chars + ellipsis)
  const hexPreview = ev.payload_hex
    ? ev.payload_hex.slice(0, 40) + (ev.payload_hex.length > 40 ? "…" : "")
    : "—";
  const plaintext = `username=${ev.username ?? "?"}&password=${ev.password ?? "?"}`;

  card.innerHTML = `
    <div class="who">Bad Insecure Bank · ${ev.mode}</div>

    <div class="wire-breakdown">
      <div class="wb-label">What Wireshark sees on the wire (captured JSON body):</div>
      <div class="wb-before">
        <div class="wb-row"><span class="wk">wrapped_key</span><span class="wv wv-key">"${ev.wrapped_key ?? "?"}"</span></div>
        <div class="wb-row"><span class="wk">payload_hex</span><span class="wv wv-enc">"${hexPreview}"</span></div>
      </div>
      <div class="wb-arrow">▼ Shor factors N=${ev.rsa_N} = ${ev.factors?.[0]}×${ev.factors?.[1]} → private key recovered → decrypt</div>
      <div class="wb-label wb-label-after">Decrypted plaintext (what the payload actually says):</div>
      <div class="wb-after">${plaintext}</div>
    </div>

    <div class="creds">
      <div><span>username</span><strong>${ev.username ?? "?"}</strong></div>
      <div><span>password</span><strong>${ev.password ?? "?"}</strong></div>
    </div>
    <button class="drain">💸 Drain to attacker wallet →</button>
    <p class="result"></p>`;

  $("loot").prepend(card);
  card.querySelector(".drain").addEventListener("click", async (e) => {
    const btn = e.target; btn.disabled = true; btn.textContent = "draining…";
    const r = await fetch("/api/drain", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bank: "bad", username: ev.username, password: ev.password }) }).then((x) => x.json());
    const res = card.querySelector(".result");
    if (r.ok) {
      res.className = "result done";
      res.textContent = `✔ moved $${(r.moved||0).toLocaleString()} into your wallet — victim balance now $${(r.victim_balance||0).toLocaleString()}`;
      btn.textContent = "account drained";
      const wb = $("wallet-balance");
      wb.textContent = "$" + (r.wallet_balance || 0).toLocaleString();
      wb.parentElement.classList.remove("bump"); void wb.offsetWidth; wb.parentElement.classList.add("bump");
    } else { res.textContent = r.error || "drain failed"; btn.disabled = false; btn.textContent = "retry drain"; }
  });
}

let toastTimer = null;
function toast(text) {
  const t = $("toast"); t.textContent = text; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 4200);
}

// --- controls ---
$("pause").addEventListener("click", () => {
  manualPause = !manualPause;
  updatePauseUI();
  if (!isPaused()) flushQueue();
});
$("clear").addEventListener("click", () => {
  queue = [];
  $("feed").innerHTML = '<div class="empty" id="empty">Cleared. New traffic will appear here.</div>';
});
function flushQueue() {
  // render oldest-first so ordering matches arrival
  const items = queue.slice().reverse();
  queue = [];
  for (const it of items) renderLine(it.kind, it.cls, it.tag, it.body);
}

// hover over the feed pauses it automatically so you can read without losing your place
// (script runs at the bottom of body, so the DOM is already ready — attach directly)
$("feed").addEventListener("mouseenter", () => { hoverPause = true; updatePauseUI(); });
$("feed").addEventListener("mouseleave", () => { hoverPause = false; updatePauseUI(); if (!isPaused()) flushQueue(); });

document.querySelectorAll(".chip").forEach((chip) => chip.addEventListener("click", () => {
  document.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
  chip.classList.add("active");
  currentFilter = chip.dataset.filter;
  document.querySelectorAll("#feed .line").forEach((el) => {
    el.classList.toggle("hidden-by-filter", !matchesFilter(el.dataset.kind, currentFilter));
  });
}));

boot();
