const $ = (id) => document.getElementById(id);
const CHARS = "!@#$%^&*<>?/{}[]=+ABCDEF0123456789ΨΦλ∮";
const rand = (s) => s[Math.floor(Math.random() * s.length)];
let latticeStop = null, scrambleTimers = [], pollTimer = null;

// ---------- config ----------
async function loadConfig() {
  const cfg = await fetch("/api/config").then((r) => r.json());
  [["tier"], ["def-tier"]].forEach(([id]) => {
    const sel = $(id); if (!sel) return;
    Object.entries(cfg.tiers).forEach(([k, t]) => {
      const o = document.createElement("option");
      o.value = k; o.textContent = `${k} · ${t.label}`; sel.appendChild(o);
    });
    sel.value = "instant";
  });
  const b = cfg.backends;
  ["backend", "atk-backend"].forEach((id) => {
    const sel = $(id); if (!sel) return;
    const aer = document.createElement("option");
    aer.value = "aer"; aer.textContent = "Aer simulator (local)"; sel.appendChild(aer);
    const ibm = document.createElement("option");
    ibm.value = "ibm";
    ibm.textContent = b.ibm ? "IBM Quantum (hardware)" : `IBM Quantum — ${b.ibm_reason}`;
    ibm.disabled = !b.ibm; sel.appendChild(ibm);
  });
}
$("shots").addEventListener("input", (e) => ($("shots-val").textContent = e.target.value));
$("atk-shots").addEventListener("input", (e) => ($("atk-shots-val").textContent = e.target.value));

// ---------- terminal ----------
function term(line, cls = "") {
  const t = $("terminal");
  t.innerHTML += `\n${cls ? `<span class="${cls}">${line}</span>` : line}`;
  t.scrollTop = t.scrollHeight;
}
const termClear = () => ($("terminal").innerHTML = "> initializing target…");

// ---------- symmetric vault rendering ----------
const ROWS = [
  ["type", "type"], ["algorithm", "algorithm"], ["hardness", "hardness"],
  ["key_size", "key size"], ["quantum_attack", "quantum attack"], ["status", "status"],
];
function renderKV(elId, profile) {
  const dl = $(elId); dl.innerHTML = "";
  ROWS.forEach(([key, label]) => {
    const row = document.createElement("div");
    row.innerHTML = `<dt>${label}</dt><dd>${profile[key]}</dd>`;
    dl.appendChild(row);
  });
}
function renderTarget(pub) {
  $("rsa-role").textContent = pub.profiles.rsa.role;
  $("kem-role").textContent = pub.profiles.mlkem.role;
  renderKV("rsa-kv", pub.profiles.rsa);
  renderKV("kem-kv", pub.profiles.mlkem);
  $("rsa-hash-val").textContent = pub.hash.digest.slice(0, 32) + "…";
  $("kem-secret-val").textContent = pub.mlkem.shared_secret_preview;
  const cells = renderGlyphs(pub.rsa.ciphertext.length);
  if (latticeStop) latticeStop();
  latticeStop = startLattice();
  return cells;
}

// ---------- glyphs ----------
function renderGlyphs(count) {
  const field = $("rsa-glyphs"); field.innerHTML = "";
  return Array.from({ length: count }, () => {
    const g = document.createElement("div");
    g.className = "glyph"; g.textContent = rand(CHARS); field.appendChild(g); return g;
  });
}
function startScramble(cells) {
  stopScramble();
  cells.forEach((g) => g.classList.add("scrambling"));
  scrambleTimers = cells.map((g) => setInterval(() => (g.textContent = rand(CHARS)), 60 + Math.random() * 80));
}
function stopScramble() { scrambleTimers.forEach(clearInterval); scrambleTimers = []; }
function collapseTo(cells, text) {
  stopScramble();
  const chars = text.split("");
  cells.forEach((g, i) => setTimeout(() => {
    g.classList.remove("scrambling"); g.classList.add("locked");
    g.textContent = chars[i] === " " ? "␣" : (chars[i] ?? "");
  }, 140 * i + 200));
}

// ---------- phase ring ----------
function phaseSpin(on) {
  $("phase").classList.toggle("spinning", on);
  $("phase-text").textContent = on ? "estimating phase…" : "idle";
  if (on) $("phase-arc").style.strokeDashoffset = 327;
}
function phaseLock(order) {
  $("phase").classList.remove("spinning");
  $("phase-arc").style.strokeDashoffset = 0;
  $("phase-needle").style.transform = "rotate(210deg)";
  $("phase-text").textContent = order ? `order r = ${order}` : "period locked";
}

// ---------- lattice ----------
function startLattice() {
  const canvas = $("lattice-canvas"), ctx = canvas.getContext("2d");
  canvas.width = canvas.clientWidth; canvas.height = canvas.clientHeight;
  const N = 42, pts = Array.from({ length: N }, () => ({
    x: Math.random(), y: Math.random(), vx: (Math.random() - .5) * 6e-4, vy: (Math.random() - .5) * 6e-4,
  }));
  let raf;
  const draw = () => {
    const w = canvas.width, h = canvas.height; ctx.clearRect(0, 0, w, h);
    pts.forEach((p) => { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > 1) p.vx *= -1; if (p.y < 0 || p.y > 1) p.vy *= -1; });
    for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {
      const dx = (pts[i].x - pts[j].x) * w, dy = (pts[i].y - pts[j].y) * h, d = Math.hypot(dx, dy);
      if (d < 70) { ctx.strokeStyle = `rgba(139,125,246,${.28 * (1 - d / 70)})`;
        ctx.beginPath(); ctx.moveTo(pts[i].x * w, pts[i].y * h); ctx.lineTo(pts[j].x * w, pts[j].y * h); ctx.stroke(); }
    }
    pts.forEach((p) => { ctx.fillStyle = "rgba(139,125,246,.9)"; ctx.beginPath(); ctx.arc(p.x * w, p.y * h, 1.6, 0, 7); ctx.fill(); });
    raf = requestAnimationFrame(draw);
  };
  draw(); return () => cancelAnimationFrame(raf);
}

// ---------- shared: run the SSE attack ----------
function resetVaults() {
  $("vault-rsa").classList.remove("breached"); $("vault-kem").classList.remove("holding");
  $("rsa-verdict").className = "verdict"; $("rsa-verdict").textContent = "";
  $("kem-verdict").className = "verdict"; $("kem-verdict").textContent = "";
}
async function streamAttack(body, cells) {
  startScramble(cells); phaseSpin(true);
  const resp = await fetch("/api/attack", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const reader = resp.body.getReader(), dec = new TextDecoder(); let buf = "";
  while (true) {
    const { value, done } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream: true });
    const parts = buf.split("\n\n"); buf = parts.pop();
    for (const part of parts) {
      const line = part.split("\n").find((l) => l.startsWith("data:"));
      if (!line) continue;
      const payload = line.slice(5).trim(); if (!payload) continue;
      handleEvent(JSON.parse(payload), cells);
    }
  }
  const mk = await fetch("/api/mlkem-attack").then((r) => r.json());
  $("vault-kem").classList.add("holding");
  $("kem-verdict").className = "verdict safe";
  $("kem-verdict").textContent = "✔ ML-KEM holds — no period to find.";
  term(""); term("→ pointing the same attack at ML-KEM…", "t-dim"); term(mk.explanation, "t-dim");
}
function handleEvent(ev, cells) {
  switch (ev.event) {
    case "start": term(`[shor] target N=${ev.N} on backend=${ev.backend}`, "t-ok"); break;
    case "log": term(ev.message); break;
    case "factored":
      phaseLock(ev.order);
      term(`[shor] N = ${ev.p} × ${ev.q}  (order r=${ev.order ?? "—"}, ${ev.attempts} attempt(s), ${ev.shots} shots, ${ev.method})`, "t-hit");
      break;
    case "recovered":
      term(`[attack] reconstructed private key d = ${ev.private_key}`, "t-hit");
      term(`[attack] unwrapped session key = ${ev.session_key}`, "t-hit");
      term(`[attack] decrypted plaintext = "${ev.plaintext}"`, "t-hit");
      collapseTo(cells, ev.plaintext);
      $("vault-rsa").classList.add("breached");
      $("rsa-verdict").className = "verdict broken";
      $("rsa-verdict").textContent = `✘ Broken — secret was "${ev.plaintext}".`;
      break;
    case "failed":
      stopScramble(); phaseSpin(false);
      term("[shor] no usable order this run — add shots or re-run.", "t-warn");
      $("rsa-verdict").textContent = "no result — re-run"; break;
    case "error":
      stopScramble(); phaseSpin(false); term(`[error] ${ev.message}`, "t-warn"); break;
  }
}

// ---------- SOLO ----------
async function runSolo() {
  $("run").disabled = true; termClear(); resetVaults();
  const setup = await fetch("/api/setup", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tier: $("tier").value, secret_message: $("secret").value || "SECRET", mlkem_param: "ML-KEM-768" }),
  }).then((r) => r.json());
  const cells = renderTarget(setup);
  term(`RSA(N=${setup.rsa.N}, e=${setup.rsa.e}) wraps a session key; session key encrypts the data`, "t-dim");
  term(`same secret also protected by ${setup.mlkem.param_set}`, "t-dim");
  term(`attacker captures: wrapped_key=${setup.rsa.wrapped_key}, ciphertext=[${setup.rsa.ciphertext.join(", ")}]`, "t-dim"); term("");
  await streamAttack({
    N: setup.rsa.N, e: setup.rsa.e, wrapped_key: setup.rsa.wrapped_key, ciphertext: setup.rsa.ciphertext,
    shots: +$("shots").value, backend: $("backend").value,
  }, cells);
  $("run").disabled = false;
}
$("run").addEventListener("click", () => runSolo().catch((e) => { term(`[error] ${e.message}`, "t-warn"); $("run").disabled = false; }));

// ---------- MODE + ROLE switching ----------
document.querySelectorAll(".mode-btn").forEach((btn) => btn.addEventListener("click", () => {
  document.querySelectorAll(".mode-btn").forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
  const two = btn.dataset.mode === "two";
  $("panel-solo").hidden = two; $("panel-two").hidden = !two;
  $("mode-hint").textContent = two
    ? "One person seals a secret in a room; the other joins and breaks it."
    : "Seal a secret and break it yourself.";
}));
document.querySelectorAll(".role-card").forEach((card) => card.addEventListener("click", () => {
  $("role-pick").hidden = true;
  if (card.dataset.role === "defender") { $("body-defender").hidden = false; initDefender(); }
  else $("body-attacker").hidden = false;
}));

// ---------- DEFENDER ----------
async function initDefender() {
  const { code } = await fetch("/api/room", { method: "POST" }).then((r) => r.json());
  $("def-code").textContent = code; $("def-status").textContent = "room open — set a secret";
  $("def-seal").dataset.code = code;
}
$("def-seal").addEventListener("click", async () => {
  const code = $("def-seal").dataset.code; if (!code) return;
  await fetch(`/api/room/${code}/seal`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ secret_message: $("def-secret").value || "SECRET", tier: $("def-tier").value, mlkem_param: "ML-KEM-768" }),
  });
  $("def-status").textContent = "sealed ✓"; $("def-wait").hidden = false;
  termClear(); term(`[defender] room ${code}: secret sealed. share the code.`, "t-ok");
  // poll for the attacker's result to reveal on the defender's screen
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const { result } = await fetch(`/api/room/${code}/result`).then((r) => r.json());
    if (result) {
      clearInterval(pollTimer);
      $("def-status").textContent = "cracked by attacker ✗";
      term(`[defender] attacker recovered your secret: "${result.plaintext}"`, "t-hit");
      term(`[defender] your N factored as ${result.factors[0]} × ${result.factors[1]}`, "t-hit");
    }
  }, 1500);
});

// ---------- ATTACKER ----------
let atkCells = null, atkPublic = null;
$("atk-join").addEventListener("click", async () => {
  const code = $("atk-code").value.trim().toUpperCase(); if (code.length < 4) return;
  const res = await fetch(`/api/room/${code}`).then((r) => r.json()).catch(() => null);
  if (!res || !res.sealed) { $("atk-note").textContent = "Room not found or not sealed yet — check the code."; return; }
  atkPublic = res; termClear(); resetVaults();
  atkCells = renderTarget(res);
  term(`[attacker] joined room ${code}. target captured (you never see the secret).`, "t-ok");
  term(`captured: wrapped_key=${res.rsa.wrapped_key}, ciphertext=[${res.rsa.ciphertext.join(", ")}]`, "t-dim");
  $("atk-note").textContent = `Joined room ${code}. Break it when ready.`;
  $("atk-run").disabled = false; $("atk-run").dataset.code = code;
});
$("atk-run").addEventListener("click", async () => {
  const code = $("atk-run").dataset.code; if (!code || !atkCells) return;
  $("atk-run").disabled = true;
  await streamAttack({ room: code, shots: +$("atk-shots").value, backend: $("atk-backend").value }, atkCells);
  $("atk-run").disabled = false;
});

loadConfig();