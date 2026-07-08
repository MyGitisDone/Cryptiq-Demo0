const $ = (id) => document.getElementById(id);
let CFG = null, MODE = "signin", TOKEN = sessionStorage.getItem("token") || null;

// fetch with a timeout, so a stuck/dead backend shows an error instead of
// silently hanging the UI forever
async function fetchJson(url, opts, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { ...opts, signal: ctrl.signal });
    return await r.json();
  } catch (err) {
    if (err.name === "AbortError") throw new Error("Server didn't respond (timed out). Is it still running?");
    throw new Error("Couldn't reach the server. Is it still running?");
  } finally {
    clearTimeout(t);
  }
}

async function boot() {
  try {
    CFG = await fetchJson("/api/config");
  } catch (err) {
    document.querySelector(".wrap").innerHTML = `<p class="msg err">${err.message}</p>`;
    return;
  }
  document.body.dataset.theme = CFG.theme;
  document.title = CFG.name;
  $("bank-name").textContent = CFG.name;
  $("tagline").textContent = CFG.tagline;
  $("theme-badge").textContent = CFG.key.tiny
    ? "🔓 weak encryption" : "🔒 quantum-safe";
  $("wire-note").textContent = CFG.key.tiny
    ? `This bank wraps your login with a ${CFG.key.bits}-bit RSA key (toy). That's trivially breakable — on purpose.`
    : `This bank wraps your login with a ${CFG.key.bits}-bit key exchange. An eavesdropper can't recover it.`;
  if (TOKEN) loadAccount();
}

// tabs
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
  t.classList.add("active"); MODE = t.dataset.tab;
  $("submit").textContent = MODE === "signup" ? "Create account" : "Sign in";
  $("msg").textContent = "";
}));

// submit auth (client-side encryption of credentials)
$("submit").addEventListener("click", async () => {
  const u = $("u").value.trim(), p = $("p").value;
  if (!u || !p) { setMsg("msg", "Enter a username and password.", "err"); return; }
  setMsg("msg", "encrypting & sending…", "");
  try {
    const N = BigInt(CFG.key.N), e = CFG.key.e;
    const { session, wrapped } = QChannel.wrapSessionKey(N, e);
    const payload_hex = await QChannel.seal(session, `username=${u}&password=${p}`);
    const res = await fetchJson("/api/auth", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: MODE, wrapped_key: wrapped.toString(), payload_hex }),
    });

    if (!res.ok) { setMsg("msg", res.error || "failed", "err"); return; }
    if (MODE === "signup") {
      setMsg("msg", "Account created — now sign in.", "ok");
      document.querySelector('.tab[data-tab="signin"]').click();
      return;
    }
    TOKEN = res.token; sessionStorage.setItem("token", TOKEN);
    loadAccount();
  } catch (err) {
    setMsg("msg", err.message, "err");
  }
});

async function loadAccount() {
  try {
    const a = await fetchJson("/api/account", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: TOKEN }) });
    if (!a.ok) { TOKEN = null; sessionStorage.removeItem("token"); return; }
    $("auth").hidden = true; $("account").hidden = false;
    $("acct-user").textContent = a.username;
    $("balance").textContent = "$" + a.balance.toLocaleString();
    $("acct-no").textContent = a.account_no;
    $("routing").textContent = a.routing;
    $("opened").textContent = a.opened;
  } catch (err) {
    setMsg("msg", err.message, "err");
  }
}

$("logout").addEventListener("click", () => {
  TOKEN = null; sessionStorage.removeItem("token");
  $("account").hidden = true; $("auth").hidden = false; $("msg").textContent = "";
});

function setMsg(id, text, cls) { const el = $(id); el.textContent = text; el.className = "msg " + (cls || ""); }
boot();
