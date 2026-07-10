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
  // Web Crypto (crypto.subtle) only works in a "secure context" — https, or
  // http://127.0.0.1 / http://localhost. Opening this page via a LAN IP or
  // any other plain-HTTP address leaves crypto.subtle undefined, and every
  // sign-up/sign-in attempt would otherwise fail with a cryptic
  // "Cannot read properties of undefined (reading 'digest')" browser error.
  if (!window.crypto || !window.crypto.subtle) {
    document.querySelector(".wrap").innerHTML = `
      <div class="card">
        <p class="msg err" style="margin:0">
          This page needs to be opened via <code>http://127.0.0.1</code> or
          <code>http://localhost</code> — your browser's encryption API
          (Web Crypto) is disabled on <code>${location.origin}</code>
          because it isn't a secure origin.
        </p>
        <p class="wire-note" style="margin-top:14px">
          Current URL: <code>${location.href}</code><br>
          Try: <code>http://127.0.0.1:${location.port || "80"}${location.pathname}</code>
        </p>
      </div>`;
    return;
  }

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
    ? "🔓 weak encryption" : "🔒 quantum-safe (ML-KEM-768)";
  $("wire-note").textContent = CFG.key.tiny
    ? `This bank wraps your login with a ${CFG.key.bits}-bit RSA key (toy). That's trivially breakable — on purpose.`
    : `This bank protects your login with real ML-KEM-768 (FIPS 203), generated fresh in your browser. An eavesdropper genuinely cannot recover it — not "too big to factor," but a different kind of math with no known break.`;
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
    let body;
    if (CFG.key.tiny) {
      // RSA path — wrap a session key under the bank's tiny public key.
      const N = BigInt(CFG.key.N), e = CFG.key.e;
      const { session, wrapped } = QChannel.wrapSessionKey(N, e);
      const payload_hex = await QChannel.seal(session, `username=${u}&password=${p}`);
      body = { mode: MODE, wrapped_key: wrapped.toString(), payload_hex };
    } else {
      // ML-KEM path — generate a fresh ephemeral keypair, send the
      // encapsulation key to the server, get back a ciphertext, decapsulate
      // locally to recover the same shared secret the server derived.
      const { ek, dk } = await QChannel.mlkemKeygen();
      const kexRes = await fetchJson("/api/kex-encaps", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ek_b64: QChannel.toB64(ek) }),
      });
      if (!kexRes.ok) { setMsg("msg", kexRes.error || "key exchange failed", "err"); return; }
      const ct = QChannel.fromB64(kexRes.ct_b64);
      const sharedSecret = await QChannel.mlkemDecaps(ct, dk);
      const payload_hex = await QChannel.seal(sharedSecret, `username=${u}&password=${p}`);
      body = { mode: MODE, kem_ct_b64: kexRes.ct_b64, payload_hex };
    }

    const res = await fetchJson("/api/auth", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
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
