// channel.js — browser side of the wire scheme. Must match backend/channel.py.
//
// Bad bank:  RSA key wrap (BigInt modpow), tiny modulus. No external
//            dependencies — always works, even offline.
// Good bank: real ML-KEM-768 via @noble/post-quantum, loaded lazily from a
//            CDN only when actually needed. Loading is wrapped so that a CDN
//            hiccup can only ever break the ML-KEM path — it can no longer
//            take down this whole module (and therefore the Bad bank too),
//            which is what happened when a single top-level `import` failed.

const _enc = new TextEncoder();

async function sha256(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}
function concat(...arrs) {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function fromB64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
function toB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// sessionKey is either a BigInt (RSA path) or a Uint8Array (ML-KEM shared
// secret) — both sides of channel.py/channel.js agree on this duck-typing.
async function deriveKb(sessionKey) {
  if (sessionKey instanceof Uint8Array) {
    return sha256(sessionKey);
  }
  return sha256(_enc.encode(sessionKey.toString(10)));
}
async function keystream(kb, length) {
  const out = new Uint8Array(length);
  let filled = 0, counter = 0;
  while (filled < length) {
    const block = await sha256(concat(kb, _enc.encode(String(counter))));
    const take = Math.min(block.length, length - filled);
    out.set(block.subarray(0, take), filled);
    filled += take; counter += 1;
  }
  return out;
}
async function seal(sessionKey, plaintextStr) {
  const pt = _enc.encode(plaintextStr);
  const kb = await deriveKb(sessionKey);
  const ks = await keystream(kb, pt.length);
  const ct = new Uint8Array(pt.length);
  for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
  const tag = (await sha256(concat(kb, _enc.encode("tag"), ct))).subarray(0, 8);
  return toHex(concat(ct, tag));
}

// ── RSA path (Bad bank) — pure JS, no external dependency ─────────────────
function modpow(base, exp, mod) {
  base %= mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}
function randomSessionKey(N) {
  const rb = crypto.getRandomValues(new Uint8Array(30));
  let s = 0n;
  for (const b of rb) s = (s << 8n) | BigInt(b);
  const span = N - 2n;
  return 2n + (span > 0n ? s % span : 0n);
}
function wrapSessionKey(N, e) {
  const s = randomSessionKey(N);
  const wrapped = modpow(s, BigInt(e), N);
  return { session: s, wrapped };
}

// ── ML-KEM-768 path (Good bank) — lazy-loaded from a CDN ───────────────────
// Real FIPS 203 key encapsulation via @noble/post-quantum (audited, same
// family as noble-curves/noble-hashes). The browser generates a fresh
// ephemeral keypair every session; the server never holds a long-term
// private key for this bank at all.
//
// Loading is deferred to first use (not a top-level import) specifically so
// that a CDN failure only ever surfaces as a clear error at the moment
// someone actually tries to use the Good bank — it can't silently break
// this entire file, which is what a failed top-level `import` would do.
let _mlkemPromise = null;

function loadMlKem() {
  if (_mlkemPromise) return _mlkemPromise;
  const sources = [
    "https://esm.sh/@noble/post-quantum@0.5.4/ml-kem.js",
    "https://cdn.jsdelivr.net/npm/@noble/post-quantum@0.5.4/+esm",
  ];
  _mlkemPromise = (async () => {
    const errors = [];
    for (const url of sources) {
      try {
        const mod = await import(/* @vite-ignore */ url);
        if (mod && mod.ml_kem768) return mod.ml_kem768;
        errors.push(`${url}: module loaded but ml_kem768 export missing`);
      } catch (err) {
        errors.push(`${url}: ${err.message || err}`);
      }
    }
    throw new Error(
      "Could not load the ML-KEM library from any CDN. This bank's " +
      "quantum-safe key exchange needs internet access to fetch " +
      "@noble/post-quantum the first time. Errors:\n" + errors.join("\n")
    );
  })();
  return _mlkemPromise;
}

async function mlkemKeygen() {
  const kem = await loadMlKem();
  const keys = kem.keygen();
  return { ek: keys.publicKey, dk: keys.secretKey };
}
async function mlkemDecaps(ct, dk) {
  const kem = await loadMlKem();
  return kem.decapsulate(ct, dk);
}

window.QChannel = {
  seal, wrapSessionKey,
  mlkemKeygen, mlkemDecaps,
  toB64, fromB64,
};
