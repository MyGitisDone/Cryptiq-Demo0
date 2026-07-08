// channel.js — browser side of the wire scheme. Must match backend/channel.py.
// Session key -> SHA-256 keystream (Web Crypto) + BigInt RSA wrap.

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

async function deriveKb(sessionKey) {
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

// BigInt modular exponentiation
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
  // 30 random bytes -> BigInt, reduced into [2, N)
  const rb = crypto.getRandomValues(new Uint8Array(30));
  let s = 0n;
  for (const b of rb) s = (s << 8n) | BigInt(b);
  const span = N - 2n;
  return 2n + (span > 0n ? s % span : 0n);
}

// Wrap a fresh session key under the bank's public key; return {wrapped, session}
function wrapSessionKey(N, e) {
  const s = randomSessionKey(N);
  const wrapped = modpow(s, BigInt(e), N);
  return { session: s, wrapped };
}

window.QChannel = { seal, wrapSessionKey };
