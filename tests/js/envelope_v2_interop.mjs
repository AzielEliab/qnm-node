/**
 * Python ↔ JS envelope v2 body.
 *
 * HKDF matches aziel-runtime src/fed-mesh/e2e.js (salt and info are
 * FED-MESH-1.0). Associated data matches src/transport/envelope-v2.js:
 * UTF-8 canonical JSON of the header, passed to AES-GCM.
 *
 * Usage: node tests/js/envelope_v2_interop.mjs tests/fixtures/envelope-v2-vectors.json
 * Prints one JSON object. Does not write the fixture.
 */
import { readFileSync } from "node:fs";

const X_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function utf8(value) {
  return new TextEncoder().encode(String(value));
}

function canonicalize(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "number") return JSON.stringify(value);
  if (t === "string") return JSON.stringify(value);
  if (t === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((key) => JSON.stringify(key) + ":" + canonicalize(value[key])).join(",") + "}";
  }
  throw new Error("canonicalize refused");
}

function hexToBytes(hex) {
  const raw = String(hex);
  const out = new Uint8Array(raw.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(raw.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToB64url(bytes) {
  let s = "";
  for (const byte of bytes) s += String.fromCharCode(byte);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function b64urlToBytes(value) {
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
  const bin = atob(value.replaceAll("-", "+").replaceAll("_", "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function headerAad(header) {
  return utf8(canonicalize({
    recipient: header.recipient,
    sender: header.sender,
    seq: header.seq,
    type: header.type,
    version: header.version,
  }));
}

async function importX25519Seed(seed) {
  const pkcs8 = new Uint8Array(X_PKCS8_PREFIX.length + seed.length);
  pkcs8.set(X_PKCS8_PREFIX, 0);
  pkcs8.set(seed, X_PKCS8_PREFIX.length);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, true, ["deriveBits"]);
}

async function publicRaw(privateKey) {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return b64urlToBytes(String(jwk.x || ""));
}

async function sharedKey(privateKey, remotePublic, fromHandle, toHandle, seq) {
  const pub = await crypto.subtle.importKey("raw", remotePublic, { name: "X25519" }, true, []);
  const bits = await crypto.subtle.deriveBits({ name: "X25519", public: pub }, privateKey, 256);
  const hkdf = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveBits"]);
  const aes = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8("FED-MESH-1.0"),
      info: utf8(`FED-MESH-1.0|${fromHandle}|${toHandle}|${seq}`),
    },
    hkdf,
    256,
  );
  return crypto.subtle.importKey("raw", aes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function openBody(boxSeedHex, section) {
  const box = await importX25519Seed(hexToBytes(boxSeedHex));
  const key = await sharedKey(box, b64urlToBytes(section.eph_public_key), section.sender, section.recipient, section.seq);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBytes(section.nonce_hex), additionalData: headerAad(section) },
    key,
    b64urlToBytes(section.ciphertext),
  );
  return new TextDecoder().decode(plain);
}

async function sealBody(section, recipientPublic) {
  const eph = await importX25519Seed(hexToBytes(section.eph_seed_hex));
  const ephPublic = await publicRaw(eph);
  const key = await sharedKey(eph, recipientPublic, section.sender, section.recipient, section.seq);
  const nonce = hexToBytes(section.nonce_hex);
  const packed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: headerAad(section) },
      key,
      utf8(section.plaintext),
    ),
  );
  return { eph_public_key: bytesToB64url(ephPublic), ciphertext: bytesToB64url(packed) };
}

const fixture = JSON.parse(readFileSync(process.argv[2], "utf8"));
const recipientPublic = b64urlToBytes(fixture.recipient_box_public);
const pythonPlain = await openBody(fixture.recipient_box_seed_hex, fixture.python);
const jsSealed = await sealBody(fixture.js, recipientPublic);
const report = {
  python_plaintext: pythonPlain,
  python_ok: pythonPlain === fixture.python.plaintext,
  js_ciphertext: jsSealed.ciphertext,
  js_eph_public_key: jsSealed.eph_public_key,
  js_matches_fixture: jsSealed.ciphertext === fixture.js.ciphertext && jsSealed.eph_public_key === fixture.js.eph_public_key,
};
process.stdout.write(JSON.stringify(report));
