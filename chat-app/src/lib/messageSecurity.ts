/**
 * Message security: integrity (SHA-256), authenticity (RSA signature), and
 * confidentiality (RSA-encrypted secret messages).
 *
 * The servers only relay `username` and `message`, so everything rides inside
 * the message string as:
 *     "<sha256hex>:<rsaSignatureBase64>:<body>"
 * The hash is hex and the signature is base64 — neither contains ":" — so the
 * first two colons are the delimiters and the body (after the 2nd colon) may
 * contain anything.
 *
 * The body is either plaintext (public message) or, for a secret message, an
 * encrypted envelope prefixed with a sentinel. The hash and signature are
 * computed over the body exactly as sent, so tamper- and impersonation
 * detection work for encrypted messages too.
 *
 * KEYS — each client makes TWO RSA key pairs on join and registers both public
 * halves as one bundle:
 *   - signing:    RSASSA-PKCS1-v1_5 / SHA-256  (prove who sent a message)
 *   - encryption: RSA-OAEP / SHA-256           (let others encrypt to us)
 * A separate key is required because a key can't both sign and encrypt.
 *
 * ENCRYPTION is hybrid (the real-world pattern): the message is encrypted with
 * a one-time AES-GCM key, and that AES key is wrapped with each recipient's
 * RSA-OAEP public key. RSA alone can only encrypt ~190 bytes; hybrid handles
 * any length while RSA still guards confidentiality (it protects the AES key).
 * We wrap the key for both the target AND ourselves, so the sender can also
 * read the message it sent.
 */

const RSA_SIGN = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;
const RSA_ENC = { name: "RSA-OAEP", hash: "SHA-256" } as const;
const AES = { name: "AES-GCM", length: 256 } as const;
const SEP = ":";
const SECRET_PREFIX = "\u0000ENC\u0000";

export type Payload = { hash: string; signature: string; body: string };
export type PublicKeyBundle = { sign: string; enc: string };
type Envelope = { iv: string; data: string; keys: Record<string, string> };

// --- key management ---------------------------------------------------------

export function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { ...RSA_SIGN, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["sign", "verify"],
  );
}

export function generateEncryptionKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { ...RSA_ENC, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["encrypt", "decrypt"],
  );
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  return toBase64(await crypto.subtle.exportKey("spki", key));
}

/** Pack both public keys into the single string the server relays. */
export function makeBundle(signPublicKey: string, encPublicKey: string): string {
  return JSON.stringify({ sign: signPublicKey, enc: encPublicKey });
}

export function parseBundle(value: string | undefined): PublicKeyBundle | null {
  if (!value) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      typeof (parsed as PublicKeyBundle).sign === "string" &&
      typeof (parsed as PublicKeyBundle).enc === "string"
    ) {
      return parsed as PublicKeyBundle;
    }
  } catch {
    // not a bundle
  }
  return null;
}

export function importVerifyKey(base64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", fromBase64(base64), RSA_SIGN, true, ["verify"]);
}

export function importEncryptKey(base64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", fromBase64(base64), RSA_ENC, true, ["encrypt"]);
}

// --- signing / integrity ----------------------------------------------------

/** Wrap a body with its hash and RSA signature for the wire. */
export async function signBody(body: string, signPrivateKey: CryptoKey): Promise<string> {
  const hash = await sha256Hex(body);
  const signature = toBase64(await crypto.subtle.sign(RSA_SIGN.name, signPrivateKey, encode(body)));
  return `${hash}${SEP}${signature}${SEP}${body}`;
}

export function parsePayload(payload: string): Payload | null {
  const first = payload.indexOf(SEP);
  if (first === -1) return null;
  const second = payload.indexOf(SEP, first + 1);
  if (second === -1) return null;
  return {
    hash: payload.slice(0, first),
    signature: payload.slice(first + 1, second),
    body: payload.slice(second + 1),
  };
}

export async function isBodyIntact(payload: Payload): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/.test(payload.hash)) return false;
  return (await sha256Hex(payload.body)) === payload.hash;
}

export async function isSignatureValid(payload: Payload, verifyKey: CryptoKey): Promise<boolean> {
  try {
    return await crypto.subtle.verify(RSA_SIGN.name, verifyKey, fromBase64(payload.signature), encode(payload.body));
  } catch {
    return false;
  }
}

// --- confidentiality (secret messages) --------------------------------------

export function isSecretBody(body: string): boolean {
  return body.startsWith(SECRET_PREFIX);
}

export function parseEnvelope(body: string): Envelope | null {
  if (!isSecretBody(body)) return null;
  try {
    return JSON.parse(body.slice(SECRET_PREFIX.length)) as Envelope;
  } catch {
    return null;
  }
}

/** What a non-recipient sees: the raw ciphertext (gibberish). */
export function ciphertextOf(envelope: Envelope): string {
  return envelope.data;
}

/** Encrypt `text` for every recipient; only their private keys can unwrap it. */
export async function encryptBody(
  text: string,
  recipients: [username: string, encPublicKey: CryptoKey][],
): Promise<string> {
  const aesKey = await crypto.subtle.generateKey(AES, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: AES.name, iv }, aesKey, encode(text));
  const rawAes = await crypto.subtle.exportKey("raw", aesKey);

  const keys: Record<string, string> = {};
  for (const [username, publicKey] of recipients) {
    keys[username] = toBase64(await crypto.subtle.encrypt({ name: RSA_ENC.name }, publicKey, rawAes));
  }

  const envelope: Envelope = { iv: toBase64(iv), data: toBase64(data), keys };
  return SECRET_PREFIX + JSON.stringify(envelope);
}

/** Decrypt an envelope if it was addressed to us; null if not, or on failure. */
export async function decryptEnvelope(
  envelope: Envelope,
  myUsername: string,
  encPrivateKey: CryptoKey,
): Promise<string | null> {
  const wrapped = envelope.keys[myUsername];
  if (!wrapped) return null;
  try {
    const rawAes = await crypto.subtle.decrypt({ name: RSA_ENC.name }, encPrivateKey, fromBase64(wrapped));
    const aesKey = await crypto.subtle.importKey("raw", rawAes, { name: AES.name }, false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt(
      { name: AES.name, iv: fromBase64(envelope.iv) },
      aesKey,
      fromBase64(envelope.data),
    );
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

// --- primitives -------------------------------------------------------------

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encode(text: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>;
}

function toBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(base64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
