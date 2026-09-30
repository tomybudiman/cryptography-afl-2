/**
 * Message security: content integrity (SHA-256 hash) + sender authenticity
 * (RSA signature).
 *
 * The servers only relay `username` and `message`, so both proofs ride inside
 * the message string as:
 *     "<sha256hex>:<rsaSignatureBase64>:<text>"
 * The hash is hex and the signature is base64 — neither contains ":" — so the
 * first two colons are the delimiters, and the text (everything after the 2nd
 * colon) may contain anything, including colons.
 *
 * Recipient logic (see Chat.tsx):
 *   - hash of received text != embedded hash   -> content changed in transit
 *   - signature invalid for the CLAIMED sender -> impersonation ("fake user")
 *   - both pass                                 -> genuine
 *
 * RSA is RSASSA-PKCS1-v1_5 / SHA-256 / 2048-bit via Web Crypto. Each client
 * makes a key pair on join, registers its PUBLIC key, and signs with the
 * PRIVATE key. An impersonator can copy a victim's name but not their private
 * key, so the signature won't verify against the victim's registered key.
 */

const RSA = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;
const SEP = ":";

export type Payload = { hash: string; signature: string; text: string };

export function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { ...RSA, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["sign", "verify"],
  );
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  return toBase64(await crypto.subtle.exportKey("spki", key));
}

export function importPublicKey(base64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", fromBase64(base64), RSA, true, ["verify"]);
}

/** Build the wire payload: hash of text, RSA signature of text, then the text. */
export async function signPayload(text: string, privateKey: CryptoKey): Promise<string> {
  const hash = await sha256Hex(text);
  const signature = toBase64(await crypto.subtle.sign(RSA.name, privateKey, encode(text)));
  return `${hash}${SEP}${signature}${SEP}${text}`;
}

export function parsePayload(payload: string): Payload | null {
  const first = payload.indexOf(SEP);
  if (first === -1) return null;
  const second = payload.indexOf(SEP, first + 1);
  if (second === -1) return null;
  return {
    hash: payload.slice(0, first),
    signature: payload.slice(first + 1, second),
    text: payload.slice(second + 1),
  };
}

/** Pull the readable text out of a payload for display (synchronous). */
export function extractText(payload: string): string {
  return parsePayload(payload)?.text ?? payload;
}

/** Was the text untouched since it was signed? (hash still matches) */
export async function isTextIntact(payload: Payload): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/.test(payload.hash)) return false;
  return (await sha256Hex(payload.text)) === payload.hash;
}

/** Does the signature prove the text came from the holder of `publicKey`? */
export async function isSignatureValid(payload: Payload, publicKey: CryptoKey): Promise<boolean> {
  try {
    return await crypto.subtle.verify(RSA.name, publicKey, fromBase64(payload.signature), encode(payload.text));
  } catch {
    return false;
  }
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encode(text: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>;
}

function toBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
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
