import crypto from "crypto";

const keyHex = "2cc757397503ffc5c8ea4bb56d874a5d25543b3cdd30208d717069bd1c98213b";
const ivHex = "de815c74f7f402d7cdb0df4cd59e27ff";
const key = Buffer.from(keyHex, "hex");
const iv = Buffer.from(ivHex, "hex");
/**
 * The KEY and IV must be sent securely to RECIPIENT.
 * Only SENDER and RECIPIENT should know about these KEY and IV.
 */

const message = "this is a secret message";
console.log("Plaintext:", message);

// SENDER generate CIPHERTEXT
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
let ciphertext = cipher.update(message, "utf8", "hex");
ciphertext += cipher.final("hex");
console.log("Ciphertext:", ciphertext);
