import crypto from "crypto";

/**
 * First of all, the RECIPIENT obtains KEY and IV securely
 * from the SENDER
 */
const keyHex = "2cc757397503ffc5c8ea4bb56d874a5d25543b3cdd30208d717069bd1c98213b";
const ivHex = "de815c74f7f402d7cdb0df4cd59e27ff";
const key = Buffer.from(keyHex, "hex");
const iv = Buffer.from(ivHex, "hex");

/**
 * Then, the RECIPIENT obtains CIPHERTEXT from the
 * communication with the SENDER
 */
const ciphertextHex = "5d27a28bb82dd7fbc1dae8af8fc61ab23ae9239f409ba43cdccc28fb201844a6";
const ciphertext = Buffer.from(ciphertextHex, "hex");

// RECIPIENT recover PLAINTEXT
const senderDecipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
let recoveredMessageBySender: string = senderDecipher.update(ciphertext, undefined, "utf8");
recoveredMessageBySender += senderDecipher.final("utf8");
console.log("Recovered Plaintext:", recoveredMessageBySender);
