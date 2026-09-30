import crypto from "crypto";

const senderPrivateKeyPem = `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgi7FvAAeGTM8dO9nFk5Ad
BfIFcSC7GN7q6i1h00QCvsChRANCAARvw03U4DvxPR2CA+9ExmXFOLM9nZlbbued
MTjus48c1CBSRXqJRV9dje+bZVH6GEkLkco/wtibi9oFUCG8m/aa
-----END PRIVATE KEY-----`;
const senderPrivateKey = crypto.createPrivateKey(senderPrivateKeyPem);
/**
 * The SENDER PRIVATE KEY must be kept securely.
 * No one else should know about this PRIVATE KEY.
 * Meanwhile, the PUBLIC KEY can be shared to others.
 * In this case, the RECIPIENT should know about this SENDER PUBLIC KEY.
 */

const message = "this is a secret message";
console.log("Message:", message);

const data = Buffer.from(message);
const signature = crypto.sign("sha256", data, senderPrivateKey);
console.log("Signature:", signature.toString("hex"));
