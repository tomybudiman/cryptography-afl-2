import crypto from "crypto";

/**
 * First of all, the RECIPIENT obtains SENDER PUBLIC KEY
 */
const senderPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokv16UQrLV5lT8EnbMet
YM8DSXOYbYf2tf1DsBYUpnHLx+ZEFw7pSvoIblyMO+9xH0rxRHXom5K85vltHl8w
O/P8VNUox8ua9DK0gZQ8M/VkoB8u+LnMPMA0L4BiUQE5d4Dv3mVEfnbmyLyv37iY
BIV8jvEn+LoeBnX/NNo/zncAilw4uAq5mOayuZJtIdCdyCcNNvrVZsJpMQ4uguFM
ywXOVQihGnwHCIpKsllaH/2uSwz3Zl6kndUMWOH1qSuTkRcCY6s6dsHsJ2NsjRyZ
m8ktMbLgeKtnSVXAQGVxZR8obiuPaYHaahV0VzleRnNb2VLBW6FvoXixrbt7uU/p
swIDAQAB
-----END PUBLIC KEY-----`;
const senderPublicKey = crypto.createPublicKey(senderPublicKeyPem);

/**
 * Then, the RECIPIENT obtains MESSAGE and SIGNATURE
 * from the communication with the SENDER
 */
const signatureHex = "1c9fca3cbff8018a650ef417770589c2b078819cbcd49adc071c37659353405ccedfd22c56d0c2c0936d041009126c461a43513720eed9b1b436b6cfaf8dd531d4585b2e2cce24d9609e207f05112e43627d110ded6e3cb9a29e3e4d01b69dfd8e6d570a302efe3802c2cc2ea0db0b82cceec8250368996aaa7306f516ac370786ff3d8247f392d6c284db18015be8ee1170c1f9e33cffbfc39b4f58b7eea7e9df4155450911c2f3f2e196df8a1a7c148c199e56c39e07b68c9696baef84c645e099b4d36f7c02dc0dc3c43fc3d1f73d10d24be803fc0ae698e87ae6209b1279b61f401e5ff579f5668ecebb1dd841ee618f1d82494f4d984d8e9424ffe3e164";
const signature = Buffer.from(signatureHex, "hex");

const message = "this is a secret message";
const data = Buffer.from(message);

// RECIPIENT verifies SIGNATURE
const isValid = crypto.verify("sha256", data, senderPublicKey, signature);
console.log("RSA signature verified:", isValid);
