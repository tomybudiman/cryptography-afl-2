import crypto from "crypto";

/**
 * First of all, the SENDER obtains the RECIPIENT PUBLIC KEY.
 */
const recipientPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyd+47GXJWHgRISCF7frO
ec+G2SyTx0jXkCdqoAjA7pZcjFS0H5dkFUZHoKSv/O8E/6UnZZWs0GM9NUrnv7dm
yK1Y5kwuWBNUKlmhQkEldGb5BWRk5fd3vVrsV5Gwao2ehWhT0dUum393IHJMBWe3
4hRoXgF1PVnaG87A8+pLPIvfvSQZKXKTRlKACaPscWpWOe6iDxWBuaD+dxM0r7Uq
XHMhJn5HdDSufplBW+8L7OCCmAUkpRtaeSAQpl9bG6l6amP1+q9SylAgl/2irby8
QJHotHtXcFYvEB7CNRxWqD5flKlvSRNoRw+4tiEnwIX+hvMEkAf4Gw0d8YeYJk0W
bQIDAQAB
-----END PUBLIC KEY-----`;
const recipientPublicKey = crypto.createPublicKey(recipientPublicKeyPem);

const message = "this is a secret message";
console.log("Plaintext:", message);

// SENDER generate CIPHERTEXT
const data = Buffer.from(message);
const ciphertext = crypto.publicEncrypt(recipientPublicKey, data);
console.log("Ciphertext:", ciphertext.toString("hex"));
