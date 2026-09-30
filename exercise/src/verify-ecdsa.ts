import crypto from "crypto";

/**
 * First of all, the RECIPIENT obtains SENDER PUBLIC KEY
 */
const senderPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEb8NN1OA78T0dggPvRMZlxTizPZ2ZW27n
nTE47rOPHNQgUkV6iUVfXY3vm2VR+hhJC5HKP8LYm4vaBVAhvJv2mg==
-----END PUBLIC KEY-----`;
const senderPublicKey = crypto.createPublicKey(senderPublicKeyPem);

/**
 * Then, the RECIPIENT obtains MESSAGE and SIGNATURE
 * from the communication with the SENDER
 */
const signatureHex = "3046022100c8323bdb84dc809e42ea77fe5bea999d8dce8c32e9c29a7dbe87e1fbbc17956c022100b362b347610cf97790e078ec38d9c3541214d91029bd2c385c2c418fb58ef216";
const signature = Buffer.from(signatureHex, "hex");

const message = "this is a secret message";
const data = Buffer.from(message);

// RECIPIENT verifies SIGNATURE
const isVerified = crypto.verify("sha256", data, senderPublicKey, signature);
console.log("ECDSA signature verified:", isVerified);
