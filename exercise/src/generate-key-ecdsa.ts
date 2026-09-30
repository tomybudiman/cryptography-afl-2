import crypto from "crypto";

const options = {
  namedCurve: "secp256k1", // name of the curve
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
};

const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", options);
console.log("Private Key:", privateKey);
console.log("Public Key:", publicKey);
