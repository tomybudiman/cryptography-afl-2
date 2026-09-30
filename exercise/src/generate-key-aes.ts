import crypto from "crypto";

const key = crypto.randomBytes(32); // secret key
const iv = crypto.randomBytes(16); // initialization vector
console.log("Key:", key.toString("hex"));
console.log("IV:", iv.toString("hex"));
