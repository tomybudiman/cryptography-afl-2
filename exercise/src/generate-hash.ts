import crypto from "crypto";

const message = "this is a secret message";
console.log("Message:", message);

// SENDER generate MD5 hash
const md5Hash = crypto.createHash("md5").update(message).digest("hex");
console.log("MD5 Hash:", md5Hash);

// SENDER generate SHA-1 hash
const sha1Hash = crypto.createHash("sha1").update(message).digest("hex");
console.log("SHA1 Hash:", sha1Hash);

// SENDER generate SHA-2 hash
const sha256Hash = crypto.createHash("sha256").update(message).digest("hex");
console.log("SHA256 Hash:", sha256Hash);
