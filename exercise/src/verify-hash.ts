import crypto from "crypto";

/**
 * First of all, the RECIPIENT obtains MESSAGE and HASH
 * (can be MD5, SHA1, or SHA256) from the SENDER
 */
const message = "this is a secret message";
const senderHash = "2cf33591c3b28b382668952e236cccd5"; // md5 hash

// the RECIPIENT need to create their own version of the hash
const recipientHash = crypto.createHash("md5").update(message).digest("hex");
const isValid = (senderHash == recipientHash);
console.log("MD5 verification result is:", isValid);
