import crypto from "crypto";

const senderPrivateKeyPem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCiS/XpRCstXmVP
wSdsx61gzwNJc5hth/a1/UOwFhSmccvH5kQXDulK+ghuXIw773EfSvFEdeibkrzm
+W0eXzA78/xU1SjHy5r0MrSBlDwz9WSgHy74ucw8wDQvgGJRATl3gO/eZUR+dubI
vK/fuJgEhXyO8Sf4uh4Gdf802j/OdwCKXDi4CrmY5rK5km0h0J3IJw02+tVmwmkx
Di6C4UzLBc5VCKEafAcIikqyWVof/a5LDPdmXqSd1QxY4fWpK5ORFwJjqzp2wewn
Y2yNHJmbyS0xsuB4q2dJVcBAZXFlHyhuK49pgdpqFXRXOV5Gc1vZUsFboW+heLGt
u3u5T+mzAgMBAAECggEAFvOPDzHouT3ELgcuwB9s0Wf1GwoR4Et+BDaQv/IfcXpe
SyKxNmGRdFzvnEvSORefc8FxZTEXeAjEVhWn7MehVpkmcgjC/543h5k0Fa8U5HQr
isleJyZ/T4gO2TjaroHx0oiVY2oGyaue73xfks/UD6+g8cYA1Rfc7yT4tky3AUdx
QmCEYGfj2QpfefIs4evWr0Kup+DVeH0cELTUAhUC4urznyOmvDG6mpVBGmefMWTA
3C0qttrxvHahhl8f6qbojJN6j2lhgznpFtb1IjHyJf4Jp0aWIoDIX47k6RzEawCT
+M0SdTVoy3qHO0Utm5PgZby3UnnlfrSN+A2eDY1ZoQKBgQDVN5WzSc90bfBYzQt9
mBjXAxlThwTc1xWaiA8KMd6xFG3T7Ejs2pD6NXyPsItfNyrcAHeI2njI+ufkeHip
aQ82/9jVSY3BDHwlkPu57lF8VymstL/d8Kkoo43kiHgXruZV/K8Kgr/faLwQY/ft
zFAFyB6k3Sz7RZEmQsLTEVEgTwKBgQDC3Lm9M44hAzxi3Vg7VHFhCROHO/Z8cm9c
XZ6OTeNsiXbC/0DP/IICbhJhMKGhYun2LJXnh6dOOoFgFk+2RQE0JKH4bhZgpiw+
jnLblFKQEQUpDlgtexySY0mO0Z/bNbJ/UYbQogm9/dUP0cQ7iFmWGwGW038sMaQ9
LP/IR1XDXQKBgFnTcxP3cpjggDNJHyAoZb6fpZnU9i17x7Q0wfFPlTwRGTwA/bAb
XJysz+9RN0ZD3aCV6cYUFHLHkc5lGqB0jF5lZxpkRH4iHmNNM1/fkSDLL9l8xKBh
9UITtYGkJMQFgTCUpcHN17vtSd214Auk2cm1x4M5UuwBIOd3lNCLKRxtAoGBAJKv
gYpxos4rF2v834xZ9rdrE647b0MjCb1oJBFPhKGRoTsM1wc6N8wIfAF5kFJimWhd
C8MslL8Iv5dLdFnq/Ar6gIr4pBPBQ5Ebvk6ZCsW0akQLrkkeYdW4tAi0uDdV5rZ8
8pVfRSImUBsGd0exTm72iW22bAcin1YF584mFONpAoGAOw4jhKqdSdDX27bv5OpD
PiLszCGWnbdQHKTDSM5HXZ+ajaHTxkc6s+Q4frYi+n/ryMz7BDyKcSmzJkxHz/kU
91nCFItEKXYDTuhE+F5E1bsLQg0sKy86rhzmVZmu8JrFqyt9Lg1yaKKFZz2gbzy8
sjApLTWBF2wukg0H8wjsFqg=
-----END PRIVATE KEY-----`;
const senderPrivateKey = crypto.createPrivateKey(senderPrivateKeyPem);
/**
 * The SENDER PRIVATE KEY must be kept secure.
 * No one else should know about this PRIVATE KEY.
 * Meanwhile, the PUBLIC KEY can be shared with others.
 * In this case, the RECIPIENT should know about this SENDER PUBLIC KEY.
 */

const message = "this is a secret messages";
console.log("Message:", message);

const data = Buffer.from(message);
const signature = crypto.sign("sha256", data, senderPrivateKey);
console.log("Signature:", signature.toString("hex"));
