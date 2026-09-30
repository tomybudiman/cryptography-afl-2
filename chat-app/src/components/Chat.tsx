"use client";

import { type FormEvent, useEffect, useRef, useState } from "react";
import { io, type Socket } from "socket.io-client";
import {
  ciphertextOf,
  decryptEnvelope,
  encryptBody,
  exportPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importEncryptKey,
  importVerifyKey,
  isBodyIntact,
  isSecretBody,
  isSignatureValid,
  makeBundle,
  parseBundle,
  parseEnvelope,
  parsePayload,
  signBody,
} from "@/lib/messageSecurity";
import styles from "./Chat.module.scss";

type ConnectionStatus = "connecting" | "connected" | "disconnected" | "left";

// "checking" -> verifying; "ok" -> genuine; "tampered" -> content changed in
// transit; "fake" -> signature doesn't match the claimed sender (impersonation).
type MessageStatus = "checking" | "ok" | "tampered" | "fake";

type ChatMessage = {
  id: number;
  username: string;
  message: string;
  status: MessageStatus;
  encrypted: boolean; // was sent as a secret (RSA-encrypted) message
  readable: boolean; // could we decrypt it (false = we only see ciphertext)
};

type ProcessContext = {
  users: Map<string, string>;
  keyCache: Map<string, CryptoKey>;
  myUsername: string;
  encPrivateKey: CryptoKey | null;
};

type ProcessResult = { status: MessageStatus; text: string; encrypted: boolean; readable: boolean };

// Import (and cache) the signing public key of a user, from their bundle.
async function getVerifyKey(bundle: string | undefined, cache: Map<string, CryptoKey>) {
  const parsed = parseBundle(bundle);
  if (!parsed) return null;
  let key = cache.get(parsed.sign);
  if (!key) {
    try {
      key = await importVerifyKey(parsed.sign);
    } catch {
      return null;
    }
    cache.set(parsed.sign, key);
  }
  return key;
}

// Import (and cache) the encryption public key of a user, from their bundle.
async function getEncryptKey(bundle: string | undefined, cache: Map<string, CryptoKey>) {
  const parsed = parseBundle(bundle);
  if (!parsed) return null;
  let key = cache.get(parsed.enc);
  if (!key) {
    try {
      key = await importEncryptKey(parsed.enc);
    } catch {
      return null;
    }
    cache.set(parsed.enc, key);
  }
  return key;
}

// Verify a message and, if it's an encrypted secret for us, decrypt it.
async function processMessage(sender: string, rawMessage: string, ctx: ProcessContext): Promise<ProcessResult> {
  const parsed = parsePayload(rawMessage);
  if (!parsed) return { status: "tampered", text: rawMessage, encrypted: false, readable: true };

  const encrypted = isSecretBody(parsed.body);
  const envelope = encrypted ? parseEnvelope(parsed.body) : null;
  const cipherText = envelope ? ciphertextOf(envelope) : parsed.body;

  // 1) integrity: was the transmitted body changed?
  if (!(await isBodyIntact(parsed))) {
    return { status: "tampered", text: cipherText, encrypted, readable: false };
  }

  // 2) authenticity: does the signature match the CLAIMED sender's key?
  const verifyKey = await getVerifyKey(ctx.users.get(sender), ctx.keyCache);
  const status: MessageStatus = verifyKey && (await isSignatureValid(parsed, verifyKey)) ? "ok" : "fake";

  // 3) confidentiality: decrypt if this secret message was addressed to us.
  if (encrypted) {
    if (!envelope) return { status: "tampered", text: parsed.body, encrypted: true, readable: false };
    if (ctx.encPrivateKey) {
      const plain = await decryptEnvelope(envelope, ctx.myUsername, ctx.encPrivateKey);
      if (plain !== null) return { status, text: plain, encrypted: true, readable: true };
    }
    return { status, text: cipherText, encrypted: true, readable: false };
  }

  return { status, text: parsed.body, encrypted: false, readable: true };
}

// Synchronous first paint: show plaintext, or ciphertext for secret messages,
// before the async decrypt/verify resolves.
function previewMessage(rawMessage: string): { text: string; encrypted: boolean } {
  const parsed = parsePayload(rawMessage);
  if (!parsed) return { text: rawMessage, encrypted: false };
  if (isSecretBody(parsed.body)) {
    const envelope = parseEnvelope(parsed.body);
    return { text: envelope ? ciphertextOf(envelope) : parsed.body, encrypted: true };
  }
  return { text: parsed.body, encrypted: false };
}

const statusLabels: Record<ConnectionStatus, string> = {
  connecting: "Connecting to server…",
  connected: "Connected to the server",
  disconnected: "Server disconnected. Reconnecting…",
  left: "Not connected",
};

export default function Chat() {
  const socketRef = useRef<Socket | null>(null);
  const messageInputRef = useRef<HTMLInputElement>(null);
  const messageListRef = useRef<HTMLUListElement>(null);
  const nextMessageIdRef = useRef(0);
  // username -> public key bundle (JSON), mirrored from the server's directory.
  const usersRef = useRef<Map<string, string>>(new Map());
  // Cache of imported public keys, so we don't re-import for every message.
  const publicKeyCacheRef = useRef<Map<string, CryptoKey>>(new Map());
  // Our own RSA key pairs for this session: one for signing, one for decrypting.
  const signKeyPairRef = useRef<CryptoKeyPair | null>(null);
  const encKeyPairRef = useRef<CryptoKeyPair | null>(null);
  // Current username, mirrored to a ref so socket handlers read it live.
  const usernameRef = useRef("");
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [usernameInput, setUsernameInput] = useState("");
  const [username, setUsername] = useState("");
  const [messageInput, setMessageInput] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [userCount, setUserCount] = useState(0);
  // The user we're secretly (end-to-end encrypted) chatting with. "" = public.
  const [secretTarget, setSecretTarget] = useState("");

  useEffect(() => {
    const socket = io("http://localhost:4000");
    socketRef.current = socket;

    socket.on("connect", () => {
      console.log("Connected to the server");
      setStatus("connected");
    });

    socket.on("disconnect", (reason) => {
      // Leaving the chat disconnects on purpose, so it isn't a server problem.
      if (reason === "io client disconnect") return;

      console.log("Server disconnected");
      setStatus("disconnected");
    });

    socket.on("init", (keys: [string, string][]) => {
      keys.forEach(([user, key]) => usersRef.current.set(user, key));
      console.log(`\nThere are currently ${usersRef.current.size} users in the chat`);
      setUserCount(usersRef.current.size);
    });

    socket.on("newUser", (data) => {
      const { username: user, publicKey } = data ?? {};
      if (typeof user !== "string" || typeof publicKey !== "string") return;

      usersRef.current.set(user, publicKey);
      console.log(`${user} joined the chat`);
      setUserCount(usersRef.current.size);
    });

    socket.on("message", (data) => {
      const { username: senderUsername, message: rawMessage } = data ?? {};
      // The server relays whatever clients send, so ignore anything that isn't plain text.
      if (typeof senderUsername !== "string" || typeof rawMessage !== "string") return;

      // Show the message right away (in arrival order), then patch in the
      // verification/decryption result once the async checks resolve.
      const id = nextMessageIdRef.current++;
      const preview = previewMessage(rawMessage);
      setMessages((prev) => [
        ...prev,
        {
          id,
          username: senderUsername,
          message: preview.text,
          status: "checking",
          encrypted: preview.encrypted,
          readable: !preview.encrypted,
        },
      ]);

      void processMessage(senderUsername, rawMessage, {
        users: usersRef.current,
        keyCache: publicKeyCacheRef.current,
        myUsername: usernameRef.current,
        encPrivateKey: encKeyPairRef.current?.privateKey ?? null,
      }).then(({ status, text, encrypted, readable }) => {
        setMessages((prev) =>
          prev.map((m) => (m.id === id ? { ...m, status, message: text, encrypted, readable } : m)),
        );
      });
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, []);

  useEffect(() => {
    const list = messageListRef.current;
    if (list) list.scrollTop = list.scrollHeight;
  }, [messages]);

  const handleUsernameSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const input = usernameInput.trim();
    if (!input) return;

    // Make two RSA key pairs for this session — one to sign, one to receive
    // encrypted messages — and register both public halves as one bundle. The
    // private halves never leave here.
    const [signKeyPair, encKeyPair] = await Promise.all([generateSigningKeyPair(), generateEncryptionKeyPair()]);
    signKeyPairRef.current = signKeyPair;
    encKeyPairRef.current = encKeyPair;
    const [signPublicKey, encPublicKey] = await Promise.all([
      exportPublicKey(signKeyPair.publicKey),
      exportPublicKey(encKeyPair.publicKey),
    ]);
    const bundle = makeBundle(signPublicKey, encPublicKey);
    usersRef.current.set(input, bundle); // so we can verify/encrypt to ourselves

    socketRef.current?.emit("registerPublicKey", { username: input, publicKey: bundle });
    usernameRef.current = input;
    setUsername(input);
  };

  const handleMessageSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const text = messageInput.trim();
    if (!text) return;

    // !secret <name> — start a private conversation with one user. Messages
    // will be encrypted with their public key so only they can read them.
    const secretMatch = text.match(/^!secret (\w+)$/);
    if (secretMatch) {
      const target = secretMatch[1];
      setSecretTarget(target);
      console.log(`Now secretly chatting with ${target}`);
      setMessageInput("");
      messageInputRef.current?.focus();
      return;
    }

    // !exit — leave secret mode and go back to public chat.
    if (/^!exit$/.test(text)) {
      console.log(`No more secretly chatting with ${secretTarget}`);
      setSecretTarget("");
      setMessageInput("");
      messageInputRef.current?.focus();
      return;
    }

    const signPrivateKey = signKeyPairRef.current?.privateKey;
    if (!signPrivateKey) return;

    // In secret mode, encrypt the text for the target (and for ourselves, so we
    // can read our own message). Everyone else only sees ciphertext.
    let body = text;
    if (secretTarget) {
      const targetKey = await getEncryptKey(usersRef.current.get(secretTarget), publicKeyCacheRef.current);
      if (!targetKey) {
        console.warn(`Cannot send: no public key for ${secretTarget}`);
        return;
      }
      const recipients: [string, CryptoKey][] = [[secretTarget, targetKey]];
      const myKey = await getEncryptKey(usersRef.current.get(username), publicKeyCacheRef.current);
      if (myKey) recipients.push([username, myKey]);
      body = await encryptBody(text, recipients);
    }

    // Sign so recipients can verify the message is really from us and unaltered.
    const payload = await signBody(body, signPrivateKey);
    socketRef.current?.emit("message", { username, message: payload });
    setMessageInput("");
    messageInputRef.current?.focus();
  };

  const handleLeave = () => {
    console.log("Exiting...");
    socketRef.current?.disconnect();
    setStatus("left");
    setUsername("");
    setMessageInput("");
    setMessages([]);
    usersRef.current.clear();
    publicKeyCacheRef.current.clear();
    signKeyPairRef.current = null;
    encKeyPairRef.current = null;
    usernameRef.current = "";
    setUserCount(0);
    setSecretTarget("");
  };

  const handleRejoin = () => {
    setStatus("connecting");
    socketRef.current?.connect();
  };

  const isConnected = status === "connected";

  return (
    <section className={styles.chat}>
      <h1 className={styles.chat__title}>Chat App</h1>
      <p className={`${styles.chat__status} ${styles[`chat__status--${status}`]}`} role="status">
        {statusLabels[status]}
      </p>

      {status === "left" ? (
        <div className={styles.chat__session}>
          <p className={styles.chat__notice}>You have left the chat.</p>
          <button className={styles.chat__button} type="button" onClick={handleRejoin} autoFocus>
            Join again
          </button>
        </div>
      ) : username ? (
        <>
          <div className={styles.chat__session}>
            <p className={styles.chat__welcome}>
              Welcome, <strong>{username}</strong> to the chat
              {userCount > 0 && <span className={styles.chat__count}> · {userCount} in chat</span>}
            </p>
            <button
              className={`${styles.chat__button} ${styles["chat__button--secondary"]}`}
              type="button"
              onClick={handleLeave}
            >
              Leave
            </button>
          </div>
          <ul ref={messageListRef} className={styles.chat__messages} role="log" aria-label="Chat messages">
            {messages.map(({ id, username: senderUsername, message: senderMessage, status, encrypted, readable }) => {
              const isOwn = senderUsername === username && status !== "fake";
              const className = [
                styles.chat__message,
                styles[`chat__message--${isOwn ? "own" : "other"}`],
                status === "tampered" || status === "fake" ? styles["chat__message--flagged"] : "",
              ]
                .filter(Boolean)
                .join(" ");
              return (
                <li key={id} className={className}>
                  <span className={styles.chat__sender}>
                    {isOwn ? "You" : senderUsername}
                    {encrypted && " 🔒"}
                  </span>
                  {encrypted && !readable ? (
                    <span className={styles.chat__cipher}>{senderMessage}</span>
                  ) : (
                    senderMessage
                  )}
                  {status === "tampered" && (
                    <span className={styles.chat__warning} role="alert">
                      ⚠ This message may have been changed during transmission.
                    </span>
                  )}
                  {status === "fake" && (
                    <span className={styles.chat__warning} role="alert">
                      ⚠ this user is fake
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
          {secretTarget && (
            <p className={styles.chat__secret} role="status">
              🔒 Secret chat with <strong>{secretTarget}</strong> — type <code>!exit</code> to stop
            </p>
          )}
          <form className={styles.chat__form} onSubmit={handleMessageSubmit}>
            <label htmlFor="message" className={`${styles.chat__label} ${styles["chat__label--hidden"]}`}>
              Message
            </label>
            <div className={styles.chat__row}>
              <input
                ref={messageInputRef}
                className={styles.chat__input}
                id="message"
                type="text"
                value={messageInput}
                onChange={(event) => setMessageInput(event.target.value)}
                placeholder="Type a message…"
                maxLength={500}
                autoComplete="off"
                autoFocus
                required
              />
              <button
                className={styles.chat__button}
                type="submit"
                disabled={!isConnected || !messageInput.trim()}
              >
                Send
              </button>
            </div>
          </form>
        </>
      ) : (
        <form className={styles.chat__form} onSubmit={handleUsernameSubmit}>
          <label htmlFor="username" className={styles.chat__label}>
            Enter your username
          </label>
          <div className={styles.chat__row}>
            <input
              className={styles.chat__input}
              id="username"
              type="text"
              value={usernameInput}
              onChange={(event) => setUsernameInput(event.target.value)}
              maxLength={32}
              autoComplete="nickname"
              autoFocus
              required
            />
            <button
              className={styles.chat__button}
              type="submit"
              disabled={!isConnected || !usernameInput.trim()}
            >
              Join
            </button>
          </div>
        </form>
      )}
    </section>
  );
}
