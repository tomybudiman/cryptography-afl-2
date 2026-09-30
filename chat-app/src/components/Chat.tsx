"use client";

import { type FormEvent, useEffect, useRef, useState } from "react";
import { io, type Socket } from "socket.io-client";
import {
  exportPublicKey,
  extractText,
  generateKeyPair,
  importPublicKey,
  isSignatureValid,
  isTextIntact,
  parsePayload,
  signPayload,
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
};

// Decide whether an incoming message is genuine, changed in transit, or fake.
async function verifyMessage(
  sender: string,
  rawMessage: string,
  users: Map<string, string>,
  keyCache: Map<string, CryptoKey>,
): Promise<MessageStatus> {
  const parsed = parsePayload(rawMessage);
  if (!parsed) return "tampered";
  if (!(await isTextIntact(parsed))) return "tampered";

  // Verify the signature against the CLAIMED sender's registered public key.
  const publicKeyB64 = users.get(sender);
  if (!publicKeyB64) return "fake"; // no registered key -> can't prove identity

  try {
    let key = keyCache.get(publicKeyB64);
    if (!key) {
      key = await importPublicKey(publicKeyB64);
      keyCache.set(publicKeyB64, key);
    }
    return (await isSignatureValid(parsed, key)) ? "ok" : "fake";
  } catch {
    return "fake";
  }
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
  // username -> public key (base64 SPKI), mirrored from the server's directory.
  const usersRef = useRef<Map<string, string>>(new Map());
  // Cache of imported public keys, so we don't re-import for every message.
  const publicKeyCacheRef = useRef<Map<string, CryptoKey>>(new Map());
  // Our own RSA key pair for this session; we sign outgoing messages with it.
  const keyPairRef = useRef<CryptoKeyPair | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [usernameInput, setUsernameInput] = useState("");
  const [username, setUsername] = useState("");
  const [messageInput, setMessageInput] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [userCount, setUserCount] = useState(0);
  // The name we send as. null = our real (registered) name; a string = impersonating.
  const [impersonating, setImpersonating] = useState<string | null>(null);

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
      // verification result once the async checks resolve.
      const id = nextMessageIdRef.current++;
      setMessages((prev) => [
        ...prev,
        { id, username: senderUsername, message: extractText(rawMessage), status: "checking" },
      ]);

      void verifyMessage(senderUsername, rawMessage, usersRef.current, publicKeyCacheRef.current).then(
        (status) => {
          setMessages((prev) => prev.map((m) => (m.id === id ? { ...m, status } : m)));
        },
      );
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

    // Make an RSA key pair for this session and register the public half so
    // others can verify our signatures. The private half never leaves here.
    const keyPair = await generateKeyPair();
    keyPairRef.current = keyPair;
    const publicKey = await exportPublicKey(keyPair.publicKey);
    usersRef.current.set(input, publicKey); // so we can verify our own messages

    socketRef.current?.emit("registerPublicKey", { username: input, publicKey });
    setUsername(input);
  };

  const handleMessageSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const text = messageInput.trim();
    if (!text) return;

    // !impersonate <name> — start sending under someone else's name. This works
    // because the server trusts whatever username the client puts on a message;
    // it's the vulnerability, not a feature.
    const impersonateMatch = text.match(/^!impersonate (\w+)$/);
    if (impersonateMatch) {
      const target = impersonateMatch[1];
      setImpersonating(target);
      console.log(`Now impersonating as ${target}`);
      setMessageInput("");
      messageInputRef.current?.focus();
      return;
    }

    // !exit — go back to our real registered name.
    if (/^!exit$/.test(text)) {
      setImpersonating(null);
      console.log(`Now you are ${username}`);
      setMessageInput("");
      messageInputRef.current?.focus();
      return;
    }

    // Sign with OUR private key, even when impersonating. That's the point:
    // an impersonator can put someone else's name on the message but can't
    // produce that person's signature, so the recipient will spot the fake.
    const privateKey = keyPairRef.current?.privateKey;
    if (!privateKey) return;

    const effectiveUsername = impersonating ?? username;
    const payload = await signPayload(text, privateKey);
    socketRef.current?.emit("message", { username: effectiveUsername, message: payload });
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
    keyPairRef.current = null;
    setUserCount(0);
    setImpersonating(null);
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
            {messages.map(({ id, username: senderUsername, message: senderMessage, status }) => {
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
                  <span className={styles.chat__sender}>{isOwn ? "You" : senderUsername}</span>
                  {senderMessage}
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
          {impersonating && (
            <p className={styles.chat__impersonating} role="status">
              Impersonating <strong>{impersonating}</strong> — type <code>!exit</code> to stop
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
