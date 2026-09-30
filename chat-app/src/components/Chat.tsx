"use client";

import { type FormEvent, useEffect, useRef, useState } from "react";
import { io, type Socket } from "socket.io-client";
import styles from "./Chat.module.scss";

type ConnectionStatus = "connecting" | "connected" | "disconnected" | "left";

type ChatMessage = {
  id: number;
  username: string;
  message: string;
};

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
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [usernameInput, setUsernameInput] = useState("");
  const [username, setUsername] = useState("");
  const [messageInput, setMessageInput] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);

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

    socket.on("message", (data) => {
      const { username: senderUsername, message: senderMessage } = data ?? {};
      // The server relays whatever clients send, so ignore anything that isn't plain text.
      if (typeof senderUsername !== "string" || typeof senderMessage !== "string") return;

      const id = nextMessageIdRef.current++;
      setMessages((prev) => [...prev, { id, username: senderUsername, message: senderMessage }]);
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

  const handleUsernameSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const input = usernameInput.trim();
    if (!input) return;

    setUsername(input);
  };

  const handleMessageSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const message = messageInput.trim();
    if (!message) return;

    socketRef.current?.emit("message", { username, message });
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
            {messages.map(({ id, username: senderUsername, message: senderMessage }) => {
              const isOwn = senderUsername === username;
              return (
                <li
                  key={id}
                  className={`${styles.chat__message} ${styles[`chat__message--${isOwn ? "own" : "other"}`]}`}
                >
                  <span className={styles.chat__sender}>{isOwn ? "You" : senderUsername}</span>
                  {senderMessage}
                </li>
              );
            })}
          </ul>
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
