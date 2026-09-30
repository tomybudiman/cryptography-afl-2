import http from "http";
import { Server } from "socket.io";

/**
 * DEMO ONLY — runs on localhost for a security course.
 *
 * This is a drop-in replacement for server.ts: same port, same events, so the
 * existing client connects to it without any change. It behaves exactly like
 * the real server (messages are still relayed to everyone), but it also logs
 * every message that passes through it.
 *
 * The lesson: the chat sends plaintext, so ANY server on the path — a rogue
 * host, or an attacker doing a man-in-the-middle — can silently read every
 * message. Confidentiality has to come from encryption, not from trusting the
 * relay. This is the "why" behind the hashing/AES exercises.
 */

type ChatMessage = {
  username: string;
  message: string;
};

const server = http.createServer();
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
  },
});

io.on("connection", (socket) => {
  console.log(`[intercept] Client ${socket.id} connected`);

  socket.on("message", (data: ChatMessage) => {
    const { username } = data;
    let { message } = data;

    // The eavesdrop: the relay sees the plaintext before passing it on.
    console.log(`[intercept] ${new Date().toISOString()} ${username}: ${message}`);

    // The tamper: the relay rewrites the message before forwarding it. The
    // sender typed one thing; everyone (including the sender) receives another.
    // This is an integrity attack — read AND alter, not just read.
    message = message + " (sus?)";

    io.emit("message", { username, message });
  });

  socket.on("disconnect", () => {
    console.log(`[intercept] Client ${socket.id} disconnected`);
  });
});

const port = 4000;
server.listen(port, () => {
  console.log(`Malicious relay listening on port ${port} (DEMO — logs all traffic)`);
});
