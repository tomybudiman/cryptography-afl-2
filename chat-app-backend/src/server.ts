import http from "http";
import { Server } from "socket.io";

type ChatMessage = {
  username: string;
  message: string;
};

type PublicKeyRegistration = {
  username: string;
  publicKey: string;
};

const server = http.createServer();
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
  },
});

// username -> public key, so clients can encrypt for each other.
const users = new Map<string, string>();

io.on("connection", (socket) => {
  console.log(`Client ${socket.id} connected`);

  // Send the newcomer the public keys of everyone already registered.
  socket.emit("init", Array.from(users.entries()));

  socket.on("registerPublicKey", (data: PublicKeyRegistration) => {
    const { username, publicKey } = data;
    users.set(username, publicKey);
    console.log(`${username} registered with public key.`);
    io.emit("newUser", { username, publicKey });
  });

  socket.on("message", (data: ChatMessage) => {
    const { username, message } = data;
    io.emit("message", { username, message });
  });

  socket.on("disconnect", () => {
    console.log(`Client ${socket.id} disconnected`);
  });
});

const port = 4000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
