const express = require('express');
const http = require('http');
const { Server: SocketIOServer } = require('socket.io');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

/*
 * Simple chat server that stores users and public keys in memory and
 * relays encrypted messages between connected clients.  This server
 * deliberately avoids any encryption/decryption logic; encryption is
 * handled on the client using openpgp.js.  Each user registers with a
 * username and publicKey.  Messages are sent via Socket.io and
 * broadcast to the recipient.  A REST endpoint allows clients to
 * retrieve public keys by username.
 */

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

app.use(cors());
app.use(express.json());

// -----------------------------------------------------------------------------
// Serve the frontend via Express
//
// To simplify deployment behind a Tor onion service, the backend now serves
// the static frontend files directly.  This means the entire application
// (HTML, JavaScript, and API) lives on a single port.  When running behind a
// Tor hidden service, you only need to expose this one port.
//
// The `frontend` directory is resolved relative to this file.  We register
// Express static middleware to serve all assets (HTML, JS, images).  For
// convenience, we also provide a catch‑all route that sends back the
// `index.html` for any unknown path (except API routes).  This supports
// simple client‑side routing should it be added later.
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
app.use(express.static(FRONTEND_DIR));

// Catch‑all route for non‑API GET requests.  This should be placed after
// API routes so that `/api/*` paths are handled normally.  When a user
// navigates directly to `/` or any other non‑API path, the SPA entry point
// `index.html` is returned.
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
});

// Data persistence.  Users and messages are stored in JSON files
// under the `data` directory.  On startup we load existing data
// into in‑memory structures.  After any change we write the data
// back to disk.  This provides simple persistence across restarts
// without requiring a database.
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

// Ensure the data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR);
}

// In‑memory storage for users and messages.  Each user maps to an
// object containing their public key.  Messages are an array of
// objects { id, from, to, ciphertext, timestamp }.
const users = new Map();
const messages = [];

// Load persisted users
try {
  if (fs.existsSync(USERS_FILE)) {
    const userList = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    userList.forEach((u) => {
      users.set(u.username, { publicKey: u.publicKey });
    });
  }
} catch (err) {
  console.error('Error loading users file:', err);
}

// Load persisted messages
try {
  if (fs.existsSync(MESSAGES_FILE)) {
    const msgs = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
    msgs.forEach((m) => messages.push(m));
  }
} catch (err) {
  console.error('Error loading messages file:', err);
}

/**
 * Register a user by username and public key.  If the username is
 * already taken, respond with an error.  Otherwise store the user and
 * return success.
 */
app.post('/api/register', (req, res) => {
  const { username, publicKey } = req.body;
  if (!username || !publicKey) {
    return res.status(400).json({ error: 'username and publicKey are required' });
  }
  if (users.has(username)) {
    return res.status(400).json({ error: 'username already exists' });
  }
  users.set(username, { publicKey });
  console.log(`Registered user ${username}`);
  // Persist users to disk.  Convert the map to an array of plain
  // objects for JSON serialization.
  try {
    const userArray = Array.from(users.entries()).map(([uname, data]) => ({ username: uname, publicKey: data.publicKey }));
    fs.writeFileSync(USERS_FILE, JSON.stringify(userArray, null, 2));
  } catch (err) {
    console.error('Error writing users file:', err);
  }
  return res.json({ success: true });
});

/**
 * Get a user by username.  Returns the publicKey so clients can
 * encrypt messages to this user.
 */
app.get('/api/users/:username', (req, res) => {
  const { username } = req.params;
  const user = users.get(username);
  if (!user) {
    return res.status(404).json({ error: 'user not found' });
  }
  return res.json({ username, publicKey: user.publicKey });
});

/**
 * List all users (for demo purposes).  Only returns usernames and
 * fingerprints, not private keys.
 */
app.get('/api/users', (req, res) => {
  const list = Array.from(users.entries()).map(([username, data]) => ({
    username,
    publicKey: data.publicKey,
  }));
  return res.json(list);
});

/**
 * Retrieve encrypted messages between two users.  Requires query
 * parameters `user1` and `user2`.  Returns all messages where
 * (from == user1 and to == user2) OR (from == user2 and to == user1),
 * ordered by timestamp.  If the parameters are missing, return
 * status 400.
 */
app.get('/api/messages', (req, res) => {
  const { user1, user2 } = req.query;
  if (!user1 || !user2) {
    return res.status(400).json({ error: 'user1 and user2 query parameters are required' });
  }
  const conv = messages.filter(
    (m) => (m.from === user1 && m.to === user2) || (m.from === user2 && m.to === user1)
  );
  // Sort by timestamp ascending
  conv.sort((a, b) => a.timestamp - b.timestamp);
  return res.json(conv);
});

/**
 * Socket.io connection handler.  Each client must supply its
 * username on connection.  The server tracks which socket belongs to
 * which username.
 */
const socketsByUsername = new Map();

io.on('connection', (socket) => {
  console.log('Socket connected', socket.id);

  socket.on('registerUsername', (username) => {
    console.log(`Socket ${socket.id} registered as ${username}`);
    socketsByUsername.set(username, socket);
  });

  /**
   * Relay an encrypted message from sender to recipient.  Expect
   * payload: { to, from, ciphertext }.  Store the message in
   * messages array and emit to the recipient if connected.
   */
  socket.on('sendMessage', (payload) => {
    // Accept arbitrary message payloads; enforce required fields
    const { to, from, ciphertext, type = 'text', filename = null } = payload;
    if (!to || !from || !ciphertext) return;
    const msg = {
      id: uuidv4(),
      from,
      to,
      ciphertext,
      type,
      filename,
      timestamp: Date.now(),
    };
    messages.push(msg);
    // Persist messages to disk.  Write entire array; this is
    // acceptable for small demo apps.  For larger apps a database
    // should be used instead.
    try {
      fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
    } catch (err) {
      console.error('Error writing messages file:', err);
    }
    console.log(`Message from ${from} to ${to}`);
    const recipientSocket = socketsByUsername.get(to);
    if (recipientSocket) {
      recipientSocket.emit('message', msg);
    }
  });

  socket.on('disconnect', () => {
    console.log('Socket disconnected', socket.id);
    // Remove the socket from the username map
    for (const [username, s] of socketsByUsername.entries()) {
      if (s === socket) {
        socketsByUsername.delete(username);
        break;
      }
    }
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});