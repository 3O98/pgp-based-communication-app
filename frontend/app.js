/*
 * Improved UI logic for the PGP encrypted messenger.  This script powers
 * user registration, key generation/import, contact management and
 * encrypted chat.  It uses OpenPGP.js v4 for cryptographic
 * operations and Socket.IO for real‑time communication.  The UI
 * leverages Tailwind CSS classes defined in index.html.
 */

// DOM references for registration
const registrationPanel = document.getElementById('registrationPanel');
const regUsernameInput = document.getElementById('regUsername');
const regPassInput = document.getElementById('regPass');
const regGenerateBtn = document.getElementById('regGenerateBtn');
const regImportFile = document.getElementById('regImportFile');
const regImportBtn = document.getElementById('regImportBtn');
const regImportText = document.getElementById('regImportText');
const regImportPasteBtn = document.getElementById('regImportPasteBtn');
const regRegisterBtn = document.getElementById('regRegisterBtn');
const regStatus = document.getElementById('regStatus');
const regLoginBtn = document.getElementById('regLoginBtn');

// DOM references for server URL and the main chat interface
const serverURLInput = document.getElementById('serverURLInput');
const contactsPanel = document.getElementById('contactsPanel');
const chatPanel = document.getElementById('chatPanel');
const userInfo = document.getElementById('userInfo');
const exportKeyBtn = document.getElementById('exportKeyBtn');
const copyPublicKeyBtn = document.getElementById('copyPublicKeyBtn');
const userFingerprint = document.getElementById('userFingerprint');
const addContactInput = document.getElementById('addContactInput');
const addContactBtn = document.getElementById('addContactBtn');
const contactSearchInput = document.getElementById('contactSearchInput');
const contactsList = document.getElementById('contactsList');
const requestsContainer = document.getElementById('requestsContainer');
const requestsList = document.getElementById('requestsList');
const requestsBadge = document.getElementById('requestsBadge');
const requestActions = document.getElementById('requestActions');
const acceptRequestBtn = document.getElementById('acceptRequestBtn');
const declineRequestBtn = document.getElementById('declineRequestBtn');
const chatMessages = document.getElementById('chatMessages');
const chatInput = document.getElementById('chatInput');
const sendChatBtn = document.getElementById('sendChatBtn');
const attachImageBtn = document.getElementById('attachImageBtn');
const imageInput = document.getElementById('imageInput');
const activeChatName = document.getElementById('activeChatName');

// Theme toggle
const themeToggle = document.getElementById('themeToggle');
const themeIcon = document.getElementById('themeIcon');

// Server status indicator references
const serverStatus = document.getElementById('serverStatus');
const statusDot = document.getElementById('statusDot');
const statusLabel = document.getElementById('statusLabel');

// Global state
let username = null;
let passphrase = null;
let privateKeyArmored = null;
let publicKeyArmored = null;
let privateKey = null; // OpenPGP private key object
const friends = new Map(); // friendUsername -> { publicKeyArmored }
const messagesByFriend = new Map(); // friendUsername -> array of { from, text }

// Request state: messages from unknown senders
const requestsMessagesByUser = new Map(); // username -> array of { from, text, timestamp, verified }
const requestsUnreadCounts = new Map(); // username -> count
let currentFriend = null;
let socket = null;

// Track unread message counts per friend
const unreadCounts = new Map();

// Server URL (default).  Will be updated from the input field as needed.
let serverUrl = serverURLInput ? serverURLInput.value.trim() : 'http://127.0.0.1:3001';

// Watch for changes to the server URL input and update serverUrl variable
if (serverURLInput) {
  serverURLInput.addEventListener('change', () => {
    const val = serverURLInput.value.trim();
    if (val) {
      serverUrl = val;
    }
  });
}

// Filter contacts when the search input changes
if (contactSearchInput) {
  contactSearchInput.addEventListener('input', () => {
    updateContactsList();
  });
}

// Image attachment handling.  Clicking the attach button triggers the
// hidden file input.  When a file is selected the image is read,
// encrypted and sent via PGP as described in sendImage().
if (attachImageBtn && imageInput) {
  attachImageBtn.addEventListener('click', () => {
    imageInput.click();
  });
  imageInput.addEventListener('change', () => {
    const file = imageInput.files[0];
    // Reset value so selecting the same file again triggers change event
    imageInput.value = '';
    if (file) {
      sendImage(file);
    }
  });
}

/**
 * Handle image selection from the hidden file input.  Reads the image as a
 * Data URL, encrypts it with the recipient's public key and sends it
 * over the socket with a type of 'image'.  The plaintext sent via PGP
 * contains a JSON string with the data URL and metadata so the
 * recipient can reconstruct and display the image.  The function
 * enforces a maximum file size of 2 MB to prevent performance issues.
 * @param {File} file
 */
async function sendImage(file) {
  if (!currentFriend) {
    alert('Select a contact to chat with');
    return;
  }
  if (!file) return;
  const maxSize = 2 * 1024 * 1024; // 2 MB
  if (file.size > maxSize) {
    alert('Image is too large (max 2MB)');
    return;
  }
  // Ensure the friend exists and we have their public key
  const friend = friends.get(currentFriend);
  if (!friend || !friend.publicKeyArmored) {
    alert('Contact not found or missing public key');
    return;
  }
  // Read the file as a data URL
  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
  try {
    // Prepare plaintext payload as JSON so we can include metadata
    const payload = JSON.stringify({ dataUrl, filename: file.name, mime: file.type });
    // Parse recipient public key
    const recipientKeys = (await openpgp.key.readArmored(friend.publicKeyArmored)).keys;
    const messageObj = openpgp.message.fromText(payload);
    const encrypted = await openpgp.encrypt({
      message: messageObj,
      publicKeys: recipientKeys,
      privateKeys: [privateKey],
    });
    const ciphertext = encrypted.data;
    // Emit the encrypted message with image type and filename
    socket.emit('sendMessage', {
      to: currentFriend,
      from: username,
      ciphertext,
      type: 'image',
      filename: file.name,
    });
    // Locally update our conversation with the image
    const timestamp = Date.now();
    const msgs = messagesByFriend.get(currentFriend) || [];
    msgs.push({ from: username, type: 'image', dataUrl, filename: file.name, timestamp, verified: true });
    messagesByFriend.set(currentFriend, msgs);
    unreadCounts.set(currentFriend, 0);
    saveLocalHistory();
    updateContactsList();
    renderMessages(currentFriend);
  } catch (err) {
    console.error('Error encrypting image', err);
    alert('Error encrypting image: ' + err.message);
  }
}

/**
 * Initialize theme based on local storage.  Applies or removes
 * the `dark` class on the document's root element and updates
 * the theme icon accordingly.
 */
function initTheme() {
  const savedTheme = localStorage.getItem('theme');
  const root = document.documentElement;
  if (savedTheme === 'dark') {
    root.classList.add('dark');
    themeIcon.textContent = '🌚';
  } else {
    root.classList.remove('dark');
    themeIcon.textContent = '🌞';
  }
}

// Toggle between light and dark modes and persist preference
themeToggle.addEventListener('click', () => {
  const root = document.documentElement;
  if (root.classList.contains('dark')) {
    root.classList.remove('dark');
    themeIcon.textContent = '🌞';
    localStorage.setItem('theme', 'light');
  } else {
    root.classList.add('dark');
    themeIcon.textContent = '🌚';
    localStorage.setItem('theme', 'dark');
  }
});

// Apply the saved theme on initial load
initTheme();

/**
 * Helper function to display status messages in the registration panel.
 * @param {string} msg
 */
function setRegStatus(msg) {
  regStatus.textContent = msg;
}

/**
 * Generate a new ECC key pair using OpenPGP.js v4.  Stores the
 * armored keys in global variables and decrypts the private key
 * immediately so it can be used for signing and decryption.
 */
regGenerateBtn.addEventListener('click', async () => {
  const uname = regUsernameInput.value.trim();
  const pass = regPassInput.value;
  if (!uname) {
    alert('Please enter a username before generating keys');
    return;
  }
  try {
    // Use curve25519 for ECC keys in v4.  Provide a user ID with
    // name and email to satisfy the OpenPGP v4 requirement.
    const keyOptions = {
      type: 'ecc',
      curve: 'curve25519',
      userIds: [{ name: uname, email: `${uname}@example.com` }],
    };
    // Only set passphrase if provided; otherwise the private key will be generated unencrypted
    if (pass) {
      keyOptions.passphrase = pass;
    }
    const { privateKeyArmored: privArm, publicKeyArmored: pubArm } = await openpgp.generateKey(keyOptions);
    privateKeyArmored = privArm;
    publicKeyArmored = pubArm;
    // Parse and decrypt the private key for later use
    const privObj = (await openpgp.key.readArmored(privateKeyArmored)).keys[0];
    // If a passphrase was provided, decrypt; otherwise key is already unlocked
    if (pass) {
      await privObj.decrypt(pass);
    }
    privateKey = privObj;
    setRegStatus('Generated a new key pair.  Remember to export your private key!');
    console.log('Generated new keys');
  } catch (err) {
    console.error(err);
    alert('Error generating keys: ' + err.message);
  }
});

/**
 * Import an existing armored private key from a file.  Reads the
 * file, decrypts it using the provided passphrase and derives the
 * corresponding public key.  Stores the results in global variables.
 */
regImportBtn.addEventListener('click', async () => {
  const file = regImportFile.files[0];
  const uname = regUsernameInput.value.trim();
  const pass = regPassInput.value;
  if (!file) {
    alert('Please choose a private key file');
    return;
  }
  if (!uname) {
    alert('Please enter a username before importing a key');
    return;
  }
  const reader = new FileReader();
  reader.onload = async () => {
    try {
      privateKeyArmored = reader.result;
      const privObj = (await openpgp.key.readArmored(privateKeyArmored)).keys[0];
      // Decrypt only if a passphrase was provided
      if (pass) {
        await privObj.decrypt(pass);
      }
      privateKey = privObj;
      // Derive the public key from the private key
      const pubObj = privObj.toPublic();
      publicKeyArmored = typeof pubObj.armor === 'function' ? pubObj.armor() : pubObj.toString();
      setRegStatus('Imported private key successfully.');
    } catch (err) {
      console.error(err);
      alert('Error importing private key: ' + err.message);
    }
  };
  reader.readAsText(file);
});

// Import a private key pasted into the textarea.  This allows users
// to manually provide an armored private key instead of selecting a
// file.  The username must be provided.  If a passphrase is supplied
// in the passphrase input, the key will be decrypted; otherwise it
// is assumed to be unencrypted.
regImportPasteBtn.addEventListener('click', async () => {
  const uname = regUsernameInput.value.trim();
  const pass = regPassInput.value;
  const armored = regImportText?.value?.trim() || '';
  if (!armored) {
    alert('Please paste your private key');
    return;
  }
  if (!uname) {
    alert('Please enter a username before importing a key');
    return;
  }
  try {
    privateKeyArmored = armored;
    const privObj = (await openpgp.key.readArmored(privateKeyArmored)).keys[0];
    if (pass) {
      await privObj.decrypt(pass);
    }
    privateKey = privObj;
    // Derive the public key from the private key
    const pubObj = privObj.toPublic();
    publicKeyArmored = typeof pubObj.armor === 'function' ? pubObj.armor() : pubObj.toString();
    setRegStatus('Imported pasted private key successfully.');
  } catch (err) {
    console.error(err);
    alert('Error importing pasted key: ' + err.message);
  }
});

/**
 * Register the user with the backend server.  Requires that a key
 * pair has been generated or imported.  On success, it connects
 * to the Socket.IO server, initializes state and shows the chat UI.
 */
regRegisterBtn.addEventListener('click', async () => {
  const uname = regUsernameInput.value.trim();
  const pass = regPassInput.value;
  if (!uname || !publicKeyArmored || !privateKeyArmored) {
    alert('Please provide username and generate or import keys');
    return;
  }
  try {
    // Send registration request
    const res = await fetch(`${serverUrl}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: uname, publicKey: publicKeyArmored }),
    });
    const data = await res.json();
    if (!res.ok) {
      setRegStatus(data.error || 'Registration failed');
      return;
    }
    // Update global state
    username = uname;
    passphrase = pass;
    // Decrypt the private key again to ensure it's ready for use, but only if passphrase exists
    const privObj = (await openpgp.key.readArmored(privateKeyArmored)).keys[0];
    if (passphrase) {
      await privObj.decrypt(passphrase);
    }
    privateKey = privObj;
    // Update UI
    setRegStatus('Registered successfully!');
    registrationPanel.classList.add('hidden');
    contactsPanel.classList.remove('hidden');
    chatPanel.classList.remove('hidden');
    userInfo.textContent = username;
    // Compute and display fingerprint
    try {
      const pubObjForFp = (await openpgp.key.readArmored(publicKeyArmored)).keys[0];
      const fp = pubObjForFp.getFingerprint ? pubObjForFp.getFingerprint() : (pubObjForFp.keyPacket && pubObjForFp.keyPacket.getFingerprint && pubObjForFp.keyPacket.getFingerprint());
      if (fp) {
        userFingerprint.textContent = 'Fingerprint: ' + fp;
      }
    } catch (err) {
      console.error('Error computing fingerprint', err);
    }
    // Reset contacts and messages
    friends.clear();
    messagesByFriend.clear();
    currentFriend = null;
    updateContactsList();
    // Connect to Socket.IO using helper
    connectSocket();
    // Load any local history and unread counts for this user
    loadLocalHistory();
    // Disable messaging until a contact or request is selected
    sendChatBtn.disabled = true;
    chatInput.disabled = true;
    chatInput.placeholder = '';
  } catch (err) {
    console.error(err);
    alert('Error registering: ' + err.message);
  }
});

/**
 * Log in an existing user.  Requires that the username and passphrase
 * are provided, and that the user has imported their private key.
 * The private key is used to derive the public key, which must match
 * the public key stored on the server for the given username.  On
 * success the UI is switched to the chat view and the socket
 * connection is established.
 */
regLoginBtn.addEventListener('click', async () => {
  const uname = regUsernameInput.value.trim();
  const pass = regPassInput.value;
  if (!uname) {
    alert('Please provide a username');
    return;
  }
  // Update server URL from input
  serverUrl = serverURLInput.value.trim() || serverUrl;
  if (!privateKeyArmored) {
    alert('Import or paste your private key before logging in');
    return;
  }
  try {
    // Parse the private key and decrypt only if passphrase provided
    const privObj = (await openpgp.key.readArmored(privateKeyArmored)).keys[0];
    if (pass) {
      await privObj.decrypt(pass);
    }
    privateKey = privObj;
    // Derive public key from private key
    const pubObj = privObj.toPublic();
    publicKeyArmored = typeof pubObj.armor === 'function' ? pubObj.armor() : pubObj.toString();
    // Fetch user record from server
    const res = await fetch(`${serverUrl}/api/users/${encodeURIComponent(uname)}`);
    const data = await res.json();
    if (!res.ok) {
      alert(data.error || 'User not found on server.  Perhaps you need to register first.');
      return;
    }
    if (data.publicKey !== publicKeyArmored) {
      alert('Provided private key does not match the public key stored on the server for this username.');
      return;
    }
    // Set global state and update UI
    username = uname;
    passphrase = pass;
    registrationPanel.classList.add('hidden');
    contactsPanel.classList.remove('hidden');
    chatPanel.classList.remove('hidden');
    userInfo.textContent = username;
    // Compute and display fingerprint
    try {
      const pubObjForFp = (await openpgp.key.readArmored(publicKeyArmored)).keys[0];
      const fp = pubObjForFp.getFingerprint ? pubObjForFp.getFingerprint() : (pubObjForFp.keyPacket && pubObjForFp.keyPacket.getFingerprint && pubObjForFp.keyPacket.getFingerprint());
      if (fp) {
        userFingerprint.textContent = 'Fingerprint: ' + fp;
      }
    } catch (err) {
      console.error('Error computing fingerprint', err);
    }
    friends.clear();
    messagesByFriend.clear();
    currentFriend = null;
    updateContactsList();
    setRegStatus('Logged in successfully!');
    // Connect socket
    connectSocket();
    // Load any local history and unread counts
    loadLocalHistory();
    // Disable messaging until a contact or request is selected
    sendChatBtn.disabled = true;
    chatInput.disabled = true;
    chatInput.placeholder = '';
  } catch (err) {
    console.error(err);
    alert('Error logging in: ' + err.message);
  }
});

/**
 * Export the user's private key as a downloadable file.  Creates
 * a temporary anchor element and triggers a download of the armored
 * key.  Prompts the user to choose a location to save the file.
 */
exportKeyBtn.addEventListener('click', () => {
  if (!privateKeyArmored) {
    alert('No private key to export.  Generate or import a key first.');
    return;
  }
  const blob = new Blob([privateKeyArmored], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${username || 'private'}-private-key.asc`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 0);
});

// Copy the public key to clipboard
copyPublicKeyBtn.addEventListener('click', () => {
  if (!publicKeyArmored) {
    alert('No public key to copy');
    return;
  }
  navigator.clipboard.writeText(publicKeyArmored).then(() => {
    alert('Public key copied to clipboard');
  }).catch((err) => {
    console.error(err);
    alert('Failed to copy public key');
  });
});

/**
 * Handle adding a new contact.  Fetches the friend's public key from
 * the backend and stores it in the `friends` map.  Initializes an
 * empty messages array for the friend.  Updates the contacts list UI.
 */
addContactBtn.addEventListener('click', async () => {
  const friendUsername = addContactInput.value.trim();
  if (!friendUsername) {
    alert('Enter a friend username');
    return;
  }
  if (friends.has(friendUsername)) {
    alert('Contact already added');
    return;
  }
  try {
    const res = await fetch(`${serverUrl}/api/users/${friendUsername}`);
    const data = await res.json();
    if (!res.ok) {
      alert(data.error || 'Unable to fetch user');
      return;
    }
    friends.set(friendUsername, { publicKeyArmored: data.publicKey });
    messagesByFriend.set(friendUsername, []);
    addContactInput.value = '';
    updateContactsList();
    // If this user previously sent a request, merge their request messages
    if (requestsMessagesByUser.has(friendUsername)) {
      const reqMsgs = requestsMessagesByUser.get(friendUsername);
      const existingMsgs = messagesByFriend.get(friendUsername) || [];
      messagesByFriend.set(friendUsername, existingMsgs.concat(reqMsgs));
      requestsMessagesByUser.delete(friendUsername);
      requestsUnreadCounts.delete(friendUsername);
      updateRequestsList();
      saveRequests();
      saveLocalHistory();
    }
  } catch (err) {
    console.error(err);
    alert('Error adding contact: ' + err.message);
  }
});

/**
 * Send an encrypted message to the currently selected friend.  Uses
 * the friend's public key to encrypt and the user's private key to
 * sign.  Stores the plaintext message locally and updates the UI.
 */
sendChatBtn.addEventListener('click', async () => {
  const text = chatInput.value.trim();
  if (!currentFriend) {
    alert('Select a contact to chat with');
    return;
  }
  if (!text) {
    return;
  }
  const friend = friends.get(currentFriend);
  if (!friend) {
    alert('Contact not found');
    return;
  }
  try {
    // Parse recipient public key
    const recipientKeys = (await openpgp.key.readArmored(friend.publicKeyArmored)).keys;
    const messageObj = openpgp.message.fromText(text);
    const encrypted = await openpgp.encrypt({
      message: messageObj,
      publicKeys: recipientKeys,
      privateKeys: [privateKey],
    });
    const ciphertext = encrypted.data;
    // Send via socket
    socket.emit('sendMessage', { to: currentFriend, from: username, ciphertext, type: 'text' });
    // Store plaintext locally with timestamp and mark verified (we trust our own messages)
    const timestamp = Date.now();
    const msgs = messagesByFriend.get(currentFriend) || [];
    msgs.push({ from: username, text, timestamp, verified: true });
    messagesByFriend.set(currentFriend, msgs);
    // Reset unread count for current friend (we are sending)
    unreadCounts.set(currentFriend, 0);
    // Persist to local storage
    saveLocalHistory();
    // Update UI
    chatInput.value = '';
    updateContactsList();
    renderMessages(currentFriend);
  } catch (err) {
    console.error('Error encrypting message', err);
    alert('Error encrypting message: ' + err.message);
  }
});

/**
 * Update the contacts list UI.  Renders each friend as a clickable
 * list item.  Highlights the currently active chat.  Clicking a
 * contact will select it, display their name in the chat header
 * and render the message history for that contact.
 */
function updateContactsList() {
  contactsList.innerHTML = '';
  const query = (contactSearchInput?.value || '').toLowerCase();
  // Create sortable array of [username, info] pairs
  const sortable = [];
  friends.forEach((info, uname) => {
    sortable.push([uname, info]);
  });
  // Sort by last message timestamp (descending)
  sortable.sort((a, b) => {
    const [ua] = a;
    const [ub] = b;
    const msgsA = messagesByFriend.get(ua) || [];
    const msgsB = messagesByFriend.get(ub) || [];
    const tsA = msgsA.length ? (msgsA[msgsA.length - 1].timestamp || 0) : 0;
    const tsB = msgsB.length ? (msgsB[msgsB.length - 1].timestamp || 0) : 0;
    return tsB - tsA;
  });
  for (const [uname, info] of sortable) {
    if (query && !uname.toLowerCase().includes(query)) continue;
    const li = document.createElement('li');
    li.className = 'p-2 rounded cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-700 flex flex-col';
    // Highlight active friend
    if (currentFriend === uname) {
      li.classList.add('bg-blue-100', 'dark:bg-blue-900');
    }
    // Top row: name and time/unread
    const topRow = document.createElement('div');
    topRow.className = 'flex justify-between items-center';
    const nameSpan = document.createElement('span');
    nameSpan.textContent = uname;
    nameSpan.className = 'font-medium';
    topRow.appendChild(nameSpan);
    const rightInfo = document.createElement('div');
    rightInfo.className = 'flex items-center space-x-2';
    // Last message time
    const msgs = messagesByFriend.get(uname) || [];
    if (msgs.length > 0) {
      const last = msgs[msgs.length - 1];
      const time = last.timestamp ? new Date(last.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
      if (time) {
        const timeSpan = document.createElement('span');
        timeSpan.textContent = time;
        timeSpan.className = 'text-xs text-gray-500 dark:text-gray-400';
        rightInfo.appendChild(timeSpan);
      }
    }
    // Unread badge
    const unread = unreadCounts.get(uname) || 0;
    if (unread > 0) {
      const badge = document.createElement('span');
      badge.textContent = unread;
      badge.className = 'inline-block px-2 py-0.5 text-xs rounded-full bg-red-500 text-white';
      rightInfo.appendChild(badge);
    }
    topRow.appendChild(rightInfo);
    li.appendChild(topRow);
    // Second row: last message snippet
    if (msgs.length > 0) {
      const last = msgs[msgs.length - 1];
      let snippet;
      if (last.type === 'image') {
        snippet = '📷 Image';
      } else {
        snippet = last.text || '';
        if (snippet.length > 40) snippet = snippet.slice(0, 37) + '...';
      }
      const snippetSpan = document.createElement('span');
      snippetSpan.textContent = snippet;
      snippetSpan.className = 'text-xs text-gray-600 dark:text-gray-400 truncate mt-1';
      li.appendChild(snippetSpan);
    }
    li.addEventListener('click', () => {
      // Reset unread count for this friend
      unreadCounts.set(uname, 0);
      selectFriend(uname);
    });
    contactsList.appendChild(li);
  }
  // Also refresh the requests list to keep badge and highlights in sync
  updateRequestsList();
}

/**
 * Update the requests list UI.  Renders each unknown sender as a clickable
 * list item.  Shows the number of pending senders in the badge.  Clicking
 * a request selects that request conversation, displays messages and shows
 * accept/decline actions.
 */
function updateRequestsList() {
  // Determine if there are any requests
  const numRequests = requestsMessagesByUser.size;
  if (numRequests === 0) {
    // Hide the requests container and badge
    if (requestsContainer) requestsContainer.classList.add('hidden');
    if (requestsBadge) requestsBadge.classList.add('hidden');
    return;
  }
  // Show container
  if (requestsContainer) requestsContainer.classList.remove('hidden');
  // Update badge with number of request senders
  if (requestsBadge) {
    requestsBadge.textContent = String(numRequests);
    requestsBadge.classList.remove('hidden');
  }
  // Clear existing list
  requestsList.innerHTML = '';
  // Create sortable array based on last message time
  const entries = Array.from(requestsMessagesByUser.entries());
  entries.sort((a, b) => {
    const msgsA = a[1];
    const msgsB = b[1];
    const tsA = msgsA.length ? (msgsA[msgsA.length - 1].timestamp || 0) : 0;
    const tsB = msgsB.length ? (msgsB[msgsB.length - 1].timestamp || 0) : 0;
    return tsB - tsA;
  });
  entries.forEach(([uname, msgs]) => {
    const li = document.createElement('li');
    li.className = 'p-2 rounded cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-700 flex flex-col';
    // Highlight if this request is active
    if (currentFriend === uname && !friends.has(uname)) {
      li.classList.add('bg-blue-100', 'dark:bg-blue-900');
    }
    // Top row: name and time/unread
    const topRow = document.createElement('div');
    topRow.className = 'flex justify-between items-center';
    const nameSpan = document.createElement('span');
    nameSpan.textContent = uname;
    nameSpan.className = 'font-medium';
    topRow.appendChild(nameSpan);
    const rightInfo = document.createElement('div');
    rightInfo.className = 'flex items-center space-x-2';
    // Last message time
    if (msgs.length > 0) {
      const last = msgs[msgs.length - 1];
      const time = last.timestamp ? new Date(last.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
      if (time) {
        const timeSpan = document.createElement('span');
        timeSpan.textContent = time;
        timeSpan.className = 'text-xs text-gray-500 dark:text-gray-400';
        rightInfo.appendChild(timeSpan);
      }
    }
    // Unread badge
    const unread = requestsUnreadCounts.get(uname) || 0;
    if (unread > 0) {
      const badge = document.createElement('span');
      badge.textContent = unread;
      badge.className = 'inline-block px-2 py-0.5 text-xs rounded-full bg-red-500 text-white';
      rightInfo.appendChild(badge);
    }
    topRow.appendChild(rightInfo);
    li.appendChild(topRow);
    // Second row: last message snippet
    if (msgs.length > 0) {
      const last = msgs[msgs.length - 1];
      let snippet;
      if (last.type === 'image') {
        snippet = '📷 Image';
      } else {
        snippet = last.text || '';
        if (snippet.length > 40) snippet = snippet.slice(0, 37) + '...';
      }
      const snippetSpan = document.createElement('span');
      snippetSpan.textContent = snippet;
      snippetSpan.className = 'text-xs text-gray-600 dark:text-gray-400 truncate mt-1';
      li.appendChild(snippetSpan);
    }
    li.addEventListener('click', () => {
      // Reset unread count for this request
      requestsUnreadCounts.set(uname, 0);
      currentFriend = uname;
      activeChatName.textContent = uname;
      // Show accept/decline buttons and disable input
      if (requestActions) requestActions.classList.remove('hidden');
      sendChatBtn.disabled = true;
      chatInput.disabled = true;
      chatInput.placeholder = 'Accept request to reply';
      renderMessages(uname);
      updateRequestsList();
    });
    requestsList.appendChild(li);
  });
}

/**
 * Select a friend as the active chat.  Updates the current
 * conversation, loads any persisted messages from the server and
 * renders them.  If the conversation includes messages that this
 * user sent, they cannot be decrypted (because they were encrypted
 * for the recipient).  These will be displayed as a placeholder.
 * @param {string} friend
 */
async function selectFriend(friend) {
  currentFriend = friend;
  activeChatName.textContent = friend;
  // Determine if this is a known friend or a request
  const isFriend = friends.has(friend);
  // Update UI for contacts and requests accordingly
  updateContactsList();
  updateRequestsList();
  if (!isFriend) {
    // Request: show accept/decline buttons, disable sending
    if (requestActions) requestActions.classList.remove('hidden');
    sendChatBtn.disabled = true;
    chatInput.disabled = true;
    chatInput.placeholder = 'Accept request to reply';
    renderMessages(friend);
    return;
  }
  // Friend: hide request actions and enable sending
  if (requestActions) requestActions.classList.add('hidden');
  sendChatBtn.disabled = false;
  chatInput.disabled = false;
  chatInput.placeholder = 'Type a message...';
  // Fetch conversation history from the server
  try {
    const res = await fetch(
      `${serverUrl}/api/messages?user1=${encodeURIComponent(username)}&user2=${encodeURIComponent(friend)}`
    );
    const data = await res.json();
    if (!res.ok) {
      console.error(data.error);
      // Even if the request fails, render any local messages
      renderMessages(friend);
      return;
    }
    const history = [];
    for (const msg of data) {
      if (msg.from === username) {
        history.push({ from: username, text: '(sent message)' });
        continue;
      }
      try {
        const messageObj = await openpgp.message.readArmored(msg.ciphertext);
        const decrypted = await openpgp.decrypt({
          message: messageObj,
          privateKeys: [privateKey],
        });
        history.push({ from: msg.from, text: decrypted.data });
      } catch (err) {
        console.error('Error decrypting message from history', err);
      }
    }
    messagesByFriend.set(friend, history);
    renderMessages(friend);
  } catch (err) {
    console.error('Error fetching conversation', err);
    renderMessages(friend);
  }
}

/**
 * Render the conversation with a given friend.  Clears the chat
 * messages container and displays each message as a styled bubble.
 * Incoming messages appear on the left; outgoing messages on the right.
 * @param {string} friend
 */
function renderMessages(friend) {
  chatMessages.innerHTML = '';
  // Use messages from friends map or requests map depending on relationship
  let msgs;
  if (friends.has(friend)) {
    msgs = messagesByFriend.get(friend) || [];
  } else {
    msgs = requestsMessagesByUser.get(friend) || [];
  }
  msgs.forEach((msg) => {
    const { from, type = 'text', text = '', dataUrl = '', filename = '', timestamp, verified } = msg;
    // Container for each message to align timestamp and bubble
    const wrapper = document.createElement('div');
    wrapper.classList.add('flex', 'flex-col', 'w-full');
    if (from === username) {
      wrapper.classList.add('items-end');
    } else {
      wrapper.classList.add('items-start');
    }
    // Message bubble
    const bubble = document.createElement('div');
    // Message bubble styling: larger padding, rounded corners
    bubble.classList.add('px-4', 'py-3', 'max-w-md', 'rounded-2xl', 'break-words');
    if (from === username) {
      bubble.classList.add('bg-blue-500', 'text-white');
    } else {
      bubble.classList.add('bg-gray-200', 'dark:bg-gray-700', 'text-gray-900', 'dark:text-gray-100');
    }
    if (type === 'image') {
      // Display image in bubble
      const img = document.createElement('img');
      img.src = dataUrl;
      img.alt = filename || 'Image';
      img.classList.add('max-w-full', 'rounded-lg');
      bubble.appendChild(img);
    } else {
      bubble.textContent = text;
    }
    // Metadata row
    const meta = document.createElement('div');
    meta.classList.add('mt-1', 'flex', 'items-center', 'space-x-1', 'text-xs');
    const timeSpan = document.createElement('span');
    const date = timestamp ? new Date(timestamp) : new Date();
    timeSpan.textContent = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    timeSpan.classList.add('text-gray-500', 'dark:text-gray-400');
    meta.appendChild(timeSpan);
    // Verification indicator
    if (from !== username) {
      const verSpan = document.createElement('span');
      if (verified === false) {
        verSpan.textContent = '⚠️';
        verSpan.title = 'Signature could not be verified';
      } else {
        verSpan.textContent = '✅';
        verSpan.title = 'Signature verified';
      }
      meta.appendChild(verSpan);
    }
    wrapper.appendChild(bubble);
    wrapper.appendChild(meta);
    chatMessages.appendChild(wrapper);
  });
  // Scroll to bottom after rendering
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

/**
 * Persist the current message history to local storage.  Saves
 * conversations under a key specific to the current user.  Only
 * messagesByFriend is persisted (excluding public keys and other
 * state).  Timestamps and verification flags are included.
 */
function saveLocalHistory() {
  if (!username) return;
  const obj = {};
  messagesByFriend.forEach((msgs, friend) => {
    obj[friend] = msgs;
  });
  try {
    localStorage.setItem(`pgpHistory_${username}`, JSON.stringify(obj));
  } catch (err) {
    console.error('Error saving local history', err);
  }
  saveRequests();
}

/**
 * Load message history from local storage into messagesByFriend.
 * Unread counts are reset.  Should be called after a successful
 * registration or login.  If no history exists, nothing happens.
 */
function loadLocalHistory() {
  if (!username) return;
  try {
    const dataStr = localStorage.getItem(`pgpHistory_${username}`);
    if (dataStr) {
      const data = JSON.parse(dataStr);
      for (const friend in data) {
        messagesByFriend.set(friend, data[friend]);
        unreadCounts.set(friend, 0);
      }
      updateContactsList();
    }
  } catch (err) {
    console.error('Error loading local history', err);
  }
  loadRequests();
}

/**
 * Persist request messages and unread counts to local storage.  Requests are
 * stored separately from normal message history under keys specific to the
 * current user.  This is called automatically from saveLocalHistory().
 */
function saveRequests() {
  if (!username) return;
  const obj = {};
  requestsMessagesByUser.forEach((msgs, user) => {
    obj[user] = msgs;
  });
  try {
    localStorage.setItem(`pgpRequests_${username}`, JSON.stringify(obj));
    const counts = {};
    requestsUnreadCounts.forEach((count, user) => {
      counts[user] = count;
    });
    localStorage.setItem(`pgpRequestsUnread_${username}`, JSON.stringify(counts));
  } catch (err) {
    console.error('Error saving request history', err);
  }
}

/**
 * Load request messages and unread counts from local storage.  Called after
 * registration or login to restore any pending message requests.
 */
function loadRequests() {
  if (!username) return;
  try {
    const dataStr = localStorage.getItem(`pgpRequests_${username}`);
    if (dataStr) {
      const data = JSON.parse(dataStr);
      for (const user in data) {
        requestsMessagesByUser.set(user, data[user]);
      }
    }
    const countsStr = localStorage.getItem(`pgpRequestsUnread_${username}`);
    if (countsStr) {
      const counts = JSON.parse(countsStr);
      for (const user in counts) {
        requestsUnreadCounts.set(user, counts[user]);
      }
    }
    updateRequestsList();
  } catch (err) {
    console.error('Error loading request history', err);
  }
}

// Allow pressing Enter in the message input to send
chatInput.addEventListener('keyup', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendChatBtn.click();
  }
});

// Accept a request: add the sender as a friend and move messages to normal history
acceptRequestBtn?.addEventListener('click', async () => {
  const requester = currentFriend;
  if (!requester) return;
  try {
    // Fetch the sender's public key from the server
    const res = await fetch(`${serverUrl}/api/users/${encodeURIComponent(requester)}`);
    const data = await res.json();
    if (!res.ok) {
      alert(data.error || 'Failed to fetch user info');
      return;
    }
    // Add to friends and messages
    friends.set(requester, { publicKeyArmored: data.publicKey });
    // Move messages from requests to normal history
    const reqMsgs = requestsMessagesByUser.get(requester) || [];
    messagesByFriend.set(requester, reqMsgs);
    requestsMessagesByUser.delete(requester);
    requestsUnreadCounts.delete(requester);
    // Persist
    saveLocalHistory();
    // Reset state
    currentFriend = requester;
    // Update UI
    if (requestActions) requestActions.classList.add('hidden');
    sendChatBtn.disabled = false;
    chatInput.disabled = false;
    chatInput.placeholder = 'Type a message...';
    updateContactsList();
    updateRequestsList();
    renderMessages(requester);
  } catch (err) {
    console.error('Error accepting request', err);
    alert('Error accepting request: ' + err.message);
  }
});

// Decline a request: remove the request and messages
declineRequestBtn?.addEventListener('click', () => {
  const requester = currentFriend;
  if (!requester) return;
  // Remove request messages and counts
  requestsMessagesByUser.delete(requester);
  requestsUnreadCounts.delete(requester);
  // Persist
  saveRequests();
  // Reset UI
  currentFriend = null;
  activeChatName.textContent = '';
  chatMessages.innerHTML = '';
  if (requestActions) requestActions.classList.add('hidden');
  sendChatBtn.disabled = true;
  chatInput.disabled = true;
  chatInput.placeholder = '';
  updateRequestsList();
});

/**
 * Establish a Socket.IO connection to the configured server and set
 * up event handlers for incoming messages.  Uses the global
 * `username`, `privateKey`, and `serverUrl` variables.  Should be
 * called after a successful registration or login.
 */
function connectSocket() {
  // Disconnect existing socket if any
  if (socket) {
    try {
      socket.disconnect();
    } catch (_) {
      /* ignore */
    }
  }
  // Indicate connecting status
  if (statusDot && statusLabel) {
    statusDot.classList.remove('bg-red-500', 'bg-green-500');
    statusDot.classList.add('bg-yellow-400');
    statusLabel.textContent = 'Connecting…';
  }
  socket = io(serverUrl);
  socket.on('connect', () => {
    console.log('Socket connected');
    if (statusDot && statusLabel) {
      statusDot.classList.remove('bg-red-500', 'bg-yellow-400');
      statusDot.classList.add('bg-green-500');
      statusLabel.textContent = 'Online';
    }
    socket.emit('registerUsername', username);
  });
  socket.on('disconnect', () => {
    console.log('Socket disconnected');
    if (statusDot && statusLabel) {
      statusDot.classList.remove('bg-green-500', 'bg-yellow-400');
      statusDot.classList.add('bg-red-500');
      statusLabel.textContent = 'Offline';
    }
  });
  socket.on('connect_error', () => {
    console.log('Socket connection error');
    if (statusDot && statusLabel) {
      statusDot.classList.remove('bg-green-500', 'bg-yellow-400');
      statusDot.classList.add('bg-red-500');
      statusLabel.textContent = 'Offline';
    }
  });
  socket.on('message', async (msg) => {
    try {
      const from = msg.from;
      const msgType = msg.type || 'text';
      const timestamp = msg.timestamp || Date.now();
      // Read and decrypt the message
      const messageObj = await openpgp.message.readArmored(msg.ciphertext);
      const opts = { message: messageObj, privateKeys: [privateKey] };
      // If the sender is a known friend, include their public key for signature verification
      if (friends.has(from)) {
        const senderInfo = friends.get(from);
        if (senderInfo && senderInfo.publicKeyArmored) {
          try {
            const senderPubKeys = (await openpgp.key.readArmored(senderInfo.publicKeyArmored)).keys;
            opts.publicKeys = senderPubKeys;
          } catch (e) {
            // ignore failure to parse sender key
          }
        }
      }
      const decrypted = await openpgp.decrypt(opts);
      const plaintext = decrypted.data;
      let verified = true;
      if (decrypted.signatures && decrypted.signatures.length > 0) {
        try {
          const sigResult = decrypted.signatures[0];
          if (sigResult.verified) {
            verified = await sigResult.verified;
          }
        } catch (err) {
          verified = false;
        }
      }
      // Determine whether this is a friend or a request
      const isFriend = friends.has(from);
      let entry;
      if (msgType === 'image') {
        // Parse the JSON payload for image
        let imageData = null;
        try {
          imageData = JSON.parse(plaintext);
        } catch (e) {
          console.error('Failed to parse image payload', e);
        }
        const { dataUrl = '', filename = '' } = imageData || {};
        entry = { from, type: 'image', dataUrl, filename, timestamp, verified };
      } else {
        // Plain text message
        entry = { from, type: 'text', text: plaintext, timestamp, verified };
      }
      if (isFriend) {
        // Existing friend: append to friend history
        if (!messagesByFriend.has(from)) {
          messagesByFriend.set(from, []);
        }
        messagesByFriend.get(from).push(entry);
        if (currentFriend !== from) {
          const count = unreadCounts.get(from) || 0;
          unreadCounts.set(from, count + 1);
        }
        saveLocalHistory();
        updateContactsList();
        if (currentFriend === from) {
          renderMessages(currentFriend);
        }
      } else {
        // Unknown sender: treat as request
        if (!requestsMessagesByUser.has(from)) {
          requestsMessagesByUser.set(from, []);
        }
        requestsMessagesByUser.get(from).push(entry);
        if (currentFriend !== from) {
          const c = requestsUnreadCounts.get(from) || 0;
          requestsUnreadCounts.set(from, c + 1);
        }
        saveRequests();
        updateRequestsList();
        if (currentFriend === from) {
          renderMessages(currentFriend);
        }
      }
    } catch (err) {
      console.error('Error handling incoming message', err);
    }
  });
}