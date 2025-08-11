# Messenger‑PGP App

This is a simple proof‑of‑concept chat application that uses PGP encryption on the client to provide end‑to‑end privacy.  It demonstrates how you can layer automatic encryption/decryption on top of a real‑time messaging backend.  Messages are encrypted with the recipient’s public key and decrypted locally using the sender’s private key, so the server never sees plaintext.

## Structure

```
messenger-pgp-app/
  backend/
    package.json      # lists server dependencies (express, socket.io)
    server.js         # simple Express + Socket.io relay server
  frontend/
    index.html        # user interface with registration, contacts and chat
    app.js            # client‑side logic using openpgp.js and socket.io
```

## Running the backend

You need Node.js installed.  Change into the `backend` folder and install dependencies:

```bash
cd messenger-pgp-app/backend
npm install
node server.js
```

This starts an Express server on port `3001` that exposes endpoints to register users and look up public keys.  It also runs a Socket.io server used for real‑time message delivery.

> **Note**: In the latest version the backend also serves the static frontend.  If you access the root of the server (`http://127.0.0.1:3001`) in your browser you’ll see the chat UI without needing a separate Python server.  This makes it easier to deploy behind a Tor hidden service because only a single port is exposed.

## Running the frontend

The frontend is completely static and is now served by the Node backend.  After starting the server as shown above, open your browser and go to:

```
http://127.0.0.1:3001/
```

The registration panel allows you to:

* **Enter a username.**  Your username is tied to your public key on the server.
* **Optionally specify a passphrase.**  If left blank your private key will be generated unencrypted.  You can still import an encrypted key from a file or from the text area.
* **Specify the server URL.**  The default is `http://127.0.0.1:3001`, but you can point it to a remote server or a Tor `.onion` address.
* **Generate a new key pair** or **import an existing private key** from a file or by pasting it into the text area.  If you import a key, the corresponding public key is derived automatically.
* **Register** or **log in**.  Registration uploads your username and public key to the server.  Logging in fetches the stored public key and verifies that your derived public key matches it.

After registering/logging in you’ll see your fingerprint, an option to copy your public key, and a list of contacts and pending message requests.  You can add contacts by username, accept or decline message requests, and exchange messages.  Messages are encrypted with your friends’ public keys and decrypted locally using your private key.

You can also **send and receive images**.  Click the camera icon in the chat bar to select an image (up to 2 MB).  The image is read as a Data URL, encrypted with PGP and sent as a message of type `image`.  On the receiving side the client decrypts the payload, extracts the data URL and displays the image inline.  Image messages show a camera icon in the contact list.

all conversations are stored encrypted on the server.  Locally, message history is cached in your browser’s storage so you can reload the page without losing past chats.  Signature verification badges indicate whether a message has a valid signature from the purported sender.

## Tor hidden services and obfs4 bridges

To protect your IP address and improve censorship resistance you can run the backend as a Tor hidden service and use an obfs4 bridge to connect to the Tor network.  The general idea is to expose only a single port (our Node server) as a hidden service and then connect to it via Tor Browser.

### 1. Install Tor and obfs4proxy

Ensure Tor is installed on your system.  On Linux you can install `tor` and the obfuscation transport with:

```bash
sudo apt install tor obfs4proxy
```

On Windows, install **Tor Browser** and leave it running.  For advanced setups you can install the **Tor Expert Bundle** and `obfs4proxy.exe`.

### 2. Configure the server as a hidden service

Edit your `torrc` (located in `%APPDATA%\tor\torrc` on Windows or `/etc/tor/torrc` on Linux) and add the following lines:

```
# Expose the messenger backend as a hidden service on port 80
HiddenServiceDir /path/to/hidden_service/
HiddenServicePort 80 127.0.0.1:3001

## Use the obfs4 pluggable transport for this client
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
```

After restarting Tor, a file named `hostname` will appear in `HiddenServiceDir`.  It contains your new `.onion` address.  Copy this address and set it as the **Server URL** in the registration panel.

If you are behind a network that blocks Tor, you will need to use an **obfs4 bridge** to connect.  Bridges make Tor traffic look like random bytes.  You can request bridges from the Tor Project or run your own.  To configure a bridge, append lines like the following to your `torrc`:

```
# Example obfs4 bridge line (replace IP, port and fingerprint)
Bridge obfs4 121.32.16.102:9020 LCJCJDTPPLPPWMCNNKLEMSGETQLSCMDWSYGTKLFL cert=OeGVmoMzOvI5QyYNyotNZUvWkEirSfMoL0U51BxpgyZwpnpfFYhpovYnTmaWh3oq7c/m2o iat-mode=0
```

This format is described in the Tor documentation: you install `obfs4proxy`, set `ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy` (for servers) and configure `Bridge obfs4` lines with your bridge’s IP, port, fingerprint and certificate【105258575999821†L222-L272】.  On the client side you enable bridges with `UseBridges 1` and specify your bridge lines.

### 3. Serve the frontend from the backend

In this version the Node backend serves the static frontend.  You can now access your messenger at:

```
http://<your-onion-address>
```

in Tor Browser.  The UI includes a **Server URL** field where you can paste the `.onion` address.  All API requests and WebSocket connections will then route through Tor.

### 4. Limitations

While this project demonstrates end‑to‑end encryption and introduces Tor hidden services, it remains a proof of concept.  It does **not** implement authentication beyond verifying that a provided private key matches the stored public key.  Use strong passphrases if you encrypt your private key, and be aware that an attacker who compromises your device could extract your key.  Always run Tor Browser to connect to `.onion` addresses.

## Security notice

This example is **not ready for production**.  It lacks proper multi‑factor authentication, key revocation, forward secrecy and many other features needed for a secure messenger.  It is intended to illustrate how OpenPGP can be integrated into a chat application so that encryption and decryption happen locally without user intervention.  Use at your own risk. That said it is fully open source so you welcome to check stuff for yourself.
