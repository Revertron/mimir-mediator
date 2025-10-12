# Mediator (Alpha) — Group Chat Backend for Mimir Messenger

`mimir-mediator` is the experimental alpha implementation of a **multi-user chat room server** for [Mimir Messenger](https://github.com/Revertron/Mimir).  
It provides decentralized group chat functionality over the **Yggdrasil network**, using **yggquic** as its QUIC-based transport layer.

---

## ✨ Features

- Multi-room, multi-user chat support.
- Authenticated connections using Ed25519 public keys.
- Per-room permissions (owner, admin, moderator, user, read-only, banned).
- Persistent storage via `modernc.org/sqlite`.
- Live message broadcasting to connected subscribers.
- Cryptographic verification of signed requests.
- Automatic creation and deletion of per-chat tables.
- Safe concurrent handling of many users and chats.

---

## 🧱 Dependencies

- Go ≥ 1.22
- Revertron's fork of `github.com/Revertron/yggquic`
- `modernc.org/sqlite`
- `github.com/yggdrasil-network/yggdrasil-go/src/core`

---

## ⚙️ Build instructions

```bash
git clone https://github.com/Revertron/mimir-mediator.git
cd mediator
go mod init mediator
go get modernc.org/sqlite
go get github.com/Revertron/yggquic
go get github.com/yggdrasil-network/yggdrasil-go/src/core
go build -o mediator mediator.go
```
You’ll end up with a binary named `mediator`.

---

## 🚀 Running

The mediator requires one or more **Yggdrasil peer endpoints** for bootstrapping:

```bash
./mediator -peer tcp://203.0.113.5:12345 -peer tcp://203.0.113.6:12345
```

At first run, it will:

* Generate a persistent Ed25519 keypair (`mediator.key`).
* Create a SQLite database (`mediator.db`).
* Launch a Yggdrasil node and begin accepting QUIC client connections.

You’ll see log output with your public key prefix (for debugging).

---

## 🧩 Database schema

### Global tables

| Table                                 | Purpose                            |
| ------------------------------------- | ---------------------------------- |
| `nonces(pubkey, nonce, ts)`           | Nonces used during authentication. |
| `chats(id, owner_pubkey, created_at)` | Registry of all chat rooms.        |

### Per-chat tables

Each chat room `id` has its own three tables:

| Table           | Purpose                                                       |
| --------------- | ------------------------------------------------------------- |
| `settings-{id}` | Room metadata (name, description, avatar, permissions).       |
| `users-{id}`    | Members list and their roles (owner/admin/mod/user/readonly). |
| `messages-{id}` | Stored messages (id, timestamp, blob, author).                |

---

## 🔐 Authentication

1. Client sends **GET_NONCE(pubkey)** → receives random 32-byte nonce.
2. Client signs this nonce using **Ed25519.Sign(priv, nonce)**.
3. Client sends **AUTH(pubkey, nonce, signature)** → if valid, session becomes authenticated.

Signatures must satisfy:

* Valid Ed25519 signature
* First two signature bytes are zero (`sig[0]==0 && sig[1]==0`)

Nonces are stored in the DB and can be purged daily.

---

## 🧾 Protocol overview

Each request/response is a framed binary packet.

### Request

```
[version:1=0x01][cmd:1][reqId:2][len:4][payload:len]
```

### Response

```
[status:1][reqId:2][len:4][payload:len]
```

### Status codes

| Value  | Meaning |
| ------ | ------- |
| `0x00` | OK      |
| `0x01` | Error   |

---

## 🧠 Commands summary

| Cmd                   | Code | Direction | Description                                     |
| --------------------- | ---- | --------- | ----------------------------------------------- |
| `GET_NONCE`           | 0x01 | C→S       | Request a new nonce for authentication.         |
| `AUTH`                | 0x02 | C→S       | Authenticate with pubkey + signature.           |
| `CREATE_CHAT`         | 0x10 | C→S       | Create a new chat (signed over `nonce+key`).    |
| `DELETE_CHAT`         | 0x11 | C→S       | Delete owned chat.                              |
| `ADD_USER`            | 0x20 | C→S       | Add a user to an existing chat.                 |
| `DELETE_USER`         | 0x21 | C→S       | Ban/remove user from chat.                      |
| `LEAVE_CHAT`          | 0x22 | C→S       | User leaves chat (deleted from users table).    |
| `GET_USER_CHATS`      | 0x23 | C→S       | List all chats user belongs to (not banned).    |
| `SEND_MESSAGE`        | 0x30 | C→S       | Send encrypted message blob to chat.            |
| `DELETE_MESSAGE`      | 0x31 | C→S       | Delete message (admin/mod only).                |
| `GET_MESSAGE`         | 0x32 | C→S       | Retrieve one message by ID.                     |
| `GET_LAST_MESSAGE_ID` | 0x33 | C→S       | Query the latest message ID.                    |
| `GOT_MESSAGE`         | 0x34 | S→C       | Server-pushed new message notification.         |
| `SUBSCRIBE`           | 0x35 | C→S       | Subscribe connection to live updates of a chat. |

---

## 🧩 Permissions bitmask

| Bit    | Name           | Meaning                      |
| ------ | -------------- | ---------------------------- |
| `0x80` | `permOwner`    | Chat creator, full control.  |
| `0x40` | `permAdmin`    | Administrative privileges.   |
| `0x20` | `permMod`      | Can moderate users/messages. |
| `0x10` | `permUser`     | Regular participant.         |
| `0x08` | `permReadOnly` | May only read, not post.     |
| `0x01` | `permBanned`   | User is banned from chat.    |

---

## 🛰️ Message broadcasting

When a user sends a message:

1. It’s inserted into the `messages-{id}` table.
2. The server broadcasts the message to all connected subscribers of that chat (except sender).
3. Subscribers receive it immediately with:

   ```
   [statusOK][reqId=0][len][payload=[msg_id][msg_len][msg_blob]]
   ```
4. This happens asynchronously.

---

## 🧹 Connection lifecycle

* On connect: client sends `protoClient` byte (`0x00`).
* On disconnect: the server automatically unsubscribes the user from all subscribed chats.
* On Ctrl+C: server closes cleanly (SQLite + Yggdrasil node shutdown).

---

## ⚠️ Limitations (Alpha)

* No message encryption on server-side (payloads are stored raw as encrypted blobs from clients).
* No TTL cleanup for old nonces (to be added).
* No user nickname or text rank logic implemented yet.
* Owner cannot leave their own chat (must delete instead).
* No system messages for join/leave/banned actions (TODO markers present).

---

## 🧰 File structure

| File           | Purpose                         |
| -------------- | ------------------------------- |
| `mediator.go`  | Full server implementation.     |
| `mediator.db`  | SQLite database (auto-created). |
| `mediator.key` | Server Ed25519 keypair.         |

---

## 🧩 Example workflow

1. **Authenticate:**

    * `GET_NONCE(pubkey)`
    * `AUTH(pubkey, nonce, signature)`

2. **Create chat:**

    * `CREATE_CHAT(owner_pubkey, nonce, key, signature, name, desc, avatar)`

3. **Invite users:**

    * `ADD_USER(chat_id, pubkey)`

4. **Subscribe to messages:**

    * `SUBSCRIBE(chat_id)`

5. **Send and receive messages:**

    * `SEND_MESSAGE(chat_id, blob)`
    * Receive live updates via `GOT_MESSAGE`.

6. **Leave chat:**

    * `LEAVE_CHAT(chat_id)`

7. **Query chats:**

    * `GET_USER_CHATS()`

---

## 🧪 Development notes

* `requestId` (u16) is echoed in every response, allowing pipelined async requests.
* Max payload size: 32 MB.
* SQLite WAL mode is used for better concurrency.
* Designed to be embedded into Yggdrasil-based distributed messengers.

---

## 📜 License

MIT License © 2025 [Revertron](https://github.com/Revertron)
Use freely with attribution. This software is experimental and provided **as is**.