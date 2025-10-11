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
