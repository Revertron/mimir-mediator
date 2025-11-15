// mediator.go
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"mediator/hybridcache"
	//"net"
	"os"
	"os/signal"
	"path/filepath"
	//"strings"
	"sync"
	"time"

	"crypto/tls"

	_ "modernc.org/sqlite"

	"github.com/Revertron/yggquic"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

/*
Networking overview (client protocol, similar feel to tracker.go):

- First byte on connection: 0x00 = client protocol selector (protoClient).
- After that, each request is a frame:
    [version:1=0x01][cmd:1][len:4 big-endian][payload:len]
- Server replies:
    [status:1 (0=OK,1=ERR)][len:4][payload]

Common binary atoms:
- pubkey: 32 bytes
- signature: 64 bytes
- u64/u32/u16: big-endian
- string: [u16 len][bytes...]
- blob: [u32 len][bytes...]

Commands (cmd codes):
 0x01 GET_NONCE(pubkey) -> OK: nonce(32)
 0x02 AUTH(pubkey, nonce(32), signature(64)) -> OK
 0x10 CREATE_CHAT(owner_pubkey(32), nonce(32), counter(4), signature(64),
                  name(string<=20), description(string<=200), avatar(blob<=200KB))
         -> OK: chat_id(u64)
         (signature is over nonce||counter, must satisfy sig[0]==0 && sig[1]==0)
 0x11 DELETE_CHAT(chat_id(u64), owner_pubkey, nonce(string), signature(64)) -> OK: 1 byte (0/1)
 0x20 ADD_USER(chat_id(u64), user_pubkey(32)) -> OK
 0x21 DELETE_USER(chat_id(u64), user_pubkey(32)) -> OK
 0x30 SEND_MESSAGE(chat_id(u64), blob) -> OK: message_id(u64)
 0x31 DELETE_MESSAGE(chat_id(u64), message_id(u64)) -> OK
 0x32 GET_MESSAGE(chat_id(u64), message_id(u64)) -> OK: [message_id(u64)][blob]
 0x33 GET_LAST_MESSAGE_ID(chat_id(u64)) -> OK: last_id(u64)

Authorization:
- GET_NONCE, AUTH: always allowed.
- CREATE_CHAT, DELETE_CHAT: per-parameter nonce/signature (not connection auth strictly required, but typically you will be AUTHed anyway).
- ADD_USER, DELETE_USER, SEND_MESSAGE, DELETE_MESSAGE, GET_MESSAGE, GET_LAST_MESSAGE_ID:
    require authenticated connection; we check the caller's pubkey membership & perms in users-{id}.

Permissions (perms_flags bitmask):
- 0x80 owner
- 0x40 admin
- 0x20 moderator
- 0x10 user
- 0x08 read-only user
- 0x01 banned  (in users-{id} a separate "banned" column exists as well; this bit is maintained too)

Extra schema:
- global table "nonces(pubkey BLOB(32), nonce TEXT, ts INTEGER, PRIMARY KEY(pubkey))"
- global table "chats(id INTEGER PRIMARY KEY, owner_pubkey BLOB(32), created_at INTEGER NOT NULL)"
- settings-{id}(name, description, avatar, perms_flags, created_at, extra JSON)
    - users-{id}(pubkey, nickname, text_rank, perms_flags, accepted_at, changed_at, banned)
- messages-{id}(id INTEGER PK AUTOINCREMENT, ts, blob, author)

Signature rules:
- Ed25519 signature must verify against message = nonce (as bytes of the UTF-8 string)
- Additional constraint: signature’s first 16 bits are zero (sig[0]==0 && sig[1]==0).

Note:
- Nonces are stored; you said daily purge, so no TTL enforced here.
*/

const (
	version     = 1
	protoClient = 0x00

	// commands
	cmdGetNonce          = 0x01
	cmdAuth              = 0x02
	cmdPing              = 0x03
	cmdCreateChat        = 0x10
	cmdDeleteChat        = 0x11
	cmdAddUser           = 0x20
	cmdDeleteUser        = 0x21
	cmdLeaveChat         = 0x22
	cmdGetUserChats      = 0x23
	cmdSendMessage       = 0x30
	cmdDeleteMessage     = 0x31
	cmdGotMessage        = 0x32 // Server sends it to the client after receiving a message from some user.
	cmdGetLastMessageID  = 0x33
	cmdSubscribe         = 0x35
	cmdGetMessagesSince  = 0x36 // NEW: batch fetch messages
	cmdSendInvite        = 0x40
	cmdGotInvite         = 0x41 // Server sends it to the client when delivering an invite.
	cmdInviteResponse    = 0x42 // Client responds to invite (accept/reject)
	cmdUpdateMemberInfo  = 0x50 // Client sends encrypted member info (nickname, info, avatar)
	cmdRequestMemberInfo = 0x51 // Server requests member info from client
	cmdGetMembersInfo    = 0x52 // Client requests all members info
	cmdGetMembers        = 0x53 // Client requests all member pubkeys (lightweight)
	cmdGotMemberInfo     = 0x54 // Server push: member info updated

	// response status
	statusOK  = 0x00
	statusErr = 0x01

	// permission bits
	permOwner    = 0x80
	permAdmin    = 0x40
	permMod      = 0x20
	permUser     = 0x10
	permReadOnly = 0x08
	permBanned   = 0x01

	// system event codes (first byte of system message body)
	// System messages are stored as regular messages with mediator as author
	sysUserAdded      = 0x01
	sysUserEntered    = 0x02 // reserved
	sysUserLeft       = 0x03
	sysUserBanned     = 0x04
	sysChatDeleted    = 0x05
	sysChatInfoChange = 0x06
	sysPermsChanged   = 0x07

	maxNameLen       = 20
	maxDescLen       = 200
	maxAvatarBytes   = 200 * 1024
	dbFile           = "mediator.db"
	keyFile          = "mediator.key"
	selfCertValidHrs = 24
)

type serverState struct {
	db        *sql.DB
	node      *core.Core
	transport *yggquic.YggdrasilTransport
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	authMu    sync.Mutex
	// chatSubscriptions: chatID → set of client connections
	chatMu            sync.RWMutex
	chatSubscriptions map[int64]map[*clientConn]struct{}
	cache             *hybridcache.HybridCache
	// authenticated clients tracking: pubkey → set of client connections (multi-device support)
	authClientsMu        sync.RWMutex
	authenticatedClients map[[32]byte]map[*clientConn]struct{}
}

// connection-scoped state
type clientConn struct {
	conn   *yggquic.Conn
	s      *serverState
	authed bool
	pub    [32]byte
	chats  map[int64]struct{} // chats this client subscribed to
}

func main() {
	var peers []string
	fs := flag.NewFlagSet("mediator", flag.ExitOnError)
	fs.Func("peer", "bootstrap Ygg peers (can be given multiple times)", func(s string) error {
		peers = append(peers, s)
		return nil
	})
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
	if len(peers) == 0 {
		fmt.Fprintf(os.Stderr, "Usage:\n  %s -peer PEER1 [-peer PEER2 ...]\n", os.Args[0])
		os.Exit(1)
	}

	priv := loadOrGenKey()
	pub := priv.Public().(ed25519.PublicKey)

	// Build self-signed cert (short-lived)
	certDER, err := createSelfSignedCert(pub, priv, selfCertValidHrs)
	if err != nil {
		log.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	// Start Yggdrasil core and quic transport
	node, err := core.New(&cert, nil)
	if err != nil {
		log.Fatal(err)
	}
	m, err := yggquic.NewWithNode(node, &cert, peers, 120)
	if err != nil {
		log.Fatal(err)
	}

	// Open SQLite (modernc.org/sqlite)
	if err := os.MkdirAll(filepath.Dir("./"+dbFile), 0700); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`); err != nil {
		log.Fatal(err)
	}
	if err := initGlobalSchema(db); err != nil {
		log.Fatal(err)
	}
	// Migrate per-chat users tables to use changed_at instead of last_perm_change
	migrateUsersChangedAt(db)

	cache, err := hybridcache.NewHybridCache("mediator-cache", 512*1024*1024) // 512 MB RAM/disk hybrid
	if err != nil {
		log.Fatalf("cache init: %v", err)
	}
	defer cache.Close()

	st := &serverState{
		db:                   db,
		node:                 node,
		transport:            m.GetTransport(),
		priv:                 priv,
		pub:                  pub,
		chatSubscriptions:    make(map[int64]map[*clientConn]struct{}),
		cache:                cache,
		authenticatedClients: make(map[[32]byte]map[*clientConn]struct{}),
	}

	log.Printf("mediator started; pubkey: %x", pub[:])
	log.Printf("listening for client requests…")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start periodic invite cleanup
	go st.inviteCleanupWorker(ctx)

	// Ctrl+C
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		log.Println("Shutting down mediator…")
		cancel()
		m.Close()
		db.Close()
	}()

	// Accept loop
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		c, err := m.Accept()
		if err != nil {
			continue
		}
		go st.serveClient(ctx, c)
	}
}

func (s *serverState) serveClient(ctx context.Context, c *yggquic.Conn) {
	defer c.Close()
	log.Printf("[DEBUG] New client connection from %x", c.Public[:])

	// protocol discriminator (like in tracker)
	var disc [1]byte
	if _, err := io.ReadFull(c.Stream, disc[:]); err != nil {
		log.Printf("[DEBUG] Failed to read protocol discriminator: %v", err)
		return
	}
	log.Printf("[DEBUG] Protocol discriminator: 0x%02x (expected 0x%02x)", disc[0], protoClient)
	if disc[0] != protoClient {
		log.Printf("[DEBUG] Invalid protocol discriminator, closing connection")
		return
	}

	cc := &clientConn{conn: c, s: s, chats: make(map[int64]struct{})}
	defer cc.s.unsubscribeAll(cc)
	log.Printf("[DEBUG] Client connection initialized, entering command loop")

	for {
		if err := c.Stream.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			log.Printf("[DEBUG] Failed to set read deadline: %v", err)
			return
		}
		// Frame: [ver][cmd][len u32][payload]
		var hdr [8]byte
		if _, err := io.ReadFull(c.Stream, hdr[:]); err != nil {
			log.Printf("[DEBUG] Failed to read frame header: %v", err)
			return
		}
		if hdr[0] != version {
			log.Printf("[DEBUG] Bad version: got 0x%02x, expected 0x%02x", hdr[0], version)
			_ = cc.writeErr(0, "bad version")
			return
		}
		cmd := hdr[1]
		reqId := binary.BigEndian.Uint16(hdr[2:4])
		plen := binary.BigEndian.Uint32(hdr[4:8])
		log.Printf("[DEBUG] Received command: 0x%02x, reqId=%d, payloadLen=%d", cmd, reqId, plen)
		if plen > (32 << 20) { // 32MB sanity
			log.Printf("[DEBUG] Payload too large: %d bytes", plen)
			_ = cc.writeErr(0, "payload too large")
			return
		}
		payload := make([]byte, plen)
		if _, err := io.ReadFull(c.Stream, payload); err != nil {
			log.Printf("[DEBUG] Failed to read payload: %v", err)
			return
		}

		switch cmd {
		case cmdGetNonce:
			cc.handleGetNonce(reqId, payload)
		case cmdAuth:
			cc.handleAuth(reqId, payload)
		case cmdPing:
			cc.handlePing(reqId)
		case cmdCreateChat:
			cc.handleCreateChat(reqId, payload)
		case cmdDeleteChat:
			cc.handleDeleteChat(reqId, payload)
		case cmdAddUser:
			cc.handleAddUser(reqId, payload)
		case cmdDeleteUser:
			cc.handleDeleteUser(reqId, payload)
		case cmdGetUserChats:
			cc.handleGetUserChats(reqId, payload)
		case cmdLeaveChat:
			cc.handleLeaveChat(reqId, payload)
		case cmdSubscribe:
			cc.handleSubscribe(reqId, payload)
		case cmdGetMessagesSince:
			cc.handleGetMessagesSince(reqId, payload)
		case cmdSendMessage:
			cc.handleSendMessage(reqId, payload)
		case cmdDeleteMessage:
			cc.handleDeleteMessage(reqId, payload)
		case cmdGetLastMessageID:
			cc.handleGetLastMessageID(reqId, payload)
		case cmdSendInvite:
			cc.handleSendInvite(reqId, payload)
		case cmdInviteResponse:
			cc.handleInviteResponse(reqId, payload)
		case cmdUpdateMemberInfo:
			cc.handleUpdateMemberInfo(reqId, payload)
		case cmdGetMembersInfo:
			cc.handleGetMembersInfo(reqId, payload)
		case cmdGetMembers:
			cc.handleGetMembers(reqId, payload)
		default:
			_ = cc.writeErr(0, "unknown cmd")
			return
		}
	}
}

// ---------------- crypto / keys ----------------

func loadOrGenKey() ed25519.PrivateKey {
	if b, err := os.ReadFile(keyFile); err == nil && len(b) == ed25519.PrivateKeySize {
		priv := ed25519.PrivateKey(b)
		log.Printf("Loaded mediator key from %s – private: %x… public: %x", keyFile, priv[:4], priv.Public().(ed25519.PublicKey)[:])
		return priv
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, priv, 0600); err != nil {
		log.Fatal(err)
	}
	log.Printf("Generated new mediator key (saved to %s) – private: %x… public: %x", keyFile, priv[:4], priv.Public().(ed25519.PublicKey)[:])
	return priv
}

func createSelfSignedCert(pub ed25519.PublicKey, priv ed25519.PrivateKey, validHours int) ([]byte, error) {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(validHours) * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	return x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
}

// ---------------- DB schema ----------------

func initGlobalSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS nonces(
  pubkey BLOB(32) PRIMARY KEY,
  nonce  BLOB(32) NOT NULL,
  ts     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chats(
  id           INTEGER PRIMARY KEY,
  owner_pubkey BLOB(32) NOT NULL,
  created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invites(
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp      INTEGER NOT NULL,
  from_pubkey    BLOB(32) NOT NULL,
  to_pubkey      BLOB(32) NOT NULL,
  chat_id        INTEGER NOT NULL,
  encrypted_data BLOB NOT NULL,
  sent           INTEGER NOT NULL DEFAULT 0,
  UNIQUE(to_pubkey, chat_id)
);
`)
	if err != nil {
		return err
	}

	// Best-effort migration for existing databases missing the 'sent' column
	// Ignore error if column already exists.
	_, _ = db.Exec(`ALTER TABLE invites ADD COLUMN sent INTEGER NOT NULL DEFAULT 0`)
	return nil
}

// migrateUsersChangedAt best-effort migration: rename last_perm_change -> changed_at
func migrateUsersChangedAt(db *sql.DB) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'users-%'`)
	if err != nil {
		log.Printf("migration: list users tables failed: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		// Try to rename column; ignore errors (already migrated or old SQLite)
		q := fmt.Sprintf(`ALTER TABLE %q RENAME COLUMN last_perm_change TO changed_at`, name)
		if _, err := db.Exec(q); err != nil {
			// Try creating column if rename failed and changed_at missing
			// This is a noop if column already exists or rename succeeded
			_, _ = db.Exec(fmt.Sprintf(`ALTER TABLE %q ADD COLUMN changed_at INTEGER NOT NULL DEFAULT 0`, name))
		}
	}
}

func chatTableNames(id int64) (settings, users, messages string) {
	settings = fmt.Sprintf("settings-%d", id)
	users = fmt.Sprintf("users-%d", id)
	messages = fmt.Sprintf("messages-%d", id)
	return
}

// generateMessageGuid creates a GUID for system messages using the same
// algorithm as the client: (hash(data) << 32) ^ timestamp
// This matches the Kotlin implementation: data.contentHashCode().toLong() shl 32 xor time
func generateMessageGuid(ts int64, data []byte) int64 {
	// Compute hash similar to Kotlin's ByteArray.contentHashCode()
	hash := int32(1)
	for _, b := range data {
		hash = 31*hash + int32(int8(b))
	}
	return (int64(hash) << 32) ^ ts
}

func rand32() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// leave zeros on RNG failure; still keep length
	}
	return b
}

// broadcastSystemMessage creates, stores, and broadcasts a system message
// If storeInDB is false, only broadcasts without database storage (e.g., for chat deletion)
// Returns the message ID (0 if not stored) and any error
func (s *serverState) broadcastSystemMessage(chatID int64, body []byte, sender *clientConn, storeInDB bool) (int64, error) {
	now := time.Now().Unix()
	guid := generateMessageGuid(now, body)

	var msgID int64
	if storeInDB {
		// Insert into messages table
		msgTbl := fmt.Sprintf("messages-%d", chatID)
		res, err := s.db.Exec(
			fmt.Sprintf(`INSERT INTO %q(ts, guid, author) VALUES(?,?,?)`, msgTbl),
			now, guid, s.pub,
		)
		if err != nil {
			return 0, fmt.Errorf("failed to insert system message: %w", err)
		}
		msgID, _ = res.LastInsertId()

		// Store body in cache
		key := fmt.Sprintf("%016x:%016x", chatID, guid)
		if err := s.cache.Set(key, body, 24*time.Hour); err != nil {
			log.Printf("cache set failed for system message: %v", err)
		}
	}

	// Broadcast as regular message: [chat_id(i64)][msg_id(i64)][guid(i64)][author(32)][blob_len(u32)][blob]
	push := make([]byte, 8+8+8+32+4+len(body))
	off := 0
	binary.BigEndian.PutUint64(push[off:off+8], uint64(chatID))
	off += 8
	binary.BigEndian.PutUint64(push[off:off+8], uint64(msgID))
	off += 8
	binary.BigEndian.PutUint64(push[off:off+8], uint64(guid))
	off += 8
	copy(push[off:off+32], s.pub[:])
	off += 32
	binary.BigEndian.PutUint32(push[off:off+4], uint32(len(body)))
	off += 4
	copy(push[off:], body)

	if sender != nil {
		go s.broadcastMessage(chatID, sender, push)
	} else {
		go s.broadcastToChat(chatID, nil, cmdGotMessage, push)
	}

	return msgID, nil
}

func createChatTables(tx *sql.Tx, id int64) error {
	sett, users, msgs := chatTableNames(id)
	ddl := fmt.Sprintf(`
CREATE TABLE %q(
  name TEXT NOT NULL CHECK(length(name) <= %d),
  description TEXT NOT NULL CHECK(length(description) <= %d),
  avatar BLOB,
  perms_flags INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  extra TEXT
);
CREATE TABLE %q(
  pubkey BLOB(32) PRIMARY KEY,
  text_rank TEXT,
  perms_flags INTEGER NOT NULL,
  accepted_at INTEGER NOT NULL,
  changed_at INTEGER NOT NULL,
  banned INTEGER NOT NULL DEFAULT 0,
  info BLOB
);
CREATE TABLE %q(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  guid INTEGER NOT NULL UNIQUE,
  author BLOB(32) NOT NULL
);
`, sett, maxNameLen, maxDescLen, users, msgs)
	_, err := tx.Exec(ddl)
	return err
}

// ---------------- wire helpers ----------------

func (cc *clientConn) writeOK(requestId uint16, payload []byte) error {
	var hdr [7]byte
	hdr[0] = statusOK
	binary.BigEndian.PutUint16(hdr[1:3], requestId)
	binary.BigEndian.PutUint32(hdr[3:7], uint32(len(payload)))
	if _, err := cc.conn.Stream.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := cc.conn.Stream.Write(payload)
		return err
	}
	return nil
}

func (cc *clientConn) writeErr(requestId uint16, msg string) error {
	log.Printf("[DEBUG] sending error for requestId=%d: %s\n", requestId, msg)
	// payload: [u16 len][bytes]
	b := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(b[0:2], uint16(len(msg)))
	copy(b[2:], []byte(msg))

	var hdr [7]byte
	hdr[0] = statusErr
	binary.BigEndian.PutUint16(hdr[1:3], requestId)
	binary.BigEndian.PutUint32(hdr[3:7], uint32(len(b)))

	if _, err := cc.conn.Stream.Write(hdr[:]); err != nil {
		return err
	}
	_, err := cc.conn.Stream.Write(b)
	return err
}

func rdI64(b []byte, off *int) (int64, error) {
	if *off+8 > len(b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := int64(binary.BigEndian.Uint64(b[*off : *off+8]))
	*off += 8
	return v, nil
}

// Keep rdU64 for timestamps and other unsigned values
func rdU64(b []byte, off *int) (uint64, error) {
	if *off+8 > len(b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint64(b[*off : *off+8])
	*off += 8
	return v, nil
}
func rdU32(b []byte, off *int) (uint32, error) {
	if *off+4 > len(b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint32(b[*off : *off+4])
	*off += 4
	return v, nil
}
func rdU16(b []byte, off *int) (uint16, error) {
	if *off+2 > len(b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint16(b[*off : *off+2])
	*off += 2
	return v, nil
}
func rdBytes(b []byte, off *int, n int) ([]byte, error) {
	if *off+n > len(b) {
		return nil, io.ErrUnexpectedEOF
	}
	v := b[*off : *off+n]
	*off += n
	return v, nil
}
func rdStr(b []byte, off *int) (string, error) {
	if *off+2 > len(b) {
		return "", io.ErrUnexpectedEOF
	}
	l := int(binary.BigEndian.Uint16(b[*off : *off+2]))
	*off += 2
	if *off+l > len(b) {
		return "", io.ErrUnexpectedEOF
	}
	s := string(b[*off : *off+l])
	*off += l
	return s, nil
}
func rdBlob(b []byte, off *int) ([]byte, error) {
	if *off+4 > len(b) {
		return nil, io.ErrUnexpectedEOF
	}
	l := int(binary.BigEndian.Uint32(b[*off : *off+4]))
	*off += 4
	return rdBytes(b, off, l)
}

// ---------------- command handlers ----------------

func (cc *clientConn) handleGetNonce(reqID uint16, p []byte) {
	// payload: pubkey(32)
	off := 0
	raw, err := rdBytes(p, &off, 32)
	if err != nil {
		_ = cc.writeErr(reqID, "bad pubkey")
		return
	}
	var pk [32]byte
	copy(pk[:], raw)

	// generate random 32-byte nonce
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		_ = cc.writeErr(reqID, "rng failure")
		return
	}
	now := time.Now().Unix()

	_, err = cc.s.db.Exec(`INSERT INTO nonces(pubkey, nonce, ts)
		VALUES(?,?,?)
		ON CONFLICT(pubkey) DO UPDATE SET nonce=excluded.nonce, ts=excluded.ts`,
		pk[:], nonce[:], now)
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}

	// response: nonce(32)
	if err := cc.writeOK(reqID, nonce[:]); err != nil {
		log.Printf("[DEBUG] handleGetNonce: writeOK failed: %v", err)
		return
	}
}

func (cc *clientConn) handleAuth(reqID uint16, p []byte) {
	// payload: pubkey(32), nonce(32), signature(64)
	off := 0
	rawpk, err := rdBytes(p, &off, 32)
	if err != nil {
		_ = cc.writeErr(reqID, "bad pubkey")
		return
	}
	nonce, err := rdBytes(p, &off, 32)
	if err != nil {
		_ = cc.writeErr(reqID, "bad nonce")
		return
	}
	sig, err := rdBytes(p, &off, 64)
	if err != nil {
		_ = cc.writeErr(reqID, "bad signature")
		return
	}
	var pk [32]byte
	copy(pk[:], rawpk)

	// check nonce exists
	var dbNonce []byte
	err = cc.s.db.QueryRow(`SELECT nonce FROM nonces WHERE pubkey = ?`, pk[:]).Scan(&dbNonce)
	if err != nil || !equalBytes(dbNonce, nonce) {
		_ = cc.writeErr(reqID, "unknown nonce")
		return
	}
	if !ed25519.Verify(pk[:], nonce, sig) {
		_ = cc.writeErr(reqID, "invalid signature")
		return
	}

	// Delete used nonce to prevent replay and allow new nonces for other operations
	if _, err := cc.s.db.Exec(`DELETE FROM nonces WHERE pubkey=?`, pk[:]); err != nil {
		log.Printf("Warning: failed to delete auth nonce for %x: %v", pk[:4], err)
	}
	log.Printf("[DEBUG] user %x authenticated", pk[:4])

	cc.authed = true
	cc.pub = pk

	// Register this client as authenticated (multi-device support)
	cc.s.authClientsMu.Lock()
	if cc.s.authenticatedClients[pk] == nil {
		cc.s.authenticatedClients[pk] = make(map[*clientConn]struct{})
	}
	cc.s.authenticatedClients[pk][cc] = struct{}{}
	deviceCount := len(cc.s.authenticatedClients[pk])
	cc.s.authClientsMu.Unlock()
	log.Printf("[DEBUG] Registered device for user %x (total devices: %d)", pk[:4], deviceCount)

	// Send OK response first
	_ = cc.writeOK(reqID, nil)

	// Check for and send any pending invites after successful authentication
	go cc.s.sendPendingInvites(cc)
}

func (cc *clientConn) handlePing(reqID uint16) {
	// payload empty
	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleCreateChat(reqID uint16, p []byte) {
	// payload: owner_pubkey(32), nonce(32), counter(4),
	// signature(64) over (nonce||counter),
	// name(str<=20), description(str<=200), avatar(blob<=200k)

	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "not authenticated")
		return
	}

	rawpk, err := rdBytes(p, &off, 32)
	if err != nil {
		_ = cc.writeErr(reqID, "bad owner pubkey")
		return
	}
	if !equalBytes(rawpk, cc.pub[:]) {
		_ = cc.writeErr(reqID, "keys mismatch")
		return
	}

	nonce, err := rdBytes(p, &off, 32)
	if err != nil {
		_ = cc.writeErr(reqID, "bad nonce")
		return
	}
	counter, err := rdBytes(p, &off, 4)
	if err != nil {
		_ = cc.writeErr(reqID, "bad counter")
		return
	}
	sig, err := rdBytes(p, &off, 64)
	if err != nil {
		_ = cc.writeErr(reqID, "bad signature")
		return
	}
	name, err := rdStr(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad name")
		return
	}
	desc, err := rdStr(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad description")
		return
	}
	avatar, err := rdBlob(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad avatar")
		return
	}
	if len(name) > maxNameLen || len(desc) > maxDescLen || len(avatar) > maxAvatarBytes {
		_ = cc.writeErr(reqID, "field too large")
		return
	}
	var owner [32]byte
	copy(owner[:], rawpk)

	// verify nonce from DB and delete it
	var dbNonce []byte
	if err := cc.s.db.QueryRow(`SELECT nonce FROM nonces WHERE pubkey=?`, owner[:]).Scan(&dbNonce); err != nil || !equalBytes(dbNonce, nonce) {
		_ = cc.writeErr(reqID, "unknown nonce")
		return
	}

	// signature filter + verification over nonce||counter
	if !(len(sig) == 64 && sig[0] == 0 && sig[1] == 0) {
		_ = cc.writeErr(reqID, "signature filter failed")
		return
	}
	msg := append(append([]byte{}, nonce...), counter...)
	if !ed25519.Verify(owner[:], msg, sig) {
		_ = cc.writeErr(reqID, "invalid signature")
		return
	}

	// Delete used nonce to prevent replay
	if _, err := cc.s.db.Exec(`DELETE FROM nonces WHERE pubkey=?`, owner[:]); err != nil {
		log.Printf("Warning: failed to delete nonce for %x: %v", owner[:4], err)
		// Don't fail the request, just log warning
	}

	// generate chat id (positive int64)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		_ = cc.writeErr(reqID, "rng")
		return
	}
	chatID := int64(binary.BigEndian.Uint64(b[:]) & math.MaxInt64)
	if chatID == 0 {
		chatID = 1 // avoid 0
	}

	tx, err := cc.s.db.Begin()
	if err != nil {
		_ = cc.writeErr(reqID, "db begin")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// global chats row
	now := time.Now().Unix()
	if _, err := tx.Exec(`INSERT INTO chats(id, owner_pubkey, created_at) VALUES(?,?,?)`,
		chatID, owner[:], now); err != nil {
		_ = cc.writeErr(reqID, "db chat meta")
		return
	}

	// per-chat tables
	if err := createChatTables(tx, chatID); err != nil {
		_ = cc.writeErr(reqID, "db create tables")
		return
	}
	sett, users, _ := chatTableNames(chatID)

	// default perms for room settings (you can tune later). Put 0; you can store policy bits here.
	if _, err := tx.Exec(fmt.Sprintf(`INSERT INTO %q(name, description, avatar, perms_flags, created_at, extra)
		VALUES(?,?,?,?,?,NULL)`, sett),
		name, desc, avatar, 0, now); err != nil {
		_ = cc.writeErr(reqID, "db settings")
		return
	}

	// insert owner in users with owner bit; not banned
	if _, err := tx.Exec(fmt.Sprintf(`INSERT INTO %q(pubkey, text_rank, perms_flags, accepted_at, changed_at, banned, info)
        VALUES(?,?,?,?,?,0,?)`, users),
		owner[:], "", permOwner|permUser, now, now, nil); err != nil {
		_ = cc.writeErr(reqID, "db owner")
		return
	}

	if err := tx.Commit(); err != nil {
		_ = cc.writeErr(reqID, "db commit")
		return
	}

	// response: chat_id(i64)
	resp := make([]byte, 8)
	binary.BigEndian.PutUint64(resp, uint64(chatID))
	_ = cc.writeOK(reqID, resp)
}

func (cc *clientConn) handleDeleteChat(reqID uint16, p []byte) {
	// payload: chat_id(i64), owner_pubkey(32), nonce(str), signature(64)
	off := 0
	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}

	// check owner matches chats.owner_pubkey
	var storedOwner []byte
	if err := cc.s.db.QueryRow(`SELECT owner_pubkey FROM chats WHERE id=?`, chatID).Scan(&storedOwner); err != nil {
		_ = cc.writeErr(reqID, "no such chat")
		return
	}
	if !cc.authed || !equalBytes(storedOwner, cc.pub[:]) {
		_ = cc.writeErr(reqID, "not an owner")
		return
	}

	tx, err := cc.s.db.Begin()
	if err != nil {
		_ = cc.writeErr(reqID, "db begin")
		return
	}
	defer func() { _ = tx.Rollback() }()

	sett, users, msgs := chatTableNames(chatID)
	stmts := []string{
		fmt.Sprintf(`DROP TABLE IF EXISTS %q;`, sett),
		fmt.Sprintf(`DROP TABLE IF EXISTS %q;`, users),
		fmt.Sprintf(`DROP TABLE IF EXISTS %q;`, msgs),
		`DELETE FROM chats WHERE id=?;`,
	}
	for i, q := range stmts {
		if i == len(stmts)-1 {
			if _, err := tx.Exec(q, chatID); err != nil {
				_ = cc.writeErr(reqID, "db drop")
				return
			}
			continue
		}
		if _, err := tx.Exec(q); err != nil {
			_ = cc.writeErr(reqID, "db drop")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		_ = cc.writeErr(reqID, "db commit")
		return
	}

	// System message: chat deleted (broadcast only; tables dropped)
	// Format: [event_code(1)][actor(32)][random(32)]
	ts := time.Now().Unix()
	body := make([]byte, 1+32+32)
	body[0] = sysChatDeleted
	copy(body[1:33], cc.pub[:])
	copy(body[33:65], rand32())

	// Generate GUID (no database storage since chat is deleted)
	guid := generateMessageGuid(ts, body)

	// Broadcast using cmdGotMessage format: [chat_id(i64)][msg_id(i64)][guid(i64)][author(32)][blob_len(u32)][blob]
	// msg_id is 0 since there's no database entry
	push := make([]byte, 8+8+8+32+4+len(body))
	off2 := 0
	binary.BigEndian.PutUint64(push[off2:off2+8], uint64(chatID))
	off2 += 8
	binary.BigEndian.PutUint64(push[off2:off2+8], 0) // msg_id = 0 (no database entry)
	off2 += 8
	binary.BigEndian.PutUint64(push[off2:off2+8], uint64(guid))
	off2 += 8
	copy(push[off2:off2+32], cc.s.pub[:])
	off2 += 32
	binary.BigEndian.PutUint32(push[off2:off2+4], uint32(len(body)))
	off2 += 4
	copy(push[off2:], body)
	go cc.s.broadcastToChat(chatID, cc, cmdGotMessage, push)

	// Remove from subscription map
	cc.s.chatMu.Lock()
	if subs, ok := cc.s.chatSubscriptions[chatID]; ok {
		delete(subs, cc)
		if len(subs) == 0 {
			delete(cc.s.chatSubscriptions, chatID)
		}
	}
	cc.s.chatMu.Unlock()

	// Remove from client’s personal subscription list
	delete(cc.chats, chatID)

	// return OK: 1 byte (1)
	_ = cc.writeOK(reqID, []byte{1})
}

func (cc *clientConn) handleAddUser(reqID uint16, p []byte) {
	// requires cc.authed true and perms: owner/admin/mod
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	newUser, err := rdBytes(p, &off, 32)
	if err != nil {
		_ = cc.writeErr(reqID, "bad new user pubkey")
		return
	}

	role, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}
	if !hasAny(role, permOwner|permAdmin|permMod) {
		_ = cc.writeErr(reqID, "insufficient perms")
		return
	}

	usersTbl := fmt.Sprintf("users-%d", chatID)
	now := time.Now().Unix()

	_, err = cc.s.db.Exec(fmt.Sprintf(`INSERT INTO %q(pubkey, text_rank, perms_flags, accepted_at, changed_at, banned, info)
        VALUES(?,?,?,?,?,0,?)
        ON CONFLICT(pubkey) DO UPDATE SET banned=0, perms_flags=excluded.perms_flags`, usersTbl),
		newUser, "", permUser, now, now, nil)
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}
	// System message: user added by cc.pub (include 32-byte random tail)
	// Format: [event_code(1)][target_user(32)][actor(32)][random(32)]
	body := make([]byte, 1+32+32+32)
	body[0] = sysUserAdded
	copy(body[1:33], newUser)
	copy(body[33:65], cc.pub[:])
	copy(body[65:97], rand32())

	if _, err := cc.s.broadcastSystemMessage(chatID, body, cc, true); err != nil {
		log.Printf("ERROR: %v", err)
		_ = cc.writeErr(reqID, "db error")
		return
	}

	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleDeleteUser(reqID uint16, p []byte) {
	off := 0
	// "delete" = set banned bit in perms_flags and banned=1
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	userPK, err := rdBytes(p, &off, 32)
	if err != nil {
		_ = cc.writeErr(reqID, "bad user pubkey")
		return
	}

	role, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}
	if !hasAny(role, permOwner|permAdmin|permMod) {
		_ = cc.writeErr(reqID, "insufficient perms")
		return
	}

	usersTbl := fmt.Sprintf("users-%d", chatID)
	now := time.Now().Unix()
	_, err = cc.s.db.Exec(fmt.Sprintf(`UPDATE %q SET banned=1, perms_flags=(perms_flags | ?), changed_at=? WHERE pubkey=?`, usersTbl),
		permBanned, now, userPK)
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}
	// System message: user banned by cc.pub (include 32-byte random tail)
	// Format: [event_code(1)][target_user(32)][actor(32)][random(32)]
	body := make([]byte, 1+32+32+32)
	body[0] = sysUserBanned
	copy(body[1:33], userPK)
	copy(body[33:65], cc.pub[:])
	copy(body[65:97], rand32())

	if _, err := cc.s.broadcastSystemMessage(chatID, body, cc, true); err != nil {
		log.Printf("ERROR: %v", err)
		_ = cc.writeErr(reqID, "db error")
		return
	}

	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleGetUserChats(reqID uint16, p []byte) {
	if !cc.authed {
		_ = cc.writeErr(0, "auth required")
		return
	}

	rows, err := cc.s.db.Query(`SELECT id FROM chats`)
	if err != nil {
		_ = cc.writeErr(0, "db error")
		return
	}
	defer rows.Close()

	var chatIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			continue
		}

		usersTbl := fmt.Sprintf("users-%d", id)
		var banned int
		err := cc.s.db.QueryRow(fmt.Sprintf(
			`SELECT banned FROM %q WHERE pubkey=?`, usersTbl),
			cc.pub[:],
		).Scan(&banned)

		if errors.Is(err, sql.ErrNoRows) {
			continue // user not in this chat
		}
		if err != nil {
			continue // table missing or other error — skip
		}
		if banned != 0 {
			continue // user banned, skip
		}
		chatIDs = append(chatIDs, id)
	}

	// Encode result
	resp := make([]byte, 4+len(chatIDs)*8)
	binary.BigEndian.PutUint32(resp[0:4], uint32(len(chatIDs)))
	for i, id := range chatIDs {
		binary.BigEndian.PutUint64(resp[4+i*8:], uint64(id))
	}

	_ = cc.writeOK(reqID, resp)
}

func (cc *clientConn) handleLeaveChat(reqID uint16, p []byte) {
	if !cc.authed {
		_ = cc.writeErr(0, "auth required")
		return
	}
	off := 0
	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(0, "bad chat id")
		return
	}

	// Check that user is actually part of this chat
	role, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok {
		_ = cc.writeErr(reqID, "not a member")
		return
	}
	if role&permOwner != 0 {
		_ = cc.writeErr(reqID, "owner can't leave")
		return
	}
	if banned {
		_ = cc.writeErr(reqID, "banned user")
		return
	}

	// Remove from subscription map
	cc.s.chatMu.Lock()
	if subs, ok := cc.s.chatSubscriptions[chatID]; ok {
		delete(subs, cc)
		if len(subs) == 0 {
			delete(cc.s.chatSubscriptions, chatID)
		}
	}
	cc.s.chatMu.Unlock()

	// Remove from client’s personal subscription list
	delete(cc.chats, chatID)

	// System message: user left (include 32-byte random tail)
	// Format: [event_code(1)][user(32)][random(32)]
	body := make([]byte, 1+32+32)
	body[0] = sysUserLeft
	copy(body[1:33], cc.pub[:])
	copy(body[33:65], rand32())

	if _, err := cc.s.broadcastSystemMessage(chatID, body, cc, true); err != nil {
		log.Printf("ERROR: %v", err)
		_ = cc.writeErr(reqID, "db error")
		return
	}

	usersTbl := fmt.Sprintf("users-%d", chatID)
	_, err = cc.s.db.Exec(fmt.Sprintf(`DELETE FROM %q WHERE pubkey=?`, usersTbl), cc.pub[:])
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}

	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleSubscribe(reqID uint16, p []byte) {
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	log.Printf("Searching for chatId %d permissions", chatID)
	role, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}
	// read-only cannot send
	if role&permReadOnly != 0 {
		_ = cc.writeErr(reqID, "read-only user")
		return
	}

	// Get last message ID for this chat
	msgTbl := fmt.Sprintf("messages-%d", chatID)
	var lastID sql.NullInt64
	err = cc.s.db.QueryRow(fmt.Sprintf(`SELECT IFNULL(MAX(id),0) FROM %q`, msgTbl)).Scan(&lastID)
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}

	cc.s.subscribe(chatID, cc)

	// Return OK with last_message_id in payload
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, uint64(lastID.Int64))
	_ = cc.writeOK(reqID, out)

	// Request member info update from client
	go cc.requestMemberInfo(chatID)
}

// handleGetMessagesSince fetches multiple messages in a single request
// Request: [chatId(i64)][sinceMessageId(i64)][limit(u32)]
// Response: [count(u32)][[chatId(i64)][msgId(i64)][guid(u64)][author(32)][blobLen(u32)][blob]...]
func (cc *clientConn) handleGetMessagesSince(reqID uint16, p []byte) {
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	sinceMessageID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad message id")
		return
	}
	limitRaw, err := rdU32(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad limit")
		return
	}
	if limitRaw == 0 || limitRaw > 500 {
		_ = cc.writeErr(reqID, "limit must be between 1 and 500")
		return
	}

	// Ensure caller is a chat member (read perms implied)
	_, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}

	msgTbl := fmt.Sprintf("messages-%d", chatID)
	rows, err := cc.s.db.Query(
		fmt.Sprintf(`SELECT id, guid, author FROM %q WHERE id>? ORDER BY id ASC LIMIT ?`, msgTbl),
		sinceMessageID,
		int(limitRaw),
	)
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}
	defer rows.Close()

	type message struct {
		id     int64
		guid   int64
		author []byte
		blob   []byte
	}

	var msgs []message
	for rows.Next() {
		var m message
		if err := rows.Scan(&m.id, &m.guid, &m.author); err != nil {
			_ = cc.writeErr(reqID, "db error")
			return
		}
		// Fetch blob from hybrid cache using chatID+guid key
		key := fmt.Sprintf("%016x:%016x", chatID, m.guid)
		blob, ok, err := cc.s.cache.Get(key)
		if err != nil {
			_ = cc.writeErr(reqID, "cache error")
			return
		}
		if !ok {
			continue
		}
		m.blob = blob
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint32(len(msgs)))

	for _, m := range msgs {
		binary.Write(buf, binary.BigEndian, uint64(chatID))
		binary.Write(buf, binary.BigEndian, uint64(m.id))
		binary.Write(buf, binary.BigEndian, m.guid)
		buf.Write(m.author)
		binary.Write(buf, binary.BigEndian, uint32(len(m.blob)))
		buf.Write(m.blob)
	}

	_ = cc.writeOK(reqID, buf.Bytes())
}

func (cc *clientConn) handleSendMessage(reqID uint16, p []byte) {
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	guid, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad guid")
		return
	}
	blob, err := rdBlob(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad blob")
		return
	}

	role, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}
	// read-only cannot send
	if role&permReadOnly != 0 {
		_ = cc.writeErr(reqID, "read-only user")
		return
	}

	msgTbl := fmt.Sprintf("messages-%d", chatID)
	now := time.Now().Unix()
	// Store only metadata (ts, guid, author)
	res, err := cc.s.db.Exec(
		fmt.Sprintf(`INSERT INTO %q(ts, guid, author) VALUES(?,?,?)`, msgTbl),
		now, guid, cc.pub[:],
	)
	if err != nil {
		log.Printf("ERROR: Failed to insert message into %s: %v (guid=%d, author=%x)", msgTbl, err, guid, cc.pub[:4])
		_ = cc.writeErr(reqID, "db error - failed to insert message")
		return
	}

	// Store (author||blob) in hybrid cache for short-term retention
	// Layout: [author(32)][blob]
	key := fmt.Sprintf("%016x:%016x", chatID, guid)
	if err := cc.s.cache.Set(key, blob, 24*time.Hour); err != nil {
		log.Printf("cache set failed: %v", err)
	}

	id, _ := res.LastInsertId()
	// After message successfully inserted:
	// Broadcast payload: [chat_id(i64)][msg_id(i64)][guid(i64)][author(32)][blob_len(u32)][blob]
	out := make([]byte, 8+8+8+32+4+len(blob))
	off2 := 0
	binary.BigEndian.PutUint64(out[off2:off2+8], uint64(chatID))
	off2 += 8
	binary.BigEndian.PutUint64(out[off2:off2+8], uint64(id))
	off2 += 8
	binary.BigEndian.PutUint64(out[off2:off2+8], uint64(guid))
	off2 += 8
	copy(out[off2:off2+32], cc.pub[:])
	off2 += 32
	binary.BigEndian.PutUint32(out[off2:off2+4], uint32(len(blob)))
	off2 += 4
	copy(out[off2:], blob)

	// notify others
	cc.s.broadcastMessage(chatID, cc, out)

	// and respond to sender
	out2 := make([]byte, 8)
	binary.BigEndian.PutUint64(out2, uint64(id))
	_ = cc.writeOK(reqID, out2)
}

func (cc *clientConn) handleDeleteMessage(reqID uint16, p []byte) {
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	msgID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad message id")
		return
	}
	role, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned || !hasAny(role, permOwner|permAdmin|permMod) {
		_ = cc.writeErr(reqID, "insufficient perms")
		return
	}
	msgTbl := fmt.Sprintf("messages-%d", chatID)
	_, err = cc.s.db.Exec(fmt.Sprintf(`DELETE FROM %q WHERE id=?`, msgTbl), msgID)
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}
	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleGetLastMessageID(reqID uint16, p []byte) {
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	_, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}
	msgTbl := fmt.Sprintf("messages-%d", chatID)
	var lastID sql.NullInt64
	err = cc.s.db.QueryRow(fmt.Sprintf(`SELECT IFNULL(MAX(id),0) FROM %q`, msgTbl)).Scan(&lastID)
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, uint64(lastID.Int64))
	_ = cc.writeOK(reqID, out)
}

func (cc *clientConn) handleSendInvite(reqID uint16, p []byte) {
	// payload: to_pubkey(32), chat_id(i64), encrypted_data(blob)
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}

	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	toPubkey, err := rdBytes(p, &off, 32)
	if err != nil {
		_ = cc.writeErr(reqID, "bad to_pubkey")
		return
	}
	encryptedData, err := rdBlob(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad encrypted data")
		return
	}

	log.Printf("Searching for chatId %d permissions", chatID)
	// Verify sender is a member of the chat with permission to invite
	role, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}
	if !hasAny(role, permOwner|permAdmin|permMod) {
		_ = cc.writeErr(reqID, "insufficient perms")
		return
	}

	// Check if invite already exists
	var existingID int64
	err = cc.s.db.QueryRow(`SELECT id FROM invites WHERE to_pubkey=? AND chat_id=?`,
		toPubkey, chatID).Scan(&existingID)
	if err == nil {
		// Invite already exists
		_ = cc.writeErr(reqID, "invite already exists")
		return
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		_ = cc.writeErr(reqID, "db error")
		return
	}

	// Insert invite into database
	now := time.Now().Unix()
	result, err := cc.s.db.Exec(`INSERT INTO invites(timestamp, from_pubkey, to_pubkey, chat_id, encrypted_data) VALUES(?,?,?,?,?)`,
		now, cc.pub[:], toPubkey, chatID, encryptedData)
	if err != nil {
		_ = cc.writeErr(reqID, "db insert error")
		return
	}

	inviteID, _ := result.LastInsertId()
	log.Printf("Invite created: from %x… to %x… for chat %d (id=%d)", cc.pub[:4], toPubkey[:4], chatID, inviteID)

	// Check if recipient is currently connected and authenticated (multi-device support)
	var toPubArr [32]byte
	copy(toPubArr[:], toPubkey)

	cc.s.authClientsMu.RLock()
	recipientConns := cc.s.authenticatedClients[toPubArr]
	cc.s.authClientsMu.RUnlock()

	if len(recipientConns) > 0 {
		// Recipient is connected on one or more devices, send invite to all
		log.Printf("Recipient %x is connected on %d device(s), sending invite to all", toPubArr[:4], len(recipientConns))
		for recipientConn := range recipientConns {
			go cc.s.sendInviteToClient(recipientConn, inviteID, now, cc.pub[:], chatID, encryptedData)
		}
	} else {
		log.Printf("Recipient %x not connected, invite stored for later delivery", toPubArr[:4])
	}

	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleInviteResponse(reqID uint16, p []byte) {
	// payload: invite_id(i64), accepted(u8)
	// accepted: 0 = reject, 1 = accept
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}

	inviteID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad invite id")
		return
	}
	if off+1 > len(p) {
		_ = cc.writeErr(reqID, "bad accepted flag")
		return
	}
	accepted := p[off]
	off += 1

	if accepted != 0 && accepted != 1 {
		_ = cc.writeErr(reqID, "invalid accepted value")
		return
	}

	// Look up the invite
	var chatID int64
	var fromPubkey []byte
	var toPubkey []byte
	err = cc.s.db.QueryRow(`SELECT chat_id, from_pubkey, to_pubkey FROM invites WHERE id=?`, inviteID).
		Scan(&chatID, &fromPubkey, &toPubkey)
	if err != nil {
		log.Printf("Invite %d not found: %v", inviteID, err)
		_ = cc.writeErr(reqID, "invite not found")
		return
	}

	// Verify that the responder is the intended recipient
	var toPubArr [32]byte
	copy(toPubArr[:], toPubkey)
	if !equalBytes(cc.pub[:], toPubArr[:]) {
		_ = cc.writeErr(reqID, "not recipient of this invite")
		return
	}

	if accepted == 1 {
		// User accepted: add to members table and request info
		log.Printf("Invite %d accepted by %x for chat %d", inviteID, cc.pub[:4], chatID)

		usersTbl := fmt.Sprintf("users-%d", chatID)
		now := time.Now().Unix()

		// Add user to members table with user permissions
		_, err = cc.s.db.Exec(fmt.Sprintf(`INSERT INTO %q(pubkey, text_rank, perms_flags, accepted_at, changed_at, banned, info)
            VALUES(?,?,?,?,?,0,?)
            ON CONFLICT(pubkey) DO UPDATE SET banned=0, perms_flags=excluded.perms_flags`, usersTbl),
			cc.pub[:], "", permUser, now, 0, nil)
		if err != nil {
			log.Printf("Failed to add user to chat %d: %v", chatID, err)
			_ = cc.writeErr(reqID, "db error")
			return
		}

		// System message: user added by inviter (include 32-byte random tail)
		// Format: [event_code(1)][target_user(32)][actor(32)][random(32)]
		body := make([]byte, 1+32+32+32)
		body[0] = sysUserAdded
		copy(body[1:33], cc.pub[:])
		copy(body[33:65], fromPubkey)
		copy(body[65:97], rand32())

		if _, err := cc.s.broadcastSystemMessage(chatID, body, cc, true); err != nil {
			log.Printf("ERROR: %v", err)
			_ = cc.writeErr(reqID, "db error")
			return
		}

		// Delete the invite
		_, err = cc.s.db.Exec(`DELETE FROM invites WHERE id=?`, inviteID)
		if err != nil {
			log.Printf("Failed to delete invite %d: %v", inviteID, err)
			_ = cc.writeErr(reqID, "db error")
			return
		}

		// Request member info from client (with timestamp 0 to get all)
		// Find the client connection for this user and request info
		// For now, if they're already connected on this same conn, send immediately
		// Otherwise they'll be asked when they subscribe
		go cc.requestMemberInfo(chatID)

		log.Printf("Added %x to chat %d members, requesting member info", cc.pub[:4], chatID)

	} else {
		// User rejected: just delete the invite
		log.Printf("Invite %d rejected by %x", inviteID, cc.pub[:4])

		_, err = cc.s.db.Exec(`DELETE FROM invites WHERE id=?`, inviteID)
		if err != nil {
			log.Printf("Failed to delete invite %d: %v", inviteID, err)
			_ = cc.writeErr(reqID, "db error")
			return
		}

		log.Printf("Deleted rejected invite %d", inviteID)
	}

	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleUpdateMemberInfo(reqID uint16, p []byte) {
	// payload: chat_id(i64), timestamp(u64), encrypted_blob(blob)
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}

	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	timestamp, err := rdU64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad timestamp")
		return
	}
	encryptedBlob, err := rdBlob(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad encrypted blob")
		return
	}

	// Verify user is a member of the chat
	_, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}

	// Store encrypted member info in users table and bump changed_at
	usersTbl := fmt.Sprintf("users-%d", chatID)
	query := fmt.Sprintf(`UPDATE %q SET info=?, changed_at=? WHERE pubkey=?`, usersTbl)
	_, err = cc.s.db.Exec(query, encryptedBlob, timestamp, cc.pub[:])
	if err != nil {
		log.Printf("Failed to update member info for %x in chat %d: %v", cc.pub[:4], chatID, err)
		_ = cc.writeErr(reqID, "db error")
		return
	}

	// Broadcast updated member info to subscribers (excluding sender) in the same
	// format as handleGetMembersInfo: [count(u32)][pubkey(32)][infoLen(u32)][info][timestamp(u64)]
	payload := make([]byte, 4+32+4+len(encryptedBlob)+8)
	off2 := 0
	binary.BigEndian.PutUint32(payload[off2:off2+4], 1)
	off2 += 4
	copy(payload[off2:off2+32], cc.pub[:])
	off2 += 32
	binary.BigEndian.PutUint32(payload[off2:off2+4], uint32(len(encryptedBlob)))
	off2 += 4
	copy(payload[off2:off2+len(encryptedBlob)], encryptedBlob)
	off2 += len(encryptedBlob)
	binary.BigEndian.PutUint64(payload[off2:off2+8], timestamp)
	go cc.s.broadcastToChat(chatID, cc, cmdGotMemberInfo, payload)

	log.Printf("Updated member info for %x in chat %d (size=%d bytes)",
		cc.pub[:4], chatID, len(encryptedBlob))
	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleGetMembersInfo(reqID uint16, p []byte) {
	// payload: chat_id(i64), timestamp(u64)
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}

	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	sinceTimestamp, err := rdU64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad timestamp")
		return
	}

	// Verify user is a member of the chat
	_, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}

	// Query ALL non-banned members, returning full info only if changed since timestamp
	// This gives client a consistent view of membership + selective info updates
	usersTbl := fmt.Sprintf("users-%d", chatID)
	rows, err := cc.s.db.Query(fmt.Sprintf(
		`SELECT pubkey, info, changed_at FROM %q WHERE banned = 0`, usersTbl))

	if err != nil {
		log.Printf("Failed to query members info for chat %d: %v", chatID, err)
		_ = cc.writeErr(reqID, "db error")
		return
	}
	defer rows.Close()

	// Collect member info
	type memberInfo struct {
		pubkey    []byte
		info      []byte // nil if no info OR if not changed since timestamp
		timestamp int64
	}
	var members []memberInfo

	for rows.Next() {
		var m memberInfo
		var infoBytes []byte
		var changedAt int64
		if err := rows.Scan(&m.pubkey, &infoBytes, &changedAt); err != nil {
			continue
		}

		// Only include info if it's non-null AND (timestamp=0 OR changed after timestamp)
		if infoBytes != nil && (sinceTimestamp == 0 || uint64(changedAt) > sinceTimestamp) {
			m.info = infoBytes
		} else {
			m.info = nil // Signal to client: no update needed
		}
		m.timestamp = changedAt
		members = append(members, m)
	}

	// Build response: [count(u32)][[pubkey(32)][infoLen(u32)][encryptedInfo][timestamp(u64)]...]
	payloadSize := 4 // count
	for _, m := range members {
		payloadSize += 32 + 4 + len(m.info) + 8
	}

	payload := make([]byte, payloadSize)
	offset := 0

	// Write count
	binary.BigEndian.PutUint32(payload[offset:], uint32(len(members)))
	offset += 4

	// Write each member's info
	for _, m := range members {
		// pubkey (32 bytes)
		copy(payload[offset:], m.pubkey)
		offset += 32

		// info length + data
		binary.BigEndian.PutUint32(payload[offset:], uint32(len(m.info)))
		offset += 4
		copy(payload[offset:], m.info)
		offset += len(m.info)

		// timestamp
		binary.BigEndian.PutUint64(payload[offset:], uint64(m.timestamp))
		offset += 8
	}

	log.Printf("Sending %d member(s) info for chat %d to %x", len(members), chatID, cc.pub[:4])
	_ = cc.writeOK(reqID, payload)
}

// handleGetMembers returns the list of all non-banned members with pubkey, permissions, and online state
// Response format: [count(u32)][[pubkey(32)][perms(1)][online(1)] repeated]
func (cc *clientConn) handleGetMembers(reqID uint16, p []byte) {
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}

	chatID, err := rdI64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}

	// Verify requester is a member (not banned)
	if _, banned, ok := cc.lookupPerms(chatID, cc.pub[:]); !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}

	usersTbl := fmt.Sprintf("users-%d", chatID)
	rows, err := cc.s.db.Query(fmt.Sprintf(`SELECT pubkey, perms_flags FROM %q WHERE banned=0`, usersTbl))
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}
	defer rows.Close()

	type member struct {
		pubkey [32]byte
		perms  byte
		online byte
	}
	var members []member

	for rows.Next() {
		var pk []byte
		var perms int64
		if err := rows.Scan(&pk, &perms); err != nil {
			continue
		}
		if len(pk) != 32 {
			continue
		}

		var m member
		copy(m.pubkey[:], pk)
		m.perms = byte(perms)

		// Check online state: look up if this pubkey has any connections subscribed to this chat
		m.online = 0
		var pkArr [32]byte
		copy(pkArr[:], pk)

		cc.s.authClientsMu.RLock()
		clientConns := cc.s.authenticatedClients[pkArr]
		cc.s.authClientsMu.RUnlock()

		if len(clientConns) > 0 {
			cc.s.chatMu.RLock()
			chatSubs := cc.s.chatSubscriptions[chatID]
			for conn := range clientConns {
				if _, subscribed := chatSubs[conn]; subscribed {
					m.online = 1
					break
				}
			}
			cc.s.chatMu.RUnlock()
		}

		members = append(members, m)
	}

	// Build response: [count(u32)][[pubkey(32)][perms(1)][online(1)] repeated]
	out := make([]byte, 4+34*len(members))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(members)))
	off2 := 4
	for _, m := range members {
		copy(out[off2:off2+32], m.pubkey[:])
		off2 += 32
		out[off2] = m.perms
		off2 += 1
		out[off2] = m.online
		off2 += 1
	}
	_ = cc.writeOK(reqID, out)
}

// requestMemberInfo requests updated member info from the client for a specific chat
func (cc *clientConn) requestMemberInfo(chatID int64) {
	// Get last update timestamp from database (if info exists)
	usersTbl := fmt.Sprintf("users-%d", chatID)
	var lastUpdate int64

	// Try to get the existing info timestamp
	// If no info exists yet, use 0 as lastUpdate
	err := cc.s.db.QueryRow(fmt.Sprintf(`SELECT IFNULL(changed_at, 0) FROM %q WHERE pubkey=?`, usersTbl), cc.pub[:]).
		Scan(&lastUpdate)
	if err != nil {
		log.Printf("Could not get last update for %x in chat %d: %v", cc.pub[:4], chatID, err)
		lastUpdate = 0
	}

	// Build request payload: [chatID(i64)][lastUpdate(u64)]
	payload := make([]byte, 16)
	binary.BigEndian.PutUint64(payload[0:8], uint64(chatID))
	binary.BigEndian.PutUint64(payload[8:16], uint64(lastUpdate))

	// Send request as a push notification (using cmdRequestMemberInfo as reqID)
	if err := cc.writeOK(cmdRequestMemberInfo, payload); err != nil {
		log.Printf("Failed to request member info from %x for chat %d: %v", cc.pub[:4], chatID, err)
		return
	}

	log.Printf("Requested member info from %x for chat %d (last update: %d)", cc.pub[:4], chatID, lastUpdate)
}

// ---------------- utilities ----------------

// Subscribe the connection to a chat
func (s *serverState) subscribe(chatID int64, cc *clientConn) {
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	set, ok := s.chatSubscriptions[chatID]
	if !ok {
		set = make(map[*clientConn]struct{})
		s.chatSubscriptions[chatID] = set
	}
	set[cc] = struct{}{}
	cc.chats[chatID] = struct{}{}
}

// Unsubscribe the connection from all chats (called on disconnect)
func (s *serverState) unsubscribeAll(cc *clientConn) {
	s.chatMu.Lock()
	for chatID := range cc.chats {
		if set, ok := s.chatSubscriptions[chatID]; ok {
			delete(set, cc)
			if len(set) == 0 {
				delete(s.chatSubscriptions, chatID)
			}
		}
	}
	cc.chats = make(map[int64]struct{})
	s.chatMu.Unlock()

	// Remove from authenticated clients map if this client was authenticated (multi-device support)
	if cc.authed {
		s.authClientsMu.Lock()
		if conns, exists := s.authenticatedClients[cc.pub]; exists {
			delete(conns, cc)
			if len(conns) == 0 {
				delete(s.authenticatedClients, cc.pub)
				log.Printf("[DEBUG] Removed last device for user %x", cc.pub[:4])
			} else {
				log.Printf("[DEBUG] Removed device for user %x (%d remaining)", cc.pub[:4], len(conns))
			}
		}
		s.authClientsMu.Unlock()
	}
}

// Broadcast message to all subscribers of chatID except sender
func (s *serverState) broadcastMessage(chatID int64, sender *clientConn, msgPayload []byte) {
	s.chatMu.RLock()
	defer s.chatMu.RUnlock()
	set, ok := s.chatSubscriptions[chatID]
	if !ok {
		return
	}
	for cc := range set {
		if cc == sender {
			continue
		}
		// asynchronous, ignore write errors
		go cc.writeOK(cmdGotMessage, msgPayload)
	}
}

// broadcastToChat sends a custom payload with the given requestId to all subscribers except sender
func (s *serverState) broadcastToChat(chatID int64, sender *clientConn, requestId uint16, payload []byte) {
	s.chatMu.RLock()
	defer s.chatMu.RUnlock()
	set, ok := s.chatSubscriptions[chatID]
	if !ok {
		return
	}
	for cc := range set {
		if cc == sender {
			continue
		}
		go cc.writeOK(requestId, payload)
	}
}

func hasAny(v byte, mask byte) bool { return (v & mask) != 0 }

func (cc *clientConn) lookupPerms(chatID int64, pub []byte) (role byte, banned bool, ok bool) {
	// Verify user membership & perms
	usersTbl := fmt.Sprintf("users-%d", chatID)
	var perms int64
	var ban int64
	err := cc.s.db.QueryRow(fmt.Sprintf(`SELECT perms_flags, banned FROM %q WHERE pubkey=?`, usersTbl), pub).
		Scan(&perms, &ban)
	if err != nil {
		return 0, false, false
	}
	return byte(perms), ban != 0, true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	ok := byte(0)
	for i := range a {
		ok |= a[i] ^ b[i]
	}
	return ok == 0
}

// ---------------- invite delivery ----------------

// sendInviteToClient sends an invite notification to a connected client
func (s *serverState) sendInviteToClient(cc *clientConn, inviteID int64, timestamp int64, fromPubkey []byte, chatID int64, encryptedData []byte) bool {
	// Get chat metadata
	var chatName, chatDesc string
	var chatAvatar []byte
	settTbl := fmt.Sprintf("settings-%d", chatID)
	err := s.db.QueryRow(fmt.Sprintf(`SELECT name, description, avatar FROM %q`, settTbl)).
		Scan(&chatName, &chatDesc, &chatAvatar)
	if err != nil {
		log.Printf("Failed to get chat metadata for %d: %v", chatID, err)
		return false
	}

	// Build payload: inviteId(8), chat_id(8), from_pubkey(32), timestamp(8),
	// chat_name(str), chat_desc(str), chat_avatar(blob), encrypted_data(blob)
	// Must match Android client format in MediatorClient.kt line 606
	payloadSize := 8 + 8 + 32 + 8 +
		2 + len(chatName) +
		2 + len(chatDesc) +
		4 + len(chatAvatar) +
		4 + len(encryptedData)

	payload := make([]byte, payloadSize)
	off := 0

	// invite_id
	binary.BigEndian.PutUint64(payload[off:], uint64(inviteID))
	off += 8

	// chat_id
	binary.BigEndian.PutUint64(payload[off:], uint64(chatID))
	off += 8

	// from_pubkey
	copy(payload[off:], fromPubkey)
	off += 32

	// timestamp
	binary.BigEndian.PutUint64(payload[off:], uint64(timestamp))
	off += 8

	// chat_name (string)
	binary.BigEndian.PutUint16(payload[off:], uint16(len(chatName)))
	off += 2
	copy(payload[off:], chatName)
	off += len(chatName)

	// chat_desc (string)
	binary.BigEndian.PutUint16(payload[off:], uint16(len(chatDesc)))
	off += 2
	copy(payload[off:], chatDesc)
	off += len(chatDesc)

	// chat_avatar (blob)
	binary.BigEndian.PutUint32(payload[off:], uint32(len(chatAvatar)))
	off += 4
	copy(payload[off:], chatAvatar)
	off += len(chatAvatar)

	// encrypted_data (blob)
	binary.BigEndian.PutUint32(payload[off:], uint32(len(encryptedData)))
	off += 4
	copy(payload[off:], encryptedData)

	// Send as notification using cmdGotInvite with reqID=0
	if err := cc.writeOK(cmdGotInvite, payload); err != nil {
		log.Printf("Failed to send invite notification to %x: %v", cc.pub[:4], err)
		return false
	}

	// Mark invite as sent (best-effort)
	if _, err := s.db.Exec(`UPDATE invites SET sent=1 WHERE id=?`, inviteID); err != nil {
		log.Printf("Warning: failed to mark invite %d as sent: %v", inviteID, err)
	}

	// NOTE: Do NOT delete the invite here. The invite stays in the database until the user
	// accepts or rejects it via handleInviteResponse. This ensures we have a record of the
	// invitation and the user can be added to the members table with confirmation.
	log.Printf("Successfully delivered invite %d to connected user %x (invite kept for response)", inviteID, cc.pub[:4])
	return true
}

// sendPendingInvites sends all pending invites for a user to their connected client
func (s *serverState) sendPendingInvites(cc *clientConn) {
	// Fetch all unsent invites for this user
	rows, err := s.db.Query(`SELECT id, timestamp, from_pubkey, chat_id, encrypted_data FROM invites WHERE to_pubkey=? AND sent=0`, cc.pub[:])
	if err != nil {
		log.Printf("Failed to query pending invites for %x: %v", cc.pub[:4], err)
		return
	}
	defer rows.Close()

	type invite struct {
		id            int64
		timestamp     int64
		fromPubkey    []byte
		chatID        int64
		encryptedData []byte
	}

	var invites []invite
	for rows.Next() {
		var inv invite
		if err := rows.Scan(&inv.id, &inv.timestamp, &inv.fromPubkey, &inv.chatID, &inv.encryptedData); err != nil {
			continue
		}
		invites = append(invites, inv)
	}

	if len(invites) == 0 {
		return
	}

	log.Printf("Sending %d pending invite(s) to %x", len(invites), cc.pub[:4])
	for _, inv := range invites {
		s.sendInviteToClient(cc, inv.id, inv.timestamp, inv.fromPubkey, inv.chatID, inv.encryptedData)
	}
}

// inviteCleanupWorker periodically removes old invites from the database
func (s *serverState) inviteCleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Run once immediately on startup
	s.cleanupOldInvites()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupOldInvites()
		}
	}
}

// cleanupOldInvites deletes invites older than 3 days
func (s *serverState) cleanupOldInvites() {
	const threeDaysSeconds = 3 * 24 * 60 * 60 // 259200 seconds
	now := time.Now().Unix()
	cutoff := now - threeDaysSeconds

	result, err := s.db.Exec(`DELETE FROM invites WHERE timestamp < ?`, cutoff)
	if err != nil {
		log.Printf("Failed to clean up old invites: %v", err)
		return
	}

	if count, _ := result.RowsAffected(); count > 0 {
		log.Printf("Cleaned up %d old invite(s) (older than 3 days)", count)
	}
}

// ---------------- end ----------------
