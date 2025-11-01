// mediator.go
package main

import (
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
	"net"

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
- users-{id}(pubkey, nickname, text_rank, perms_flags, accepted_at, last_perm_change, banned)
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
	cmdGetNonce         = 0x01
	cmdAuth             = 0x02
	cmdPing             = 0x03
	cmdCreateChat       = 0x10
	cmdDeleteChat       = 0x11
	cmdAddUser          = 0x20
	cmdDeleteUser       = 0x21
	cmdLeaveChat        = 0x22
	cmdGetUserChats     = 0x23
	cmdSendMessage      = 0x30
	cmdDeleteMessage    = 0x31
	cmdGetMessage       = 0x32
	cmdGetLastMessageID = 0x33
	cmdGotMessage       = 0x34 // Server sends it to the client after receiving a message from some user.
	cmdSubscribe        = 0x35
	cmdSendInvite       = 0x40
	cmdGotInvite        = 0x41 // Server sends it to the client when delivering an invite.

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
	chatSubscriptions map[uint64]map[*clientConn]struct{}
	cache             *hybridcache.HybridCache
	// invite delivery tracking
	inviteDialMu  sync.Mutex
	inviteDialers map[[32]byte]struct{} // pubkeys currently being dialed
	inviteQueue   chan [32]byte         // queue of pubkeys to dial for invite delivery
}

// connection-scoped state
type clientConn struct {
	conn   *yggquic.Conn
	s      *serverState
	authed bool
	pub    [32]byte
	chats  map[uint64]struct{} // chats this client subscribed to
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

	cache, err := hybridcache.NewHybridCache("mediator-cache", 512*1024*1024) // 512 MB RAM/disk hybrid
	if err != nil {
		log.Fatalf("cache init: %v", err)
	}
	defer cache.Close()

	st := &serverState{
		db:                db,
		node:              node,
		transport:         m.GetTransport(),
		priv:              priv,
		pub:               pub,
		chatSubscriptions: make(map[uint64]map[*clientConn]struct{}),
		cache:             cache,
		inviteDialers:     make(map[[32]byte]struct{}),
		inviteQueue:       make(chan [32]byte, 100),
	}

	log.Printf("mediator started; pubkey: %x", pub[:])
	log.Printf("listening for client requests…")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start invite delivery workers
	for i := 0; i < 3; i++ { // 3 concurrent workers
		go st.inviteDeliveryWorker(ctx)
	}

	// Start periodic invite cleanup and retry
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

	cc := &clientConn{conn: c, s: s, chats: make(map[uint64]struct{})}
	defer cc.s.unsubscribeAll(cc)
	log.Printf("[DEBUG] Client connection initialized, entering command loop")

	for {
		if err := c.Stream.SetReadDeadline(time.Now().Add(10 * time.Minute)); err != nil {
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
		case cmdSendMessage:
			cc.handleSendMessage(reqId, payload)
		case cmdDeleteMessage:
			cc.handleDeleteMessage(reqId, payload)
		case cmdGetMessage:
			cc.handleGetMessage(reqId, payload)
		case cmdGetLastMessageID:
			cc.handleGetLastMessageID(reqId, payload)
		case cmdSendInvite:
			cc.handleSendInvite(reqId, payload)
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
  UNIQUE(to_pubkey, chat_id)
);
`)
	return err
}

func chatTableNames(id uint64) (settings, users, messages string) {
	settings = fmt.Sprintf("settings-%d", id)
	users = fmt.Sprintf("users-%d", id)
	messages = fmt.Sprintf("messages-%d", id)
	return
}

func createChatTables(tx *sql.Tx, id uint64) error {
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
  nickname TEXT,
  text_rank TEXT,
  perms_flags INTEGER NOT NULL,
  accepted_at INTEGER NOT NULL,
  last_perm_change INTEGER NOT NULL,
  banned INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE %q(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  guid INTEGER NOT NULL,
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
	_ = cc.writeOK(reqID, nil)
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

	// generate chat id
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		_ = cc.writeErr(reqID, "rng")
		return
	}
	chatID := binary.BigEndian.Uint64(b[:])
	chatID &= math.MaxInt64 // mask off the sign bit
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
	if _, err := tx.Exec(fmt.Sprintf(`INSERT INTO %q(pubkey, nickname, text_rank, perms_flags, accepted_at, last_perm_change, banned)
		VALUES(?,?,?,?,?,?,0)`, users),
		owner[:], "", "", permOwner|permUser, now, now); err != nil {
		_ = cc.writeErr(reqID, "db owner")
		return
	}

	if err := tx.Commit(); err != nil {
		_ = cc.writeErr(reqID, "db commit")
		return
	}

	// response: chat_id(u64)
	resp := make([]byte, 8)
	binary.BigEndian.PutUint64(resp, chatID)
	_ = cc.writeOK(reqID, resp)
}

func (cc *clientConn) handleDeleteChat(reqID uint16, p []byte) {
	// payload: chat_id(u64), owner_pubkey(32), nonce(str), signature(64)
	off := 0
	chatID, err := rdU64(p, &off)
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
	chatID, err := rdU64(p, &off)
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

	_, err = cc.s.db.Exec(fmt.Sprintf(`INSERT INTO %q(pubkey, nickname, text_rank, perms_flags, accepted_at, last_perm_change, banned)
		VALUES(?,?,?,?,?,?,0)
		ON CONFLICT(pubkey) DO UPDATE SET banned=0, perms_flags=excluded.perms_flags`, usersTbl),
		newUser, "", "", permUser, now, now)
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}
	// TODO add a "user added/entered" system message to the chat
	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleDeleteUser(reqID uint16, p []byte) {
	off := 0
	// "delete" = set banned bit in perms_flags and banned=1
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdU64(p, &off)
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
	_, err = cc.s.db.Exec(fmt.Sprintf(`UPDATE %q SET banned=1, perms_flags=(perms_flags | ?), last_perm_change=? WHERE pubkey=?`, usersTbl),
		permBanned, now, userPK)
	if err != nil {
		_ = cc.writeErr(reqID, "db error")
		return
	}
	// TODO add a "user banned" system message to the chat
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

	var chatIDs []uint64
	for rows.Next() {
		var id uint64
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
		binary.BigEndian.PutUint64(resp[4+i*8:], id)
	}

	_ = cc.writeOK(reqID, resp)
}

func (cc *clientConn) handleLeaveChat(reqID uint16, p []byte) {
	if !cc.authed {
		_ = cc.writeErr(0, "auth required")
		return
	}
	off := 0
	chatID, err := rdU64(p, &off)
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

	// TODO add a "user left" system message to the chat
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
	chatID, err := rdU64(p, &off)
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
	cc.s.subscribe(chatID, cc)
	_ = cc.writeOK(reqID, nil)
}

func (cc *clientConn) handleSendMessage(reqID uint16, p []byte) {
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdU64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	guid, err := rdU64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad message id")
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
		_ = cc.writeErr(reqID, "db error")
		return
	}

	// Store blob in hybrid cache for short-term retention
	key := fmt.Sprintf("%016x:%016x", chatID, guid)
	if err := cc.s.cache.Set(key, blob, 24*time.Hour); err != nil {
		log.Printf("cache set failed: %v", err)
	}

	id, _ := res.LastInsertId()
	// After message successfully inserted:
	out := make([]byte, 8+8+8+4+len(blob))
	binary.BigEndian.PutUint64(out[0:8], chatID)
	binary.BigEndian.PutUint64(out[8:16], uint64(id))
	binary.BigEndian.PutUint64(out[16:24], guid)
	binary.BigEndian.PutUint32(out[24:28], uint32(len(blob)))
	copy(out[28:], blob)

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
	chatID, err := rdU64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	msgID, err := rdU64(p, &off)
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

func (cc *clientConn) handleGetMessage(reqID uint16, p []byte) {
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdU64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad chat id")
		return
	}
	msgID, err := rdU64(p, &off)
	if err != nil {
		_ = cc.writeErr(reqID, "bad message id")
		return
	}
	_, banned, ok := cc.lookupPerms(chatID, cc.pub[:])
	if !ok || banned {
		_ = cc.writeErr(reqID, "not a member or banned")
		return
	}

	msgTbl := fmt.Sprintf("messages-%d", chatID)
	var id int64
	var ts int64
	var guid uint64
	var author []byte
	// Look up GUID for this message in DB
	err = cc.s.db.QueryRow(fmt.Sprintf(`SELECT id, ts, guid, author FROM %q WHERE id=?`, msgTbl), msgID).
		Scan(&id, &ts, &guid, &author)
	if err != nil {
		_ = cc.writeErr(reqID, "not found")
		return
	}

	key := fmt.Sprintf("%016x:%016x", chatID, guid)
	blob, ok, err := cc.s.cache.Get(key)
	if err != nil {
		_ = cc.writeErr(reqID, "cache error")
		return
	}
	if !ok {
		_ = cc.writeErr(reqID, "message expired")
		return
	}

	// response: [message_id(u64)][blob]
	out := make([]byte, 8+4+8+len(blob))
	binary.BigEndian.PutUint64(out[0:8], uint64(id))
	binary.BigEndian.PutUint64(out[8:16], guid)
	binary.BigEndian.PutUint32(out[16:20], uint32(len(blob)))
	copy(out[20:], blob)
	_ = cc.writeOK(reqID, out)
}

func (cc *clientConn) handleGetLastMessageID(reqID uint16, p []byte) {
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}
	chatID, err := rdU64(p, &off)
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
	// payload: to_pubkey(32), chat_id(u64), encrypted_data(blob)
	off := 0
	if !cc.authed {
		_ = cc.writeErr(reqID, "auth required")
		return
	}

	chatID, err := rdU64(p, &off)
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
	_, err = cc.s.db.Exec(`INSERT INTO invites(timestamp, from_pubkey, to_pubkey, chat_id, encrypted_data) VALUES(?,?,?,?,?)`,
		now, cc.pub[:], toPubkey, chatID, encryptedData)
	if err != nil {
		_ = cc.writeErr(reqID, "db insert error")
		return
	}

	// Queue invite for delivery
	var toPubArr [32]byte
	copy(toPubArr[:], toPubkey)
	select {
	case cc.s.inviteQueue <- toPubArr:
		log.Printf("Invite created and queued: from %x… to %x… for chat %d", cc.pub[:4], toPubkey[:4], chatID)
	default:
		log.Printf("Invite queue full, invite stored but not queued: from %x… to %x…", cc.pub[:4], toPubkey[:4])
	}

	_ = cc.writeOK(reqID, nil)
}

// ---------------- utilities ----------------

// Subscribe the connection to a chat
func (s *serverState) subscribe(chatID uint64, cc *clientConn) {
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
	defer s.chatMu.Unlock()
	for chatID := range cc.chats {
		if set, ok := s.chatSubscriptions[chatID]; ok {
			delete(set, cc)
			if len(set) == 0 {
				delete(s.chatSubscriptions, chatID)
			}
		}
	}
	cc.chats = make(map[uint64]struct{})
}

// Broadcast message to all subscribers of chatID except sender
func (s *serverState) broadcastMessage(chatID uint64, sender *clientConn, msgPayload []byte) {
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

func hasAny(v byte, mask byte) bool { return (v & mask) != 0 }

func (cc *clientConn) lookupPerms(chatID uint64, pub []byte) (role byte, banned bool, ok bool) {
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

// inviteDeliveryWorker processes invite delivery queue
func (s *serverState) inviteDeliveryWorker(ctx context.Context) {
	backoff := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case userPub := <-s.inviteQueue:
			// Check if already dialing
			s.inviteDialMu.Lock()
			if _, exists := s.inviteDialers[userPub]; exists {
				s.inviteDialMu.Unlock()
				continue // already being dialed
			}
			s.inviteDialers[userPub] = struct{}{}
			s.inviteDialMu.Unlock()

			// Process this user's invites
			go func(pub [32]byte) {
				defer func() {
					s.inviteDialMu.Lock()
					delete(s.inviteDialers, pub)
					s.inviteDialMu.Unlock()
				}()

				// Try to deliver invites with retry
				for attempt := 0; attempt < 3; attempt++ {
					select {
					case <-ctx.Done():
						return
					default:
					}

					if attempt > 0 {
						select {
						case <-ctx.Done():
							return
						case <-time.After(backoff):
						}
					}

					if s.deliverInvitesToUser(ctx, pub) {
						return // success
					}
					log.Printf("Failed to deliver invites to %x… (attempt %d/3)", pub[:4], attempt+1)
				}
				log.Printf("Giving up on delivering invites to %x… after 3 attempts", pub[:4])
			}(userPub)
		}
	}
}

// inviteCleanupWorker periodically scans for old invites and retries pending ones
func (s *serverState) inviteCleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Run once immediately on startup
	s.processPendingInvites()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processPendingInvites()
		}
	}
}

// processPendingInvites checks all pending invites, deletes old ones, and retries others
func (s *serverState) processPendingInvites() {
	const threeDaysSeconds = 3 * 24 * 60 * 60 // 259200 seconds
	now := time.Now().Unix()

	// Query all pending invites with their unique recipients
	rows, err := s.db.Query(`SELECT DISTINCT to_pubkey, MIN(timestamp) as oldest_ts FROM invites GROUP BY to_pubkey`)
	if err != nil {
		log.Printf("Failed to query pending invites: %v", err)
		return
	}
	defer rows.Close()

	var toDelete [][32]byte
	var toRetry [][32]byte

	for rows.Next() {
		var toPubkey []byte
		var oldestTs int64
		if err := rows.Scan(&toPubkey, &oldestTs); err != nil {
			continue
		}

		age := now - oldestTs
		var pub [32]byte
		copy(pub[:], toPubkey)

		if age > threeDaysSeconds {
			// Mark for deletion
			toDelete = append(toDelete, pub)
		} else {
			// Mark for retry
			toRetry = append(toRetry, pub)
		}
	}

	// Delete old invites
	for _, pub := range toDelete {
		result, err := s.db.Exec(`DELETE FROM invites WHERE to_pubkey=?`, pub[:])
		if err != nil {
			log.Printf("Failed to delete old invites for %x…: %v", pub[:4], err)
		} else {
			if count, _ := result.RowsAffected(); count > 0 {
				log.Printf("Deleted %d old invite(s) for %x… (older than 3 days)", count, pub[:4])
			}
		}
	}

	// Queue for retry (if not already being dialed)
	for _, pub := range toRetry {
		s.inviteDialMu.Lock()
		_, alreadyDialing := s.inviteDialers[pub]
		s.inviteDialMu.Unlock()

		if alreadyDialing {
			continue // skip, already being processed
		}

		// Try to queue (non-blocking)
		select {
		case s.inviteQueue <- pub:
			log.Printf("Queued pending invite retry for %x…", pub[:4])
		default:
			// Queue full, skip this retry cycle
		}
	}

	if len(toDelete) > 0 || len(toRetry) > 0 {
		log.Printf("Invite cleanup: deleted %d old, queued %d for retry", len(toDelete), len(toRetry))
	}
}

// deliverInvitesToUser connects to a user and delivers all pending invites
func (s *serverState) deliverInvitesToUser(ctx context.Context, userPub [32]byte) bool {
	// Fetch all invites for this user
	rows, err := s.db.Query(`SELECT id, timestamp, from_pubkey, chat_id, encrypted_data FROM invites WHERE to_pubkey=?`, userPub[:])
	if err != nil {
		log.Printf("Failed to query invites for %x…: %v", userPub[:4], err)
		return false
	}
	defer rows.Close()

	type invite struct {
		id            int64
		timestamp     int64
		fromPubkey    []byte
		chatID        uint64
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
		return true // no invites to deliver
	}

	// Dial the user
	userPubHex := fmt.Sprintf("%x", userPub[:])
	conn, err := s.transport.DialContext(ctx, "yggdrasil", userPubHex)
	if err != nil {
		log.Printf("Failed to dial %x…: %v", userPub[:4], err)
		return false
	}
	defer conn.Close()

	// Authenticate as mediator
	if !s.authenticateToUser(conn, userPub) {
		log.Printf("Failed to authenticate to %x…", userPub[:4])
		return false
	}

	// Deliver each invite
	success := true
	for _, inv := range invites {
		// Get chat metadata
		var chatName, chatDesc string
		var chatAvatar []byte
		settTbl := fmt.Sprintf("settings-%d", inv.chatID)
		err := s.db.QueryRow(fmt.Sprintf(`SELECT name, description, avatar FROM %q`, settTbl)).
			Scan(&chatName, &chatDesc, &chatAvatar)
		if err != nil {
			log.Printf("Failed to get chat metadata for %d: %v", inv.chatID, err)
			continue
		}

		if s.sendInviteMessage(conn, inv.timestamp, inv.fromPubkey, inv.chatID, chatName, chatDesc, chatAvatar, inv.encryptedData) {
			// Delete invite from database
			_, err := s.db.Exec(`DELETE FROM invites WHERE id=?`, inv.id)
			if err != nil {
				log.Printf("Failed to delete delivered invite %d: %v", inv.id, err)
			} else {
				log.Printf("Successfully delivered invite %d to %x…", inv.id, userPub[:4])
			}
		} else {
			log.Printf("Failed to send invite %d to %x…", inv.id, userPub[:4])
			success = false
		}
	}

	return success
}

// authenticateToUser performs authentication as mediator to user's client
func (s *serverState) authenticateToUser(conn net.Conn, userPub [32]byte) bool {
	// Send GET_NONCE request
	reqID := uint16(1)
	payload := s.pub[:]

	var reqFrame [8]byte
	reqFrame[0] = version
	reqFrame[1] = cmdGetNonce
	binary.BigEndian.PutUint16(reqFrame[2:4], reqID)
	binary.BigEndian.PutUint32(reqFrame[4:8], uint32(len(payload)))

	if _, err := conn.Write(reqFrame[:]); err != nil {
		return false
	}
	if _, err := conn.Write(payload); err != nil {
		return false
	}

	// Read nonce response
	var respHdr [7]byte
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return false
	}
	if _, err := io.ReadFull(conn, respHdr[:]); err != nil {
		return false
	}

	if respHdr[0] != statusOK {
		return false
	}

	payloadLen := binary.BigEndian.Uint32(respHdr[3:7])
	if payloadLen != 32 {
		return false
	}

	var nonce [32]byte
	if _, err := io.ReadFull(conn, nonce[:]); err != nil {
		return false
	}

	// Sign nonce
	signature := ed25519.Sign(s.priv, nonce[:])

	// Send AUTH request
	reqID = 2
	authPayload := make([]byte, 32+32+64)
	copy(authPayload[0:32], s.pub[:])
	copy(authPayload[32:64], nonce[:])
	copy(authPayload[64:128], signature)

	reqFrame[0] = version
	reqFrame[1] = cmdAuth
	binary.BigEndian.PutUint16(reqFrame[2:4], reqID)
	binary.BigEndian.PutUint32(reqFrame[4:8], uint32(len(authPayload)))

	if _, err := conn.Write(reqFrame[:]); err != nil {
		return false
	}
	if _, err := conn.Write(authPayload); err != nil {
		return false
	}

	// Read AUTH response
	if _, err := io.ReadFull(conn, respHdr[:]); err != nil {
		return false
	}

	return respHdr[0] == statusOK
}

// sendInviteMessage sends an invitation notification to connected user
func (s *serverState) sendInviteMessage(conn net.Conn, timestamp int64, fromPubkey []byte, chatID uint64, chatName, chatDesc string, chatAvatar, encryptedData []byte) bool {

	// Build payload: timestamp(8), from_pubkey(32), chat_id(8),
	// chat_name(str), chat_desc(str), chat_avatar(blob), encrypted_data(blob)
	payloadSize := 8 + 32 + 8 +
		2 + len(chatName) +
		2 + len(chatDesc) +
		4 + len(chatAvatar) +
		4 + len(encryptedData)

	payload := make([]byte, payloadSize)
	off := 0

	// timestamp
	binary.BigEndian.PutUint64(payload[off:], uint64(timestamp))
	off += 8

	// from_pubkey
	copy(payload[off:], fromPubkey)
	off += 32

	// chat_id
	binary.BigEndian.PutUint64(payload[off:], chatID)
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

	// Send as cmdGotInvite (no request/response, just notification)
	var frame [8]byte
	frame[0] = version
	frame[1] = cmdGotInvite
	binary.BigEndian.PutUint16(frame[2:4], 0) // reqID=0 for notifications
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))

	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return false
	}
	if _, err := conn.Write(frame[:]); err != nil {
		return false
	}
	if _, err := conn.Write(payload); err != nil {
		return false
	}

	return true
}

// ---------------- end ----------------
