package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TLV Tag definitions (purpose-based)
const (
	// Authentication & Crypto
	TAG_PUBKEY    = 0x01 // 32 bytes - client's public key
	TAG_SIGNATURE = 0x02 // 64 bytes - Ed25519 signature
	TAG_NONCE     = 0x03 // 32 bytes - challenge nonce
	TAG_COUNTER   = 0x04 // 4 bytes u32 - PoW counter

	// Identifiers
	TAG_CHAT_ID      = 0x10 // 8 bytes i64
	TAG_MESSAGE_ID   = 0x11 // 8 bytes i64/u64
	TAG_MESSAGE_GUID = 0x12 // 8 bytes i64
	TAG_INVITE_ID    = 0x13 // 8 bytes i64
	TAG_SINCE_ID     = 0x14 // 8 bytes i64 - for fetching since
	TAG_USER_PUBKEY  = 0x15 // 32 bytes - target user (not self)

	// Variable Data
	TAG_CHAT_NAME    = 0x20 // string
	TAG_CHAT_DESC    = 0x21 // string
	TAG_CHAT_AVATAR  = 0x22 // blob
	TAG_MESSAGE_BLOB = 0x23 // blob
	TAG_MEMBER_INFO  = 0x24 // blob (encrypted)
	TAG_INVITE_DATA  = 0x25 // blob (encrypted)

	// Scalars
	TAG_LIMIT       = 0x30 // 4 bytes u32 - query limit
	TAG_COUNT       = 0x31 // 4 bytes u32 - array count
	TAG_TIMESTAMP   = 0x32 // 8 bytes u64
	TAG_PERMS       = 0x33 // 1 byte - permission flags
	TAG_ONLINE      = 0x34 // 1 byte - online status
	TAG_ACCEPTED    = 0x35 // 1 byte - invite response
	TAG_LAST_UPDATE = 0x36 // 8 bytes u64 - for incremental sync
	TAG_LAST_SEEN   = 0x37 // 8 bytes u64 - Unix timestamp in seconds
)

// TLVField represents a single Type-Length-Value field
type TLVField struct {
	Tag   byte
	Value []byte
}

// TLVMap is a map of tag to value for easy access
type TLVMap map[byte][]byte

// writeVarint writes a variable-length integer (up to 4 bytes, 28 bits)
// Uses Protocol Buffers style encoding: 7 bits data + 1 bit continuation flag
func writeVarint(w io.Writer, value uint32) error {
	for i := 0; i < 4; i++ {
		b := byte(value & 0x7F) // Take lowest 7 bits
		value >>= 7
		if value != 0 {
			b |= 0x80 // Set continuation bit
		}
		if _, err := w.Write([]byte{b}); err != nil {
			return err
		}
		if value == 0 {
			return nil
		}
	}
	return errors.New("varint overflow: value too large for 4 bytes")
}

// readVarint reads a variable-length integer from a byte reader
func readVarint(r io.ByteReader) (uint32, error) {
	var result uint32
	var shift uint
	for i := 0; i < 4; i++ { // Max 4 bytes
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		result |= uint32(b&0x7F) << shift
		if (b & 0x80) == 0 {
			return result, nil
		}
		shift += 7
	}
	return 0, errors.New("varint overflow: more than 4 bytes")
}

// readVarintFromBytes reads a varint from a byte slice at the given offset
// Returns the value and the number of bytes consumed
func readVarintFromBytes(data []byte, offset int) (uint32, int, error) {
	var result uint32
	var shift uint
	consumed := 0
	for i := 0; i < 4; i++ {
		if offset+i >= len(data) {
			return 0, 0, errors.New("varint: unexpected end of data")
		}
		b := data[offset+i]
		consumed++
		result |= uint32(b&0x7F) << shift
		if (b & 0x80) == 0 {
			return result, consumed, nil
		}
		shift += 7
	}
	return 0, 0, errors.New("varint overflow: more than 4 bytes")
}

// writeTLV writes a single TLV field to the writer
func writeTLV(w io.Writer, tag byte, value []byte) error {
	// Write tag
	if _, err := w.Write([]byte{tag}); err != nil {
		return err
	}
	// Write length as varint
	if err := writeVarint(w, uint32(len(value))); err != nil {
		return err
	}
	// Write value
	if len(value) > 0 {
		if _, err := w.Write(value); err != nil {
			return err
		}
	}
	return nil
}

// parseTLVs parses a TLV-encoded payload and returns a map of tag -> value
func parseTLVs(payload []byte) (TLVMap, error) {
	result := make(TLVMap)
	offset := 0

	for offset < len(payload) {
		// Read tag
		if offset >= len(payload) {
			break
		}
		tag := payload[offset]
		offset++

		// Read length (varint)
		length, consumed, err := readVarintFromBytes(payload, offset)
		if err != nil {
			return nil, fmt.Errorf("error reading length for tag 0x%02X: %v", tag, err)
		}
		offset += consumed

		// Read value
		if offset+int(length) > len(payload) {
			return nil, fmt.Errorf("tag 0x%02X length %d exceeds payload bounds", tag, length)
		}
		value := payload[offset : offset+int(length)]
		offset += int(length)

		// Store in map (later occurrence overwrites earlier)
		result[tag] = value
	}

	return result, nil
}

// TLV helper functions for common data types

// tlvGetBytes extracts a byte array from TLVMap, returns error if missing or wrong size
func tlvGetBytes(m TLVMap, tag byte, expectedSize int) ([]byte, error) {
	val, ok := m[tag]
	if !ok {
		return nil, fmt.Errorf("missing required tag 0x%02X", tag)
	}
	if expectedSize > 0 && len(val) != expectedSize {
		return nil, fmt.Errorf("tag 0x%02X: expected %d bytes, got %d", tag, expectedSize, len(val))
	}
	return val, nil
}

// tlvGetBytesOptional extracts bytes, returns nil if missing
func tlvGetBytesOptional(m TLVMap, tag byte) []byte {
	return m[tag]
}

// tlvGetU64 extracts a big-endian u64
func tlvGetU64(m TLVMap, tag byte) (uint64, error) {
	val, err := tlvGetBytes(m, tag, 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(val), nil
}

// tlvGetI64 extracts a big-endian i64
func tlvGetI64(m TLVMap, tag byte) (int64, error) {
	val, err := tlvGetU64(m, tag)
	return int64(val), err
}

// tlvGetU32 extracts a big-endian u32
func tlvGetU32(m TLVMap, tag byte) (uint32, error) {
	val, err := tlvGetBytes(m, tag, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(val), nil
}

// tlvGetU8 extracts a single byte
func tlvGetU8(m TLVMap, tag byte) (byte, error) {
	val, err := tlvGetBytes(m, tag, 1)
	if err != nil {
		return 0, err
	}
	return val[0], nil
}

// tlvGetString extracts a UTF-8 string
func tlvGetString(m TLVMap, tag byte) (string, error) {
	val, ok := m[tag]
	if !ok {
		return "", fmt.Errorf("missing required tag 0x%02X", tag)
	}
	return string(val), nil
}

// tlvGetStringOptional extracts a string, returns empty if missing
func tlvGetStringOptional(m TLVMap, tag byte) string {
	val := m[tag]
	if val == nil {
		return ""
	}
	return string(val)
}

// TLV encoding helper functions

// tlvEncodeBytes encodes a byte array into a buffer
func tlvEncodeBytes(w io.Writer, tag byte, value []byte) error {
	return writeTLV(w, tag, value)
}

// tlvEncodeU64 encodes a u64 as big-endian
func tlvEncodeU64(w io.Writer, tag byte, value uint64) error {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)
	return writeTLV(w, tag, buf)
}

// tlvEncodeI64 encodes an i64 as big-endian
func tlvEncodeI64(w io.Writer, tag byte, value int64) error {
	return tlvEncodeU64(w, tag, uint64(value))
}

// tlvEncodeU32 encodes a u32 as big-endian
func tlvEncodeU32(w io.Writer, tag byte, value uint32) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	return writeTLV(w, tag, buf)
}

// tlvEncodeU8 encodes a single byte
func tlvEncodeU8(w io.Writer, tag byte, value byte) error {
	return writeTLV(w, tag, []byte{value})
}

// tlvEncodeString encodes a UTF-8 string
func tlvEncodeString(w io.Writer, tag byte, value string) error {
	return writeTLV(w, tag, []byte(value))
}

// buildTLVPayload is a helper to build a complete TLV payload
// Returns the payload bytes
func buildTLVPayload(buildFunc func(w io.Writer) error) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := buildFunc(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}